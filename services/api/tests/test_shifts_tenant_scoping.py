"""Every query in the shifts module is scoped to the caller's tenant EXPLICITLY, not only by row-level security.

The module's own header said every query was "automatically filtered to the current tenant by Postgres row-level security". Row-level security does not apply to a superuser, which is what every service connects as in the default
deployment, so there, for any authenticated tenant: GET /shifts listed every tenant's shifts; POST /shifts closed EVERY tenant's active shift; PUT /shifts/{id}/handoff overwrote any tenant's shift; and GET /shifts/handoff-items returned every
tenant's open alerts. Found by a two-tenant flow test of the real API: 6 of 70 steps failed as the superuser (and none as the non-superuser, which is the point of RLS). The module had no tests at all.
These call the handlers with a fake database and assert that every statement touching a tenant table filters on, and binds, the caller's tenant.
"""
from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import shifts as shifts_mod
from app.api.v1.endpoints.shifts import (
    HandoffNotes,
    ShiftCreate,
    add_handoff_notes,
    create_shift,
    get_current_shift,
    list_handoff_items,
    list_shifts,
)
from fastapi import HTTPException

TENANT_TABLES = ("aisoc_shifts", "alerts", "cases")


def _user(tenant: uuid.UUID | None = None) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant or uuid.uuid4(), role="analyst", email="a@example.com")


def _shift_row(**over: Any) -> Any:
    base = {
        "id": uuid.uuid4(), "name": "Day shift", "status": "active", "lead_id": None, "lead_name": None, "lead_role": None, "analyst_count": 1,
        "alerts_handled": 0, "escalations": 0, "handoff_notes": None, "started_at": datetime.now(UTC), "ended_at": None,
    }
    base.update(over)
    return SimpleNamespace(_mapping=base, **base)


def _item_row(**over: Any) -> Any:
    base = {"id": uuid.uuid4(), "title": "t", "priority": "high", "status": "new", "assigned_to_id": None, "notes": None}
    base.update(over)
    return SimpleNamespace(**base)


def _db(*payloads: Any) -> MagicMock:
    """A fake session that records (sql, params) for every execute() and returns the queued results. Params are the SECOND argument here (these handlers do not use bindparams)."""
    db = MagicMock()
    db.executed = []
    queue = iter(payloads)

    async def _execute(clause: Any, params: dict | None = None, *a: Any, **k: Any) -> MagicMock:
        db.executed.append((re.sub(r"\s+", " ", str(clause)).strip(), dict(params or {})))
        payload = next(queue, None)
        result = MagicMock()
        rows = payload if isinstance(payload, list) else ([payload] if payload is not None else [])
        result.fetchall = MagicMock(return_value=rows)
        result.fetchone = MagicMock(return_value=rows[0] if rows else None)
        return result

    db.execute = AsyncMock(side_effect=_execute)
    db.commit = AsyncMock()
    return db


def _assert_scoped(db: Any, tenant: uuid.UUID, *, expect_statements: int | None = None) -> None:
    touching = [(sql, params) for sql, params in db.executed if any(t in sql for t in TENANT_TABLES)]
    assert touching, "no statement touched a tenant table"
    if expect_statements is not None:
        assert len(touching) == expect_statements
    for sql, params in touching:
        if sql.upper().startswith("INSERT"):
            assert params["tenant_id"] == str(tenant), f"INSERT without the caller's tenant: {sql}"
            continue
        assert "tenant_id = :tenant_id" in sql, f"statement is not tenant-scoped: {sql}"
        assert params.get("tenant_id") == str(tenant), f"wrong or missing tenant bound: {params} for {sql}"


@pytest.mark.asyncio
class TestEveryHandlerScopesToTheCallersTenant:
    async def test_list_shifts(self) -> None:
        user = _user()
        db = _db([_shift_row()])
        await list_shifts(current_user=user, db=db, status_filter=None, limit=20)
        _assert_scoped(db, user.tenant_id, expect_statements=1)

    async def test_list_shifts_with_a_status_filter_keeps_the_tenant_filter(self) -> None:
        user = _user()
        db = _db([_shift_row()])
        await list_shifts(current_user=user, db=db, status_filter="active", limit=5)
        _assert_scoped(db, user.tenant_id)
        assert db.executed[0][1]["status"] == "active" and db.executed[0][1]["limit"] == 5

    async def test_get_current_shift(self) -> None:
        user = _user()
        db = _db(_shift_row())
        await get_current_shift(current_user=user, db=db)
        _assert_scoped(db, user.tenant_id, expect_statements=1)

    async def test_creating_a_shift_closes_only_the_callers_active_shift(self) -> None:
        """It used to close EVERY tenant's active shift whenever any tenant started one."""
        user = _user()
        db = _db(None, _shift_row())
        await create_shift(body=ShiftCreate(name="Night"), current_user=user, db=db)
        _assert_scoped(db, user.tenant_id, expect_statements=2)
        closing = db.executed[0][0]
        assert closing.upper().startswith("UPDATE AISOC_SHIFTS") and "status = 'active' AND tenant_id = :tenant_id" in closing
        assert db.executed[1][0].upper().startswith("INSERT INTO AISOC_SHIFTS")

    async def test_handoff_items_scopes_both_the_alerts_and_the_cases_query(self) -> None:
        """It used to return EVERY tenant's open alerts (titles and AI summaries) to any analyst."""
        user = _user()
        db = _db([_item_row()], [_item_row()])
        await list_handoff_items(current_user=user, db=db, priority=None, limit=50)
        _assert_scoped(db, user.tenant_id, expect_statements=2)
        assert {t for sql, _ in db.executed for t in ("FROM alerts", "FROM cases") if t in sql} == {"FROM alerts", "FROM cases"}

    async def test_handoff_items_with_a_priority_filter_keeps_the_tenant_filter(self) -> None:
        user = _user()
        db = _db([_item_row()], [_item_row()])
        await list_handoff_items(current_user=user, db=db, priority="critical", limit=10)
        _assert_scoped(db, user.tenant_id, expect_statements=2)
        assert all(p["priority"] == "critical" and p["limit"] == 10 for _, p in db.executed)

    async def test_the_handoff_write_names_the_shift_and_the_tenant(self) -> None:
        """It used to overwrite ANY tenant's shift by id."""
        user = _user()
        db = _db(_shift_row(status="completed"))
        await add_handoff_notes(shift_id=str(uuid.uuid4()), body=HandoffNotes(notes="n"), current_user=user, db=db)
        _assert_scoped(db, user.tenant_id, expect_statements=1)
        assert "WHERE id::text = :shift_id AND tenant_id = :tenant_id" in db.executed[0][0]
        db.commit.assert_awaited_once()

    async def test_another_tenants_shift_is_a_404_and_nothing_is_committed(self) -> None:
        user = _user()
        db = _db(None)  # the scoped UPDATE matches no row
        with pytest.raises(HTTPException) as exc:
            await add_handoff_notes(shift_id=str(uuid.uuid4()), body=HandoffNotes(notes="n"), current_user=user, db=db)
        assert exc.value.status_code == 404 and exc.value.detail == "Shift not found"
        db.commit.assert_not_awaited()

    async def test_no_active_shift_for_this_tenant_is_a_404(self) -> None:
        with pytest.raises(HTTPException) as exc:
            await get_current_shift(current_user=_user(), db=_db(None))
        assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_two_tenants_bind_two_different_tenant_ids() -> None:
    a, b = _user(), _user()
    db_a, db_b = _db([_shift_row()]), _db([_shift_row()])
    await list_shifts(current_user=a, db=db_a, status_filter=None, limit=20)
    await list_shifts(current_user=b, db=db_b, status_filter=None, limit=20)
    assert db_a.executed[0][1]["tenant_id"] == str(a.tenant_id) != db_b.executed[0][1]["tenant_id"] == str(b.tenant_id)


class TestStaticGuard:
    """Independent of the fake database: no statement in the source may touch a tenant table without filtering on tenant_id."""

    SRC = Path(shifts_mod.__file__).read_text(encoding="utf-8")

    def statements(self) -> list[str]:
        return [m.group(1) for m in re.finditer(r'text\(\s*f?"""(.*?)"""', self.SRC, re.S)]

    def test_there_are_statements_to_check(self) -> None:
        assert len(self.statements()) >= 7

    def test_every_select_and_update_on_a_tenant_table_filters_on_the_tenant(self) -> None:
        offenders = []
        for sql in self.statements():
            flat = re.sub(r"\s+", " ", sql).strip()
            if re.match(r"(SELECT|UPDATE)", flat, re.I) and any(re.search(rf"\b(FROM|UPDATE) {t}\b", flat) for t in TENANT_TABLES) and "tenant_id = :tenant_id" not in flat:
                offenders.append(flat[:90])
        assert offenders == [], f"statements that rely on RLS alone: {offenders}"

    def test_the_module_no_longer_claims_rls_alone_does_the_filtering(self) -> None:
        assert "automatically filtered to the current tenant by\nPostgres row-level security" not in self.SRC
        assert "ALSO filtered to the current tenant explicitly" in self.SRC
