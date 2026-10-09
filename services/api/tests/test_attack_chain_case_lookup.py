"""GET /cases/{id}/attack-chain finds the case in aisoc_cases, where the cases API writes it.

The endpoint looked the case up in the old `cases` table, which nothing writes, so it answered 404 case_not_found for EVERY real case (shown on real Postgres, and fixed there: a case with no alerts is 200 case_has_no_linked_alerts, a case linked to an alert finds it as the
seed, tenant B and a nonexistent id still get 404).
"""
import re
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import attack_chain as ac


def user():
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="analyst", email="a@example.test")


def fake_db(*results):
    """execute() answers queued results in order; each result is a Row-like (for .first()) or None. Statements are recorded as (sql, params)."""
    db = MagicMock()
    db.executed = []
    queue = iter(results)

    async def execute(stmt, params=None, *a, **k):
        db.executed.append((" ".join(str(stmt).split()), params if params is not None else dict(stmt.compile().params)))
        payload = next(queue, None)
        res = MagicMock()
        res.first.return_value = payload
        res.scalar_one_or_none.return_value = None
        return res

    db.execute = AsyncMock(side_effect=execute)
    return db


async def call(db, u, case_id=None):
    return await ac.get_attack_chain(case_id=case_id or uuid.uuid4(), db=db, user=u, window="24h")


@pytest.mark.asyncio
class TestTheLookup:
    async def test_it_reads_aisoc_cases_scoped_by_id_and_tenant(self):
        u, cid = user(), uuid.uuid4()
        db = fake_db(SimpleNamespace(alert_ids=[]))
        await call(db, u, cid)
        sql, params = db.executed[0]
        assert sql == "SELECT alert_ids FROM aisoc_cases WHERE id = :id AND tenant_id = :tid" and params == {"id": cid, "tid": u.tenant_id}
        assert not re.search(r"FROM cases\b", sql)

    async def test_a_missing_case_is_404_case_not_found(self):
        with pytest.raises(HTTPException) as exc:
            await call(fake_db(None), user())
        assert exc.value.status_code == 404 and exc.value.detail == "case_not_found"

    async def test_another_tenants_case_looks_exactly_like_a_missing_one(self):
        """The lookup matches no row for the caller's tenant, so the answer is the same 404."""
        with pytest.raises(HTTPException) as exc:
            await call(fake_db(None), user())
        assert (exc.value.status_code, exc.value.detail) == (404, "case_not_found")

    async def test_a_case_with_no_alerts_is_an_empty_chain_not_an_error(self):
        u, cid = user(), uuid.uuid4()
        out = await call(fake_db(SimpleNamespace(alert_ids=[])), u, cid)
        assert out["reason"] == "case_has_no_linked_alerts" and out["chain"] == [] and out["seed_alert_id"] is None
        assert out["case_id"] == str(cid) and out["tenant_id"] == str(u.tenant_id)

    async def test_null_alert_ids_are_treated_as_none(self):
        out = await call(fake_db(SimpleNamespace(alert_ids=None)), user())
        assert out["reason"] == "case_has_no_linked_alerts"

    async def test_the_alerts_on_the_case_are_looked_up_within_the_tenant(self):
        u, a1, a2 = user(), uuid.uuid4(), uuid.uuid4()
        db = fake_db(SimpleNamespace(alert_ids=[a1, str(a2)]))
        await call(db, u)
        assert len(db.executed) >= 2
        sql, params = db.executed[1]
        assert "FROM alerts" in sql and "tenant_id" in sql and u.tenant_id in params.values()
        flat = str(params.values())
        assert str(a1) in flat or a1.hex in flat


def test_the_legacy_case_model_is_gone_from_the_endpoint():
    src = (Path(ac.__file__)).read_text(encoding="utf-8")
    assert "app.models.case" not in src and "select(Case)" not in src and "aisoc_cases" in src
