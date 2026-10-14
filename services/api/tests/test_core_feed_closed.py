"""CORE's closed-incident report: which alerts it may resolve, and which it must leave alone."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.inbox_core_feed import ClosedItem, ClosedReport, apply_closed
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

TENANT = uuid.uuid4()


def _db(rowcounts):
    db = MagicMock()
    db.executed = []

    async def execute(stmt, *a, **k):
        db.executed.append(stmt)
        return MagicMock(rowcount=rowcounts.pop(0))

    db.execute = AsyncMock(side_effect=execute)
    return db


def _sql(stmt) -> tuple[str, dict]:
    compiled = stmt.compile(dialect=postgresql.dialect())
    return str(compiled), compiled.params


def test_a_report_rejects_ids_and_vendors_that_could_be_abused():
    with pytest.raises(ValidationError):
        ClosedItem(uid='huntress:1"|.*')
    with pytest.raises(ValidationError):
        ClosedReport(vendor="Huntress; DROP", closed=[])
    with pytest.raises(ValidationError):
        ClosedReport(vendor="huntress", closed=[ClosedItem(uid=f"huntress:{i}") for i in range(501)])


@pytest.mark.asyncio
async def test_only_new_alerts_in_this_tenant_for_this_vendor_are_resolved():
    db = _db([2])
    rep = ClosedReport(
        vendor="huntress", closed=[ClosedItem(uid="huntress:1", state="resolved"), ClosedItem(uid="petra:9"), ClosedItem(uid="huntress:2")]
    )
    assert await apply_closed(db, TENANT, rep) == 2
    sql, params = _sql(db.executed[0])
    assert sql.lower().startswith("update alerts")
    assert "tenant_id" in sql and "status = " in sql
    assert TENANT in params.values()
    assert "new" in params.values() and "resolved" in params.values()
    assert "raw_event" in sql and " IN " in sql.upper(), sql
    ids = [v for v in params.values() if isinstance(v, list | tuple)]
    flat = {x for v in ids for x in v if str(x).startswith("huntress:")}
    assert flat == {"huntress:1", "huntress:2"}, "only this vendor's incident ids are matched, and exactly (no pattern matching)"


@pytest.mark.asyncio
async def test_nothing_to_do_makes_no_database_call():
    db = _db([])
    assert await apply_closed(db, TENANT, ClosedReport(vendor="huntress", closed=[ClosedItem(uid="petra:1")])) == 0
    assert db.executed == []


@pytest.mark.asyncio
async def test_many_ids_are_applied_in_chunks_and_counted():
    db = _db([100, 100, 30])
    rep = ClosedReport(vendor="huntress", closed=[ClosedItem(uid=f"huntress:{i}") for i in range(230)])
    assert await apply_closed(db, TENANT, rep) == 230
    assert len(db.executed) == 3
