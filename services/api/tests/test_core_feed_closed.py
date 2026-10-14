"""CORE's closed-incident report: which alerts it may resolve, and which it must leave alone."""

import re
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.inbox_core_feed import ClosedItem, ClosedReport, apply_closed, closed_uid_regex
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


def test_the_regex_matches_only_the_exact_incident_ids():
    pattern = closed_uid_regex(["huntress:4821", "huntress:7"])
    assert re.search(pattern, '{"finding":{"uid":"huntress:4821","title":"x"}}')
    assert re.search(pattern, '{"finding": {"uid": "huntress:7"}}')
    assert not re.search(pattern, '{"finding":{"uid":"huntress:48210"}}'), "a longer id must not match"
    assert not re.search(pattern, '{"finding":{"uid":"huntress:482"}}')
    assert not re.search(pattern, '{"finding":{"uid":"petra:4821"}}')


def test_dots_in_ids_are_literal_not_wildcards():
    assert not re.search(closed_uid_regex(["petra:a.b"]), '{"uid":"petra:aXb"}')


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
    pattern = next(v for v in params.values() if isinstance(v, str) and "huntress:1" in v)
    assert "petra:9" not in pattern, "an id for another vendor is ignored"


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
