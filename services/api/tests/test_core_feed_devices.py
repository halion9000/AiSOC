"""CORE's device report: it names the machine on stored alerts that have none, and touches nothing else."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.inbox_core_feed import DeviceItem, DevicesReport, apply_devices
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


def _sql(stmt):
    compiled = stmt.compile(dialect=postgresql.dialect())
    return str(compiled), compiled.params


def test_a_report_rejects_a_bad_vendor_an_empty_host_and_too_many_items():
    with pytest.raises(ValidationError):
        DevicesReport(vendor="Huntress; DROP", items=[])
    with pytest.raises(ValidationError):
        DeviceItem(uid="huntress:1", hostname="")
    with pytest.raises(ValidationError):
        DevicesReport(vendor="huntress", items=[DeviceItem(uid=f"huntress:{i}", hostname="h") for i in range(501)])


@pytest.mark.asyncio
async def test_only_alerts_of_this_vendor_in_this_tenant_with_no_host_are_updated():
    db = _db([1, 1])
    report = DevicesReport(vendor="huntress", items=[DeviceItem(uid="huntress:1", hostname="WS-1"), DeviceItem(uid="petra:9", hostname="X"), DeviceItem(uid="huntress:2", hostname="  WS-2  ")])
    assert await apply_devices(db, TENANT, report) == 2
    assert len(db.executed) == 2, "the other vendor's uid is skipped without a query"
    sql, params = _sql(db.executed[0])
    assert sql.lower().startswith("update alerts")
    assert "tenant_id" in sql and TENANT in params.values()
    assert "jsonb_array_length" in sql.lower() and "affected_hosts" in sql, "only an EMPTY host list may be filled"
    assert ["WS-1"] in params.values() and "huntress:1" in params.values()
    assert ["WS-2"] in _sql(db.executed[1])[1].values(), "the name is trimmed"


@pytest.mark.asyncio
async def test_a_blank_hostname_after_trimming_changes_nothing():
    db = _db([])
    report = DevicesReport(vendor="huntress", items=[DeviceItem(uid="huntress:1", hostname="   ")])
    assert await apply_devices(db, TENANT, report) == 0
    assert db.executed == []


@pytest.mark.asyncio
async def test_the_count_is_what_the_database_reports_updated():
    db = _db([0, 1])  # the first alert already has a host, the second did not
    report = DevicesReport(vendor="huntress", items=[DeviceItem(uid="huntress:1", hostname="A"), DeviceItem(uid="huntress:2", hostname="B")])
    assert await apply_devices(db, TENANT, report) == 1
