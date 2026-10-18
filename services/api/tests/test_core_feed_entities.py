"""CORE's entity report: it gives stored alerts the host, user and address a vendor's evidence names, only where those lists are empty."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.inbox_core_feed import EntitiesReport, EntityItem, apply_entities
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


def test_a_report_rejects_a_bad_vendor_and_too_many_items():
    with pytest.raises(ValidationError):
        EntitiesReport(vendor="Blumira; DROP", items=[])
    with pytest.raises(ValidationError):
        EntitiesReport(vendor="blumira", items=[EntityItem(uid=f"blumira:{i}", username="u") for i in range(501)])


@pytest.mark.asyncio
async def test_each_given_field_updates_only_an_empty_list_of_this_vendors_alert_in_this_tenant():
    db = _db([1, 1, 1])
    report = EntitiesReport(vendor="blumira", items=[EntityItem(uid="blumira:1", hostname="WS-1", username="  a@b.com ", src_ip="203.0.113.9"), EntityItem(uid="petra:9", username="x")])
    assert await apply_entities(db, TENANT, report) == 3
    assert len(db.executed) == 3, "one update per field given, and the other vendor's uid is skipped without a query"
    columns = []
    for stmt in db.executed:
        sql, params = _sql(stmt)
        assert sql.lower().startswith("update alerts") and TENANT in params.values() and "blumira:1" in params.values()
        assert "jsonb_array_length" in sql.lower(), "only an EMPTY list may be filled"
        columns.append([c for c in ("affected_hosts", "affected_users", "affected_ips") if f"{c} =" in sql.replace("  ", " ") or f"SET {c}" in sql][0])
    assert columns == ["affected_hosts", "affected_users", "affected_ips"]
    assert ["a@b.com"] in _sql(db.executed[1])[1].values(), "the value is trimmed"


@pytest.mark.asyncio
async def test_blank_and_missing_fields_change_nothing():
    db = _db([])
    report = EntitiesReport(vendor="blumira", items=[EntityItem(uid="blumira:1", hostname="   "), EntityItem(uid="blumira:2")])
    assert await apply_entities(db, TENANT, report) == 0
    assert db.executed == []


@pytest.mark.asyncio
async def test_the_count_is_what_the_database_reports_updated():
    db = _db([0, 1])  # the first alert already has a user, the second did not
    report = EntitiesReport(vendor="blumira", items=[EntityItem(uid="blumira:1", username="a"), EntityItem(uid="blumira:2", username="b")])
    assert await apply_entities(db, TENANT, report) == 1


@pytest.mark.asyncio
async def test_a_link_is_set_only_on_an_alert_that_has_none_and_only_when_it_is_https():
    db = _db([1])
    report = EntitiesReport(vendor="huntress", items=[EntityItem(uid="huntress:1", url="https://acme.huntress.io/account/infection_reports/1")])
    assert await apply_entities(db, TENANT, report) == 1
    assert len(db.executed) == 1
    sql, params = _sql(db.executed[0])
    assert sql.lower().startswith("update alerts") and TENANT in params.values() and "huntress:1" in params.values()
    assert "raw_event" in sql and "IS NULL" in sql.upper(), "an alert that already has a link keeps it"
    assert {"url": "https://acme.huntress.io/account/infection_reports/1"} in params.values()
    with pytest.raises(ValidationError):
        EntityItem(uid="huntress:1", url="javascript:alert(1)")
    with pytest.raises(ValidationError):
        EntityItem(uid="huntress:1", url="http://insecure.example.com/x")
