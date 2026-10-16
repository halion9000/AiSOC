"""The connector run log: an entry only when a source's status or message CHANGES, trimmed to the newest 200, readable only by the connector's own tenant."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import connectors as connectors_endpoint
from app.api.v1.endpoints import inbox_core_feed as cf
from app.services import connector_run_log as log
from fastapi import HTTPException
from sqlalchemy.dialects import postgresql

TENANT, OTHER, CONNECTOR = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


def _sql(stmt):
    c = stmt.compile(dialect=postgresql.dialect())
    return str(c), c.params


def _db(last=None):
    """A session whose first query (the last logged entry) answers ``last``; everything else is recorded."""
    db = MagicMock()
    db.executed, db.added = [], []

    async def execute(stmt, *a, **k):
        db.executed.append(stmt)
        r = MagicMock()
        r.first.return_value = last
        return r

    db.execute = AsyncMock(side_effect=execute)
    db.add = MagicMock(side_effect=db.added.append)
    db.flush = AsyncMock()
    return db


async def _record(db, status="warning", message="48 device(s) belong to clients not mapped yet", fetched=5, sent=5):
    return await log.record_if_changed(db, TENANT, CONNECTOR, status=status, message=message, fetched=fetched, sent=sent, now=NOW)


# ---- when an entry is written ----------------------------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_first_report_is_logged_with_everything_the_card_would_show():
    db = _db(last=None)
    assert await _record(db) is True
    (entry,) = db.added
    assert (entry.tenant_id, entry.connector_id, entry.at) == (TENANT, CONNECTOR, NOW)
    assert (entry.status, entry.message, entry.fetched, entry.sent) == ("warning", "48 device(s) belong to clients not mapped yet", 5, 5)


@pytest.mark.asyncio
async def test_the_same_status_and_message_again_is_not_logged_again():
    db = _db(last=NS(status="warning", message="48 device(s) belong to clients not mapped yet"))
    assert await _record(db) is False
    assert db.added == [] and len(db.executed) == 1, "only the lookup ran: nothing written, nothing trimmed"


@pytest.mark.asyncio
async def test_a_different_message_with_the_same_status_is_logged():
    db = _db(last=NS(status="warning", message="47 device(s) belong to clients not mapped yet"))
    assert await _record(db) is True and len(db.added) == 1


@pytest.mark.asyncio
async def test_a_different_status_with_the_same_message_is_logged():
    db = _db(last=NS(status="error", message="same words"))
    assert await _record(db, status="warning", message="same words") is True


@pytest.mark.asyncio
async def test_recovery_to_ok_is_logged_once_and_then_ok_after_ok_is_not():
    after_warning = _db(last=NS(status="warning", message="x"))
    assert await _record(after_warning, status="ok", message=None) is True
    assert after_warning.added[0].message is None
    after_ok = _db(last=NS(status="ok", message=None))
    assert await _record(after_ok, status="ok", message=None) is False


def test_whitespace_and_empty_messages_count_as_no_message():
    assert log.clean_message("  hello  ") == "hello"
    assert log.clean_message("   ") is None and log.clean_message(None) is None and log.clean_message("") is None
    assert log.differs_from_last(NS(status="ok", message="  "), "ok", None) is False


# ---- trimming ------------------------------------------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_after_a_write_only_the_newest_200_of_this_connector_are_kept():
    db = _db(last=None)
    await _record(db)
    sql, params = _sql(db.executed[-1])
    assert sql.startswith("DELETE FROM connector_run_log") and "NOT IN" in sql
    assert "connector_id =" in sql.split("NOT IN")[0], "the delete itself, not just the list of rows to keep, is limited to this connector"
    assert CONNECTOR in params.values() and log.LOG_KEEP == 200 and 200 in params.values()


# ---- the status report writes the log ---------------------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_report_logs_the_message_for_a_warning_but_no_message_for_ok(monkeypatch):
    recorded = []

    async def fake_record(db, tenant_id, connector_id, **kw):
        recorded.append(kw)
        return True

    monkeypatch.setattr(cf, "record_if_changed", fake_record)
    row = NS(id=CONNECTOR, connector_config={"vendor": "ninjaone"})
    db = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    db.execute = AsyncMock(return_value=result)
    report = cf.StatusReport(
        sources=[
            cf.SourceReport(vendor="ninjaone", status="warning", fetched=4, sent=4, message="0 of 12 alerts matched a Halo ticket"),
            cf.SourceReport(vendor="ninjaone", status="ok", fetched=1, sent=1, message="ignored on ok"),
        ]
    )
    assert await cf.apply_report(db, TENANT, report, now=NOW) == 2
    assert [(r["status"], r["message"], r["fetched"], r["sent"]) for r in recorded] == [
        ("warning", "0 of 12 alerts matched a Halo ticket", 4, 4),
        ("ok", None, 1, 1),
    ]


# ---- reading it ----------------------------------------------------------------------------------------------------------------------------------------


def _read_db(owned: bool, rows=()):
    db = MagicMock()
    db.executed = []

    async def execute(stmt, *a, **k):
        db.executed.append(stmt)
        r = MagicMock()
        r.scalar_one_or_none.return_value = CONNECTOR if owned else None
        r.scalars.return_value.all.return_value = list(rows)
        return r

    db.execute = AsyncMock(side_effect=execute)
    return db


@pytest.mark.asyncio
async def test_another_tenants_connector_log_is_a_404_and_no_log_rows_are_read():
    db = _read_db(owned=False)
    with pytest.raises(HTTPException) as err:
        await connectors_endpoint.get_connector_log(CONNECTOR, NS(tenant_id=OTHER), db, limit=100)
    assert err.value.status_code == 404
    assert len(db.executed) == 1, "the ownership check stopped it before the log was queried"
    sql, params = _sql(db.executed[0])
    assert "connectors.tenant_id" in sql and OTHER in params.values()


@pytest.mark.asyncio
async def test_the_log_is_returned_newest_first_scoped_to_the_tenant_and_limited():
    rows = [
        NS(at=NOW, status="ok", message=None, fetched=2, sent=2),
        NS(at=NOW - timedelta(hours=1), status="warning", message="HaloPSA isn't connected in CORE", fetched=2, sent=2),
    ]
    db = _read_db(owned=True, rows=rows)
    out = await connectors_endpoint.get_connector_log(CONNECTOR, NS(tenant_id=TENANT), db, limit=50)
    assert [(e.status, e.message) for e in out] == [("ok", None), ("warning", "HaloPSA isn't connected in CORE")]
    sql, params = _sql(db.executed[1])
    assert "ORDER BY connector_run_log.at DESC" in sql and "connector_run_log.tenant_id" in sql
    assert TENANT in params.values() and 50 in params.values()
