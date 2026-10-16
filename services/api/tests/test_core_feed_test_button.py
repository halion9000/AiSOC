"""The Test button on a CORE-fed card answers from what CORE last reported. It used to ask the connectors service, which has nothing to ask, and said "successful" for a failing feed."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import connectors as ep

NOW = datetime(2026, 10, 16, 17, 0, tzinfo=UTC)


def feed(health="healthy", last_error=None, seen=NOW - timedelta(minutes=3)):
    cfg = {"vendor": "blumira", "managed_by": "core"}
    if last_error:
        cfg["last_error"] = last_error
    return NS(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        connector_type="core_feed",
        health_status=health,
        last_sync=seen,
        connector_config=cfg,
        auth_config={},
    )


def test_a_feed_whose_last_run_failed_fails_the_test_with_the_reason_CORE_gave():
    v = ep.core_feed_verdict(feed("unhealthy", "couldn't read blumira: Blumira returned 403"), NOW)
    assert v["success"] is False and v["error"] == "couldn't read blumira: Blumira returned 403"


def test_a_failed_run_with_no_reason_still_fails():
    assert ep.core_feed_verdict(feed("unhealthy"), NOW)["success"] is False


def test_a_warning_passes_but_carries_the_warning_so_it_is_not_hidden():
    v = ep.core_feed_verdict(
        feed("degraded", "Alerts are flowing, but ninjaone devices: 48 device(s) belong to clients not mapped yet"), NOW
    )
    assert v["success"] is True and "48 device(s)" in v["message"]


def test_a_healthy_feed_that_checked_in_recently_passes():
    assert ep.core_feed_verdict(feed(), NOW)["success"] is True


def test_a_feed_CORE_stopped_reporting_on_fails_even_though_its_last_run_was_fine():
    v = ep.core_feed_verdict(feed(seen=NOW - timedelta(minutes=40)), NOW)
    assert v["success"] is False and "40 minutes" in v["error"]


def test_a_feed_that_has_never_reported_fails():
    assert ep.core_feed_verdict(feed(seen=None), NOW)["success"] is False


@pytest.mark.asyncio
async def test_the_endpoint_never_calls_the_connectors_service_or_overwrites_the_health_CORE_reported(monkeypatch):
    row = feed("unhealthy", "Blumira returned 403", seen=datetime.now(UTC))
    db = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()
    proxy = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(ep, "_proxy_test_connection", proxy)
    out = await ep.test_existing_connector(row.id, NS(tenant_id=row.tenant_id), db)
    assert out["success"] is False and out["error"] == "Blumira returned 403"
    proxy.assert_not_awaited()
    assert db.execute.await_count == 1 and not db.commit.await_count, "only the lookup ran: nothing was written"
