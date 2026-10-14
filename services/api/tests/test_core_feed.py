def _feed_row(**over):
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415
    from types import SimpleNamespace  # noqa: PLC0415

    now = datetime.now(UTC)
    base = {
        "id": "00000000-0000-0000-0000-0000000000aa",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "name": "Huntress (via CORE)",
        "connector_type": "core_feed",
        "category": "edr",
        "is_enabled": True,
        "connector_config": {"vendor": "huntress", "managed_by": "core"},
        "health_status": "healthy",
        "last_sync": now - timedelta(minutes=3),
        "last_health_check": now,
        "last_event_at": now - timedelta(days=2),
        "events_ingested": 371,
        "events_dropped": 0,
        "error_count": 0,
        "tags": [],
        "created_at": now,
        "updated_at": now,
    }
    base.update(over)
    return SimpleNamespace(**base)


def test_a_quiet_core_feed_that_checked_in_recently_is_not_stalled():
    """Huntress had no new incident for two days, but CORE checked 3 minutes ago: that is healthy, not stalled."""
    from app.api.v1.endpoints.connectors import _build_connector_response  # noqa: PLC0415

    assert _build_connector_response(_feed_row()).freshness.status == "green"


def test_a_core_feed_that_stopped_checking_in_is_stalled():
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from app.api.v1.endpoints.connectors import _build_connector_response  # noqa: PLC0415

    row = _feed_row(last_sync=datetime.now(UTC) - timedelta(hours=2))
    assert _build_connector_response(row).freshness.status == "red"
