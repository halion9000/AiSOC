"""A slow request is logged by route, and the connection pool says how full it is, so a failure like the Devices 500 shows up before users see it."""

import uuid as uuid_module
from datetime import UTC, datetime
from types import SimpleNamespace

from app import main as app_main
from app.api.v1.endpoints.health import note_pool_usage, pool_peak, pool_usage, reset_pool_history


def test_a_request_over_the_threshold_is_logged_and_one_under_it_is_not(monkeypatch):
    seen = []
    monkeypatch.setattr(app_main.logger, "warning", lambda event, **kw: seen.append((event, kw)))
    assert app_main.log_if_slow("GET", "/api/v1/devices", 200, 4.2, threshold=3) is True
    assert app_main.log_if_slow("GET", "/api/v1/devices", 200, 0.4, threshold=3) is False
    assert seen == [("slow_request", {"method": "GET", "endpoint": "/api/v1/devices", "status": 200, "seconds": 4.2})]


def test_a_zero_threshold_turns_the_log_off(monkeypatch):
    seen = []
    monkeypatch.setattr(app_main.logger, "warning", lambda event, **kw: seen.append(event))
    assert app_main.log_if_slow("GET", "/x", 200, 99, threshold=0) is False
    assert seen == []


def test_the_threshold_comes_from_the_environment_and_a_bad_value_falls_back(monkeypatch):
    monkeypatch.setenv("AISOC_SLOW_REQUEST_SECONDS", "1.5")
    assert app_main.slow_request_threshold() == 1.5
    monkeypatch.setenv("AISOC_SLOW_REQUEST_SECONDS", "soon")
    assert app_main.slow_request_threshold() == 3.0


def pool(size, out, overflow):
    return SimpleNamespace(size=lambda: size, checkedout=lambda: out, _max_overflow=overflow)


def test_pool_usage_reports_how_full_it_is_and_warns_near_the_limit():
    assert pool_usage(pool(20, 3, 10)) == {"known": True, "in_use": 3, "limit": 30, "percent": 10, "near_limit": False}
    full = pool_usage(pool(20, 26, 10))
    assert full["percent"] == 87 and full["near_limit"] is True


def test_a_pool_that_cannot_say_is_unknown_not_an_error():
    assert pool_usage(object()) == {"known": False}


# ---- the device feeds on Platform Health ------------------------------------------------------------------------------------------------------------------

from datetime import timedelta  # noqa: E402

from app.api.v1.endpoints.health import device_feed_row  # noqa: E402


def test_a_tool_that_synced_recently_is_fine_and_one_silent_for_hours_is_stalled():
    now = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
    fresh = device_feed_row("huntress", 5343, now - timedelta(minutes=12), now)
    old = device_feed_row("addigy", 1799, now - timedelta(hours=5), now)
    assert (fresh["devices"], fresh["minutes_ago"], fresh["stalled"]) == (5343, 12, False)
    assert (old["minutes_ago"], old["stalled"]) == (300, True)


def test_a_time_without_a_zone_is_read_as_utc_and_none_counts_as_stalled():
    now = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
    naive = device_feed_row("x", 1, datetime(2026, 10, 19, 11, 30), now)
    assert naive["minutes_ago"] == 30 and naive["stalled"] is False
    assert device_feed_row("x", 0, None, now)["stalled"] is True
    future = device_feed_row("x", 1, now + timedelta(minutes=5), now)
    assert future["minutes_ago"] == 0, "a clock a little ahead never shows negative minutes"


# ---- how full the pool has been --------------------------------------------------------------------------------------------------------------------------


def test_a_sample_is_kept_at_most_every_fifteen_seconds_and_a_pool_of_no_size_is_ignored():
    reset_pool_history()
    assert note_pool_usage(1000.0, 5, 30) is True
    assert note_pool_usage(1010.0, 9, 30) is False, "too soon after the last"
    assert note_pool_usage(1016.0, 9, 30) is True
    assert note_pool_usage(2000.0, 1, 0) is False
    assert pool_peak(1020.0)["samples"] == 2
    reset_pool_history()


def test_the_peak_is_the_fullest_reading_in_the_window_and_says_how_long_ago():
    reset_pool_history()
    for t, used in ((1000.0, 3), (1020.0, 27), (1040.0, 5)):
        note_pool_usage(t, used, 30)
    peak = pool_peak(1100.0)
    assert (peak["peak_in_use"], peak["peak_limit"], peak["peak_percent"], peak["peak_minutes_ago"]) == (27, 30, 90, 1)
    reset_pool_history()


def test_readings_older_than_the_window_are_ignored_and_no_readings_is_said_plainly():
    reset_pool_history()
    note_pool_usage(1000.0, 29, 30)
    assert pool_peak(1000.0 + 61 * 60, window_minutes=60) == {"window_minutes": 60, "samples": 0}
    assert pool_peak(1000.0 + 61 * 60, window_minutes=120)["peak_percent"] == 97
    reset_pool_history()
    assert pool_peak(5.0) == {"window_minutes": 60, "samples": 0}


def test_a_failure_reading_the_device_feeds_leaves_the_health_page_working():
    import asyncio

    from app.api.v1.endpoints.health import _device_feeds_or_none

    class Broken:
        async def execute(self, *a, **k):
            raise RuntimeError("database down")

    assert asyncio.run(_device_feeds_or_none(Broken(), SimpleNamespace(tenant_id=uuid_module.uuid4()))) == []
    assert asyncio.run(_device_feeds_or_none(Broken(), object())) == [], "even a caller object without a tenant"
