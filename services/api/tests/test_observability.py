"""A slow request is logged by route, and the connection pool says how full it is, so a failure like the Devices 500 shows up before users see it."""

from datetime import UTC, datetime
from types import SimpleNamespace

from app import main as app_main
from app.api.v1.endpoints.health import pool_usage


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
