"""A tool that has not seen a device for 10 days is struck through; a device no tool has seen for 10 days hides itself until one does."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS

from app.api.v1.endpoints.devices import SOURCE_STALE_DAYS, auto_hidden_of, checkin_of, source_stale

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


def test_each_tools_own_check_in_time_is_read_from_the_field_that_tool_uses():
    t = ago(3).isoformat()
    assert checkin_of(NS(details={"last_online": t})) == ago(3)
    assert checkin_of(NS(details={"last_contact": t})) == ago(3)
    assert checkin_of(NS(details={"last_callback_at": t.replace("+00:00", "Z")})) == ago(3)
    assert checkin_of(NS(details={"last_sync_at": t})) == ago(3)
    assert checkin_of(NS(details={"facts": {}})) is None
    assert checkin_of(NS(details={"last_online": "not a date"})) is None
    assert checkin_of(NS(details=None)) is None


def test_a_tool_is_stale_at_ten_days_and_a_tool_with_no_time_is_not_stale():
    assert SOURCE_STALE_DAYS == 10
    assert source_stale(ago(10), NOW) is True
    assert source_stale(ago(9.5), NOW) is False
    assert source_stale(None, NOW) is False


def test_a_device_hides_only_when_every_tool_that_gives_a_time_is_stale():
    assert auto_hidden_of([ago(12), ago(30)], None, NOW) is True
    assert auto_hidden_of([ago(12), ago(2)], None, NOW) is False, "one tool checked in recently: it stays"
    assert auto_hidden_of([ago(12), None], None, NOW) is True, "a scanner that gives no time cannot show it is alive"
    assert auto_hidden_of([None, None], None, NOW) is False, "nothing says it is stale"
    assert auto_hidden_of([], None, NOW) is False


def test_a_tool_that_says_the_device_is_online_right_now_keeps_it_visible():
    assert auto_hidden_of([ago(20)], True, NOW) is False
    assert auto_hidden_of([ago(20)], False, NOW) is True
