"""Which entities are heating up: the points an entity picked up in the last four hours, and the order that puts them first."""

from datetime import UTC, datetime, timedelta

from app.api.v1.endpoints.fusion import _shape_entity, order_entities, trend_of

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)


def at(hours_ago: float) -> str:
    return (NOW - timedelta(hours=hours_ago)).isoformat()


def test_an_entity_whose_first_contribution_is_recent_is_new():
    t = trend_of([{"points": 10, "at": at(1)}, {"points": 5, "at": at(0.5)}], NOW)
    assert t == {"recent_points": 15.0, "recent_alerts": 2, "trend": "new"}


def test_an_old_entity_that_picked_up_points_lately_is_rising():
    t = trend_of([{"points": 10, "at": at(20)}, {"points": 7, "at": at(2)}], NOW)
    assert t == {"recent_points": 7.0, "recent_alerts": 1, "trend": "rising"}


def test_an_entity_with_nothing_added_for_four_hours_is_fading():
    t = trend_of([{"points": 10, "at": at(20)}, {"points": 7, "at": at(5)}], NOW)
    assert t == {"recent_points": 0.0, "recent_alerts": 0, "trend": "fading"}


def test_no_dated_contribution_gives_no_label_rather_than_a_guess():
    assert trend_of([{"points": 3}, {"points": 2, "at": "not a date"}], NOW)["trend"] is None
    assert trend_of([], NOW)["trend"] is None


def test_z_suffixed_timestamps_are_understood():
    stamp = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert trend_of([{"points": 4, "at": stamp}], NOW)["recent_alerts"] == 1


def test_recent_order_puts_what_picked_up_the_most_first_then_by_score():
    rows = [
        {"entity": "old-high", "score": 90, "recent_points": 0},
        {"entity": "hot", "score": 40, "recent_points": 30},
        {"entity": "warm-high", "score": 70, "recent_points": 5},
        {"entity": "warm-low", "score": 50, "recent_points": 5},
    ]
    assert [r["entity"] for r in order_entities(rows, "recent")] == ["hot", "warm-high", "warm-low", "old-high"]
    assert [r["entity"] for r in order_entities(rows, "score")] == [
        "old-high",
        "hot",
        "warm-high",
        "warm-low",
    ], "score order is whatever fusion ranked, untouched"


def test_the_shaped_entity_carries_the_trend_fields():
    shaped = _shape_entity(
        {"entity": "u@x", "entity_type": "user", "score": 33, "contributors": [{"points": 12, "at": at(1), "alert_id": "a"}]}, 50, NOW
    )
    assert shaped["trend"] == "new" and shaped["recent_points"] == 12.0 and shaped["recent_alerts"] == 1
