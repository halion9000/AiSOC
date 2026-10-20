"""The plain-language warnings on Platform health."""

from app.api.v1.endpoints.health import pending_migrations, platform_warnings


def _w(**over):
    base = {"down": [], "disk": None, "pending": None, "core_feed": None, "device_feeds": [], "signins": None}
    base.update(over)
    return platform_warnings(**base)


def test_a_healthy_platform_has_no_warnings():
    assert (
        _w(
            disk={"used_percent": 40.0, "free_gb": 100},
            pending=[],
            core_feed={"silent": False},
            signins={"unscored": 0, "scored_last_24h": 5},
        )
        == []
    )


def test_each_problem_is_reported_and_errors_come_first():
    out = _w(
        down=["fusion"],
        disk={"used_percent": 91.0, "free_gb": 3.2},
        pending=["094_x.sql"],
        core_feed={"silent": True},
        device_feeds=[{"vendor": "addigy", "stalled": True}, {"vendor": "ninjaone", "stalled": False}],
        signins={"unscored": 10, "scored_last_24h": 0},
    )
    levels = [w["level"] for w in out]
    assert levels == sorted(levels, key=lambda lv: lv != "error")
    text = " | ".join(w["text"] for w in out)
    for needle in ("fusion", "094_x.sql", "CORE has not reported", "91.0%", "addigy", "none are scored"):
        assert needle in text, needle
    assert "ninjaone" not in text


def test_disk_below_the_threshold_and_scored_sign_ins_do_not_warn():
    assert _w(disk={"used_percent": 84.9, "free_gb": 9}, signins={"unscored": 4, "scored_last_24h": 7}) == []


class _BadDb:
    async def execute(self, *_a, **_k):
        raise RuntimeError("no table")


async def test_unreadable_migration_state_is_unknown_not_an_error():
    assert await pending_migrations(_BadDb()) is None


def test_a_large_scoring_backlog_is_reported_but_a_small_one_is_not():
    out = _w(signins={"unscored": 21294, "scored_last_24h": 602})
    assert [w["key"] for w in out] == ["backlog"]
    assert "21,294" in out[0]["text"]
    assert _w(signins={"unscored": 999, "scored_last_24h": 602}) == []


def test_nothing_scored_at_all_is_the_louder_message_and_not_reported_twice():
    out = _w(signins={"unscored": 5000, "scored_last_24h": 0})
    assert [w["key"] for w in out] == ["signins"]
