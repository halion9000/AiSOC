"""The machines waiting for their client to be mapped can be found: grouped by tool client, never including mapped or ignored ones."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.api.v1.endpoints import devices as dev

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


def hint(vendor, vid, host, days_ago=0):
    return SimpleNamespace(vendor=vendor, vendor_client_id=vid, hostname_key=host, seen_at=NOW - timedelta(days=days_ago))


def alias(vendor, vid, name=None, ignored=False):
    return SimpleNamespace(vendor=vendor, vendor_client_id=vid, vendor_client_name=name, ignored=ignored)


def test_names_are_grouped_by_tool_and_client_biggest_first_with_the_clients_name_in_that_tool():
    hints = [hint("fieldeffect", "09a1", f"pc-{i}") for i in range(3)] + [hint("autoelevate", "ab", "srv-1"), hint("unifi", "P00190", "ap-1")]
    aliases = {("fieldeffect", "09a1"): alias("fieldeffect", "09a1", "Texas Cultural Trust"), ("unifi", "P00190"): alias("unifi", "P00190", "P00190 - Piano Office")}
    out = dev.group_unmapped(hints, aliases, set())
    assert [(g.vendor, g.name, g.devices) for g in out] == [("fieldeffect", "Texas Cultural Trust", 3), ("autoelevate", None, 1), ("unifi", "P00190 - Piano Office", 1)]
    assert out[0].hostnames == ["pc-0", "pc-1", "pc-2"]


def test_a_client_that_has_been_mapped_since_or_ignored_is_left_out():
    hints = [hint("fieldeffect", "mapped", "a"), hint("fieldeffect", "ignored", "b"), hint("fieldeffect", "waiting", "c")]
    aliases = {("fieldeffect", "ignored"): alias("fieldeffect", "ignored", ignored=True)}
    out = dev.group_unmapped(hints, aliases, {("fieldeffect", "mapped")})
    assert [g.vendor_client_id for g in out] == ["waiting"]


def test_the_newest_sighting_and_a_cap_on_the_names_listed():
    many = [hint("unifi", "x", f"ap-{i:04d}", days_ago=i % 5) for i in range(dev.UNMAPPED_NAMES_SHOWN + 40)]
    g = dev.group_unmapped(many, {}, set())[0]
    assert g.devices == dev.UNMAPPED_NAMES_SHOWN + 40
    assert len(g.hostnames) == dev.UNMAPPED_NAMES_SHOWN
    assert g.last_seen == NOW


def test_nothing_waiting_is_an_empty_list():
    assert dev.group_unmapped([], {}, set()) == []


def test_the_route_exists_before_any_device_id_route_so_it_is_not_taken_for_an_id():
    paths = [r.path for r in dev.router.routes]
    assert "/devices/unmapped" in paths
    assert not [p for p in paths[: paths.index("/devices/unmapped")] if p.endswith("/{device_id}") and "GET" in str(dev.router.routes[paths.index(p)].methods)]


def test_the_route_needs_a_login_like_the_rest_of_the_devices_page():
    route = next(r for r in dev.router.routes if r.path == "/devices/unmapped")
    assert "GET" in route.methods
