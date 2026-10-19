"""What a tool reports as wrong with a device (Huntress agent health) reaches the Devices page, and "not in Huntress" works like the other coverage gaps."""

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

from app.api.v1.endpoints.devices import DeviceOut, DeviceSourceOut, attention_of, is_missing_from


def device(os_name, sources):
    now = datetime.now(UTC)
    return DeviceOut(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        hostname="h",
        os=os_name,
        last_seen=now,
        first_seen=now,
        sources=[DeviceSourceOut(vendor=v, name="h", last_seen=now, details=d) for v, d in sources],
    )


def test_attention_collects_every_sources_problems_and_ignores_malformed_ones():
    d = device(
        "Windows 11",
        [
            ("huntress", {"needs_attention": ["Defender: Unhealthy", "Firewall: Disabled"]}),
            ("ninjaone", {"needs_attention": "not a list"}),
            ("threatmate", {"needs_attention": ["", 5, "Exposed RDP"]}),
        ],
    )
    assert attention_of(d) == ["Defender: Unhealthy", "Firewall: Disabled", "Exposed RDP"]


def test_no_reported_problem_means_no_attention():
    assert attention_of(device("Windows 11", [("huntress", {"needs_attention": []}), ("ninjaone", {})])) == []


def test_a_machine_without_a_huntress_agent_is_missing_from_it_but_phones_and_tablets_are_not():
    assert is_missing_from(device("Windows 11", [("ninjaone", {})]), "huntress")
    assert is_missing_from(device("macOS", [("ninjaone", {})]), "huntress")
    assert not is_missing_from(device("Windows 11", [("ninjaone", {}), ("huntress", {})]), "huntress")
    assert not is_missing_from(device("iOS 18", [("addigy", {})]), "huntress")


# ---- the load is shared and kept briefly, so a busy page cannot exhaust the connection pool ----------------------------------------------------------

import asyncio  # noqa: E402

import pytest  # noqa: E402
from app.api.v1.endpoints import devices as devices_module  # noqa: E402


@pytest.fixture
def counted_load(monkeypatch):
    calls = []

    async def fake_load(db, owner, tids, clients, master):
        calls.append(tuple(tids))
        await asyncio.sleep(0.05)
        return [device("Windows 11", [("huntress", {})])]

    monkeypatch.setattr(devices_module, "_load", fake_load)
    devices_module.forget_loaded()
    yield calls
    devices_module.forget_loaded()


@pytest.mark.asyncio
async def test_concurrent_requests_for_the_same_scope_share_one_load(counted_load):
    owner, tid = uuid.uuid4(), uuid.uuid4()
    results = await asyncio.gather(*[devices_module._load_cached(None, owner, [tid], {}, None) for _ in range(6)])
    assert len(counted_load) == 1, "six requests, one trip to the database"
    assert all(r is results[0] for r in results)


@pytest.mark.asyncio
async def test_a_different_scope_or_master_is_loaded_separately(counted_load):
    owner, a, b = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    await devices_module._load_cached(None, owner, [a], {}, None)
    await devices_module._load_cached(None, owner, [b], {}, None)
    await devices_module._load_cached(None, owner, [a], {}, "ninjaone")
    assert len(counted_load) == 3


@pytest.mark.asyncio
async def test_the_result_is_kept_briefly_then_refreshed(counted_load, monkeypatch):
    owner, tid = uuid.uuid4(), uuid.uuid4()
    await devices_module._load_cached(None, owner, [tid], {}, None)
    await devices_module._load_cached(None, owner, [tid], {}, None)
    assert len(counted_load) == 1
    monkeypatch.setattr(devices_module, "LOAD_CACHE_SECONDS", 0.0)
    await devices_module._load_cached(None, owner, [tid], {}, None)
    assert len(counted_load) == 2


@pytest.mark.asyncio
async def test_forgetting_makes_the_next_request_load_fresh_data(counted_load):
    owner, tid = uuid.uuid4(), uuid.uuid4()
    await devices_module._load_cached(None, owner, [tid], {}, None)
    devices_module.forget_loaded()
    await devices_module._load_cached(None, owner, [tid], {}, None)
    assert len(counted_load) == 2


@pytest.mark.asyncio
async def test_a_dismissal_clears_the_cache_before_it_commits(counted_load, monkeypatch):
    """A change must never be hidden behind the cache: after a dismissal the next request loads fresh data."""
    from types import SimpleNamespace

    owner, tid, a, b = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    await devices_module._load_cached(None, owner, [tid], {}, None)
    assert len(counted_load) == 1

    async def client_of(db, o, device_id):
        return tid

    async def dismiss_pair(db, t, x, y):
        return None

    class Db:
        committed_with_cache_empty = None

        async def commit(self):
            Db.committed_with_cache_empty = not devices_module._loaded

    monkeypatch.setattr(devices_module, "_client_of", client_of)
    monkeypatch.setattr(devices_module, "dismiss_pair", dismiss_pair)
    monkeypatch.setattr(devices_module, "_as", lambda db, o, t: __import__("contextlib").nullcontext())
    await devices_module.dismiss_duplicate(SimpleNamespace(device_a=a, device_b=b), SimpleNamespace(tenant_id=owner), Db())
    assert Db.committed_with_cache_empty is True
    await devices_module._load_cached(None, owner, [tid], {}, None)
    assert len(counted_load) == 2


def test_iphones_and_ipads_are_recognised_by_model_alone_and_never_counted_as_missing():
    from app.api.v1.endpoints.devices import is_mobile

    assert is_mobile(SimpleNamespace(os=None, model="iPhone17,3"))
    assert is_mobile(SimpleNamespace(os=None, model="iPad13,1"))
    assert is_mobile(SimpleNamespace(os="iPadOS", model=None))
    assert not is_mobile(SimpleNamespace(os="Windows 11", model="Surface Pro"))
    phone = device("iOS", [("addigy", {})])
    assert not is_missing_from(phone, "threatmate") and not is_missing_from(phone, "huntress")
    by_model = DeviceOut(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        hostname="h",
        os=None,
        model="iPhone17,3",
        last_seen=datetime.now(UTC),
        first_seen=datetime.now(UTC),
        sources=[],
    )
    assert not is_missing_from(by_model, "threatmate") and not is_missing_from(by_model, "huntress")


# ---- stale agents, a disagreement between tools, and the per-client rollup --------------------------------------------------------------------------------

from app.api.v1.endpoints.devices import STALE_AGENT_DAYS, rollup_of, stale_days_of  # noqa: E402


def with_online(d, online):
    return d.model_copy(update={"online": online})


def test_a_stale_agent_is_one_that_has_not_checked_in_for_two_weeks_and_the_worst_one_counts():
    fresh = device("Windows 11", [("huntress", {"days_since_checkin": STALE_AGENT_DAYS - 1})])
    old = device("Windows 11", [("huntress", {"days_since_checkin": 20}), ("other", {"days_since_checkin": 40})])
    assert stale_days_of(fresh) is None
    assert stale_days_of(old) == 40
    assert stale_days_of(device("Windows 11", [("huntress", {"days_since_checkin": "20"})])) is None, "only a whole number counts"
    assert stale_days_of(device("Windows 11", [("ninjaone", {})])) is None


def test_another_tool_saying_online_while_huntress_is_stale_is_a_reason_to_look():
    d = device("Windows 11", [("huntress", {"days_since_checkin": 30}), ("ninjaone", {})])
    assert attention_of(with_online(d, True)) == [
        "Another tool says this machine is online, but its Huntress agent has not checked in for 30 days"
    ]
    assert (
        attention_of(with_online(d, False)) == [] and attention_of(with_online(d, None)) == []
    ), "only a machine another tool calls online is a disagreement"
    quiet = with_online(device("Windows 11", [("huntress", {"days_since_checkin": 3})]), True)
    assert attention_of(quiet) == []


def test_the_rollup_counts_each_client_and_puts_the_worst_first():
    a, b = uuid.uuid4(), uuid.uuid4()

    def dev(tenant, name, sources, online=None):
        d = device("Windows 11", sources).model_copy(update={"tenant_id": tenant, "client_name": name, "online": online})
        return d

    rows = rollup_of(
        [
            dev(a, "Acme", [("huntress", {"needs_attention": ["Defender: Unhealthy"], "days_since_checkin": 30})]),
            dev(a, "Acme", [("ninjaone", {})]),
            dev(b, "Zed", [("huntress", {})]),
        ]
    )
    assert [r.client_name for r in rows] == ["Acme", "Zed"]
    acme, zed = rows
    assert (acme.devices, acme.needs_attention, acme.stale_agents, acme.not_in_huntress) == (2, 1, 1, 1)
    assert (zed.devices, zed.needs_attention, zed.stale_agents, zed.not_in_huntress) == (1, 0, 0, 0)
    assert rollup_of([]) == []


# ---- search by IP, export, and Huntress check-ins as "last online" ---------------------------------------------------------------------------------------

from app.api.v1.endpoints.devices import csv_cell, devices_csv, filter_devices, last_online_of  # noqa: E402


def dev(name, ips=(), client="Acme", sources=None, serial=None):
    d = device("Windows 11", sources or [("ninjaone", {})]).model_copy(
        update={"hostname": name, "ip_addresses": list(ips), "client_name": client, "serial_number": serial}
    )
    return d


def test_search_finds_a_device_by_name_serial_client_or_any_ip_address_ignoring_case():
    rows = [dev("FRONT-DESK", ["10.0.0.5", "192.168.1.20"]), dev("BACK-OFFICE", ["10.9.9.9"], client="Zed", serial="ABC123")]
    names = lambda found: [d.hostname for d in found]  # noqa: E731
    assert names(filter_devices(rows, search="front")) == ["FRONT-DESK"]
    assert names(filter_devices(rows, search="abc1")) == ["BACK-OFFICE"]
    assert names(filter_devices(rows, search="zed")) == ["BACK-OFFICE"]
    assert names(filter_devices(rows, search="192.168.1.2")) == ["FRONT-DESK"]
    assert names(filter_devices(rows, search="nothing")) == []


def test_filters_combine_and_the_result_is_sorted_by_client_then_name():
    rows = [
        dev("B", client="Zed"),
        dev("a", client="Acme"),
        dev("C", client="Acme", sources=[("huntress", {"needs_attention": ["Defender: Unhealthy"]})]),
    ]
    assert [d.hostname for d in filter_devices(rows)] == ["a", "C", "B"]
    assert [d.hostname for d in filter_devices(rows, attention=True)] == ["C"]
    assert [d.hostname for d in filter_devices(rows, vendor="huntress", attention=True)] == ["C"]
    assert filter_devices(rows, vendor="addigy") == []


def test_a_cell_that_would_run_as_a_formula_is_made_plain_text():
    assert csv_cell('=HYPERLINK("http://evil")') == '\'=HYPERLINK("http://evil")'
    assert csv_cell("+1") == "'+1" and csv_cell("-2") == "'-2" and csv_cell("@x") == "'@x"
    assert csv_cell("PC-1") == "PC-1" and csv_cell(None) == "" and csv_cell(7) == "7"


def test_the_export_has_a_header_one_row_per_device_and_safe_cells():
    rows = [
        dev("=cmd|calc", client="Acme"),
        dev("PC-2", client="Acme", sources=[("huntress", {"needs_attention": ["Defender: Unhealthy", "Tamper"]}), ("ninjaone", {})]),
    ]
    lines = devices_csv(rows).strip().splitlines()
    assert lines[0] == "Client,Device,Serial number,OS,Tools,Last online,Needs attention,Open alerts"
    assert len(lines) == 3
    assert lines[1].split(",")[1] == "'=cmd|calc"
    assert "Defender: Unhealthy; Tamper" in lines[2] and "huntress, ninjaone" in lines[2]


def test_a_huntress_check_in_counts_as_the_device_having_been_online():
    stamp = "2026-10-18T10:00:00Z"
    d = device("Windows 11", [("huntress", {"last_callback_at": stamp})])
    assert last_online_of(d.sources) == datetime(2026, 10, 18, 10, 0, tzinfo=UTC)
    newer = device("Windows 11", [("huntress", {"last_callback_at": stamp}), ("addigy", {"last_online": "2026-10-18T11:00:00Z"})])
    assert last_online_of(newer.sources) == datetime(2026, 10, 18, 11, 0, tzinfo=UTC), "the newest of the tools"


# ---- hide a device until it checks back in ---------------------------------------------------------------------------------------------------------------

from app.api.v1.endpoints.devices import hidden_since_of  # noqa: E402


def test_a_hidden_device_stays_hidden_until_a_tool_sees_it_online_after_it_was_hidden():
    hidden_at = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
    assert hidden_since_of(None, None) is None, "never hidden"
    assert hidden_since_of(hidden_at, datetime(2026, 9, 28, tzinfo=UTC)) == hidden_at, "last seen before it was hidden"
    assert hidden_since_of(hidden_at, None) == hidden_at, "no tool says anything: stays hidden"
    assert hidden_since_of(hidden_at, datetime(2026, 10, 19, 12, 0, tzinfo=UTC)) == hidden_at, "seen at the very moment: not after"
    assert hidden_since_of(hidden_at, datetime(2026, 10, 20, 8, 0, tzinfo=UTC)) is None, "back online: shown again by itself"
    assert (
        hidden_since_of(hidden_at.replace(tzinfo=None), datetime(2026, 10, 20, tzinfo=UTC)) is None
    ), "a time without a zone is read as UTC"


def test_hidden_devices_are_left_out_unless_asked_for():
    shown = dev("SHOWN")
    gone = dev("GONE").model_copy(update={"hidden_since": datetime(2026, 10, 19, tzinfo=UTC)})
    assert [d.hostname for d in filter_devices([shown, gone])] == ["SHOWN"]
    assert [d.hostname for d in filter_devices([shown, gone], hidden=True)] == ["GONE"]
    assert [d.hostname for d in filter_devices([shown, gone], hidden=True, search="sho")] == []
    assert "GONE" not in devices_csv(filter_devices([shown, gone]))


# ---- a device offline for a month stops counting ---------------------------------------------------------------------------------------------------------

from app.api.v1.endpoints.devices import LONG_OFFLINE_DAYS, long_offline  # noqa: E402


def aged(name, days, **kw):
    return dev(name, **kw).model_copy(update={"offline_days": days})


def test_a_device_offline_for_ten_days_is_long_offline_and_a_younger_one_is_not():
    assert LONG_OFFLINE_DAYS == 10
    assert long_offline(aged("A", 10)) and long_offline(aged("B", 200))
    assert not long_offline(aged("C", 9)) and not long_offline(aged("D", None))


def test_the_problem_filters_leave_a_long_offline_device_out_but_the_offline_filter_and_plain_list_keep_it():
    drawer = aged("DRAWER", 45, sources=[("huntress", {"needs_attention": ["Defender: Unhealthy"]})]).model_copy(update={"open_alerts": 2})
    fresh = aged("FRESH", 8, sources=[("huntress", {"needs_attention": ["Defender: Unhealthy"]})]).model_copy(update={"open_alerts": 1})
    rows = [drawer, fresh]
    names = lambda found: [d.hostname for d in found]  # noqa: E731
    assert names(filter_devices(rows)) == ["DRAWER", "FRESH"]
    assert names(filter_devices(rows, offline=True)) == ["DRAWER", "FRESH"]
    assert names(filter_devices(rows, attention=True)) == ["FRESH"]
    assert names(filter_devices(rows, has_alerts=True)) == ["FRESH"]
    assert names(filter_devices(rows, missing="threatmate")) == ["FRESH"]


def test_the_client_rollup_counts_a_long_offline_device_as_offline_only():
    rows = [
        aged("DRAWER", 45, sources=[("huntress", {"needs_attention": ["Defender: Unhealthy"]})]),
        aged("FRESH", 8, sources=[("huntress", {"needs_attention": ["Defender: Unhealthy"]})]),
        aged("NO-HUNTRESS-OLD", 90),
    ]
    same = uuid.uuid4()
    (row,) = rollup_of([d.model_copy(update={"tenant_id": same}) for d in rows])
    assert (row.devices, row.needs_attention, row.not_in_huntress, row.offline) == (3, 1, 0, 3)


# ---- archived clients are not offered ----------------------------------------------------------------------------------------------------------------------

import pytest  # noqa: E402
from app.api.v1.endpoints.devices import _scope  # noqa: E402
from fastapi import HTTPException  # noqa: E402


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeDb:
    def __init__(self, rows):
        self._rows = rows

    async def execute(self, _stmt):
        return _Rows(self._rows)


async def test_all_clients_leaves_out_archived_ones_but_an_archived_client_can_still_be_asked_for_by_id():
    owner, live, gone = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    rows = [
        SimpleNamespace(id=live, name="Acme", settings={}),
        SimpleNamespace(id=gone, name="Old Co (archived)", settings={"hidden": True}),
    ]
    scope, names = await _scope(_FakeDb(rows), owner, None)
    assert scope == [owner, live], "the archived client is not in 'all clients'"
    assert names[gone] == "Old Co (archived)", "its name is still known, for a device that is asked for directly"
    scope, _ = await _scope(_FakeDb(rows), owner, gone)
    assert scope == [gone]
    with pytest.raises(HTTPException):
        await _scope(_FakeDb(rows), owner, uuid.uuid4())
