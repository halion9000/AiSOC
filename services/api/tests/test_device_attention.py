"""What a tool reports as wrong with a device (Huntress agent health) reaches the Devices page, and "not in Huntress" works like the other coverage gaps."""

import uuid
from types import SimpleNamespace
from datetime import UTC, datetime

from app.api.v1.endpoints.devices import DeviceOut, DeviceSourceOut, attention_of, is_missing_from


def device(os_name, sources):
    now = datetime.now(UTC)
    return DeviceOut(
        id=uuid.uuid4(), tenant_id=uuid.uuid4(), hostname="h", os=os_name, last_seen=now, first_seen=now,
        sources=[DeviceSourceOut(vendor=v, name="h", last_seen=now, details=d) for v, d in sources],
    )


def test_attention_collects_every_sources_problems_and_ignores_malformed_ones():
    d = device("Windows 11", [
        ("huntress", {"needs_attention": ["Defender: Unhealthy", "Firewall: Disabled"]}),
        ("ninjaone", {"needs_attention": "not a list"}),
        ("threatmate", {"needs_attention": ["", 5, "Exposed RDP"]}),
    ])
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
    by_model = DeviceOut(id=uuid.uuid4(), tenant_id=uuid.uuid4(), hostname="h", os=None, model="iPhone17,3", last_seen=datetime.now(UTC), first_seen=datetime.now(UTC), sources=[])
    assert not is_missing_from(by_model, "threatmate") and not is_missing_from(by_model, "huntress")
