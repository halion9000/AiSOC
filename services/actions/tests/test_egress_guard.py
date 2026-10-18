"""SSRF: executors call hosts taken from the request (`webhook_url`, `*_base_url`, `panos_host`, ...). The guard refuses loopback, link-local (169.254.169.254, the cloud metadata address) and other never-legitimate
destinations on every httpx client, including each hop of a redirect, and ALLOWS private ranges (a customer's firewall on 10.x is the normal case)."""

import ipaddress

import httpx
import pytest
from app.security import egress_guard as g

g.install_egress_guard()
REAL_RESOLVE = g._resolve  # the autouse fixture below replaces g._resolve with a stub


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in ("ACTIONS_EGRESS_ALLOW_HOSTS", "ACTIONS_EGRESS_ALLOW_LOOPBACK", "ACTIONS_EGRESS_GUARD"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(g, "_resolve", lambda host: [])


def ip(s):
    return ipaddress.ip_address(s)


@pytest.mark.parametrize("addr", ["169.254.169.254", "127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "::ffff:169.254.169.254", "fd00:ec2::254", "100.100.100.200"])
def test_never_legitimate_destinations_are_blocked(addr):
    assert g.address_is_blocked(ip(addr))


@pytest.mark.parametrize("addr", ["8.8.8.8", "10.1.2.3", "172.16.5.5", "192.168.1.10"])
def test_public_and_private_ranges_are_allowed(addr):
    assert not g.address_is_blocked(ip(addr))


@pytest.mark.asyncio
async def test_an_executor_style_request_to_the_metadata_address_never_leaves():
    reached = []

    def handler(request):
        reached.append(request.url)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.RequestError):
            await client.post("http://169.254.169.254/latest/meta-data/", json={})
        with pytest.raises(httpx.RequestError):
            await client.post("http://localhost:8000/admin", json={})
        with pytest.raises(httpx.RequestError):
            await client.get("file:///etc/passwd")
        assert (await client.post("https://hooks.example.test/x", json={})).status_code == 200
    assert [str(u) for u in reached] == ["https://hooks.example.test/x"]


@pytest.mark.asyncio
async def test_a_public_url_that_redirects_to_metadata_is_stopped_on_the_second_hop():
    def handler(request):
        if request.url.host == "evil.example.test":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/"})
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        with pytest.raises(httpx.RequestError):
            await client.get("https://evil.example.test/")


def test_the_guard_can_be_turned_off_for_development(monkeypatch):
    monkeypatch.setenv("ACTIONS_EGRESS_GUARD", "0")
    req = httpx.Request("GET", "http://169.254.169.254/")
    g.check_request_sync(req)  # no raise


def test_name_resolutions_are_cached_including_failures(monkeypatch):
    """Every request re-resolved its host in a worker thread. A name that does not resolve (an ASGI test transport's 'testserver', a mistyped host) cost a full resolver timeout EVERY time,
    which made unrelated tests time-dependent. Results, empty ones included, are now remembered briefly."""
    import socket

    g._resolve_cache.clear()
    calls = []

    def fake_getaddrinfo(host, *a, **k):
        calls.append(host)
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert REAL_RESOLVE("nowhere.example") == []
    assert REAL_RESOLVE("nowhere.example") == []
    assert calls == ["nowhere.example"]
    g._resolve_cache.clear()


@pytest.mark.asyncio
async def test_a_single_label_host_is_not_resolved_so_an_in_process_transport_is_not_delayed(monkeypatch):
    """A name with no dot ("test", "testserver", a compose service like "aisoc-api") cannot be attacker-registered public DNS, so the guard does not resolve it (the lookup of a name that
    does not exist ran for the whole resolver timeout and made a timing-sensitive test fail). Loopback is still refused by name, and a dotted name is still resolved."""
    looked_up = []
    monkeypatch.setattr(g, "_resolve", lambda host: looked_up.append(host) or [])
    await g.check_request_async(httpx.Request("GET", "http://test/x"))
    await g.check_request_async(httpx.Request("GET", "http://aisoc-api:8000/x"))
    assert looked_up == []
    with pytest.raises(httpx.RequestError):
        await g.check_request_async(httpx.Request("GET", "http://localhost/x"))
    await g.check_request_async(httpx.Request("GET", "https://hooks.example.test/x"))
    assert looked_up == ["hooks.example.test"]


@pytest.mark.asyncio
async def test_a_refusal_is_remembered_with_host_and_reason_but_never_the_path_or_query():
    g._recent.clear()
    request = httpx.Request("GET", "http://169.254.169.254/latest/meta-data/iam?token=SECRET")
    with pytest.raises(g.EgressBlocked):
        await g.check_request_async(request)
    (entry,) = g.recent_blocked()
    assert entry["host"] == "169.254.169.254"
    assert "not a permitted destination" in entry["reason"]
    assert "SECRET" not in str(entry) and "meta-data" not in str(entry)
    g._recent.clear()
