"""SSRF: executors call hosts taken from the request (`webhook_url`, `*_base_url`, `panos_host`, ...). The guard refuses loopback, link-local (169.254.169.254, the cloud metadata address) and other never-legitimate
destinations on every httpx client, including each hop of a redirect, and ALLOWS private ranges (a customer's firewall on 10.x is the normal case)."""

import ipaddress

import httpx
import pytest
from app.security import egress_guard as g

g.install_egress_guard()


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
