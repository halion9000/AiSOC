"""SSRF: connectors call hosts that come from the tenant's own configuration, and POST /connectors/test (connectors:write) forwards that configuration here. Without a guard a user could point a connector at the cloud metadata address, this host's loopback services or another internal service.
The guard refuses loopback, link-local (which contains 169.254.169.254) and other never-legitimate destinations on every httpx client, including each hop of a redirect, and ALLOWS private ranges because on-prem integrations legitimately live there."""
import asyncio
import ipaddress
import threading
from pathlib import Path

import httpx
import pytest

from app.security import egress_guard as g

g.install_egress_guard()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in ("CONNECTORS_EGRESS_ALLOW_HOSTS", "CONNECTORS_EGRESS_ALLOW_LOOPBACK", "CONNECTORS_EGRESS_GUARD", "INGEST_SERVICE_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(g, "_resolve", lambda host: [])  # no DNS in tests: a name resolves only when a test says so


def ip(s):
    return ipaddress.ip_address(s)


class TestAddresses:
    @pytest.mark.parametrize("addr", ["169.254.169.254", "169.254.0.1", "127.0.0.1", "127.1.2.3", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "240.0.0.1", "fe80::1", "fd00:ec2::254", "100.100.100.200", "::ffff:169.254.169.254", "::ffff:127.0.0.1"])
    def test_never_legitimate_destinations_are_blocked(self, addr):
        assert g.address_is_blocked(ip(addr))

    @pytest.mark.parametrize("addr", ["10.1.2.3", "172.16.5.5", "192.168.1.10", "8.8.8.8", "1.1.1.1", "fd12:3456::1", "100.64.0.1", "2606:4700::1111"])
    def test_private_and_public_addresses_are_allowed(self, addr):
        assert not g.address_is_blocked(ip(addr))

    def test_an_ipv4_mapped_ipv6_address_is_judged_as_the_ipv4_address_it_carries(self):
        """Without the unwrap every ::ffff:x.x.x.x is blocked, but only by accident (the whole ::/8 block is "reserved"); with it a mapped PRIVATE address is judged as the private address it is, and a mapped metadata or loopback address as exactly that. Pinned directly, not through interpreter behaviour."""
        assert g._unwrap(ip("::ffff:1.2.3.4")) == ip("1.2.3.4")
        assert g._unwrap(ip("10.0.0.1")) == ip("10.0.0.1") and g._unwrap(ip("2606:4700::1111")) == ip("2606:4700::1111")
        assert not g.address_is_blocked(ip("::ffff:10.1.2.3")) and not g.address_is_blocked(ip("::ffff:8.8.8.8"))
        assert g.address_is_blocked(ip("::ffff:169.254.169.254")) and g.address_is_blocked(ip("::ffff:127.0.0.1")) and g.address_is_blocked(ip("::ffff:100.100.100.200"))

    def test_loopback_can_be_allowed_for_local_development_but_metadata_never_is(self, monkeypatch):
        monkeypatch.setenv("CONNECTORS_EGRESS_ALLOW_LOOPBACK", "1")
        assert not g.address_is_blocked(ip("127.0.0.1")) and not g.address_is_blocked(ip("::1"))
        assert g.address_is_blocked(ip("169.254.169.254")) and g.address_is_blocked(ip("fd00:ec2::254"))


class TestUrls:
    refusal = staticmethod(lambda u: g._refusal(httpx.URL(u)))

    @pytest.mark.parametrize("url", ["ftp://example.test/x", "gopher://example.test/", "file:///etc/passwd"])
    def test_only_http_and_https(self, url):
        assert self.refusal(url) is not None

    def test_a_url_with_no_host_is_refused(self):
        assert self.refusal("http:///path") is not None

    @pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8000/", "http://[::1]/", "http://0.0.0.0/", "http://[::ffff:169.254.169.254]/", "http://[fd00:ec2::254]/", "http://localhost/", "http://api.localhost/", "http://169.254.169.254:80/x"])
    def test_literal_addresses_and_localhost_are_refused(self, url):
        assert self.refusal(url) is not None

    @pytest.mark.parametrize("url", ["http://10.1.2.3/ok", "https://192.168.5.5:8089/services", "https://splunk.example.test:8089/", "http://[fd12:3456::1]/"])
    def test_private_and_unresolvable_hosts_are_allowed(self, url):
        assert self.refusal(url) is None

    def test_a_hostname_that_resolves_to_the_metadata_address_is_refused(self, monkeypatch):
        monkeypatch.setattr(g, "_resolve", lambda host: [ip("169.254.169.254")])
        assert "169.254.169.254" in self.refusal("https://innocent.example.test/")

    def test_any_blocked_address_among_several_refuses_the_name(self, monkeypatch):
        monkeypatch.setattr(g, "_resolve", lambda host: [ip("8.8.8.8"), ip("127.0.0.1")])
        assert self.refusal("https://dual.example.test/") is not None

    def test_a_name_resolving_only_to_ordinary_addresses_is_allowed(self, monkeypatch):
        monkeypatch.setattr(g, "_resolve", lambda host: [ip("8.8.8.8"), ip("10.0.0.7")])
        assert self.refusal("https://ok.example.test/") is None

    def test_an_allow_listed_host_is_allowed_even_if_it_resolves_to_loopback(self, monkeypatch):
        monkeypatch.setenv("CONNECTORS_EGRESS_ALLOW_HOSTS", "sidecar.internal, other.internal")
        monkeypatch.setattr(g, "_resolve", lambda host: [ip("127.0.0.1")])
        assert self.refusal("http://sidecar.internal:9000/") is None and self.refusal("http://other.internal/") is None
        assert self.refusal("http://not-listed.internal/") is not None

    def test_the_services_own_ingest_peer_is_always_allowed(self, monkeypatch):
        monkeypatch.setenv("INGEST_SERVICE_URL", "http://ingest-worker:8080")
        monkeypatch.setattr(g, "_resolve", lambda host: [ip("127.0.0.1")])
        assert self.refusal("http://ingest-worker:8080/v1/ingest/batch") is None

    def test_loopback_hosts_are_allowed_only_when_the_dev_switch_is_on(self, monkeypatch):
        assert self.refusal("http://localhost:8000/") is not None and self.refusal("http://127.0.0.1/") is not None
        monkeypatch.setenv("CONNECTORS_EGRESS_ALLOW_LOOPBACK", "true")
        assert self.refusal("http://localhost:8000/") is None and self.refusal("http://127.0.0.1/") is None
        assert self.refusal("http://169.254.169.254/") is not None

    def test_the_guard_can_be_turned_off(self, monkeypatch):
        monkeypatch.setenv("CONNECTORS_EGRESS_GUARD", "0")
        calls = []
        client = httpx.Client(transport=httpx.MockTransport(lambda r: calls.append(1) or httpx.Response(200)))
        client.get("http://169.254.169.254/")
        assert calls == [1]


def run(coro):
    return asyncio.run(coro)


class TestOnRealClients:
    def test_a_blocked_destination_never_reaches_the_transport(self):
        seen = []

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: seen.append(str(r.url)) or httpx.Response(200))) as c:
                with pytest.raises(g.EgressBlocked):
                    await c.get("http://169.254.169.254/latest/meta-data/")
                return (await c.get("http://10.1.2.3/ok")).status_code

        assert run(go()) == 200 and seen == ["http://10.1.2.3/ok"]

    def test_the_sync_client_is_guarded_too(self):
        seen = []
        c = httpx.Client(transport=httpx.MockTransport(lambda r: seen.append(1) or httpx.Response(200)))
        with pytest.raises(g.EgressBlocked):
            c.get("http://127.0.0.1:8000/")
        assert seen == []

    def test_a_redirect_to_the_metadata_address_is_stopped_at_the_second_hop(self):
        seen = []

        def handler(req):
            seen.append(str(req.url))
            if req.url.host == "partner.example.test":
                return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/iam/"})
            return httpx.Response(200, text="SECRET")

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as c:
                with pytest.raises(g.EgressBlocked):
                    await c.get("https://partner.example.test/start")

        run(go())
        assert seen == ["https://partner.example.test/start"]

    def test_it_is_reported_as_a_network_error_so_connectors_existing_handling_applies(self):
        assert issubclass(g.EgressBlocked, httpx.RequestError) and issubclass(g.EgressBlocked, httpx.HTTPError)

    def test_a_callers_own_request_hooks_are_kept_and_run_after_the_guard(self):
        order = []

        async def mine(request):
            order.append("mine")

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)), event_hooks={"request": [mine]}) as c:
                await c.get("http://10.0.0.5/")
                with pytest.raises(g.EgressBlocked):
                    await c.get("http://127.0.0.1/")

        run(go())
        assert order == ["mine"]  # ran for the allowed request, never for the blocked one

    def test_installing_twice_does_not_stack_the_hook(self):
        g.install_egress_guard()
        g.install_egress_guard()
        c = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
        assert len(c.event_hooks["request"]) == 1

    def test_dns_lookups_do_not_run_on_the_event_loop_thread(self, monkeypatch):
        threads = []
        monkeypatch.setattr(g, "_resolve", lambda host: threads.append(threading.current_thread().name) or [])

        async def go():
            main = threading.current_thread().name
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as c:
                await c.get("https://lookup.example.test/")
            return main

        main = run(go())
        assert threads and threads[0] != main

    def test_a_blocked_metadata_name_is_refused_through_a_real_client_when_it_resolves_there(self, monkeypatch):
        monkeypatch.setattr(g, "_resolve", lambda host: [ip("169.254.169.254")])

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as c:
                with pytest.raises(g.EgressBlocked):
                    await c.get("https://innocent.example.test/")

        run(go())


def test_the_service_entrypoint_installs_the_guard():
    src = (Path(__file__).resolve().parent.parent / "app" / "main.py").read_text(encoding="utf-8")
    assert "from app.security.egress_guard import install_egress_guard" in src
    assert "\ninstall_egress_guard()\n" in src
