"""scripts/integration/spine_test.py sends credentials to a production-shaped stack, and nothing extra to a development one.

The integration workflow boots the root docker-compose.yml, which has no development mode: ingest answers 503/401 to anything but its health route without
`Authorization: Bearer $AISOC_INGEST_SERVICE_TOKEN`, and the API answers 401 to an anonymous caller. The spine test used to send neither (its `POST
/api/v1/realtime/ticket` got `401 Unauthorized`, seen in the failure annotations of the Integration run for 082ccd85). These tests pin the contract of the
two helpers and the five call sites, with the HTTP layer mocked, so a later edit cannot quietly drop a header.
"""

import importlib.util
import sys
import types
from pathlib import Path

import httpx
import pytest
import respx

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "integration" / "spine_test.py"
API, INGEST = "http://localhost:8000", "http://localhost:8081"


@pytest.fixture
def spine(monkeypatch):
    if "websockets" not in sys.modules:  # the script imports it at module level; this test never opens a websocket
        monkeypatch.setitem(sys.modules, "websockets", types.ModuleType("websockets"))
    spec = importlib.util.spec_from_file_location("spine_test_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in ("AISOC_INGEST_SERVICE_TOKEN", "SPINE_ACCOUNT", "SPINE_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    return module


def set_credentials(monkeypatch):
    monkeypatch.setenv("AISOC_INGEST_SERVICE_TOKEN", "ingest-token-xyz")
    monkeypatch.setenv("SPINE_ACCOUNT", "spine-admin")
    monkeypatch.setenv("SPINE_PASSWORD", "correct horse battery staple")


def test_without_credentials_ingest_gets_only_the_tenant_as_before(spine):
    assert spine.ingest_headers() == {"X-Tenant-ID": spine.TENANT}


def test_with_the_service_token_ingest_gets_a_bearer_as_well(spine, monkeypatch):
    set_credentials(monkeypatch)
    assert spine.ingest_headers() == {"X-Tenant-ID": spine.TENANT, "Authorization": "Bearer ingest-token-xyz"}


@respx.mock
async def test_without_an_account_the_api_is_called_anonymously_and_no_login_is_attempted(spine):
    login = respx.post(f"{API}/api/v1/auth/login")
    async with httpx.AsyncClient() as client:
        assert await spine.api_headers(client) == {}
    assert not login.called


@respx.mock
async def test_with_an_account_it_logs_in_once_and_reuses_the_token(spine, monkeypatch):
    set_credentials(monkeypatch)
    login = respx.post(f"{API}/api/v1/auth/login").mock(
        return_value=httpx.Response(200, json={"access_token": "jwt-abc", "token_type": "bearer"})
    )
    async with httpx.AsyncClient() as client:
        first, second = await spine.api_headers(client), await spine.api_headers(client)
    assert first == second == {"Authorization": "Bearer jwt-abc"}
    assert login.call_count == 1
    assert (
        login.calls[0].request.read() == b'{"account_name":"spine-admin","password":"correct horse battery staple"}'
        or b"spine-admin" in login.calls[0].request.read()
    )


@respx.mock
async def test_a_failed_login_stops_the_test_and_never_prints_the_password(spine, monkeypatch):
    set_credentials(monkeypatch)
    respx.post(f"{API}/api/v1/auth/login").mock(return_value=httpx.Response(401, json={"detail": "Invalid credentials"}))
    async with httpx.AsyncClient() as client:
        with pytest.raises(SystemExit) as stopped:
            await spine.api_headers(client)
    message = str(stopped.value)
    assert "401" in message and "spine-admin" in message
    assert "correct horse battery staple" not in message


@respx.mock
async def test_the_three_api_calls_carry_the_bearer_and_the_ingest_post_carries_the_service_token(spine, monkeypatch):
    set_credentials(monkeypatch)
    respx.post(f"{API}/api/v1/auth/login").mock(return_value=httpx.Response(200, json={"access_token": "jwt-abc"}))
    alerts = respx.get(f"{API}/api/v1/alerts").mock(return_value=httpx.Response(200, json={"items": [{"title": "T"}]}))
    ticket = respx.post(f"{API}/api/v1/realtime/ticket").mock(return_value=httpx.Response(200, json={"token": "ws-ticket"}))
    ingest = respx.post(f"{INGEST}/v1/ingest/batch").mock(return_value=httpx.Response(200, json={"accepted": 1}))
    async with httpx.AsyncClient() as client:
        assert await spine.count_alerts_titled(client, "T") == 1
        assert (await spine.get_alert_titled(client, "T"))["title"] == "T"
        assert await spine.mint_ws_ticket(client) == "ws-ticket"
        await spine.post_event(client, "T")
    for call in (alerts.calls[0], alerts.calls[1], ticket.calls[0]):
        assert call.request.headers["authorization"] == "Bearer jwt-abc"
    sent = ingest.calls[0].request.headers
    assert sent["authorization"] == "Bearer ingest-token-xyz" and sent["x-tenant-id"] == spine.TENANT
    assert "bearer jwt-abc" not in sent["authorization"].lower()  # the two credentials are never mixed up


@respx.mock
async def test_against_a_development_stack_no_authorization_header_is_sent_at_all(spine):
    alerts = respx.get(f"{API}/api/v1/alerts").mock(return_value=httpx.Response(200, json={"items": []}))
    ingest = respx.post(f"{INGEST}/v1/ingest/batch").mock(return_value=httpx.Response(200, json={"accepted": 1}))
    async with httpx.AsyncClient() as client:
        await spine.count_alerts_titled(client, "T")
        await spine.post_event(client, "T")
    assert "authorization" not in alerts.calls[0].request.headers
    assert "authorization" not in ingest.calls[0].request.headers
