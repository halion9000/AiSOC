"""The API sends the connectors service token on every call to that service, and only to that service.

The connectors service makes outbound calls using connector configuration and decrypted credentials that its CALLER
supplies, and it had no authentication. It now requires `Authorization: Bearer <AISOC_CONNECTORS_SERVICE_TOKEN>`; the API
is its only caller, so every API client that talks to it must send the token or production would break.

While wiring this, two things that had silently never worked turned up: the API's default CONNECTORS_SERVICE_URL pointed
at port 8003 (that is the FUSION service; connectors listens on 8087), and the resource-config fetcher built
`/connectors/{id}/resource_config` without the `/api/v1` prefix the service mounts its routes under.
"""
import ast
import re
from pathlib import Path

import httpx
import pytest
import respx

from app.api.v1.endpoints import connectors as connectors_ep
from app.core.internal_auth import connectors_service_headers
from app.services import case_fanout
from app.services.effective_permissions.posture_loader import HttpResourceConfigFetcher

APP = Path(__file__).resolve().parents[1] / "app"
BASE = "http://connectors:8087"
TOKEN = "connectors-service-token-123"
CLIENT_MODULES = {  # module -> how many httpx.AsyncClient(...) it constructs (all talk to the connectors service)
    "services/case_fanout.py": 1,
    "api/v1/endpoints/federated.py": 1,
    "api/v1/endpoints/connectors.py": 2,
    "services/effective_permissions/posture_loader.py": 1,
}


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setenv("AISOC_CONNECTORS_SERVICE_TOKEN", TOKEN)


# ------------------------------------------------------------------------ helper ----
def test_the_helper_sends_the_token_as_a_bearer_credential():
    assert connectors_service_headers() == {"Authorization": f"Bearer {TOKEN}"}


@pytest.mark.parametrize("value", [None, "", "   "])
def test_no_token_configured_sends_no_header(monkeypatch, value):
    monkeypatch.delenv("AISOC_CONNECTORS_SERVICE_TOKEN", raising=False)
    if value is not None:
        monkeypatch.setenv("AISOC_CONNECTORS_SERVICE_TOKEN", value)
    assert connectors_service_headers() == {}


def test_the_token_is_stripped(monkeypatch):
    monkeypatch.setenv("AISOC_CONNECTORS_SERVICE_TOKEN", f"  {TOKEN}\n")
    assert connectors_service_headers() == {"Authorization": f"Bearer {TOKEN}"}


# --------------------------------------------------------------- structural guards ----
def _async_client_calls(path: str):
    tree = ast.parse((APP / path).read_text(encoding="utf-8"))
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == "httpx.AsyncClient"]


@pytest.mark.parametrize("module,expected", CLIENT_MODULES.items())
def test_every_client_that_talks_to_the_connectors_service_sends_the_token(module, expected):
    calls = _async_client_calls(module)
    assert len(calls) == expected, f"{module}: found {len(calls)} httpx.AsyncClient(...), expected {expected}; update CLIENT_MODULES"
    for call in calls:
        headers = [ast.unparse(k.value) for k in call.keywords if k.arg == "headers"]
        assert headers == ["connectors_service_headers()"], f"{module}:{call.lineno} builds a connectors client without the token"


def test_the_token_is_only_ever_sent_by_the_connectors_clients():
    """Sending it from some other client would hand the credential to a different host."""
    users = set()
    for f in APP.rglob("*.py"):
        if "connectors_service_headers" in f.read_text(encoding="utf-8"):
            users.add(str(f.relative_to(APP)))
    assert users == set(CLIENT_MODULES) | {"core/internal_auth.py"}, users


def test_no_other_module_that_uses_the_connectors_url_builds_an_unauthenticated_client():
    for f in APP.rglob("*.py"):
        rel = str(f.relative_to(APP))
        text = f.read_text(encoding="utf-8")
        if "CONNECTORS_SERVICE_URL" in text and rel not in CLIENT_MODULES and rel not in ("core/config.py", "api/v1/endpoints/effective_permissions.py"):
            pytest.fail(f"{rel} uses CONNECTORS_SERVICE_URL but is not in CLIENT_MODULES: does it send the token?")


# -------------------------------------------------------------------------- behavior ----
@respx.mock
@pytest.mark.asyncio
async def test_the_case_fanout_client_sends_the_token():
    route = respx.post(f"{BASE}/api/v1/connectors/okta/push_case").mock(return_value=httpx.Response(200, json={"external_id": "1"}))
    status, body, err = await case_fanout._post_to_connector_service(url=f"{BASE}/api/v1/connectors/okta/push_case", payload={"a": 1}, timeout_seconds=5)
    assert (status, err) == ("ok", None) and body == {"external_id": "1"}
    assert route.calls[0].request.headers["authorization"] == f"Bearer {TOKEN}"


@respx.mock
@pytest.mark.asyncio
async def test_the_resource_config_fetcher_uses_the_real_route_and_sends_the_token():
    """It used to call {base}/connectors/... (no /api/v1), which 404'd, and the 404 was swallowed as an empty config."""
    right = respx.post(f"{BASE}/api/v1/connectors/okta/resource_config").mock(return_value=httpx.Response(200, json={"config": {"groups": ["admins"]}}))
    old_wrong = respx.post(f"{BASE}/connectors/okta/resource_config").mock(return_value=httpx.Response(404))
    fetched = await HttpResourceConfigFetcher(BASE, {"api_token": "x"}, {"domain": "d"})("okta", "user-1", "2026-10-06T00:00:00Z")
    assert fetched == {"groups": ["admins"]}, "the config must come back, not an empty dict from a swallowed 404"
    assert right.called and not old_wrong.called
    assert right.calls[0].request.headers["authorization"] == f"Bearer {TOKEN}"


@respx.mock
@pytest.mark.asyncio
async def test_the_catalog_fetch_sends_the_token(monkeypatch):
    monkeypatch.setattr(connectors_ep.settings, "CONNECTORS_SERVICE_URL", BASE)
    route = respx.get(f"{BASE}/api/v1/connectors/schemas").mock(return_value=httpx.Response(200, json={"schemas": [{"id": "okta"}]}))
    assert await connectors_ep._fetch_catalog() == [{"id": "okta"}]
    assert route.calls[0].request.headers["authorization"] == f"Bearer {TOKEN}"


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("refusal", [httpx.Response(401), httpx.Response(503, json={"detail": "connectors service auth is not configured"})])
async def test_a_refused_token_falls_back_to_the_bundled_catalog_instead_of_breaking_the_wizard(monkeypatch, refusal):
    """Characterises a deliberate behaviour: a misconfigured token degrades to the bundled catalog (and logs it)."""
    monkeypatch.setattr(connectors_ep.settings, "CONNECTORS_SERVICE_URL", BASE)
    respx.get(f"{BASE}/api/v1/connectors/schemas").mock(return_value=refusal)
    catalog = await connectors_ep._fetch_catalog()
    assert catalog, "the bundled fallback catalog must be returned"


@respx.mock
@pytest.mark.asyncio
async def test_without_a_token_no_header_is_sent(monkeypatch):
    monkeypatch.delenv("AISOC_CONNECTORS_SERVICE_TOKEN")
    route = respx.post(f"{BASE}/api/v1/connectors/okta/push_case").mock(return_value=httpx.Response(200, json={}))
    await case_fanout._post_to_connector_service(url=f"{BASE}/api/v1/connectors/okta/push_case", payload={}, timeout_seconds=5)
    assert "authorization" not in route.calls[0].request.headers


# --------------------------------------------------------------------- the port bug ----
def test_the_default_url_points_at_the_port_the_connectors_container_listens_on():
    from app.core.config import Settings

    dockerfile = (APP.parents[1] / "connectors" / "Dockerfile").read_text(encoding="utf-8")
    port = int(re.search(r"^EXPOSE\s+(\d+)", dockerfile, re.M).group(1))
    default = Settings.model_fields["CONNECTORS_SERVICE_URL"].default
    assert default == f"http://connectors:{port}", f"default {default!r}; the container listens on {port} (8003 is the fusion service)"
    example = (APP.parents[2] / ".env.example").read_text(encoding="utf-8")
    assert f"CONNECTORS_SERVICE_URL=http://connectors:{port}" in example


# ------------------------------------------------------------------ the fusion gateway ----
@respx.mock
@pytest.mark.asyncio
async def test_the_fusion_gateway_sends_the_fusion_token_and_not_the_connectors_one(monkeypatch):
    from app.api.v1.endpoints import fusion as fusion_ep

    monkeypatch.setenv("AISOC_FUSION_SERVICE_TOKEN", "fusion-tok")
    monkeypatch.setattr(fusion_ep, "_FUSION_URL", "http://fusion:8003")
    route = respx.get("http://fusion:8003/ml/status").mock(return_value=httpx.Response(200, json={"ok": True}))
    await fusion_ep._proxy_get("/ml/status")
    sent = route.calls[0].request.headers["authorization"]
    assert sent == "Bearer fusion-tok" and TOKEN not in sent


def test_every_fusion_client_sends_the_fusion_token_and_only_that_module_uses_the_helper():
    calls = _async_client_calls("api/v1/endpoints/fusion.py")
    assert calls, "the fusion gateway builds no httpx client any more: update this test"
    for call in calls:
        assert [ast.unparse(k.value) for k in call.keywords if k.arg == "headers"] == ["fusion_service_headers()"], call.lineno
    users = {str(f.relative_to(APP)) for f in APP.rglob("*.py") if "fusion_service_headers" in f.read_text(encoding="utf-8")}
    assert users == {"api/v1/endpoints/fusion.py", "core/internal_auth.py"}, users
