"""Agents service authentication (production only): internal token or API-verified bearer."""
import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocketDisconnect

from app.core import service_auth
from app.core.service_auth import ServiceAuthMiddleware

ME = "http://api:8000/api/v1/auth/me"
AUTHZ = "http://api:8000/api/v1/auth/authorize"
PLAIN = "/api/v1/copilot/ping"   # matches no permission rule: a login is enough


async def _ok(request):
    return PlainTextResponse("reached")


async def _ws(websocket):
    await websocket.accept()
    await websocket.send_text("reached")
    await websocket.close()


def _client() -> TestClient:
    inner = Starlette(routes=[Route("/api/v1/playbooks", _ok, methods=["GET", "POST", "OPTIONS"]),
                              Route("/api/v1/playbooks/{pid}/run", _ok, methods=["POST"]), Route(PLAIN, _ok),
                              Route("/readyz", _ok), WebSocketRoute("/api/v1/investigations/x/stream", _ws)])
    return TestClient(ServiceAuthMiddleware(inner))


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    service_auth.clear_cache()
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("INTERNAL_TOKEN", "internal-secret-123")
    monkeypatch.setenv("API_URL", "http://api:8000")
    for k in ("AISOC_ENV", "APP_ENV"):
        monkeypatch.delenv(k, raising=False)


def test_development_is_unchanged(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    assert _client().get("/api/v1/playbooks").text == "reached"


def test_health_and_preflight_stay_open():
    c = _client()
    assert c.get("/readyz").status_code == 200
    assert c.options("/api/v1/playbooks").status_code == 200


def test_no_credentials_is_refused():
    assert _client().get("/api/v1/playbooks").status_code == 401


def test_internal_token_from_the_api_proxies():
    c = _client()
    assert c.get("/api/v1/playbooks", headers={"x-internal-token": "internal-secret-123"}).status_code == 200
    assert c.get("/api/v1/playbooks", headers={"x-internal-token": "wrong"}).status_code == 401


def test_internal_token_ignored_when_not_configured(monkeypatch):
    monkeypatch.setenv("INTERNAL_TOKEN", "")
    assert _client().get("/api/v1/playbooks", headers={"x-internal-token": ""}).status_code == 401


@respx.mock
def test_valid_bearer_is_verified_by_the_api_and_cached():
    route = respx.get(ME).mock(return_value=httpx.Response(200, json={"id": "u"}))
    c = _client()
    h = {"Authorization": "Bearer aisoc_goodkey"}
    assert c.get(PLAIN, headers=h).status_code == 200
    assert c.get(PLAIN, headers=h).status_code == 200
    assert route.call_count == 1, "second call served from the short cache"
    assert route.calls[0].request.headers["authorization"] == "Bearer aisoc_goodkey"


@respx.mock
def test_rejected_bearer_is_refused():
    respx.get(ME).mock(return_value=httpx.Response(401))
    assert _client().get(PLAIN, headers={"Authorization": "Bearer revoked"}).status_code == 401


@respx.mock
@pytest.mark.parametrize("failure", [httpx.ConnectError("down"), httpx.Response(500), httpx.Response(422)])
def test_api_unreachable_or_confused_fails_closed(failure):
    if isinstance(failure, Exception):
        respx.get(ME).mock(side_effect=failure)
        respx.post(AUTHZ).mock(side_effect=failure)
    else:
        respx.get(ME).mock(return_value=failure)
        respx.post(AUTHZ).mock(return_value=failure)
    c = _client()
    h = {"Authorization": "Bearer x123456"}
    assert c.get(PLAIN, headers=h).status_code == 503
    assert c.get("/api/v1/playbooks", headers=h).status_code == 503


@respx.mock
def test_a_route_that_needs_a_permission_asks_the_API_for_exactly_that_permission():
    route = respx.post(AUTHZ).mock(return_value=httpx.Response(200, json={"allowed": True}))
    c = _client()
    h = {"Authorization": "Bearer aisoc_goodkey"}
    assert c.get("/api/v1/playbooks", headers=h).status_code == 200
    assert c.post("/api/v1/playbooks/p1/run", headers=h).status_code == 200
    asked = [__import__("json").loads(call.request.content)["permission"] for call in route.calls]
    assert asked == ["playbooks:read", "playbooks:execute"]
    assert all(call.request.headers["authorization"] == "Bearer aisoc_goodkey" for call in route.calls)


@respx.mock
def test_a_caller_without_the_permission_gets_403_not_the_resource():
    respx.post(AUTHZ).mock(return_value=httpx.Response(403, json={"detail": "Permission denied"}))
    resp = _client().post("/api/v1/playbooks/p1/run", headers={"Authorization": "Bearer viewer-token"})
    assert resp.status_code == 403


@respx.mock
def test_bad_credentials_on_a_permissioned_route_are_401_not_403():
    respx.post(AUTHZ).mock(return_value=httpx.Response(401))
    assert _client().get("/api/v1/playbooks", headers={"Authorization": "Bearer expired"}).status_code == 401


@respx.mock
def test_the_cache_is_per_permission_so_one_yes_is_not_a_blanket_yes():
    def answer(request):
        import json
        return httpx.Response(200 if json.loads(request.content)["permission"] == "playbooks:read" else 403)

    respx.post(AUTHZ).mock(side_effect=answer)
    c = _client()
    h = {"Authorization": "Bearer analyst-token"}
    assert c.get("/api/v1/playbooks", headers=h).status_code == 200            # cached as playbooks:read
    assert c.post("/api/v1/playbooks/p1/run", headers=h).status_code == 403    # a DIFFERENT permission is asked, not served from cache
    assert c.get("/api/v1/playbooks", headers=h).status_code == 200


@respx.mock
def test_internal_token_calls_skip_authorization_because_the_api_already_did_it():
    route = respx.post(AUTHZ).mock(return_value=httpx.Response(403))
    me = respx.get(ME).mock(return_value=httpx.Response(401))
    r = _client().post("/api/v1/playbooks/p1/run", headers={"x-internal-token": "internal-secret-123"})
    assert r.status_code == 200 and not route.called and not me.called


@respx.mock
def test_websocket_asks_for_the_permission_of_a_GET():
    route = respx.post(AUTHZ).mock(return_value=httpx.Response(403))
    with pytest.raises(WebSocketDisconnect) as exc:
        with _client().websocket_connect("/api/v1/investigations/x/stream", headers={"Authorization": "Bearer viewer-token"}) as ws:
            ws.receive_text()
    assert exc.value.code == 4403
    import json
    assert json.loads(route.calls[0].request.content)["permission"] == "cases:read"


def test_websocket_without_credentials_is_closed_unauthorized():
    with pytest.raises(WebSocketDisconnect) as exc:
        with _client().websocket_connect("/api/v1/investigations/x/stream") as ws:
            ws.receive_text()
    assert exc.value.code == 4401


def test_websocket_with_internal_token_is_allowed():
    with _client().websocket_connect("/api/v1/investigations/x/stream", headers={"x-internal-token": "internal-secret-123"}) as ws:
        assert ws.receive_text() == "reached"


def test_real_agents_app_is_protected_in_production():
    from app.main import app
    c = TestClient(app)
    assert c.get("/api/v1/playbooks").status_code == 401
    assert c.get("/api/v1/hunt/saved").status_code == 401
    assert c.post("/api/v1/contextual/action").status_code == 401
    assert c.get("/readyz").status_code != 401
