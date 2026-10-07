"""The honeytokens and purple-team gateways: authenticated, permissioned, tenant-forced, and safe.

The console's honeytokens and purple-team pages call these paths on the API, which served neither, so those pages had no
working backend. Pointing the browser at the services directly would have been unsafe: they authenticated nobody, trusted a
caller-supplied tenant_id, and purple-team can launch adversary simulations.
"""
import json
import re
import uuid
from pathlib import Path

import httpx
import pytest
import respx
import yaml
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.api.v1.dev_auth import DEMO_TENANT_ID
from app.api.v1.endpoints import service_gateways as gw
from app.core.security import ROLE_PERMISSIONS
from app.main import app
from route_introspect import required_permissions

ROOT = Path(__file__).resolve().parents[3]
OTHER_TENANT = uuid.UUID("00000000-0000-0000-0000-0000000000bb")
ID = "11111111-2222-3333-4444-555555555555"
TOKENS = {"honeytokens": "honeytokens-svc-token", "purple-team": "purple-team-svc-token"}
HOSTS = {"honeytokens": "http://honeytokens:8005", "purple-team": "http://purple-team:8006"}
ALL = [(g, r) for g in gw.GATEWAYS for r in g.routes]


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AISOC_HONEYTOKENS_SERVICE_TOKEN", TOKENS["honeytokens"])
    monkeypatch.setenv("AISOC_PURPLE_TEAM_SERVICE_TOKEN", TOKENS["purple-team"])
    monkeypatch.delenv("HONEYTOKENS_SERVICE_URL", raising=False)
    monkeypatch.delenv("PURPLE_TEAM_SERVICE_URL", raising=False)
    yield
    app.dependency_overrides.clear()


def _client(role="platform_admin", tenant=DEMO_TENANT_ID, anonymous=False) -> TestClient:
    async def fake_db():
        yield None

    app.dependency_overrides[deps.get_db] = fake_db
    if not anonymous:
        app.dependency_overrides[deps.get_current_user] = lambda: CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant, role=role, email="t@example.com", scopes=None)
    return TestClient(app, raise_server_exceptions=False)


def _path(g, r):
    return "/api/v1/" + g.prefix + r.path.replace("{token_id}", ID).replace("{execution_id}", ID).replace("{session_id}", ID)


def _upstream(status=200, body=None):
    return respx.route().mock(return_value=httpx.Response(status, json={"ok": True} if body is None else body))


def _call(c, g, r, **kw):
    kw.setdefault("json", {} if r.method in ("POST", "PUT", "PATCH") else None)
    return c.request(r.method, _path(g, r), **kw)


def _allowed(role, permission):
    perms = ROLE_PERMISSIONS[role]
    return "*" in perms or permission in perms or f"{permission.split(':')[0]}:*" in perms


# ------------------------------------------------------------------------ registration ----
def test_every_table_entry_is_a_registered_route_with_exactly_its_permission():
    registered = {(next(iter(x.methods)), x.path): required_permissions(x) for x in gw.router.routes if isinstance(x, APIRoute)}
    assert len(registered) == len(ALL) == 25
    for g, r in ALL:
        assert registered[(r.method, f"/{g.prefix}{r.path}")] == [r.permission], f"{r.method} {g.prefix}{r.path}"


def test_the_routes_are_part_of_the_api():
    paths = app.openapi()["paths"]
    for g, r in ALL:
        assert r.method.lower() in paths[f"/api/v1/{g.prefix}{r.path}"]


# Written out by hand, NOT derived from the gateway's own table: the role matrix below computes its expectation from that
# table, so a weakened permission there would stay self-consistent. Changing a permission must be deliberate in two places.
PINNED_PERMISSIONS = {
    ("honeytokens", "POST", ""): "alerts:write",
    ("honeytokens", "GET", ""): "alerts:read",
    ("honeytokens", "GET", "/{token_id}"): "alerts:read",
    ("honeytokens", "PATCH", "/{token_id}/revoke"): "alerts:write",
    ("honeytokens", "DELETE", "/{token_id}"): "alerts:delete",
    ("honeytokens", "GET", "/{token_id}/triggers"): "alerts:read",
    ("purple-team", "POST", "/atomics/sync"): "settings:write",
    ("purple-team", "GET", "/atomics"): "alerts:read",
    ("purple-team", "POST", "/atomics/run"): "settings:write",
    ("purple-team", "GET", "/caldera/health"): "alerts:read",
    ("purple-team", "GET", "/caldera/abilities"): "alerts:read",
    ("purple-team", "GET", "/caldera/adversaries"): "alerts:read",
    ("purple-team", "GET", "/caldera/operations"): "alerts:read",
    ("purple-team", "POST", "/caldera/run"): "settings:write",
    ("purple-team", "GET", "/executions"): "alerts:read",
    ("purple-team", "PATCH", "/executions/{execution_id}/detection"): "rules:write",
    ("purple-team", "GET", "/coverage"): "alerts:read",
    ("purple-team", "POST", "/drift/snapshot"): "rules:write",
    ("purple-team", "GET", "/drift/snapshots"): "alerts:read",
    ("purple-team", "GET", "/drift/latest"): "alerts:read",
    ("purple-team", "POST", "/tabletop"): "rules:write",
    ("purple-team", "GET", "/tabletop"): "alerts:read",
    ("purple-team", "GET", "/tabletop/{session_id}"): "alerts:read",
    ("purple-team", "POST", "/tabletop/{session_id}/findings"): "rules:write",
    ("purple-team", "PATCH", "/tabletop/{session_id}/complete"): "rules:write",
}


def test_the_permission_of_every_route_is_pinned():
    actual = {(g.name, r.method, r.path): r.permission for g, r in ALL}
    assert actual == PINNED_PERMISSIONS


def test_the_canary_callback_is_not_proxied():
    """Canaries report through the service directly; their only credential is the token id, so it cannot sit behind a login."""
    assert not [p for p in app.openapi()["paths"] if "webhook" in p]


def test_running_a_simulation_and_syncing_need_the_admin_level_permission():
    needs = {(g.name, r.path): r.permission for g, r in ALL}
    assert needs[("purple-team", "/atomics/run")] == needs[("purple-team", "/caldera/run")] == needs[("purple-team", "/atomics/sync")] == "settings:write"
    assert all(r.permission == "alerts:read" for g, r in ALL if r.method == "GET")


# ------------------------------------------------------------------------ role matrix ----
@respx.mock
@pytest.mark.parametrize("role", sorted(ROLE_PERMISSIONS))
@pytest.mark.parametrize("g,r", ALL, ids=[f"{r.method} {g.prefix}{r.path}" for g, r in ALL])
def test_each_role_gets_exactly_what_its_permissions_allow(g, r, role):
    route = _upstream()
    resp = _call(_client(role=role), g, r)
    if _allowed(role, r.permission):
        assert resp.status_code == 200 and route.called, f"{role} should be allowed {r.method} {g.prefix}{r.path}"
    else:
        assert resp.status_code == 403 and not route.called, f"{role} must not reach the service via {r.method} {g.prefix}{r.path}"


@respx.mock
@pytest.mark.parametrize("g,r", ALL, ids=[f"{r.method} {g.prefix}{r.path}" for g, r in ALL])
def test_anonymous_callers_in_production_never_reach_the_service(monkeypatch, g, r):
    monkeypatch.setattr(deps, "is_dev_mode", lambda: False)
    route = _upstream()
    assert _call(_client(anonymous=True), g, r).status_code == 401
    assert not route.called


# --------------------------------------------------------------------- the tenant ----
@respx.mock
@pytest.mark.parametrize("g,r", ALL, ids=[f"{r.method} {g.prefix}{r.path}" for g, r in ALL])
def test_the_callers_tenant_replaces_whatever_the_browser_sent(g, r):
    route = _upstream()
    _call(_client(tenant=DEMO_TENANT_ID), g, r, params={"tenant_id": str(OTHER_TENANT), "limit": "5"})
    sent = route.calls[0].request
    q = httpx.QueryParams(sent.url.query)
    assert q.get_list("tenant_id") == [str(DEMO_TENANT_ID)], "another tenant's id reached the service"
    assert q.get("limit") == "5", "other query parameters must still pass"


@respx.mock
@pytest.mark.parametrize("g,r", [(g, r) for g, r in ALL if r.body_tenant], ids=lambda v: getattr(v, "path", getattr(v, "name", "")))
def test_a_body_tenant_is_replaced_and_the_rest_of_the_body_survives(g, r):
    route = _upstream()
    _call(_client(tenant=DEMO_TENANT_ID), g, r, json={"tenant_id": str(OTHER_TENANT), "name": "x", "technique_id": "T1059"})
    body = json.loads(route.calls[0].request.content)
    assert body["tenant_id"] == str(DEMO_TENANT_ID) and body["name"] == "x" and body["technique_id"] == "T1059"


@respx.mock
def test_a_body_that_has_no_tenant_still_gets_the_callers_tenant_on_routes_that_take_one():
    route = _upstream()
    g, r = gw.GATEWAYS[0], gw.GATEWAYS[0].routes[0]
    _client(tenant=DEMO_TENANT_ID).post(_path(g, r), content=b"")
    assert json.loads(route.calls[0].request.content)["tenant_id"] == str(DEMO_TENANT_ID)


@respx.mock
def test_routes_whose_body_has_no_tenant_field_are_not_given_one():
    route = _upstream()
    g = gw.GATEWAYS[1]
    r = next(x for x in g.routes if x.path == "/tabletop/{session_id}/findings")
    _call(_client(), g, r, json={"finding": "f", "severity": "high"})
    assert json.loads(route.calls[0].request.content) == {"finding": "f", "severity": "high"}


# ---------------------------------------------------------------------- credentials ----
@respx.mock
@pytest.mark.parametrize("g,r", ALL, ids=[f"{r.method} {g.prefix}{r.path}" for g, r in ALL])
def test_the_service_gets_its_own_token_and_never_the_callers_credentials(g, r):
    route = _upstream()
    _call(_client(), g, r, headers={"Authorization": "Bearer callers-own-jwt", "Cookie": "session=abc"})
    sent = route.calls[0].request
    assert sent.headers["authorization"] == f"Bearer {TOKENS[g.name]}"
    assert "callers-own-jwt" not in str(sent.headers) and "cookie" not in sent.headers


@respx.mock
def test_each_service_gets_only_its_own_token():
    route = _upstream()
    for g, r in ((gw.GATEWAYS[0], gw.GATEWAYS[0].routes[1]), (gw.GATEWAYS[1], gw.GATEWAYS[1].routes[1])):
        _call(_client(), g, r)
    sent = [(c.request.url.host, c.request.headers["authorization"]) for c in route.calls]
    assert sent == [("honeytokens", f"Bearer {TOKENS['honeytokens']}"), ("purple-team", f"Bearer {TOKENS['purple-team']}")]


@respx.mock
def test_without_a_token_configured_no_authorization_header_is_sent(monkeypatch):
    monkeypatch.delenv("AISOC_HONEYTOKENS_SERVICE_TOKEN")
    route = _upstream()
    g = gw.GATEWAYS[0]
    _call(_client(), g, g.routes[1])
    assert "authorization" not in route.calls[0].request.headers


# ---------------------------------------------------------------------------- paths ----
@respx.mock
@pytest.mark.parametrize("bad", ["%2e%2e", "a%20b", "x" * 129, "..%2fadmin", "a%2f..%2fb", "%00", ".hidden"])
def test_a_path_segment_that_is_not_a_plain_identifier_is_refused(bad):
    route = _upstream()
    resp = _client().get(f"/api/v1/honeytokens/{bad}")
    assert resp.status_code in (400, 404, 422) and not route.called, bad


@respx.mock
def test_a_normal_identifier_reaches_the_expected_upstream_url():
    route = _upstream()
    _client().get(f"/api/v1/honeytokens/{ID}/triggers", params={"limit": "10"})
    assert route.calls[0].request.url.path == f"/api/v1/honeytokens/{ID}/triggers"
    assert route.calls[0].request.url.host == "honeytokens" and route.calls[0].request.url.port == 8005


# ----------------------------------------------------------------- upstream outcomes ----
@respx.mock
@pytest.mark.parametrize("status", [401, 403, 500, 502, 503])
def test_a_service_auth_failure_or_server_error_is_a_502_never_a_401_that_would_log_the_user_out(status):
    _upstream(status, {"detail": "internal secret detail"})
    resp = _client().get("/api/v1/honeytokens")
    assert resp.status_code == 502 and "internal secret detail" not in resp.text


@respx.mock
@pytest.mark.parametrize("status", [200, 201, 404, 409, 422])
def test_ordinary_outcomes_pass_through_unchanged(status):
    _upstream(status, {"detail": "x", "n": status})
    resp = _client().get("/api/v1/honeytokens")
    assert resp.status_code == status and resp.json()["n"] == status


@respx.mock
def test_a_204_has_no_body():
    respx.route().mock(return_value=httpx.Response(204))
    g = gw.GATEWAYS[0]
    resp = _call(_client(), g, next(r for r in g.routes if r.method == "DELETE"))
    assert resp.status_code == 204 and resp.content == b""


@respx.mock
def test_a_service_that_is_not_running_is_a_503_not_a_crash():
    respx.route().mock(side_effect=httpx.ConnectError("refused"))
    resp = _client().get("/api/v1/honeytokens")
    assert resp.status_code == 503 and "not available" in resp.json()["detail"]


@respx.mock
def test_invalid_oversized_and_non_object_bodies_are_refused_before_reaching_the_service():
    route = _upstream()
    c, g = _client(), gw.GATEWAYS[0]
    url = _path(g, g.routes[0])
    assert c.post(url, content=b"{not json", headers={"content-type": "application/json"}).status_code == 400
    assert c.post(url, content=b"[1,2]", headers={"content-type": "application/json"}).status_code == 422
    assert c.post(url, content=b" " * 1_000_001, headers={"content-type": "application/json"}).status_code == 413
    assert not route.called


# --------------------------------------------------------------------------- compose ----
def _compose_env(service):
    e = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"][service].get("environment") or {}
    return e if isinstance(e, dict) else dict(x.split("=", 1) for x in e if "=" in x)


def _ref(value):
    return re.match(r"\$\{(\w+)", str(value)).group(1)


@pytest.mark.parametrize("name,var", [("honeytokens", "AISOC_HONEYTOKENS_SERVICE_TOKEN"), ("purple-team", "AISOC_PURPLE_TEAM_SERVICE_TOKEN"), ("ueba", "AISOC_UEBA_SERVICE_TOKEN")])
def test_compose_gives_each_service_its_token(name, var):
    assert _ref(_compose_env(name)[var]) == var
    if name != "ueba":
        assert _ref(_compose_env("api")[var]) == var, "the API gateway must send the same token the service enforces"


@pytest.mark.parametrize("name,url_env", [("honeytokens", "HONEYTOKENS_SERVICE_URL"), ("purple-team", "PURPLE_TEAM_SERVICE_URL")])
def test_the_gateway_reaches_each_service_on_the_port_it_really_listens_on(name, url_env):
    port = int(re.search(r"^EXPOSE\s+(\d+)", (ROOT / "services" / name / "Dockerfile").read_text(encoding="utf-8"), re.M).group(1))
    assert _compose_env("api")[url_env] == f"http://{name}:{port}"
    gateway = next(x for x in gw.GATEWAYS if x.name == name)
    assert gateway.default_url == f"http://{name}:{port}"
