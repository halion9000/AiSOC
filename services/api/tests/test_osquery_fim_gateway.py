"""The FIM gateway: authenticated, tenant-correct, and translated to what the console reads.

The console used to call the osquery service directly. That service did no authentication and trusted a
caller-supplied tenant_id, so anyone who could reach it could read any tenant's file-change history.
"""
import uuid

import httpx
import pytest
import respx
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.api.v1.dev_auth import DEMO_TENANT_ID
from app.api.v1.endpoints import osquery_fim
from app.core.security import ROLE_PERMISSIONS
from app.main import app
from route_introspect import required_permissions

BASE = "http://osquery-tls:9001"
EVENTS = f"{BASE}/api/v1/osquery/fim/events"
SUMMARY = f"{BASE}/api/v1/osquery/fim/summary"
TOKEN = "internal-osquery-token-123"
OTHER_TENANT = uuid.UUID("00000000-0000-0000-0000-0000000000bb")

ITEM = {"id": 1, "tenant_id": "x", "node_key": "n1", "hostname": "web-1", "target_path": "/etc/passwd", "action": "UPDATED",
        "md5": None, "sha256": None, "pid": None, "ppid": None, "process_name": None, "username": None,
        "event_time": "2026-10-01T12:00:00Z", "ingested_at": "2026-10-01T12:00:01Z"}
SERVICE_EVENTS = {"total": 120, "offset": 50, "limit": 25, "items": [ITEM]}
SERVICE_SUMMARY = {"tenant_id": "x", "total_events": 5, "by_action": [{"action": "UPDATED", "count": 2}], "top_paths": [{"target_path": "/etc/passwd", "count": 2}], "active_nodes": 3}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("OSQUERY_TLS_URL", BASE)
    monkeypatch.setenv("AISOC_OSQUERY_TLS_API_TOKEN", TOKEN)
    yield
    app.dependency_overrides.clear()


def _client(role="viewer", scopes=None, tenant=DEMO_TENANT_ID, anonymous=False) -> TestClient:
    async def fake_db():
        yield None

    app.dependency_overrides[deps.get_db] = fake_db
    if not anonymous:
        app.dependency_overrides[deps.get_current_user] = lambda: CurrentUser(
            user_id=uuid.uuid4(), tenant_id=tenant, role=role, email="t@example.com", scopes=scopes)
    return TestClient(app, raise_server_exceptions=False)


def _sent(route):
    return route.calls[0].request


# ------------------------------------------------------------------ the upstream call ----
@respx.mock
def test_events_forward_exactly_what_the_service_accepts_with_the_internal_token():
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    r = _client().get("/api/v1/osquery/fim/events", params={"tenant_id": "default", "page": 3, "page_size": 25,
                      "action": "UPDATED", "path_prefix": "/etc/", "node_key": "n1", "since": "2026-10-01T00:00:00"})
    assert r.status_code == 200, r.text
    q = dict(_sent(route).url.params)
    assert q == {"tenant_id": "default", "limit": "25", "offset": "50", "action": "UPDATED", "path_prefix": "/etc/",
                 "node_key": "n1", "since": "2026-10-01T00:00:00"}
    assert _sent(route).headers["authorization"] == f"Bearer {TOKEN}"


@respx.mock
def test_the_callers_own_credentials_never_go_upstream():
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    _client().get("/api/v1/osquery/fim/events", headers={"Authorization": "Bearer the-users-secret-jwt", "Cookie": "s=1"})
    assert _sent(route).headers["authorization"] == f"Bearer {TOKEN}"
    assert "the-users-secret-jwt" not in str(_sent(route).headers)
    assert "cookie" not in _sent(route).headers


@respx.mock
def test_no_token_configured_sends_no_authorization_header(monkeypatch):
    monkeypatch.setenv("AISOC_OSQUERY_TLS_API_TOKEN", "")
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    _client().get("/api/v1/osquery/fim/events")
    assert "authorization" not in _sent(route).headers


@respx.mock
def test_optional_filters_are_omitted_not_sent_empty():
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    _client().get("/api/v1/osquery/fim/events", params={"action": "", "node_key": ""})
    assert set(dict(_sent(route).url.params)) == {"tenant_id", "limit", "offset"}


@respx.mock
@pytest.mark.parametrize("page,page_size,offset", [(1, 25, 0), (2, 25, 25), (3, 10, 20), (1, 200, 0), (5, 1, 4)])
def test_paging_maps_to_limit_and_offset(page, page_size, offset):
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    _client().get("/api/v1/osquery/fim/events", params={"page": page, "page_size": page_size})
    q = dict(_sent(route).url.params)
    assert (q["limit"], q["offset"]) == (str(page_size), str(offset))


@respx.mock
def test_the_response_is_translated_to_the_consoles_shape():
    respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    d = _client().get("/api/v1/osquery/fim/events", params={"page": 3, "page_size": 25}).json()
    assert set(d) == {"events", "total", "page", "page_size"}, "the console reads events/page/page_size, not items/offset/limit"
    assert (d["total"], d["page"], d["page_size"]) == (120, 3, 25)
    assert d["events"] == [ITEM]


@respx.mock
def test_summary_is_forwarded_and_carries_active_nodes():
    route = respx.get(SUMMARY).mock(return_value=httpx.Response(200, json=SERVICE_SUMMARY))
    d = _client().get("/api/v1/osquery/fim/summary", params={"tenant_id": "default", "since": "2026-10-01T00:00:00"}).json()
    assert dict(_sent(route).url.params) == {"tenant_id": "default", "since": "2026-10-01T00:00:00"}
    assert (d["total_events"], d["active_nodes"]) == (5, 3)
    assert d["by_action"] == [{"action": "UPDATED", "count": 2}] and d["top_paths"][0]["target_path"] == "/etc/passwd"


# ---------------------------------------------------------------------- tenants ----
@respx.mock
def test_a_caller_may_read_their_own_tenant_and_omitting_it_means_their_own():
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    c = _client(tenant=OTHER_TENANT)
    assert c.get("/api/v1/osquery/fim/events", params={"tenant_id": str(OTHER_TENANT)}).status_code == 200
    assert c.get("/api/v1/osquery/fim/events").status_code == 200
    assert [dict(call.request.url.params)["tenant_id"] for call in route.calls] == [str(OTHER_TENANT)] * 2


@respx.mock
def test_a_tenant_cannot_read_another_tenants_events_and_the_service_is_not_called():
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    route2 = respx.get(SUMMARY).mock(return_value=httpx.Response(200, json=SERVICE_SUMMARY))
    c = _client(role="admin", tenant=OTHER_TENANT)  # admin is NOT platform_admin
    assert c.get("/api/v1/osquery/fim/events", params={"tenant_id": str(DEMO_TENANT_ID)}).status_code == 403
    assert c.get("/api/v1/osquery/fim/summary", params={"tenant_id": "someone-elses-tenant"}).status_code == 403
    assert not route.called and not route2.called


@respx.mock
def test_only_the_installs_default_tenant_may_read_the_literal_default_namespace():
    """Agents that send no tenant header are recorded under "default". That is the default tenant's data."""
    respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    assert _client(tenant=DEMO_TENANT_ID).get("/api/v1/osquery/fim/events", params={"tenant_id": "default"}).status_code == 200
    # a DIFFERENT tenant must not be able to read the default tenant's file-change history by asking for "default"
    assert _client(tenant=OTHER_TENANT).get("/api/v1/osquery/fim/events", params={"tenant_id": "default"}).status_code == 403


@respx.mock
def test_a_platform_admin_may_read_any_tenant():
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    c = _client(role="platform_admin", tenant=OTHER_TENANT)
    assert c.get("/api/v1/osquery/fim/events", params={"tenant_id": "default"}).status_code == 200
    assert c.get("/api/v1/osquery/fim/events", params={"tenant_id": "any-string"}).status_code == 200
    assert route.call_count == 2


@pytest.mark.parametrize("requested,expected", [(None, str(OTHER_TENANT)), ("", str(OTHER_TENANT)), ("  ", str(OTHER_TENANT)), (str(OTHER_TENANT), str(OTHER_TENANT))])
def test_resolve_tenant_defaults_to_the_callers_own(requested, expected):
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=OTHER_TENANT, role="viewer", email="e", scopes=None)
    assert osquery_fim.resolve_tenant(user, requested) == expected


# ---------------------------------------------------------------- validation/failure ----
@respx.mock
def test_input_limits_are_422_and_never_reach_the_service():
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    c = _client()
    for params in ({"page": 0}, {"page_size": 0}, {"page_size": 201}, {"page": 100001}, {"action": "x" * 33}, {"since": "s" * 65}):
        assert c.get("/api/v1/osquery/fim/events", params=params).status_code == 422, params
    assert not route.called


@respx.mock
@pytest.mark.parametrize("failure", [httpx.ConnectError("down"), httpx.Response(401), httpx.Response(503), httpx.Response(500, json={}),
                                     httpx.Response(200, text="not json"), httpx.Response(200, json=["list"]), httpx.Response(200, json={"items": "no", "total": 1})])
def test_upstream_trouble_is_a_502_never_made_up_data(failure):
    if isinstance(failure, Exception):
        respx.get(EVENTS).mock(side_effect=failure)
    else:
        respx.get(EVENTS).mock(return_value=failure)
    assert _client().get("/api/v1/osquery/fim/events").status_code == 502


@respx.mock
def test_a_summary_without_active_nodes_is_refused_not_zeroed():
    """An older service version lacking the field must be an error, not a silent 0."""
    respx.get(SUMMARY).mock(return_value=httpx.Response(200, json={k: v for k, v in SERVICE_SUMMARY.items() if k != "active_nodes"}))
    assert _client().get("/api/v1/osquery/fim/summary").status_code == 502


@respx.mock
def test_an_unconfigured_service_is_a_503(monkeypatch):
    monkeypatch.delenv("OSQUERY_TLS_URL")
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    assert _client().get("/api/v1/osquery/fim/events").status_code == 503
    assert not route.called


# ------------------------------------------------------------------- permissions ----
def test_both_routes_require_alerts_read():
    routes = [r for r in osquery_fim.router.routes if isinstance(r, APIRoute)]
    assert len(routes) == 2 and all(required_permissions(r) == ["alerts:read"] for r in routes)


@respx.mock
@pytest.mark.parametrize("role", [r for r, perms in ROLE_PERMISSIONS.items() if "alerts:read" in perms or "*" in perms])
def test_every_role_that_may_read_alerts_can_read_fim(role):
    respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    assert _client(role).get("/api/v1/osquery/fim/events").status_code == 200


@respx.mock
def test_an_api_key_without_the_scope_is_refused_and_the_service_is_not_called():
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    assert _client("admin", scopes=["cases:read"]).get("/api/v1/osquery/fim/events").status_code == 403
    assert _client("admin", scopes=["cases:read"]).get("/api/v1/osquery/fim/summary").status_code == 403
    assert not route.called
    assert _client("admin", scopes=["alerts:read"]).get("/api/v1/osquery/fim/events").status_code == 200


@respx.mock
def test_anonymous_callers_in_production_never_reach_the_service(monkeypatch):
    monkeypatch.setattr(deps, "is_dev_mode", lambda: False)
    route = respx.get(EVENTS).mock(return_value=httpx.Response(200, json=SERVICE_EVENTS))
    c = _client(anonymous=True)
    assert c.get("/api/v1/osquery/fim/events").status_code == 401
    assert c.get("/api/v1/osquery/fim/summary").status_code == 401
    assert not route.called
