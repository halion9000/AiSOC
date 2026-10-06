"""Case endpoints enforce permissions (roles and API-key scopes), not just a login.

Before this, every /cases route accepted ANY authenticated caller: a read-only
API key or a "viewer" login could create, edit and comment on cases. This file
pins both the structure (no route without a permission) and the behavior.
"""
import uuid

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import attack_chain, cases
from app.main import app

CASE = uuid.uuid4()
TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")

EXPECTED_BY_METHOD = {"GET": "cases:read", "POST": "cases:write", "PUT": "cases:write", "PATCH": "cases:write", "DELETE": "cases:delete"}


def _required_permissions(route: APIRoute) -> list[str]:
    found: list[str] = []

    def walk(dep):
        for d in dep.dependencies:
            if "require_permission" in getattr(d.call, "__qualname__", ""):
                for cell in d.call.__closure__ or ():
                    if isinstance(cell.cell_contents, str) and ":" in cell.cell_contents:
                        found.append(cell.cell_contents)
            walk(d)

    walk(route.dependant)
    return found


# ---------------------------------------------------------------- structure ----
@pytest.mark.parametrize("router", [cases.router, attack_chain.router], ids=["cases", "attack_chain"])
def test_every_case_route_enforces_the_permission_for_its_method(router):
    routes = [r for r in router.routes if isinstance(r, APIRoute)]
    assert routes, "router has no routes: the introspection is broken"
    problems = []
    for r in routes:
        for method in r.methods - {"HEAD", "OPTIONS"}:
            perms = _required_permissions(r)
            if perms != [EXPECTED_BY_METHOD[method]]:
                problems.append(f"{method} {r.path}: requires {perms or 'nothing (any logged-in user)'}, expected {EXPECTED_BY_METHOD[method]}")
    assert not problems, "case routes with the wrong or missing permission:\n  " + "\n  ".join(problems)


def test_the_two_case_routers_cover_the_whole_surface():
    routes = [r for rt in (cases.router, attack_chain.router) for r in rt.routes if isinstance(r, APIRoute)]
    assert len(routes) >= 23, "the introspection must see every case handler (23 at the time of writing)"
    assert "/cases/{case_id}/attack-chain" in {r.path for r in routes}


# ----------------------------------------------------------------- behavior ----
def _client(user: CurrentUser) -> TestClient:
    async def fake_db():
        yield None  # a 403 must happen before any database use

    app.dependency_overrides[deps.get_current_user] = lambda: user
    app.dependency_overrides[deps.get_db] = fake_db
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _reset():
    yield
    app.dependency_overrides.clear()


def _user(role="viewer", scopes=None) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email="t@example.com", scopes=scopes)


READS = [("GET", "/api/v1/cases"), ("GET", f"/api/v1/cases/{CASE}"), ("GET", f"/api/v1/cases/{CASE}/timeline"),
         ("GET", f"/api/v1/cases/{CASE}/attack-chain"), ("GET", f"/api/v1/cases/{CASE}/comments")]
WRITES = [("POST", "/api/v1/cases"), ("PATCH", f"/api/v1/cases/{CASE}"), ("POST", f"/api/v1/cases/{CASE}/comments"),
          ("POST", f"/api/v1/cases/{CASE}/notes"), ("POST", f"/api/v1/cases/{CASE}/tasks"), ("POST", f"/api/v1/cases/{CASE}/investigate")]


def _status(client, method, path):
    return client.request(method, path, json={}).status_code


@pytest.mark.parametrize("method,path", WRITES)
def test_viewer_cannot_write(method, path):
    assert _status(_client(_user("viewer")), method, path) == 403


@pytest.mark.parametrize("method,path", READS)
def test_viewer_can_read(method, path):
    assert _status(_client(_user("viewer")), method, path) != 403


@pytest.mark.parametrize("role", ["soc_analyst", "soc_lead", "threat_hunter", "tenant_admin", "admin", "platform_admin", "api_service"])
@pytest.mark.parametrize("method,path", READS + WRITES)
def test_working_roles_are_not_locked_out(role, method, path):
    assert _status(_client(_user(role)), method, path) != 403, f"{role} must keep access to {method} {path}"


@pytest.mark.parametrize("method,path", WRITES)
def test_read_only_api_key_cannot_write(method, path):
    r = _client(_user("admin", scopes=["alerts:read", "cases:read"])).request(method, path, json={})
    assert r.status_code == 403
    assert "cases:write" in r.text  # says which scope is missing


@pytest.mark.parametrize("method,path", READS)
def test_read_only_api_key_can_read(method, path):
    assert _status(_client(_user("admin", scopes=["alerts:read", "cases:read"])), method, path) != 403


@pytest.mark.parametrize("scopes", [["alerts:read", "alerts:write", "cases:read", "cases:write", "connectors:read"], ["cases:*"], ["*"]])
@pytest.mark.parametrize("method,path", READS + WRITES)
def test_keys_with_the_right_scopes_work(scopes, method, path):
    assert _status(_client(_user("admin", scopes=scopes)), method, path) != 403


def test_key_with_no_scopes_at_all_is_refused():
    assert _status(_client(_user("admin", scopes=[])), "GET", "/api/v1/cases") == 403


def test_development_anonymous_user_still_works(monkeypatch):
    """Development resolves an anonymous caller to an admin: nothing changes there."""
    from app.api.v1.dev_auth import is_dev_mode  # noqa: F401  (documented dependency of the bypass)

    assert _status(_client(_user("admin")), "POST", "/api/v1/cases") != 403
