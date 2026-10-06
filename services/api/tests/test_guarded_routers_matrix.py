"""Role x route and API-key-scope matrix for the MSSP, remediation, reports and marketplace routers.

Routes are discovered from the real routers (not listed by hand), so a new route in
any of them is checked automatically. Expectations come from the real role table.

  mssp         GET -> mssp:read, onboarding -> mssp:onboard (platform wildcard only),
               everything else -> mssp:manage
  remediation  GET -> remediation:read, everything else -> remediation:write
  reports      GET -> reports:read, everything else -> reports:write
  marketplace  install / uninstall -> settings:write (browsing stays open to any login)
"""
import re
import uuid

import httpx
import pytest
import respx
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import marketplace, mssp, remediation, reports
from app.core.security import ROLE_PERMISSIONS, has_permission
from app.main import app
from route_introspect import required_permissions

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
ID = "00000000-0000-0000-0000-0000000000aa"


def expected_permission(module, route: APIRoute, method: str) -> str | None:
    if module is mssp:
        if method == "GET":
            return "mssp:read"
        return "mssp:onboard" if route.path.endswith("/onboard") else "mssp:manage"
    if module is remediation:
        return "remediation:read" if method == "GET" else "remediation:write"
    if module is reports:
        return "reports:read" if method == "GET" else "reports:write"
    if module is marketplace:
        return "settings:write" if method in ("POST", "PUT", "PATCH", "DELETE") else None
    raise AssertionError(module)


def discover():
    rows = []
    for module in (mssp, remediation, reports, marketplace):
        for r in module.router.routes:
            if isinstance(r, APIRoute):
                for method in sorted(r.methods - {"HEAD", "OPTIONS"}):
                    rows.append((module, r, method, expected_permission(module, r, method)))
    return rows


ROWS = discover()
GUARDED = [(m, r, meth, perm) for m, r, meth, perm in ROWS if perm]
IDS = [f"{meth} /api/v1{r.path}" for _, r, meth, _ in GUARDED]
ROLES = list(ROLE_PERMISSIONS)


@pytest.fixture(autouse=True)
def _reset():
    yield
    app.dependency_overrides.clear()


def _client(user: CurrentUser) -> TestClient:
    async def fake_db():
        yield None

    app.dependency_overrides[deps.get_db] = fake_db
    app.dependency_overrides[deps.get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=False)


def _user(role="viewer", scopes=None) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email="t@example.com", scopes=scopes)


def _call(client, method, route):
    path = "/api/v1" + re.sub(r"\{[^}]+\}", ID, route.path)
    with respx.mock(assert_all_called=False) as mock:
        mock.route(host__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        return client.request(method, path, json={}).status_code


def test_discovery_found_the_routers():
    assert len([1 for m, *_ in GUARDED if m is mssp]) >= 20
    assert len([1 for m, *_ in GUARDED if m is remediation]) >= 6
    assert len([1 for m, *_ in GUARDED if m is reports]) >= 8
    assert len([1 for m, *_ in GUARDED if m is marketplace]) == 2


def test_every_route_requires_exactly_the_permission_for_its_kind():
    problems = []
    for module, route, method, perm in ROWS:
        actual = required_permissions(route)
        if perm is None:
            continue
        if actual != [perm]:
            problems.append(f"{method} {route.path}: requires {actual or 'nothing beyond a login'}, expected [{perm}]")
    assert not problems, "\n  " + "\n  ".join(problems)


def test_only_platform_wildcard_roles_may_onboard_a_child_tenant():
    holders = [r for r in ROLES if has_permission(r, "mssp:onboard")]
    assert sorted(holders) == ["admin", "platform_admin"]


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("module,route,method,perm", GUARDED, ids=IDS)
def test_each_role_gets_exactly_what_the_role_table_says(role, module, route, method, perm):
    status = _call(_client(_user(role)), method, route)
    if has_permission(role, perm):
        assert status not in (401, 403), f"{role} holds {perm} and must keep {method} {route.path} (got {status})"
    else:
        assert status == 403, f"{role} lacks {perm}; {method} {route.path} must refuse (got {status})"


@pytest.mark.parametrize("module,route,method,perm", GUARDED, ids=IDS)
def test_api_key_scopes_are_enforced(module, route, method, perm):
    assert _call(_client(_user("admin", scopes=["alerts:delete"])), method, route) == 403
    assert _call(_client(_user("admin", scopes=[perm])), method, route) not in (401, 403)


def test_viewers_and_analysts_cannot_edit_the_remediation_whitelist():
    """The motivating case: any logged-in user, a viewer included, could edit the auto-remediation whitelist."""
    wl = next(r for m, r, meth, _ in GUARDED if m is remediation and meth == "POST" and "whitelist" in r.path)
    assert _call(_client(_user("viewer")), "POST", wl) == 403
    assert _call(_client(_user("soc_analyst")), "POST", wl) == 403
    assert _call(_client(_user("soc_lead")), "POST", wl) != 403
