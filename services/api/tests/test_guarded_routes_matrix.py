"""Role x route and API-key-scope matrix for the routes that used to answer anonymously.

Expectations come from the real role table (core.security.ROLE_PERMISSIONS), so a
role that SHOULD have access is proven not locked out, and one that should not is
proven refused. A structural check keeps this table honest against the code.
"""
import uuid

import httpx
import pytest
import respx
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import airgap, api_keys, compliance, deployment, fusion, llm_status, nl_detection, stix_taxii, translation
from app.core.security import ROLE_PERMISSIONS, has_permission
from app.main import app
from route_introspect import required_permissions

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
OTHER_TENANT = uuid.UUID("00000000-0000-0000-0000-0000000000bb")
ID = "00000000-0000-0000-0000-0000000000aa"
Q = f"?tenant_id={TENANT}"

ROUTES = [  # (METHOD, concrete path, permission)
    ("GET", "/api/v1/airgap/status", "settings:read"),
    ("POST", "/api/v1/compliance/evidence/collect", "reports:write"),
    ("GET", "/api/v1/compliance/frameworks", "reports:read"),
    ("GET", f"/api/v1/compliance/frameworks/{ID}/controls", "reports:read"),
    ("GET", "/api/v1/deployment/config", "settings:read"),
    ("PUT", "/api/v1/deployment/config", "settings:write"),
    ("GET", "/api/v1/deployment/airgap/status", "settings:read"),
    ("POST", "/api/v1/deployment/airgap/bundle", "settings:write"),
    ("GET", "/api/v1/fusion/health", "alerts:read"),
    ("GET", "/api/v1/fusion/ml/status", "alerts:read"),
    ("GET", "/api/v1/fusion/metrics", "settings:read"),
    ("GET", f"/api/v1/fusion/entity-risk/queue{Q}", "alerts:read"),
    ("GET", f"/api/v1/fusion/entity-risk/stats{Q}", "alerts:read"),
    ("GET", f"/api/v1/fusion/entity-risk/ip/10.0.0.1{Q}", "alerts:read"),
    ("GET", "/api/v1/llm/status", "settings:read"),
    ("POST", "/api/v1/nl-detection/translate", "rules:write"),
    ("GET", "/api/v1/threatintel/stix/bundles", "threat_intel:read"),
    ("GET", "/api/v1/threatintel/stix/indicators", "threat_intel:read"),
    ("GET", "/api/v1/threatintel/stix/taxii/collections", "threat_intel:read"),
    ("GET", "/api/v1/threatintel/stix/misp/health", "threat_intel:read"),
    ("POST", "/api/v1/threatintel/stix/bundles", "threat_intel:write"),
    ("POST", "/api/v1/threatintel/stix/indicators", "threat_intel:write"),
    ("POST", "/api/v1/threatintel/stix/misp/dry-run", "threat_intel:write"),
    ("GET", "/api/v1/translation/formats", "rules:read"),
    ("POST", "/api/v1/translation/translate", "rules:read"),
    ("POST", "/api/v1/api-keys", "users:write"),
    ("PATCH", f"/api/v1/api-keys/{ID}", "users:write"),
    ("DELETE", f"/api/v1/api-keys/{ID}", "users:write"),
]
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


def _user(role="viewer", scopes=None, tenant=TENANT) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant, role=role, email="t@example.com", scopes=scopes)


def _call(client, method, path):
    with respx.mock(assert_all_called=False) as mock:
        mock.route(host__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        return client.request(method, path, json={}).status_code


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("method,path,perm", ROUTES)
def test_each_role_gets_exactly_what_the_role_table_says(role, method, path, perm):
    status = _call(_client(_user(role)), method, path)
    if has_permission(role, perm):
        assert status not in (401, 403), f"{role} holds {perm} and must keep {method} {path} (got {status})"
    else:
        assert status == 403, f"{role} lacks {perm}; {method} {path} must refuse (got {status})"


@pytest.mark.parametrize("method,path,perm", ROUTES)
def test_api_key_scopes_are_enforced(method, path, perm):
    wrong = "alerts:delete" if perm != "alerts:delete" else "cases:delete"
    assert _call(_client(_user("admin", scopes=[wrong])), method, path) == 403
    assert _call(_client(_user("admin", scopes=[perm])), method, path) not in (401, 403)
    assert _call(_client(_user("admin", scopes=["*"])), method, path) not in (401, 403)


def test_the_table_matches_what_the_code_actually_enforces():
    routers = [airgap, compliance, deployment, fusion, llm_status, nl_detection, stix_taxii, translation, api_keys]
    actual = {}
    for mod in routers:
        for r in mod.router.routes:
            if isinstance(r, APIRoute):
                for m in r.methods - {"HEAD", "OPTIONS"}:
                    actual[(m, "/api/v1" + r.path)] = required_permissions(r)  # r.path already includes the router prefix
    for method, path, perm in ROUTES:
        template = None
        for (m, t), perms in actual.items():
            if m == method:
                import re
                if re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", t), path.split("?")[0]):
                    template = (m, t)
                    break
        assert template is not None, f"{method} {path}: no such route"
        assert actual[template] == [perm], f"{method} {path}: code requires {actual[template]}, table says [{perm!r}]"


# ------------------------------------------------------------- fusion tenancy ----
def test_fusion_refuses_another_tenants_data():
    c = _client(_user("soc_analyst", tenant=TENANT))
    mine = c.get(f"/api/v1/fusion/entity-risk/stats?tenant_id={TENANT}").status_code
    theirs = c.get(f"/api/v1/fusion/entity-risk/stats?tenant_id={OTHER_TENANT}").status_code
    assert mine == 200 and theirs == 403


def test_fusion_platform_admin_may_cross_tenants():
    c = _client(_user("platform_admin", tenant=TENANT))
    assert c.get(f"/api/v1/fusion/entity-risk/stats?tenant_id={OTHER_TENANT}").status_code == 200


@pytest.mark.parametrize("path", ["/queue", "/stats", "/ip/10.0.0.1"])
def test_fusion_tenant_check_covers_all_three_entity_risk_routes(path):
    c = _client(_user("admin", tenant=TENANT))  # admin is NOT platform_admin
    assert c.get(f"/api/v1/fusion/entity-risk{path}?tenant_id={OTHER_TENANT}").status_code == 403
