"""Creating a tenant and listing every tenant are PLATFORM operations: only a platform administrator may do either.

HISTORY. These routes checked `admin:tenants` OR `settings:write` inside the handler. `admin:tenants` was never created or granted to
anyone, and every tenant's administrator holds `settings:write`, so ANY tenant admin could list every tenant on the platform (names, slugs,
plans) and promote
waitlist entries into new live tenants. Found while generating the capability reference (the route showed "signed in, no permission
declared"), confirmed on real Postgres (tenant A's admin listed tenant B), and fixed by moving both onto the platform permissions. The old
tests called the handlers directly with a fake user, so they
never exercised the dependency system and could not have noticed.
"""

import uuid

import pytest
from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.core.route_introspect import access_kind, required_permissions, walk_routes
from app.core.security import PLATFORM_PERMISSIONS, ROLE_PERMISSIONS, has_permission, permission_in
from app.main import app
from fastapi.testclient import TestClient

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
PROVISION = ("POST", "/api/v1/admin/tenants/provision", "mssp:onboard")
LIST = ("GET", "/api/v1/admin/tenants", "platform:cross_tenant_query")
BODY = {"waitlist_entry_id": str(uuid.uuid4()), "seed_demo": False}


@pytest.fixture(autouse=True)
def _clean_overrides():
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


def _status(user: CurrentUser, route) -> int:
    method, path, _perm = route
    return _client(user).request(method, path, json=BODY if method == "POST" else None).status_code


class TestWhatTheRoutesDeclare:
    def test_provision_needs_mssp_onboard_and_the_list_needs_platform_cross_tenant_query_and_nothing_else(self):
        found = {
            (m, p): required_permissions(r) for p, r in walk_routes(app.routes) for m in r.methods if p.startswith("/api/v1/admin/tenants")
        }
        assert found == {("POST", PROVISION[1]): ["mssp:onboard"], ("GET", LIST[1]): ["platform:cross_tenant_query"]}

    def test_both_are_platform_permissions_which_neither_the_wildcard_nor_a_resource_wildcard_grants(self):
        for _m, _p, perm in (PROVISION, LIST):
            assert perm in PLATFORM_PERMISSIONS
            assert (
                not permission_in(["*"], perm)
                and not permission_in([f"{perm.split(':')[0]}:*"], perm)
                and not permission_in(["settings:write", "settings:*"], perm)
            )

    def test_neither_route_can_be_reached_with_settings_write_any_more(self):
        for _m, _p, perm in (PROVISION, LIST):
            assert "settings:write" != perm and not permission_in(["settings:write"], perm)

    def test_every_admin_route_declares_a_permission_so_an_inline_only_check_cannot_come_back(self):
        admin = [
            (m, p, access_kind(r))
            for p, r in walk_routes(app.routes)
            if p.startswith("/api/v1/admin")
            for m in r.methods
            if m not in {"HEAD", "OPTIONS"}
        ]
        assert admin, "there are admin routes"
        assert all(kind == "permission" for _m, _p, kind in admin), admin


class TestOverHttp:
    @pytest.mark.parametrize("route", [PROVISION, LIST], ids=["provision", "list"])
    def test_only_a_platform_administrator_gets_past_the_gate_every_other_role_is_refused(self, route):
        outcomes = {role: _status(_user(role), route) for role in ROLE_PERMISSIONS}
        allowed = {role for role, code in outcomes.items() if code != 403}
        assert allowed == {role for role in ROLE_PERMISSIONS if has_permission(role, route[2])} == {"platform_admin"}, outcomes
        assert all(code == 403 for role, code in outcomes.items() if role != "platform_admin"), outcomes

    @pytest.mark.parametrize("route", [PROVISION, LIST], ids=["provision", "list"])
    def test_the_exact_regression_a_tenant_admin_holding_settings_write_and_the_wildcard_is_refused(self, route):
        admin = _user("admin")
        assert has_permission("admin", "settings:write") and has_permission(
            "admin", "alerts:write"
        ), "this role really holds the permission the old check accepted"
        assert _status(admin, route) == 403

    @pytest.mark.parametrize("route", [PROVISION, LIST], ids=["provision", "list"])
    def test_the_first_administrator_of_a_provisioned_tenant_is_refused(self, route):
        assert _status(_user("tenant_admin"), route) == 403

    @pytest.mark.parametrize("route", [PROVISION, LIST], ids=["provision", "list"])
    def test_an_api_key_is_refused_whatever_its_scopes(self, route):
        for scopes in (["*"], ["settings:write"], ["settings:write", "alerts:read", "cases:write"], ["admin:tenants"], []):
            assert _status(_user("admin", scopes=scopes), route) == 403, scopes

    @pytest.mark.parametrize("route", [PROVISION, LIST], ids=["provision", "list"])
    def test_a_caller_who_is_not_signed_in_never_reaches_the_handler(self, route):
        app.dependency_overrides.clear()
        method, path, _ = route
        assert TestClient(app, raise_server_exceptions=False).request(
            method, path, json=BODY if method == "POST" else None
        ).status_code in (401, 403)

    def test_a_platform_administrator_passes_the_permission_check_for_both(self):
        operator = _user("platform_admin")
        operator.require_permission("mssp:onboard")
        operator.require_permission("platform:cross_tenant_query")

    def test_the_refusal_names_the_permission_that_was_missing(self):
        body = _client(_user("admin")).get(LIST[1]).json()
        assert "platform:cross_tenant_query" in str(body)
