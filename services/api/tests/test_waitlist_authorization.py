"""Reading the waitlist and changing an entry are PLATFORM operations: only a platform administrator may do either.

HISTORY. These routes checked `admin:waitlist` OR `settings:write` inside the handler. `admin:waitlist` was never created or granted to
anyone, and every tenant's administrator holds `settings:write`, so any tenant admin could read every prospect's name, email, company and
role (the waitlist is the platform's sales funnel,
not tenant data) and change their status. Confirmed on real Postgres: after a prospect signed up through the public form, two ordinary
tenant admins both read it, and one changed its status to "contacted" which the other then saw. Found while auditing the operations the
capability reference lists as "signed in, no permission declared";
it is the same bug as the tenant list and provisioning routes (see test_tenant_provision_authorization.py), in the next module along.
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
ENTRY = "00000000-0000-0000-0000-0000000000aa"
LIST = ("GET", "/api/v1/waitlist/entries", None)
PATCH = ("PATCH", f"/api/v1/waitlist/entries/{ENTRY}", {"status": "contacted"})


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
    method, path, body = route
    return _client(user).request(method, path, json=body).status_code


class TestWhatTheRoutesDeclare:
    def test_the_two_admin_routes_need_mssp_onboard_and_the_signup_form_stays_public(self):
        found = {
            (m, p): (required_permissions(r), access_kind(r))
            for p, r in walk_routes(app.routes)
            for m in r.methods
            if "/waitlist" in p and m not in {"HEAD", "OPTIONS"}
        }
        assert found == {
            ("GET", "/api/v1/waitlist/entries"): (["mssp:onboard"], "permission"),
            ("PATCH", "/api/v1/waitlist/entries/{entry_id}"): (["mssp:onboard"], "permission"),
            ("POST", "/api/v1/waitlist/signup"): ([], "open"),
        }

    def test_the_permission_is_a_platform_permission_no_wildcard_grants(self):
        assert "mssp:onboard" in PLATFORM_PERMISSIONS
        assert (
            not permission_in(["*"], "mssp:onboard")
            and not permission_in(["mssp:*"], "mssp:onboard")
            and not permission_in(["settings:write", "settings:*"], "mssp:onboard")
        )


class TestOverHttp:
    @pytest.mark.parametrize("route", [LIST, PATCH], ids=["list", "update"])
    def test_only_a_platform_administrator_gets_past_the_gate_every_other_role_is_refused(self, route):
        outcomes = {role: _status(_user(role), route) for role in ROLE_PERMISSIONS}
        allowed = {role for role, code in outcomes.items() if code != 403}
        assert allowed == {role for role in ROLE_PERMISSIONS if has_permission(role, "mssp:onboard")} == {"platform_admin"}, outcomes

    @pytest.mark.parametrize("route", [LIST, PATCH], ids=["list", "update"])
    def test_the_exact_regression_a_tenant_admin_holding_settings_write_and_the_wildcard_is_refused(self, route):
        assert has_permission("admin", "settings:write"), "this role really holds the permission the old check accepted"
        assert _status(_user("admin"), route) == 403

    @pytest.mark.parametrize("route", [LIST, PATCH], ids=["list", "update"])
    def test_the_first_administrator_of_a_provisioned_tenant_is_refused(self, route):
        assert _status(_user("tenant_admin"), route) == 403

    @pytest.mark.parametrize("route", [LIST, PATCH], ids=["list", "update"])
    def test_an_api_key_is_refused_whatever_its_scopes(self, route):
        for scopes in (["*"], ["settings:write"], ["settings:write", "alerts:read"], ["admin:waitlist"], []):
            assert _status(_user("admin", scopes=scopes), route) == 403, scopes

    @pytest.mark.parametrize("route", [LIST, PATCH], ids=["list", "update"])
    def test_a_caller_who_is_not_signed_in_never_reaches_the_handler(self, route):
        app.dependency_overrides.clear()
        method, path, body = route
        assert TestClient(app, raise_server_exceptions=False).request(method, path, json=body).status_code in (401, 403)

    def test_a_platform_administrator_passes_the_permission_check(self):
        _user("platform_admin").require_permission("mssp:onboard")

    def test_the_public_signup_form_still_needs_no_sign_in(self):
        """An empty body is a 422 from validation (before any database use): not a 401 or 403, which is what signing in would have caused."""  # noqa: E501
        app.dependency_overrides.clear()
        assert TestClient(app, raise_server_exceptions=False).post("/api/v1/waitlist/signup", json={}).status_code == 422
