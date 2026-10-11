"""Deciding an approval, and publishing an investigation to a public link, are a person's acts.

FOUND by auditing every non-read route CORE's API key can reach (27; Cipher's tools call 7). POST /approvals/{id}/decide needed only cases:write, which the key holds, and checks nothing else: so the key could create an approval (the human sign-off for isolating a host, disabling a user, a destructive playbook step) and approve it itself.
POST /ledger/{run_id}/publish needed only cases:write too, so the key could publish an investigation to GET /r/{slug}, which needs no sign-in, skipping the review step. Both now also need a signed-in session (an API key, whatever its scopes, is refused). Nothing else changed: creating an approval, unpublishing, previewing and every other route behave as before.
"""
import uuid

import pytest
from fastapi.testclient import TestClient
from route_introspect import required_permissions as _required_permissions
from route_introspect import walk_routes

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser, require_signed_in_session
from app.db.rls import get_tenant_db
from app.main import app

TENANT = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
APPROVAL = "00000000-0000-0000-0000-0000000000aa"
# publish also has its own confirm step (without confirm=true the handler answers 400 "Review the /publish/preview diff first"), so the body carries it to get past that.
HUMAN_ONLY = [("POST", f"/api/v1/approvals/{APPROVAL}/decide", {"decision": "approve"}), ("POST", f"/api/v1/ledger/{APPROVAL}/publish", {"confirm": True})]


@pytest.fixture(autouse=True)
def _clean():
    yield
    app.dependency_overrides.clear()


class _NoRows:
    """A database that finds nothing: a request that gets past authorization then answers 404 (no such approval or run), which is how these tests tell 'refused' from 'reached the handler'."""

    async def execute(self, *_a, **_k):
        class R:
            def scalar_one_or_none(self):
                return None

            def scalars(self):
                class S:
                    def all(self_inner):
                        return []

                    def first(self_inner):
                        return None

                return S()

            def first(self):
                return None

            def all(self):
                return []

        return R()


def _user(scopes=None, role="admin") -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email="t@example.com", scopes=scopes)


def _call(user, method, path, body):
    async def fake_db():
        yield _NoRows()

    app.dependency_overrides[get_tenant_db] = fake_db
    app.dependency_overrides[deps.get_db] = fake_db
    app.dependency_overrides[deps.get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=False).request(method, path, json=body)


def _route(method, path_template):
    return next(r for p, r in walk_routes(app.routes) if p == path_template and method in r.methods)


class TestWhatTheRoutesDeclare:
    @pytest.mark.parametrize("method,template", [("POST", "/api/v1/approvals/{approval_id}/decide"), ("POST", "/api/v1/ledger/{run_id}/publish")])
    def test_each_still_needs_cases_write_and_now_also_a_signed_in_session(self, method, template):
        route = _route(method, template)
        assert set(_required_permissions(route)) == {"cases:write"}
        called = [d.call for d in route.dependant.dependencies]
        assert require_signed_in_session in called, f"{method} {template} does not require a signed-in session"


class TestAnApiKeyIsRefused:
    @pytest.mark.parametrize("scopes", [["cases:write"], ["*"], ["cases:write", "alerts:triage", "alerts:read"], ["cases:*"], []])
    @pytest.mark.parametrize("method,path,body", HUMAN_ONLY)
    def test_a_key_of_any_scopes_is_refused_with_a_message_that_says_why(self, scopes, method, path, body):
        response = _call(_user(scopes=scopes), method, path, body)
        assert response.status_code == 403 and "only available to a signed-in user, not an API key" in response.text

    def test_the_exact_scenario_a_key_creates_an_approval_and_cannot_approve_it(self):
        key = _user(scopes=["alerts:read", "alerts:triage", "cases:read", "cases:write", "connectors:read", "rules:read", "hunts:read", "intel:read"])
        assert _call(key, "POST", f"/api/v1/approvals/{APPROVAL}/decide", {"decision": "approve"}).status_code == 403
        assert _call(key, "POST", f"/api/v1/approvals/{APPROVAL}/decide", {"decision": "deny"}).status_code == 403


class TestAPersonStillCan:
    @pytest.mark.parametrize("method,path,body", HUMAN_ONLY)
    def test_a_signed_in_admin_gets_past_authorization_and_reaches_the_handler(self, method, path, body):
        response = _call(_user(scopes=None), method, path, body)
        assert response.status_code == 404, f"expected the handler to answer 'not found', got {response.status_code}: {response.text[:120]}"

    @pytest.mark.parametrize("method,path,body", HUMAN_ONLY)
    def test_a_person_without_cases_write_is_still_refused_by_the_permission(self, method, path, body):
        """Which roles lack cases:write is computed, not assumed (threat_hunter holds it; viewer does not)."""
        from app.core.security import ROLE_PERMISSIONS, has_permission

        without = [role for role in ROLE_PERMISSIONS if not has_permission(role, "cases:write")]
        assert "viewer" in without, "the standard roles changed: re-read this test"
        for role in without:
            response = _call(_user(scopes=None, role=role), method, path, body)
            assert response.status_code == 403 and "signed-in user, not an API key" not in response.text, role

    @pytest.mark.parametrize("method,path,body", HUMAN_ONLY)
    def test_every_standard_role_that_holds_cases_write_still_reaches_the_handler(self, method, path, body):
        from app.core.security import ROLE_PERMISSIONS, has_permission

        with_write = [role for role in ROLE_PERMISSIONS if has_permission(role, "cases:write")]
        assert len(with_write) >= 5
        for role in with_write:
            assert _call(_user(scopes=None, role=role), method, path, body).status_code == 404, role


class TestNothingElseChanged:
    def test_creating_an_approval_is_still_open_to_a_key_with_cases_write(self):
        route = _route("POST", "/api/v1/approvals")
        assert set(_required_permissions(route)) == {"cases:write"}
        assert require_signed_in_session not in [d.call for d in route.dependant.dependencies], "integrations may raise an approval: creating one was not changed"

    def test_unpublishing_and_previewing_are_still_open_to_a_key(self):
        for method, template, perm in (("DELETE", "/api/v1/ledger/publish/{slug}", "cases:write"), ("POST", "/api/v1/ledger/{run_id}/publish/preview", "cases:read")):
            route = _route(method, template)
            assert set(_required_permissions(route)) == {perm}
            assert require_signed_in_session not in [d.call for d in route.dependant.dependencies], f"{method} {template}"

    def test_exactly_two_routes_got_the_session_requirement_among_the_case_and_approval_routes(self):
        found = sorted((m, p) for p, r in walk_routes(app.routes) for m in r.methods if "cases:write" in _required_permissions(r) and require_signed_in_session in [d.call for d in r.dependant.dependencies])
        assert found == [("POST", "/api/v1/approvals/{approval_id}/decide"), ("POST", "/api/v1/ledger/{run_id}/publish")]

    def test_the_two_things_the_decide_handler_still_does_not_enforce_are_written_down_here(self):
        """Not fixed, deliberately, because each is a product decision: that the decider differs from `requested_by`, that `required_user_id` / `required_topic` are honoured, and that an `expired` approval cannot be approved. If any is ever enforced, update this and the changelog."""
        import inspect

        from app.api.v1.endpoints import approvals

        source = inspect.getsource(approvals.decide_approval)
        assert "required_user_id" not in source and "requested_by" not in source and '{"pending", "expired"}' in source
