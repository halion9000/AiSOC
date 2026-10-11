"""Who may open the tenant's live streams.

A realtime ticket carries only the tenant (claims: sub, tenant_id, type); the realtime service then streams that tenant's alert.fused, case.updated, agent, insights and graph.update messages (the graph channel delivers full entity and relationship data). So the permission check on MINTING the ticket is the whole
authorization. It was "any signed-in caller": demonstrated on real Postgres, an API key whose ONLY scope was hunts:read received a valid ticket (and so could subscribe to streams REST refuses it). The route was listed in tests/data/unguarded_routes.txt as "personal to the caller", but a ticket is not personal data:
it opens tenant-wide streams. REST needs alerts:read for the alert data and cases:read for the case data, so minting needs both. Every standard role holds both, so the console is unaffected.
"""
import uuid

import jwt
import pytest
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import realtime as realtime_ep
from app.core.route_introspect import required_permissions, walk_routes
from app.core.security import REALTIME_TICKET_AUDIENCE, ROLE_PERMISSIONS, has_permission
from app.main import app

SECRET = "s" * 48
TENANT = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
ROUTE = "/api/v1/realtime/ticket"


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    monkeypatch.setattr(realtime_ep, "realtime_ticket_secret", lambda _settings: SECRET)
    yield
    app.dependency_overrides.clear()


def _user(role="viewer", scopes=None, tenant=TENANT) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant, role=role, email="t@example.com", scopes=scopes)


def _mint(user):
    app.dependency_overrides[deps.get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=False).post(ROUTE)


class TestWhatTheRouteDeclares:
    def test_it_needs_alerts_read_and_cases_read(self):
        route = next(r for p, r in walk_routes(app.routes) if p == ROUTE and "POST" in r.methods)
        assert sorted(required_permissions(route)) == ["alerts:read", "cases:read"]

    def test_the_streams_it_opens_are_the_data_those_two_permissions_protect(self):
        """Not a test of the realtime service (a separate Node process): a pin on what this gate is standing in front of, from its own source."""
        source = (realtime_ep.__file__ and open(realtime_ep.__file__, encoding="utf-8").read()) or ""
        assert "alert.fused" in source and "case.updated" in source and "graph.update" in source


class TestWhoGetsATicket:
    def test_every_standard_role_still_gets_one_so_the_console_is_unaffected(self):
        for role in ROLE_PERMISSIONS:
            assert has_permission(role, "alerts:read") and has_permission(role, "cases:read"), f"{role} would lose live updates: check before shipping"
            assert _mint(_user(role)).status_code == 200, role

    def test_the_exact_case_a_key_whose_only_scope_is_hunts_read_gets_no_ticket(self):
        response = _mint(_user(role="admin", scopes=["hunts:read"]))
        assert response.status_code == 403 and "alerts:read" in response.text

    def test_a_key_needs_both_scopes_one_is_not_enough(self):
        for scopes in ([], ["hunts:read"], ["alerts:read"], ["cases:read"], ["rules:read", "connectors:read"]):
            assert _mint(_user(role="admin", scopes=scopes)).status_code == 403, scopes
        assert _mint(_user(role="admin", scopes=["alerts:read", "cases:read"])).status_code == 200

    def test_a_wildcard_key_gets_one(self):
        assert _mint(_user(scopes=["*"])).status_code == 200

    def test_someone_who_is_not_signed_in_gets_none(self):
        app.dependency_overrides.clear()
        assert TestClient(app, raise_server_exceptions=False).post(ROUTE).status_code in (401, 403)

    def test_the_refusal_comes_before_any_ticket_is_signed(self, monkeypatch):
        calls = []
        monkeypatch.setattr(realtime_ep, "create_realtime_ticket", lambda **kw: calls.append(kw) or "token")
        assert _mint(_user(scopes=["hunts:read"])).status_code == 403 and calls == []


class TestTheTicketItself:
    def test_it_is_for_the_callers_own_tenant_only_and_carries_no_permission(self):
        response = _mint(_user(role="admin", tenant=TENANT))
        claims = jwt.decode(response.json()["token"], SECRET, algorithms=["HS256"], audience=REALTIME_TICKET_AUDIENCE)
        assert claims["tenant_id"] == str(TENANT) and claims["type"] == "realtime_ticket"
        assert response.json()["tenant_id"] == str(TENANT)

    def test_the_other_tenant_gets_its_own_and_not_the_first(self):
        other = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        claims = jwt.decode(_mint(_user(role="admin", tenant=other)).json()["token"], SECRET, algorithms=["HS256"], audience=REALTIME_TICKET_AUDIENCE)
        assert claims["tenant_id"] == str(other)

    def test_an_unconfigured_secret_still_fails_closed_for_someone_who_is_allowed(self, monkeypatch):
        monkeypatch.setattr(realtime_ep, "realtime_ticket_secret", lambda _settings: None)
        assert _mint(_user(role="admin")).status_code == 503
