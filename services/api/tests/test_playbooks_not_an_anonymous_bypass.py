"""The API's playbook proxy must authenticate and authorize BEFORE it forwards.

The proxy attaches the shared internal token (the agents service trusts that
token in production). It had no login check, so an anonymous caller could use
it to list, create, delete and RUN playbooks through the agents service. These
tests stand in for the agents service and prove it is never reached unless the
caller is allowed.
"""
import uuid

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.core.config import settings
from app.main import app

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
PB = "pb-1"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setattr(deps, "is_dev_mode", lambda: False)  # production: anonymous gets no free admin
    monkeypatch.setattr(settings, "REALTIME_INTERNAL_TOKEN", "internal-secret-123")
    yield
    app.dependency_overrides.clear()


def _client(user: CurrentUser | None) -> TestClient:
    async def fake_db():
        yield None

    app.dependency_overrides[deps.get_db] = fake_db
    if user is not None:
        app.dependency_overrides[deps.get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=False)


def _user(role: str, scopes=None) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email="t@example.com", scopes=scopes)


CALLS = [
    ("GET", "/api/v1/playbooks", "playbooks:read"),
    ("GET", f"/api/v1/playbooks/{PB}", "playbooks:read"),
    ("GET", "/api/v1/playbooks/runs", "playbooks:read"),
    ("POST", "/api/v1/playbooks", "playbooks:write"),
    ("PUT", f"/api/v1/playbooks/{PB}", "playbooks:write"),
    ("DELETE", f"/api/v1/playbooks/{PB}", "playbooks:write"),
    ("POST", f"/api/v1/playbooks/{PB}/run", "playbooks:execute"),
]


@respx.mock
@pytest.mark.parametrize("method,path,perm", CALLS)
def test_anonymous_never_reaches_the_agents_service(method, path, perm):
    agents = respx.route(host__regex=r".*").mock(return_value=httpx.Response(200, json=[]))
    resp = _client(None).request(method, path, json={})
    assert resp.status_code == 401
    assert not agents.called, "an anonymous request was FORWARDED to the agents service with the internal token"


@respx.mock
@pytest.mark.parametrize("method,path,perm", CALLS)
@pytest.mark.parametrize("role", ["viewer", "threat_hunter", "api_service"])
def test_roles_without_playbook_access_never_reach_the_agents_service(role, method, path, perm):
    from app.core.security import has_permission

    if has_permission(role, perm):
        pytest.skip(f"{role} legitimately holds {perm}")
    agents = respx.route(host__regex=r".*").mock(return_value=httpx.Response(200, json=[]))
    assert _client(_user(role)).request(method, path, json={}).status_code == 403
    assert not agents.called


@respx.mock
def test_an_analyst_can_read_and_run_but_not_author():
    agents = respx.route(host__regex=r".*").mock(return_value=httpx.Response(200, json=[]))
    c = _client(_user("soc_analyst"))
    assert c.get("/api/v1/playbooks").status_code == 200
    assert c.post(f"/api/v1/playbooks/{PB}/run", json={}).status_code != 403
    assert c.post("/api/v1/playbooks", json={}).status_code == 403   # playbooks:write is admin / tenant_admin
    assert c.delete(f"/api/v1/playbooks/{PB}").status_code == 403
    sent = [call.request for call in agents.calls]
    assert sent and all(r.headers.get("x-internal-token") == "internal-secret-123" for r in sent)


@respx.mock
def test_a_read_only_api_key_cannot_run_or_author():
    respx.route(host__regex=r".*").mock(return_value=httpx.Response(200, json=[]))
    c = _client(_user("admin", scopes=["playbooks:read"]))
    assert c.get("/api/v1/playbooks").status_code == 200
    assert c.post(f"/api/v1/playbooks/{PB}/run", json={}).status_code == 403
    assert c.post("/api/v1/playbooks", json={}).status_code == 403
