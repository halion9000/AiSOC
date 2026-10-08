"""POST /api/v1/auth/authorize: the one place other services ask "may this caller do X?"."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.core.security import ROLE_PERMISSIONS, has_permission, known_permissions
from app.main import app

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture(autouse=True)
def _reset():
    yield
    app.dependency_overrides.clear()


def _client(user: CurrentUser | None, production: bool = False, monkeypatch=None) -> TestClient:
    async def fake_db():
        yield None

    app.dependency_overrides[deps.get_db] = fake_db
    if user is not None:
        app.dependency_overrides[deps.get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=False)


def _user(role, scopes=None):
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email="t@example.com", scopes=scopes)


def _ask(client, permission):
    return client.post("/api/v1/auth/authorize", json={"permission": permission})


@pytest.mark.parametrize("role", list(ROLE_PERMISSIONS))
@pytest.mark.parametrize("permission", ["playbooks:execute", "playbooks:write", "lake:query", "cases:write", "alerts:read", "settings:write"])
def test_answers_match_the_role_table(role, permission):
    user = _user(role)
    r = _ask(_client(user), permission)
    assert r.status_code == (200 if has_permission(role, permission) else 403)
    if r.status_code == 200:
        # The answer, plus WHO the caller is (additive): see test_the_answer_says_whose_data_the_caller_may_act_on.
        assert r.json() == {"allowed": True, "permission": permission, "tenant_id": str(TENANT), "user_id": str(user.user_id), "role": role}


def test_api_key_scopes_decide_for_keys():
    assert _ask(_client(_user("admin", scopes=["playbooks:read"])), "playbooks:read").status_code == 200
    assert _ask(_client(_user("admin", scopes=["playbooks:read"])), "playbooks:execute").status_code == 403
    assert _ask(_client(_user("viewer", scopes=["*"])), "playbooks:execute").status_code == 200


def test_unknown_permission_is_422_even_for_an_admin():
    """An admin holds every permission, so a typo must not silently come back 'allowed'."""
    assert _ask(_client(_user("admin")), "playbook:execute").status_code == 422
    assert _ask(_client(_user("platform_admin")), "nonsense").status_code == 422


def test_anonymous_in_production_is_401(monkeypatch):
    monkeypatch.setattr(deps, "is_dev_mode", lambda: False)
    assert _ask(_client(None), "cases:read").status_code == 401


def test_every_permission_the_agents_table_uses_is_known():
    from app.core.security import known_permissions as kp

    agents_uses = {"playbooks:read", "playbooks:write", "playbooks:execute", "lake:query", "settings:write", "alerts:read", "cases:read", "cases:write"}
    assert agents_uses <= kp(), f"the agents service asks about permissions the API rejects: {agents_uses - kp()}"
    assert "*" not in known_permissions()


def test_the_answer_says_whose_data_the_caller_may_act_on():
    """The agents service learns the tenant from HERE, not from a tenant_id named in a request body (which let any caller name any tenant)."""
    other_tenant = uuid.uuid4()
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=other_tenant, role="admin", email="t@example.com")
    body = _ask(_client(user), "cases:read").json()
    assert body["tenant_id"] == str(other_tenant) and body["user_id"] == str(user.user_id) and body["role"] == "admin"
    assert body["tenant_id"] != str(TENANT)  # it is the CALLER's tenant, not some default


def test_an_api_key_with_no_user_id_still_reports_its_tenant():
    key = CurrentUser(user_id=None, tenant_id=TENANT, role="admin", email="key@example.com", scopes=["cases:read"])
    r = _ask(_client(key), "cases:read")
    assert r.status_code == 200 and r.json()["tenant_id"] == str(TENANT) and r.json()["user_id"] is None


def test_a_refused_caller_is_told_nothing_about_identity():
    r = _ask(_client(_user("viewer")), "settings:write")
    assert r.status_code == 403 and "tenant_id" not in r.json()
