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
    r = _ask(_client(_user(role)), permission)
    assert r.status_code == (200 if has_permission(role, permission) else 403)
    if r.status_code == 200:
        assert r.json() == {"allowed": True, "permission": permission}


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
