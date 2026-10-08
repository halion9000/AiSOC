"""Account-level actions need a signed-in person, not an API key acting as them.

An API key resolves to the user who owns it (api_key.user_id), and these routes only ask "who is this?", never "what is this credential allowed to do?", so a key with ANY scopes, even read-only
`alerts:read`, could register or revoke that user's passkeys, subscribe or unsubscribe their push notifications, and rewrite their profile preferences. Passkeys and push subscriptions belong to a human's
devices, so they are now session-only: an API key gets HTTP 403 before anything else runs (the check is a dependency on the user parameter, so it precedes the database dependency and body validation).
"""
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.endpoints import auth, passkeys, push

CRED = uuid.uuid4()
# (method, router prefix + path, json body). Bodies are valid so a 422 can never be mistaken for the check.
ROUTES = [
    ("POST", f"{passkeys.router.prefix}/register/begin", {"device_name": "laptop"}),
    ("POST", f"{passkeys.router.prefix}/register/finish", {"credential": {}, "challenge": "abcdefgh12345678"}),
    ("GET", f"{passkeys.router.prefix}/credentials", None),
    ("DELETE", f"{passkeys.router.prefix}/credentials/{CRED}", None),
    ("POST", f"{push.router.prefix}/subscribe", {"endpoint": "https://push.example.com/x", "keys": {}}),
    ("POST", f"{push.router.prefix}/unsubscribe", {"endpoint": "https://push.example.com/x"}),
    ("POST", f"{push.router.prefix}/test", {}),
    ("PATCH", f"{auth.router.prefix}/me/preferences", {"preferences": {"theme": "dark"}}),
]
IDS = [f"{m} {p.split('/', 3)[-1] if False else p}" for m, p, _ in ROUTES]
# Every shape an API key can take: full power, read-only, and no scopes at all (a falsy list: a truthiness check would wrongly treat it as a session).
KEY_SCOPES = [["*"], ["alerts:read"], []]


def make_client(scopes):
    app = FastAPI()
    for r in (passkeys.router, push.router, auth.router):
        app.include_router(r)
    app.dependency_overrides[deps.get_current_user] = lambda: deps.CurrentUser(
        user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="admin", email="owner@example.com", scopes=scopes
    )
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("scopes", KEY_SCOPES, ids=["full-power key", "read-only key", "scopeless key"])
@pytest.mark.parametrize("method, path, body", ROUTES, ids=IDS)
def test_an_api_key_is_refused_before_anything_else_runs(method, path, body, scopes):
    response = make_client(scopes).request(method, path, json=body)
    assert response.status_code == 403, f"{method} {path} let an API key (scopes={scopes}) through: HTTP {response.status_code}"
    assert "signed-in user, not an API key" in response.json()["detail"]


@pytest.mark.parametrize("method, path, body", ROUTES, ids=IDS)
def test_a_signed_in_session_is_not_stopped_by_the_check(method, path, body):
    # scopes=None is a session (JWT) user. Whatever else happens next (no database here), it must not be THIS refusal.
    response = make_client(None).request(method, path, json=body)
    detail = response.json().get("detail", "") if response.headers.get("content-type", "").startswith("application/json") else ""
    assert "not an API key" not in str(detail)


@pytest.mark.parametrize("scopes", KEY_SCOPES)
def test_an_api_key_causes_no_side_effects_on_the_push_routes(scopes, monkeypatch):
    calls = []

    async def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return {}

    monkeypatch.setattr(push, "_proxy", spy)
    client = make_client(scopes)
    for method, path, body in ROUTES:
        if path.startswith(push.router.prefix):
            assert client.request(method, path, json=body).status_code == 403
    assert calls == [], "a push route ran its handler for an API key"


def test_the_dependency_itself():
    import asyncio

    session = deps.CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="viewer", email="a@example.com", scopes=None)
    assert asyncio.run(deps.require_signed_in_session(session)) is session
    for scopes in (["*"], ["alerts:read"], []):
        key = deps.CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="admin", email="a@example.com", scopes=scopes)
        with pytest.raises(deps.HTTPException) as err:
            asyncio.run(deps.require_signed_in_session(key))
        assert err.value.status_code == 403
