"""Signing out ends the session on the server, not just in the browser.

Logging out used to only clear the browser's copy of the tokens (and there was no logout route at all): the access and refresh tokens stayed valid until they expired, so anyone who had
copied one, or a stolen laptop, kept working access after the user "signed out". Tokens now carry a unique jti; POST /auth/logout records it in a denylist for exactly the token's remaining
life; get_current_user and /auth/refresh refuse a recorded token. If the denylist is down, logout says the session was NOT ended (503), while ordinary requests keep working (fail open).
"""
import uuid
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from app.api.v1.endpoints import auth
from app.core import token_revocation
from app.core.config import settings
from app.core.security import decode_token, get_password_hash, hash_api_key
from app.db.database import Base
from app.models.login_failure import LoginFailure
from app.models.tenant import ApiKey, Tenant, User

PASSWORD = "correct horse battery staple"


@pytest.fixture
def world(tmp_path):
    """A real database with one tenant and two users, and an app exposing the real auth router."""
    path = tmp_path / "auth.db"
    sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync, tables=[Tenant.__table__, User.__table__, ApiKey.__table__, LoginFailure.__table__])
    tenant = Tenant(id=uuid.uuid4(), name="T", slug="t-" + uuid.uuid4().hex[:6])
    alice = User(id=uuid.uuid4(), tenant_id=tenant.id, email="alice@example.com", username="alice", hashed_password=get_password_hash(PASSWORD), role="admin")
    bob = User(id=uuid.uuid4(), tenant_id=tenant.id, email="bob@example.com", username="bob", hashed_password=get_password_hash(PASSWORD), role="admin")
    raw_key = "aisoc_" + uuid.uuid4().hex
    key = ApiKey(id=uuid.uuid4(), tenant_id=tenant.id, user_id=alice.id, name="ci", key_prefix=raw_key[:12], hashed_key=hash_api_key(raw_key), scopes=["*"], is_active=True)
    with Session(sync, expire_on_commit=False) as s:  # plain values stay readable after the session closes
        s.add_all([tenant, alice, bob, key])
        s.commit()
    factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool), expire_on_commit=False)

    app = FastAPI()
    app.include_router(auth.router)

    async def session():
        async with factory() as s:
            yield s

    app.dependency_overrides[deps.get_db] = session
    yield type("World", (), {"client": TestClient(app), "alice": alice, "bob": bob, "tenant": tenant, "api_key": raw_key})
    sync.dispose()


def token_data(user):
    return {"sub": str(user.id), "tenant_id": str(user.tenant_id), "role": user.role, "email": user.email}


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def login(world, user="alice"):
    r = world.client.post("/auth/login", json={"email": f"{user}@example.com", "password": PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()


class TestTokensCarryAUniqueId:
    def test_each_token_has_its_own_jti(self, world):
        a, b = login(world), login(world)
        ids = [decode_token(t)["jti"] for t in (a["access_token"], a["refresh_token"], b["access_token"], b["refresh_token"])]
        assert all(ids) and len(set(ids)) == 4

    def test_the_token_is_otherwise_unchanged(self, world):
        claims = decode_token(login(world)["access_token"])
        assert claims["type"] == "access" and claims["email"] == "alice@example.com" and "exp" in claims


class TestLogout:
    def test_a_token_works_until_logout_and_never_after(self, world):
        tokens = login(world)
        assert world.client.get("/auth/me", headers=bearer(tokens["access_token"])).status_code == 200
        out = world.client.post("/auth/logout", headers=bearer(tokens["access_token"]))
        assert out.status_code == 200 and out.json() == {"revoked": True, "detail": "Session ended."}
        again = world.client.get("/auth/me", headers=bearer(tokens["access_token"]))
        assert again.status_code == 401 and again.json()["detail"] == "Token has been revoked"

    def test_the_refresh_token_is_revoked_too_when_given(self, world, revocation_store):
        tokens = login(world)
        world.client.post("/auth/logout", headers=bearer(tokens["access_token"]), json={"refresh_token": tokens["refresh_token"]})
        refreshed = world.client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert refreshed.status_code == 401 and "revoked" in refreshed.json()["detail"]
        assert len(revocation_store.data) == 2

    def test_without_the_refresh_token_it_still_works_for_refreshing(self, world):
        tokens = login(world)
        world.client.post("/auth/logout", headers=bearer(tokens["access_token"]))
        assert world.client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 200

    def test_other_sessions_of_the_same_user_are_unaffected(self, world):
        first, second = login(world), login(world)
        world.client.post("/auth/logout", headers=bearer(first["access_token"]))
        assert world.client.get("/auth/me", headers=bearer(second["access_token"])).status_code == 200

    def test_a_body_cannot_sign_someone_else_out(self, world, revocation_store):
        alice, bob = login(world, "alice"), login(world, "bob")
        out = world.client.post("/auth/logout", headers=bearer(alice["access_token"]), json={"refresh_token": bob["refresh_token"]})
        assert out.status_code == 200
        assert world.client.post("/auth/refresh", json={"refresh_token": bob["refresh_token"]}).status_code == 200
        assert world.client.get("/auth/me", headers=bearer(bob["access_token"])).status_code == 200
        assert len(revocation_store.data) == 1  # only alice's own access token

    def test_the_denylist_entry_lives_exactly_as_long_as_the_token(self, world, revocation_store):
        tokens = login(world)
        world.client.post("/auth/logout", headers=bearer(tokens["access_token"]))
        (ttl,) = revocation_store.ttls.values()
        assert 0 < ttl <= settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        assert ttl > settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60 - 60  # (it is the remaining lifetime, not a fixed number)

    def test_logging_out_requires_being_signed_in(self, world, monkeypatch):
        monkeypatch.setattr(deps, "is_dev_mode", lambda: False)  # in development mode an anonymous request is deliberately mapped to a demo user
        assert world.client.post("/auth/logout").status_code == 401
        assert world.client.post("/auth/logout", headers=bearer("not.a.token")).status_code == 401

    def test_a_token_issued_before_revocation_existed_is_not_claimed_to_be_revoked(self, world):
        legacy = jwt.encode({**token_data(world.alice), "type": "access", "exp": __import__("datetime").datetime.now(__import__("datetime").UTC) + timedelta(minutes=5)}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        out = world.client.post("/auth/logout", headers=bearer(legacy))
        assert out.status_code == 200
        assert out.json()["revoked"] is False and "expire" in out.json()["detail"]
        assert world.client.get("/auth/me", headers=bearer(legacy)).status_code == 200  # honest: it still works

    def test_an_api_key_is_not_a_session_and_is_never_reported_as_revoked(self, world, revocation_store):
        out = world.client.post("/auth/logout", headers=bearer(world.api_key))
        assert out.status_code == 200
        assert out.json()["revoked"] is False and "API key" in out.json()["detail"]
        assert revocation_store.data == {}
        assert world.client.get("/auth/me", headers=bearer(world.api_key)).status_code == 200  # the key still works: logout did not touch it


class TestWhenTheDenylistIsDown:
    def test_logout_says_the_session_was_not_ended(self, world, revocation_store):
        tokens = login(world)
        revocation_store.down = True
        out = world.client.post("/auth/logout", headers=bearer(tokens["access_token"]))
        assert out.status_code == 503
        assert "Could not end the session" in out.json()["detail"]
        revocation_store.down = False
        assert world.client.get("/auth/me", headers=bearer(tokens["access_token"])).status_code == 200  # and it genuinely was not ended

    def test_ordinary_requests_keep_working(self, world, revocation_store):
        tokens = login(world)
        revocation_store.down = True
        assert world.client.get("/auth/me", headers=bearer(tokens["access_token"])).status_code == 200
        assert world.client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 200


class TestTheDenylistModule:
    def test_a_token_without_an_id_is_never_revoked(self):
        import asyncio

        assert asyncio.run(token_revocation.is_revoked(None)) is False
        assert asyncio.run(token_revocation.is_revoked("")) is False

    def test_an_already_expired_token_still_gets_a_valid_ttl(self):
        assert token_revocation._seconds_until(0) == 1  # Redis rejects a zero or negative expiry

    def test_the_helpers_agree_on_what_is_revoked(self, revocation_store):
        import asyncio

        asyncio.run(token_revocation.revoke("abc", 4102444800))
        assert asyncio.run(token_revocation.is_revoked("abc")) is True
        assert asyncio.run(token_revocation.is_revoked("other")) is False
