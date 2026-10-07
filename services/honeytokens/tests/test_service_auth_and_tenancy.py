"""honeytokens: every route needs the service token (except the canary callback), and ID routes are tenant-scoped.

Every route answered anonymous requests, several for ANY tenant named in the request, and the ID-keyed routes (get, revoke,
delete, triggers) took no tenant at all, so any caller could read, revoke or delete another tenant's honeytoken by id.
The canary callback (POST /webhook/trigger) stays reachable without the service token on purpose: planted canaries report back
through it and their only credential is the unguessable token id.
"""
from __future__ import annotations

import asyncio
import re
import uuid
from datetime import UTC, datetime

import pytest
from app.api import routes as routes_module
from app.main import app
from app.models.honeytoken import Base, Honeytoken, HoneytokenTrigger
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.pool import StaticPool

TOKEN = "honeytokens-service-token-123"
GOOD = {"Authorization": f"Bearer {TOKEN}"}
UUID = "00000000-0000-0000-0000-0000000000aa"
PUBLIC = {("POST", "/api/v1/honeytokens/webhook/trigger"): "canary callback: its credential is the unguessable token id"}
INFRA = re.compile(r"^/(health|healthz|livez|readyz|metrics|docs|redoc|openapi\.json)$")


@compiles(JSONB, "sqlite")
def _jsonb_for_sqlite(type_, compiler, **kw):  # tests only: sqlite has no JSONB
    return "JSON"


def _configure(monkeypatch, *, token, environment):
    for k in ("AISOC_HONEYTOKENS_SERVICE_TOKEN", "AISOC_HONEYTOKENS_ENVIRONMENT"):
        monkeypatch.delenv(k, raising=False)
    if token:
        monkeypatch.setenv("AISOC_HONEYTOKENS_SERVICE_TOKEN", token)
    if environment is not None:
        monkeypatch.setenv("AISOC_HONEYTOKENS_ENVIRONMENT", environment)
    return TestClient(app, raise_server_exceptions=False)


def _routes():
    return sorted((m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops
                  if m in ("get", "post", "put", "patch", "delete") and not INFRA.match(p) and (m.upper(), p) not in PUBLIC)


def _call(c, method, path, headers=None):
    return c.request(method, re.sub(r"\{[^}]+\}", UUID, path), json={} if method in ("POST", "PUT", "PATCH") else None, headers=headers)


def _past(r):
    return r.status_code != 401 and not (r.status_code == 503 and "auth is not configured" in r.text)


# ------------------------------------------------------------------------- the guard ----
def test_the_sweep_sees_the_routes():
    r = _routes()
    assert len(r) >= 6 and ("DELETE", "/api/v1/honeytokens/{token_id}") in r and ("POST", "/api/v1/honeytokens") in r


@pytest.mark.parametrize("method,path", _routes())
def test_no_credentials_is_refused(monkeypatch, method, path):
    r = _call(_configure(monkeypatch, token=TOKEN, environment="production"), method, path)
    assert r.status_code == 401 and r.headers.get("www-authenticate") == "Bearer", f"{method} {path} -> {r.status_code}"


@pytest.mark.parametrize("method,path", _routes())
def test_the_right_token_gets_past_the_guard(monkeypatch, method, path):
    assert _past(_call(_configure(monkeypatch, token=TOKEN, environment="production"), method, path, GOOD))


@pytest.mark.parametrize("environment", ["production", "staging", "prod", "prodution", "", "development", "dev", "local", "test", "Development", None])
@pytest.mark.parametrize("method,path", _routes())
def test_without_a_token_every_route_fails_closed_whatever_the_environment_says(monkeypatch, environment, method, path):
    c = _configure(monkeypatch, token=None, environment=environment)
    for headers in (None, GOOD):
        r = _call(c, method, path, headers)
        assert r.status_code == 503 and "auth is not configured" in r.text, f"{environment!r} {method} {path} -> {r.status_code}"


@pytest.mark.parametrize("header", [f"Bearer {TOKEN}x", f"Bearer {TOKEN[:-1]}", f"Basic {TOKEN}", TOKEN, "Bearer ", "Bearer", ""])
def test_only_the_exact_token_is_accepted(monkeypatch, header):
    assert _configure(monkeypatch, token=TOKEN, environment="production").get("/api/v1/honeytokens", headers={"Authorization": header}).status_code == 401


def test_the_canary_callback_stays_reachable_without_the_service_token(monkeypatch):
    """It is NOT behind the service token (canaries cannot hold it); an unknown token id is simply a 404."""
    c = _configure(monkeypatch, token=TOKEN, environment="production")
    assert c.post("/api/v1/honeytokens/webhook/trigger", json={}).status_code == 422, "reached the handler (validation), not the guard"


# ------------------------------------------------------------------- tenant isolation ----
def _run_scenario(monkeypatch, scenario):
    """Run `scenario(client, session_factory, ids)` against a real (sqlite) database in ONE event loop."""
    monkeypatch.setenv("AISOC_HONEYTOKENS_SERVICE_TOKEN", TOKEN)
    monkeypatch.setenv("AISOC_HONEYTOKENS_ENVIRONMENT", "production")
    stripped = []
    for table in Base.metadata.tables.values():  # sqlite cannot render gen_random_uuid()/now() defaults
        for col in table.columns:
            if col.server_default is not None and re.search(r"gen_random_uuid|now\(\)", str(getattr(col.server_default, "arg", "")), re.I):
                stripped.append((col, col.server_default)); col.server_default = None

    async def main():
        import httpx

        engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)

        async def get_db():
            async with factory() as session:
                yield session

        app.dependency_overrides[routes_module.get_db] = get_db
        a, b = uuid.uuid4(), uuid.uuid4()
        now = datetime.now(UTC)

        async def seed(tenant, name):
            async with factory() as s:
                tok = Honeytoken(id=uuid.uuid4(), tenant_id=tenant, name=name, token_type="aws_key", token_value="AKIAFAKE", metadata_={}, status="active", created_at=now, updated_at=now)
                s.add(tok); await s.flush()
                s.add(HoneytokenTrigger(id=uuid.uuid4(), honeytoken_id=tok.id, tenant_id=tenant, source_ip="203.0.113.9", request_headers={}, request_body={}, triggered_at=now))
                await s.commit()
                return tok.id

        ids = {"a": a, "b": b, "tok_a": await seed(a, "A's token"), "tok_b": await seed(b, "B's token")}
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=GOOD) as client:
                await scenario(client, factory, ids)
        finally:
            app.dependency_overrides.pop(routes_module.get_db, None)
            await engine.dispose()

    try:
        asyncio.run(main())
    finally:
        for col, default in stripped:
            col.server_default = default


def test_a_tenant_reads_only_its_own_token(monkeypatch):
    async def scenario(c, factory, ids):
        own = await c.get(f"/api/v1/honeytokens/{ids['tok_a']}", params={"tenant_id": str(ids["a"])})
        assert own.status_code == 200 and own.json()["name"] == "A's token"
        other = await c.get(f"/api/v1/honeytokens/{ids['tok_b']}", params={"tenant_id": str(ids["a"])})
        assert other.status_code == 404, "tenant A read tenant B's token by id"
        assert (await c.get(f"/api/v1/honeytokens/{ids['tok_a']}")).status_code == 422, "the tenant is required"

    _run_scenario(monkeypatch, scenario)


def test_a_tenant_cannot_revoke_or_delete_another_tenants_token(monkeypatch):
    async def scenario(c, factory, ids):
        assert (await c.patch(f"/api/v1/honeytokens/{ids['tok_b']}/revoke", params={"tenant_id": str(ids["a"])})).status_code == 404
        assert (await c.delete(f"/api/v1/honeytokens/{ids['tok_b']}", params={"tenant_id": str(ids["a"])})).status_code == 404
        async with factory() as s:
            row = (await s.execute(select(Honeytoken).where(Honeytoken.id == ids["tok_b"]))).scalar_one()
            assert row.status == "active", "B's token was revoked by tenant A"
        # the owner can
        assert (await c.patch(f"/api/v1/honeytokens/{ids['tok_b']}/revoke", params={"tenant_id": str(ids["b"])})).json()["status"] == "revoked"
        assert (await c.delete(f"/api/v1/honeytokens/{ids['tok_b']}", params={"tenant_id": str(ids["b"])})).status_code == 204
        async with factory() as s:
            assert (await s.execute(select(Honeytoken).where(Honeytoken.id == ids["tok_b"]))).scalar_one_or_none() is None

    _run_scenario(monkeypatch, scenario)


def test_triggers_are_only_visible_to_the_owning_tenant(monkeypatch):
    async def scenario(c, factory, ids):
        mine = await c.get(f"/api/v1/honeytokens/{ids['tok_a']}/triggers", params={"tenant_id": str(ids["a"])})
        assert mine.status_code == 200 and len(mine.json()) == 1
        theirs = await c.get(f"/api/v1/honeytokens/{ids['tok_b']}/triggers", params={"tenant_id": str(ids["a"])})
        assert theirs.status_code == 200 and theirs.json() == [], "tenant A saw tenant B's trigger events (source IPs, headers)"

    _run_scenario(monkeypatch, scenario)


def test_listing_is_scoped_to_the_tenant(monkeypatch):
    async def scenario(c, factory, ids):
        rows = (await c.get("/api/v1/honeytokens", params={"tenant_id": str(ids["a"])})).json()
        assert [r["name"] for r in rows] == ["A's token"]

    _run_scenario(monkeypatch, scenario)


def test_a_token_response_carries_its_metadata_under_the_metadata_key(monkeypatch):
    """TokenOut read `metadata` off the ORM object, which is SQLAlchemy's MetaData(), so every response failed validation."""
    async def scenario(c, factory, ids):
        async with factory() as s:
            row = (await s.execute(select(Honeytoken).where(Honeytoken.id == ids["tok_a"]))).scalar_one()
            row.metadata_ = {"planted_in": "s3://finance-backups"}
            await s.commit()
        body = (await c.get(f"/api/v1/honeytokens/{ids['tok_a']}", params={"tenant_id": str(ids["a"])})).json()
        assert body["metadata"] == {"planted_in": "s3://finance-backups"} and "metadata_" not in body

    _run_scenario(monkeypatch, scenario)
