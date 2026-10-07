"""ueba: every route needs the service token, and ID routes are tenant-scoped.

Every route answered anonymous requests, several for ANY tenant named in the request, and acknowledge_anomaly took no tenant at all, so any caller could acknowledge (silence) another tenant's anomaly by id.
"""
from __future__ import annotations

import asyncio
import re
import uuid
from datetime import UTC, datetime

import pytest
from app.api import routes as routes_module
from app.main import app
from app.models.ueba import Base, UEBAAnomaly
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.pool import StaticPool

TOKEN = "ueba-service-token-123"
GOOD = {"Authorization": f"Bearer {TOKEN}"}
UUID = "00000000-0000-0000-0000-0000000000aa"
INFRA = re.compile(r"^/(health|healthz|livez|readyz|metrics|docs|redoc|openapi\.json)$")


@compiles(JSONB, "sqlite")
def _jsonb_for_sqlite(type_, compiler, **kw):  # tests only
    return "JSON"


def _configure(monkeypatch, *, token, environment):
    for k in ("AISOC_UEBA_SERVICE_TOKEN", "AISOC_UEBA_ENVIRONMENT"):
        monkeypatch.delenv(k, raising=False)
    if token:
        monkeypatch.setenv("AISOC_UEBA_SERVICE_TOKEN", token)
    if environment is not None:
        monkeypatch.setenv("AISOC_UEBA_ENVIRONMENT", environment)
    return TestClient(app, raise_server_exceptions=False)


def _routes():
    return sorted((m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops
                  if m in ("get", "post", "put", "patch", "delete") and not INFRA.match(p))


def _call(c, method, path, headers=None):
    return c.request(method, re.sub(r"\{[^}]+\}", UUID, path), json={} if method in ("POST", "PUT", "PATCH") else None, headers=headers, timeout=20)


def _past(r):
    return r.status_code != 401 and not (r.status_code == 503 and "auth is not configured" in r.text)


def test_the_sweep_sees_the_routes():
    r = _routes()
    assert len(r) >= 5 and ("PATCH", "/api/v1/ueba/anomalies/{anomaly_id}/acknowledge") in r


@pytest.mark.parametrize("method,path", _routes())
def test_no_credentials_is_refused(monkeypatch, method, path):
    r = _call(_configure(monkeypatch, token=TOKEN, environment="production"), method, path)
    assert r.status_code == 401 and r.headers.get("www-authenticate") == "Bearer", f"{method} {path} -> {r.status_code}"


@pytest.mark.parametrize("method,path", _routes())
def test_the_right_token_gets_past_the_guard(monkeypatch, method, path):
    assert _past(_call(_configure(monkeypatch, token=TOKEN, environment="production"), method, path, GOOD))


@pytest.mark.parametrize("environment", ["production", "staging", "prod", "prodution", ""])
@pytest.mark.parametrize("method,path", _routes())
def test_without_a_token_anything_but_development_fails_closed(monkeypatch, environment, method, path):
    c = _configure(monkeypatch, token=None, environment=environment)
    for headers in (None, GOOD):
        r = _call(c, method, path, headers)
        assert r.status_code == 503 and "auth is not configured" in r.text, f"{environment!r} {method} {path} -> {r.status_code}"


@pytest.mark.parametrize("environment", ["development", "dev", "local", "test", None])
def test_development_without_a_token_stays_open(monkeypatch, environment):
    c = _configure(monkeypatch, token=None, environment=environment)
    assert all(_past(_call(c, m, p)) for m, p in _routes())


@pytest.mark.parametrize("header", [f"Bearer {TOKEN}x", f"Bearer {TOKEN[:-1]}", f"Basic {TOKEN}", TOKEN, "Bearer ", "Bearer", ""])
def test_only_the_exact_token_is_accepted(monkeypatch, header):
    assert _configure(monkeypatch, token=TOKEN, environment="production").get("/api/v1/ueba/anomalies", headers={"Authorization": header}).status_code == 401


# ------------------------------------------------------------------- tenant isolation ----
def _run_scenario(monkeypatch, scenario):
    """Run `scenario(client, session_factory, ids)` against a real (sqlite) database in ONE event loop."""
    monkeypatch.setenv("AISOC_UEBA_SERVICE_TOKEN", TOKEN)
    monkeypatch.setenv("AISOC_UEBA_ENVIRONMENT", "production")
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
        ids = {"a": a, "b": b}
        async with factory() as s:
            for key, tenant in (("an_a", a), ("an_b", b)):
                row = UEBAAnomaly(id=uuid.uuid4(), tenant_id=tenant, entity_type="user", entity_id="alice", event_type="login", anomaly_score=0.9, risk_level="high", features={}, detected_at=now, acknowledged=False)
                s.add(row); ids[key] = row.id
            await s.commit()
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


def test_a_tenant_cannot_acknowledge_another_tenants_anomaly(monkeypatch):
    async def scenario(c, factory, ids):
        assert (await c.patch(f"/api/v1/ueba/anomalies/{ids['an_b']}/acknowledge", params={"tenant_id": str(ids["a"])})).status_code == 404
        async with factory() as s:
            assert (await s.execute(select(UEBAAnomaly).where(UEBAAnomaly.id == ids["an_b"]))).scalar_one().acknowledged is False, "B's anomaly was silenced by tenant A"
        assert (await c.patch(f"/api/v1/ueba/anomalies/{ids['an_b']}/acknowledge")).status_code == 422, "the tenant is required"
        ok = await c.patch(f"/api/v1/ueba/anomalies/{ids['an_b']}/acknowledge", params={"tenant_id": str(ids["b"])})
        assert ok.status_code == 200 and ok.json()["acknowledged"] is True

    _run_scenario(monkeypatch, scenario)


def test_listing_is_scoped_to_the_tenant(monkeypatch):
    async def scenario(c, factory, ids):
        rows = (await c.get("/api/v1/ueba/anomalies", params={"tenant_id": str(ids["a"]), "hours": 24})).json()
        assert [r["id"] for r in rows] == [str(ids["an_a"])]

    _run_scenario(monkeypatch, scenario)
