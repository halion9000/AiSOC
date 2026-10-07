"""Every route of the fusion service needs the service token except health and metrics, and it FAILS CLOSED.

Nothing authenticated callers, and several routes take a caller-supplied tenant_id, so anything able to reach the service
could read any tenant's entity-risk queue, submit analyst feedback, trigger a retrain or run correlation.
"""
from __future__ import annotations

import re

import pytest
from app.core.config import settings
from app.main import app
from fastapi.testclient import TestClient

TOKEN = "fusion-service-token-123"
GOOD = {"Authorization": f"Bearer {TOKEN}"}
UUID = "00000000-0000-0000-0000-0000000000aa"
PUBLIC = {("GET", "/health"): "Docker healthcheck has no token", ("GET", "/metrics"): "scraped by Prometheus"}
INFRA = re.compile(r"^/(healthz|livez|readyz|docs|redoc|openapi\.json)$")


def _client(monkeypatch, *, token, environment):
    monkeypatch.delenv("AISOC_FUSION_SERVICE_TOKEN", raising=False)
    if token:
        monkeypatch.setenv("AISOC_FUSION_SERVICE_TOKEN", token)
    monkeypatch.setattr(settings, "environment", environment)
    return TestClient(app, raise_server_exceptions=False)


def _routes():
    return sorted((m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops
                  if m in ("get", "post", "put", "patch", "delete") and not INFRA.match(p) and (m.upper(), p) not in PUBLIC)


def _call(c, method, path, headers=None):
    return c.request(method, re.sub(r"\{[^}]+\}", UUID, path), json={} if method in ("POST", "PUT", "PATCH") else None, headers=headers)


def _past(r):
    return r.status_code != 401 and not (r.status_code == 503 and "auth is not configured" in r.text)


def test_the_sweep_sees_the_routes():
    r = _routes()
    assert len(r) >= 8 and ("POST", "/process") in r and ("POST", "/ml/retrain") in r and ("GET", "/entity-risk/queue") in r


@pytest.mark.parametrize("method,path", _routes())
def test_no_credentials_is_refused(monkeypatch, method, path):
    r = _call(_client(monkeypatch, token=TOKEN, environment="production"), method, path)
    assert r.status_code == 401 and r.headers.get("www-authenticate") == "Bearer", f"{method} {path} -> {r.status_code}"


@pytest.mark.parametrize("method,path", _routes())
def test_the_right_token_gets_past_the_guard(monkeypatch, method, path):
    assert _past(_call(_client(monkeypatch, token=TOKEN, environment="production"), method, path, GOOD))


@pytest.mark.parametrize("environment", ["production", "staging", "prod", "prodution", "", "development", "dev", "local", "test", "Development", None])
@pytest.mark.parametrize("method,path", _routes())
def test_without_a_token_every_route_fails_closed_whatever_the_environment_says(monkeypatch, environment, method, path):
    c = _client(monkeypatch, token=None, environment=environment)
    for headers in (None, GOOD):
        r = _call(c, method, path, headers)
        assert r.status_code == 503 and "auth is not configured" in r.text, f"{environment!r} {method} {path} -> {r.status_code}"


@pytest.mark.parametrize("header", [f"Bearer {TOKEN}x", f"Bearer {TOKEN[:-1]}", f"Basic {TOKEN}", TOKEN, "Bearer ", "Bearer", ""])
def test_only_the_exact_token_is_accepted(monkeypatch, header):
    assert _client(monkeypatch, token=TOKEN, environment="production").post("/process", json={}, headers={"Authorization": header}).status_code == 401


def test_a_configured_token_is_enforced_in_development_too(monkeypatch):
    c = _client(monkeypatch, token=TOKEN, environment="development")
    assert c.post("/process", json={}).status_code == 401 and _past(c.post("/process", json={}, headers=GOOD))


def test_health_and_metrics_stay_open(monkeypatch):
    c = _client(monkeypatch, token=TOKEN, environment="production")
    assert c.get("/health").status_code != 401 and c.get("/metrics").status_code != 401


def test_every_public_entry_is_a_real_route():
    paths = {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops}
    assert not [k for k in PUBLIC if k not in paths]
