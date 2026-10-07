"""Every route of the threatintel service needs the service token, except health, and it FAILS CLOSED.

The guard used to cover only /api/v1/actors/* and was open whenever no token was set, so a production deployment
protected nothing unless someone remembered to configure it; GET /api/v1/iocs/search was never covered at all.
"""
from __future__ import annotations

import re

import pytest
from app.config import settings
from app.main import app
from fastapi.testclient import TestClient

TOKEN = "threatintel-token-123"
GOOD = {"Authorization": f"Bearer {TOKEN}"}
UUID = "00000000-0000-0000-0000-0000000000aa"
INFRA = re.compile(r"^/(health|healthz|livez|readyz|metrics|docs|redoc|openapi\.json)$|/health(/|$)")


def _client(monkeypatch, *, token, environment):
    monkeypatch.setattr(settings, "AISOC_THREATINTEL_SERVICE_TOKEN", token)
    monkeypatch.setattr(settings, "ENVIRONMENT", environment)
    return TestClient(app, raise_server_exceptions=False)


def _routes():
    return sorted((m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops
                  if m in ("get", "post", "put", "patch", "delete") and not INFRA.search(p))


def _call(c, method, path, headers=None):
    return c.request(method, re.sub(r"\{[^}]+\}", UUID, path), json={} if method in ("POST", "PUT", "PATCH") else None, headers=headers)


def _past_guard(r):
    return r.status_code != 401 and not (r.status_code == 503 and "auth is not configured" in r.text)


def test_the_sweep_sees_the_routes():
    routes = _routes()
    assert ("GET", "/api/v1/iocs/search") in routes and ("POST", "/api/v1/actors/attribute") in routes and len(routes) >= 4


@pytest.mark.parametrize("method,path", _routes())
def test_no_credentials_is_refused(monkeypatch, method, path):
    r = _call(_client(monkeypatch, token=TOKEN, environment="production"), method, path)
    assert r.status_code == 401, f"{method} {path} answered {r.status_code} without the token"


@pytest.mark.parametrize("method,path", _routes())
def test_the_right_token_gets_past_the_guard(monkeypatch, method, path):
    assert _past_guard(_call(_client(monkeypatch, token=TOKEN, environment="production"), method, path, GOOD))


@pytest.mark.parametrize("environment", ["production", "staging", "prod", "prodution", "", "development", "dev", "local", "test", "Development"])
@pytest.mark.parametrize("method,path", _routes())
def test_without_a_token_every_route_fails_closed_whatever_the_environment_says(monkeypatch, environment, method, path):
    c = _client(monkeypatch, token="", environment=environment)
    for headers in (None, GOOD):
        r = _call(c, method, path, headers)
        assert r.status_code == 503 and "auth is not configured" in r.text, f"{environment!r} {method} {path} -> {r.status_code}"


@pytest.mark.parametrize("header", [f"Bearer {TOKEN}x", f"Bearer {TOKEN[:-1]}", f"Basic {TOKEN}", TOKEN, "Bearer ", "Bearer", ""])
def test_only_the_exact_token_is_accepted(monkeypatch, header):
    assert _client(monkeypatch, token=TOKEN, environment="production").get("/api/v1/iocs/search", headers={"Authorization": header}).status_code == 401


def test_a_configured_token_is_enforced_in_development_too(monkeypatch):
    c = _client(monkeypatch, token=TOKEN, environment="development")
    assert c.get("/api/v1/iocs/search").status_code == 401 and _past_guard(c.get("/api/v1/iocs/search", headers=GOOD))


def test_health_stays_open(monkeypatch):
    assert _client(monkeypatch, token=TOKEN, environment="production").get("/health").status_code in (200, 503)
