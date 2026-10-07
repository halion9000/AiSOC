"""Every route of the connectors service needs the service token, except health.

Found by calling each route anonymously: nothing in this service authenticated its caller, yet it makes
outbound calls (query a SIEM, push a case to a ticketing tool, fetch a cloud resource config) using connector
configuration and decrypted credentials that the CALLER supplies in the request. Anything able to reach it could
make it call out with arbitrary configuration. The API is its only caller and now sends the token.
"""
from __future__ import annotations

import re

import pytest
from app.main import app
from fastapi.testclient import TestClient

TOKEN = "connectors-service-token-123"
GOOD = {"Authorization": f"Bearer {TOKEN}"}
UUID = "00000000-0000-0000-0000-0000000000aa"

PUBLIC = {("GET", "/api/v1/health"): "reachability probe; returns a constant"}
INFRA = re.compile(r"^/(healthz|livez|readyz|metrics|docs|redoc|openapi\.json)$")


def _configure(monkeypatch, *, token, environment):
    for key in ("AISOC_CONNECTORS_SERVICE_TOKEN", "AISOC_CONNECTORS_ENVIRONMENT"):
        monkeypatch.delenv(key, raising=False)
    if token is not None:
        monkeypatch.setenv("AISOC_CONNECTORS_SERVICE_TOKEN", token)
    if environment is not None:
        monkeypatch.setenv("AISOC_CONNECTORS_ENVIRONMENT", environment)
    return TestClient(app, raise_server_exceptions=False)


def _routes():
    out = []
    for path, ops in app.openapi()["paths"].items():
        for method in ops:
            if method in ("get", "post", "put", "patch", "delete") and not INFRA.match(path) and (method.upper(), path) not in PUBLIC:
                out.append((method.upper(), path))
    return sorted(out)


def _call(client, method, path, headers=None):
    url = re.sub(r"\{[^}]+\}", UUID, path)
    return client.request(method, url, json={} if method in ("POST", "PUT", "PATCH") else None, headers=headers)


def _past_the_guard(resp) -> bool:
    return resp.status_code != 401 and not (resp.status_code == 503 and "auth is not configured" in resp.text)


def test_the_sweep_sees_the_routes():
    routes = _routes()
    assert len(routes) >= 8, routes
    for expected in (("POST", "/api/v1/connectors/{connector_id}/query"), ("POST", "/api/v1/connectors/{connector_id}/test"),
                     ("POST", "/api/v1/connectors/{connector_id}/push_case"), ("POST", "/api/v1/connectors/{connector_id}/resource_config")):
        assert expected in routes


@pytest.mark.parametrize("method,path", _routes())
def test_no_credentials_is_refused(monkeypatch, method, path):
    r = _call(_configure(monkeypatch, token=TOKEN, environment="production"), method, path)
    assert r.status_code == 401, f"{method} {path} answered {r.status_code} without the service token"
    assert r.headers.get("www-authenticate") == "Bearer"


@pytest.mark.parametrize("method,path", _routes())
def test_the_right_token_gets_past_the_guard(monkeypatch, method, path):
    client = _configure(monkeypatch, token=TOKEN, environment="production")
    assert _past_the_guard(_call(client, method, path, GOOD)), f"{method} {path} refused the correct token"


@pytest.mark.parametrize("environment", ["production", "staging", "prod", "Production ", "prodution", ""])
@pytest.mark.parametrize("method,path", _routes())
def test_without_a_token_anything_but_development_fails_closed(monkeypatch, environment, method, path):
    client = _configure(monkeypatch, token=None, environment=environment)
    for headers in (None, GOOD):
        r = _call(client, method, path, headers)
        assert r.status_code == 503 and "auth is not configured" in r.text, f"{environment!r}: {method} {path} -> {r.status_code}"


@pytest.mark.parametrize("environment", ["development", "dev", "local", "test", "Development", None])
def test_a_development_stack_without_a_token_keeps_working(monkeypatch, environment):
    client = _configure(monkeypatch, token=None, environment=environment)
    assert client.get("/api/v1/connectors").status_code == 200


@pytest.mark.parametrize("environment", ["development", "production"])
def test_a_configured_token_is_enforced_in_every_environment(monkeypatch, environment):
    client = _configure(monkeypatch, token=TOKEN, environment=environment)
    assert client.get("/api/v1/connectors").status_code == 401
    assert client.get("/api/v1/connectors", headers=GOOD).status_code == 200


@pytest.mark.parametrize("header", [f"Bearer {TOKEN}x", f"Bearer {TOKEN[:-1]}", f"Basic {TOKEN}", TOKEN, "Bearer ", "Bearer", "", f"Token {TOKEN}", f"Bearer  {TOKEN} extra"])
def test_only_the_exact_token_is_accepted(monkeypatch, header):
    client = _configure(monkeypatch, token=TOKEN, environment="production")
    assert client.get("/api/v1/connectors", headers={"Authorization": header}).status_code == 401, header


def test_the_scheme_is_case_insensitive(monkeypatch):
    client = _configure(monkeypatch, token=TOKEN, environment="production")
    assert client.get("/api/v1/connectors", headers={"Authorization": f"bearer {TOKEN}"}).status_code == 200


def test_a_refused_request_never_reaches_a_connector(monkeypatch):
    """A query for a real connector without the token must be refused BEFORE any outbound call is attempted."""
    import app.api.router as router_module

    calls = []
    real_get = getattr(router_module, "get_connector", None)

    def spy(*args, **kwargs):  # would run if the handler were reached
        calls.append(args)
        return real_get(*args, **kwargs) if real_get else None

    if real_get:
        monkeypatch.setattr(router_module, "get_connector", spy)
    client = _configure(monkeypatch, token=TOKEN, environment="production")
    for path in ("/api/v1/connectors/okta/query", "/api/v1/connectors/okta/test", "/api/v1/connectors/okta/push_case"):
        assert client.post(path, json={"auth_config": {"api_token": "x"}, "query": {}}).status_code == 401
    assert calls == []


def test_health_stays_open(monkeypatch):
    client = _configure(monkeypatch, token=TOKEN, environment="production")
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/health").json()["service"] == "aisoc-connectors"


def test_every_public_entry_is_a_real_route():
    paths = {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops}
    stale = [k for k in PUBLIC if k not in paths]
    assert not stale, f"PUBLIC lists routes that no longer exist: {stale}"
