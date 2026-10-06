"""The osquery service's INTERNAL routes require the bearer token.

Found by reading the code against its docstrings: `POST /distributed/enqueue` said it was
protected by `Authorization: Bearer <AISOC_OSQUERY_TLS_API_TOKEN>`, but there was no such setting and no
check. Anyone who could reach the service could queue an arbitrary SQL query on any enrolled endpoint
(`host_identifier`, `query_text` and `tenant_id` all came from the caller), read the results, change which
packs run across a tenant's fleet, and read FIM events for any tenant. The agent-facing routes (enroll,
config, log, distributed read/write) were always protected by the enroll secret / node key.
"""
from __future__ import annotations

import pytest

from app.core.config import settings
from app.core.security import PLACEHOLDER_ENROLL_SECRET, enforce_secure_defaults
from app.main import app

TOKEN = "test-api-token"  # set by tests/conftest.py before the app is imported
GOOD = {"Authorization": f"Bearer {TOKEN}"}

# (method, path, json body) for each INTERNAL route
INTERNAL = [
    ("POST", "/api/v1/osquery/distributed/enqueue", {"host_identifier": "h", "tenant_id": "default", "query_text": "SELECT 1;"}),
    ("GET", "/api/v1/osquery/distributed/some-query-id", None),
    ("GET", "/api/v1/osquery/packs", None),
    ("GET", "/api/v1/osquery/packs/some-pack", None),
    ("GET", "/api/v1/osquery/packs/some-pack/render", None),
    ("POST", "/api/v1/osquery/tenants/default/packs", {"pack_id": "p"}),
    ("GET", "/api/v1/osquery/tenants/default/packs", None),
    ("DELETE", "/api/v1/osquery/tenants/default/packs/some-pack", None),
    ("GET", "/api/v1/osquery/fim/events?tenant_id=default", None),
    ("GET", "/api/v1/osquery/fim/summary?tenant_id=default", None),
]
# Agent-facing: authenticated by the enroll secret / node key, NOT by the internal token.
AGENT_PATHS = {
    "/api/v1/osquery/enroll", "/api/v1/osquery/config", "/api/v1/osquery/log",
    "/api/v1/osquery/distributed/read", "/api/v1/osquery/distributed/write",
}
HEALTH = {"/healthz", "/livez", "/readyz"}


async def _call(client, method, path, body, headers=None):
    return await client.request(method, path, json=body, headers=headers)


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(settings, "api_token", TOKEN)
    monkeypatch.setattr(settings, "environment", "production")


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body", INTERNAL)
async def test_no_credentials_is_refused(client, configured, method, path, body):
    r = await _call(client, method, path, body)
    assert r.status_code == 401, f"{method} {path} answered {r.status_code} without a token"
    assert r.headers.get("www-authenticate") == "Bearer"


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body", INTERNAL)
async def test_the_right_token_gets_past_the_gate(client, configured, method, path, body):
    r = await _call(client, method, path, body, GOOD)
    assert r.status_code not in (401, 503), f"{method} {path} refused the correct token ({r.status_code})"


@pytest.mark.asyncio
@pytest.mark.parametrize("header", [
    "Bearer wrong-token", f"Bearer {TOKEN}x", f"Bearer {TOKEN[:-1]}", "Bearer", "Bearer ", f"Basic {TOKEN}", TOKEN, "",
    f"Token {TOKEN}", f"Bearer  {TOKEN} extra",
])
async def test_only_the_exact_token_is_accepted(client, configured, header):
    r = await client.post("/api/v1/osquery/distributed/enqueue", json=INTERNAL[0][2], headers={"Authorization": header})
    assert r.status_code == 401, f"{header!r} was accepted"


@pytest.mark.asyncio
async def test_the_scheme_is_case_insensitive(client, configured):
    r = await client.post("/api/v1/osquery/distributed/enqueue", json=INTERNAL[0][2], headers={"Authorization": f"bearer {TOKEN}"})
    assert r.status_code not in (401, 503)


@pytest.mark.asyncio
async def test_a_refused_enqueue_never_touches_the_database(client, configured):
    """The gate runs before the handler: an unknown host would be a 404 if the handler had run."""
    r = await client.post("/api/v1/osquery/distributed/enqueue", json={**INTERNAL[0][2], "host_identifier": "nonexistent"})
    assert r.status_code == 401


# ------------------------------------------------------------- fail closed -----
@pytest.mark.asyncio
@pytest.mark.parametrize("environment", ["production", "staging", "prod", "Production ", "prodution", ""])
@pytest.mark.parametrize("method,path,body", INTERNAL)
async def test_without_a_token_anything_but_development_fails_closed(client, monkeypatch, environment, method, path, body):
    monkeypatch.setattr(settings, "api_token", "")
    monkeypatch.setattr(settings, "environment", environment)
    for headers in (None, GOOD, {"Authorization": "Bearer "}):
        r = await _call(client, method, path, body, headers)
        assert r.status_code == 503, f"{environment!r}: {method} {path} answered {r.status_code} with no token configured"


@pytest.mark.asyncio
@pytest.mark.parametrize("environment", ["development", "dev", "local", "test", "Development"])
async def test_a_development_stack_without_a_token_keeps_working(client, monkeypatch, environment):
    monkeypatch.setattr(settings, "api_token", "")
    monkeypatch.setattr(settings, "environment", environment)
    r = await client.get("/api/v1/osquery/packs")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_a_configured_token_is_enforced_even_in_development(client, monkeypatch):
    monkeypatch.setattr(settings, "api_token", TOKEN)
    monkeypatch.setattr(settings, "environment", "development")
    assert (await client.get("/api/v1/osquery/packs")).status_code == 401
    assert (await client.get("/api/v1/osquery/packs", headers=GOOD)).status_code == 200


# --------------------------------------------------------- agents unaffected -----
@pytest.mark.asyncio
async def test_agent_routes_never_needed_the_internal_token(client, configured):
    enroll = await client.post("/api/v1/osquery/enroll", json={"enroll_secret": "test-enroll-secret", "host_identifier": "agent-1"})
    assert enroll.status_code == 200, enroll.text
    node_key = enroll.json()["node_key"]
    for path in ("config", "distributed/read"):
        r = await client.post(f"/api/v1/osquery/{path}", json={"node_key": node_key})
        assert r.status_code == 200, f"{path}: {r.status_code} (an enrolled agent has no internal token)"


@pytest.mark.asyncio
async def test_the_internal_token_is_not_an_agent_credential(client, configured):
    r = await client.post("/api/v1/osquery/config", json={}, headers=GOOD)
    assert r.status_code == 401 and "node_key" in r.text
    bad = await client.post("/api/v1/osquery/enroll", json={"enroll_secret": TOKEN, "host_identifier": "x"}, headers=GOOD)
    assert bad.status_code in (401, 403)


# ----------------------------------------------------- every route classified -----
@pytest.mark.asyncio
async def test_every_mounted_route_is_agent_health_or_protected(client, configured):
    """A new route that is neither agent-facing nor protected must fail here, not ship open."""
    seen_internal = set()
    for path, ops in app.openapi()["paths"].items():
        if path in AGENT_PATHS or path in HEALTH:
            continue
        for method in ops:
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            url = path.replace("{query_id}", "q").replace("{pack_id}", "p").replace("{tenant_id}", "default")
            url = url + ("?tenant_id=default" if "/fim/" in path else "")
            r = await client.request(method.upper(), url, json={} if method in ("post", "put", "patch") else None)
            assert r.status_code == 401, (
                f"{method.upper()} {path} answered {r.status_code} without a token. It is not in AGENT_PATHS, so it must "
                "depend on require_api_token (or be added to AGENT_PATHS if agents authenticate to it themselves)."
            )
            seen_internal.add((method.upper(), path))
    assert len(seen_internal) >= 10, "the sweep found almost no internal routes: the schema walk is broken"


def test_the_known_internal_routes_are_all_in_the_schema():
    schema = app.openapi()["paths"]
    for method, path, _ in INTERNAL:
        template = path.split("?")[0]
        assert any(m == method.lower() and _matches(template, p) for p, ops in schema.items() for m in ops), f"{method} {template} not mounted"


def _matches(concrete: str, template: str) -> bool:
    import re
    return re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", template), concrete) is not None


# ---------------------------------------------------------------- startup guard -----
@pytest.mark.parametrize("environment", ["production", "staging", "weird", ""])
@pytest.mark.parametrize("secret", [PLACEHOLDER_ENROLL_SECRET, "", "  "])
def test_outside_development_the_placeholder_enroll_secret_refuses_to_start(monkeypatch, environment, secret):
    monkeypatch.setattr(settings, "environment", environment)
    monkeypatch.setattr(settings, "enroll_secret", secret)
    with pytest.raises(RuntimeError, match="refusing to start"):
        enforce_secure_defaults()


def test_a_real_enroll_secret_starts_in_production(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "enroll_secret", "a-long-generated-secret-value")
    enforce_secure_defaults()


@pytest.mark.parametrize("environment", ["development", "dev", "local", "test"])
def test_development_may_keep_the_placeholder(monkeypatch, environment):
    monkeypatch.setattr(settings, "environment", environment)
    monkeypatch.setattr(settings, "enroll_secret", PLACEHOLDER_ENROLL_SECRET)
    enforce_secure_defaults()


def test_the_startup_hook_really_runs_the_guard(monkeypatch):
    """The function refusing is not enough: the app's startup must call it, or the service starts anyway."""
    from fastapi.testclient import TestClient

    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "enroll_secret", PLACEHOLDER_ENROLL_SECRET)
    with pytest.raises(RuntimeError, match="refusing to start"):
        with TestClient(app):
            pass


def test_the_service_starts_normally_when_configured(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "enroll_secret", "a-long-generated-secret-value")
    with TestClient(app) as c:
        assert c.get("/healthz").status_code == 200
