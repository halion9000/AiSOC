"""EVERY route of the actions service needs the service token, except an explicit public list.

Found by calling each route anonymously: POST /live-actions/dispatch executes a vendor action synchronously
and, unlike POST /actions, goes through NONE of the blast-radius gate, approval, principal or audit checks,
yet it carried no authentication. Neither did GET /actions/{id}, whose record holds the target, parameters and
requester. The service already had the right mechanism (require_service_auth, W4.3); it was simply not applied
to those routes. This sweep makes "forgot to apply it" impossible to ship.
"""
from __future__ import annotations

import re

import pytest
from app.core.config import get_settings
from app.main import app
from fastapi.testclient import TestClient

TOKEN = "s3cr3t-service-token"
GOOD = {"Authorization": f"Bearer {TOKEN}"}
UUID = "00000000-0000-0000-0000-0000000000aa"

# (method, path) -> why anonymous callers may reach it
PUBLIC = {
    ("GET", "/api/v1/health"): "container health check",
    ("GET", "/api/v1/chatops/callback"): "a user clicking a link in Slack/Teams: authenticated by its own HMAC-signed, expiring token",
}
INFRA = re.compile(r"^/(health|healthz|livez|readyz|metrics|docs|redoc|openapi\.json)$")


@pytest.fixture(autouse=True)
def _reset_settings():
    yield
    get_settings.cache_clear()


def _configure(monkeypatch, *, token: str | None, dev: bool | None = None):
    for key in ("AISOC_ACTIONS_SERVICE_TOKEN", "AISOC_DEV_MODE"):
        monkeypatch.delenv(key, raising=False)
    if token is not None:
        monkeypatch.setenv("AISOC_ACTIONS_SERVICE_TOKEN", token)
    if dev is not None:
        monkeypatch.setenv("AISOC_DEV_MODE", "true" if dev else "false")
    get_settings.cache_clear()
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
    assert len(routes) >= 9, routes  # create, approve, reject, get-record, 3 discovery GETs, dispatch, dry-run
    assert ("POST", "/api/v1/live-actions/dispatch") in routes and ("GET", "/api/v1/actions/{action_id}") in routes


@pytest.mark.parametrize("method,path", _routes())
def test_no_credentials_is_refused(monkeypatch, method, path):
    client = _configure(monkeypatch, token=TOKEN)
    r = _call(client, method, path)
    assert r.status_code == 401, f"{method} {path} answered {r.status_code} without the service token"
    assert r.headers.get("www-authenticate") == "Bearer"


@pytest.mark.parametrize("method,path", _routes())
def test_the_right_token_gets_past_the_guard(monkeypatch, method, path):
    client = _configure(monkeypatch, token=TOKEN)
    assert _past_the_guard(_call(client, method, path, GOOD)), f"{method} {path} refused the correct token"


@pytest.mark.parametrize("method,path", _routes())
@pytest.mark.parametrize("dev", [None, False])
def test_unconfigured_outside_dev_fails_closed(monkeypatch, method, path, dev):
    client = _configure(monkeypatch, token=None, dev=dev)
    for headers in (None, GOOD):
        r = _call(client, method, path, headers)
        assert r.status_code == 503, f"{method} {path} answered {r.status_code} with no token configured"


@pytest.mark.parametrize("method,path", _routes())
def test_dev_mode_without_a_token_stays_open_for_local_development(monkeypatch, method, path):
    client = _configure(monkeypatch, token=None, dev=True)
    assert _past_the_guard(_call(client, method, path))


@pytest.mark.parametrize("header", [f"Bearer {TOKEN}x", f"Bearer {TOKEN[:-1]}", f"bearer {TOKEN}", f"Basic {TOKEN}", TOKEN, "Bearer ", "Bearer", "", f"Bearer  {TOKEN}"])
def test_only_the_exact_token_is_accepted(monkeypatch, header):
    client = _configure(monkeypatch, token=TOKEN)
    assert client.post("/api/v1/live-actions/dispatch", json={}, headers={"Authorization": header}).status_code == 401, header


def test_a_configured_token_is_enforced_even_in_dev_mode(monkeypatch):
    client = _configure(monkeypatch, token=TOKEN, dev=True)
    assert client.post("/api/v1/live-actions/dispatch", json={}).status_code == 401
    assert _past_the_guard(client.post("/api/v1/live-actions/dispatch", json={}, headers=GOOD))


def test_a_refused_dispatch_never_runs_an_executor(monkeypatch):
    """The guard sits in front of the handler: a valid-looking live request without the token must not execute."""
    from app.live_actions import LiveActionExecutor, LiveActionResult, LiveActionStatus, register_executor, reset_for_tests

    ran = []

    class _Spy(LiveActionExecutor):
        vendor_id, capability, description, requires_credentials = "spyvendor", "isolate_host", "spy", False

        async def execute(self, request):
            ran.append(request.target)
            return LiveActionResult(request_id=request.request_id, status=LiveActionStatus.SUCCEEDED, capability=self.capability, vendor_id=self.vendor_id, summary="ran")

    reset_for_tests()
    register_executor(_Spy(), source="builtin")
    client = _configure(monkeypatch, token=TOKEN)
    body = {"vendor_id": "spyvendor", "capability": "isolate_host", "target": "srv-12", "dry_run": False}
    assert client.post("/api/v1/live-actions/dispatch", json=body).status_code == 401
    assert client.post("/api/v1/live-actions/dry-run", json=body).status_code == 401
    assert ran == [], "an anonymous caller executed a vendor action"
    assert client.post("/api/v1/live-actions/dispatch", json=body, headers=GOOD).status_code == 200
    assert ran == ["srv-12"]
    reset_for_tests()


# ------------------------------------------------------------------- the public routes ----
def test_health_stays_open(monkeypatch):
    client = _configure(monkeypatch, token=TOKEN)
    assert client.get("/api/v1/health").status_code == 200


def test_the_chatops_callback_is_authenticated_by_its_signed_token_not_the_service_token(monkeypatch):
    client = _configure(monkeypatch, token=TOKEN)
    cb = "/api/v1/chatops/callback"
    assert client.get(cb).status_code == 422, "the signed token query parameter is required"
    # anything that is not a genuine HMAC-signed, unexpired token is rejected with a 400 "invalid" page, and
    # presenting the SERVICE token (as the parameter or as the bearer header) does not stand in for one
    for bad in ("forged-token-value.deadbeef", TOKEN, "a" * 40, "x.yx.yx.yx.yx.y"):
        for headers in (None, GOOD):
            r = client.get(cb, params={"token": bad}, headers=headers)
            assert r.status_code == 400 and "invalid" in r.text.lower(), (bad, headers, r.status_code)


def test_every_public_entry_is_a_real_route():
    paths = {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops}
    stale = [k for k in PUBLIC if k not in paths]
    assert not stale, f"PUBLIC lists routes that no longer exist: {stale}"
