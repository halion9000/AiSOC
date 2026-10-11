"""The SAML and OIDC endpoints that run BEFORE authentication must not echo exception text to the caller.

Found by reviewing the 12 sites that put an exception's text in a 5xx response: three of them are on pre-authentication routes, so what
they return reaches anyone. `GET /auth/saml/login` returned `SAML error: {exc}` for ANY unexpected exception while building the request or
settings (such exceptions can carry configuration detail: certificate paths, setting names), and the two OIDC discovery failures returned
the HTTP client's text. Each is already (or now) logged, so the response is generic and the detail is where an operator looks.
Deliberately NOT changed: `POST /auth/saml/acs` returns python-saml's error CODES ("invalid_response", ...) for the attacker-supplied
response, the standard diagnostic an IdP administrator needs, and not an exception's text.
"""

import logging
import sys
import types

import httpx
import pytest
from app.auth import oidc, saml
from fastapi import FastAPI
from fastapi.testclient import TestClient

INTERNAL = "[Errno 111] Connect call failed ('10.9.8.7', 8443) idp-internal.corp /etc/saml/certs/sp.key"


def _client(router):
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def oidc_configured(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "client")

    async def discover(issuer):
        raise httpx.ConnectError(INTERNAL)

    monkeypatch.setattr(oidc, "_discover", discover)


def test_oidc_login_discovery_failure_is_generic_and_unauthenticated_callers_learn_nothing(oidc_configured):
    response = _client(oidc.router).get("/auth/oidc/login")
    assert response.status_code == 502 and response.json() == {"detail": "OIDC discovery failed"}
    assert "idp-internal" not in response.text and "10.9.8.7" not in response.text


def test_oidc_callback_discovery_failure_is_generic_too(oidc_configured, monkeypatch):
    monkeypatch.setattr(oidc, "_pop_state", lambda state: {"redirect": "/", "nonce": "n", "code_verifier": "v"})
    response = _client(oidc.router).get("/auth/oidc/callback", params={"code": "c", "state": "s"})
    assert response.status_code == 502 and response.json() == {"detail": "OIDC discovery failed"}


def test_the_oidc_detail_is_logged_for_the_operator(oidc_configured, caplog):
    with caplog.at_level(logging.WARNING, logger=oidc.logger.name):
        _client(oidc.router).get("/auth/oidc/login")
    assert "idp-internal.corp" in caplog.text


@pytest.fixture
def saml_failing(monkeypatch):
    """A stand-in for python3-saml (which may not be installed) whose settings building fails with a message that names a path."""
    auth_module = types.ModuleType("onelogin.saml2.auth")

    class Broken:
        def __init__(self, *args, **kwargs):
            raise RuntimeError(INTERNAL)

    auth_module.OneLogin_Saml2_Auth = Broken
    for name in ("onelogin", "onelogin.saml2"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "onelogin.saml2.auth", auth_module)

    async def build(request):
        return {}

    monkeypatch.setattr(saml, "_build_saml_request", build)
    monkeypatch.setattr(saml, "_saml_settings", lambda: {})


def test_saml_login_unexpected_error_is_generic_and_carries_no_path_or_address(saml_failing):
    response = _client(saml.router).get("/auth/saml/login")
    assert response.status_code == 500 and response.json() == {"detail": "SAML login failed"}
    assert "/etc/saml" not in response.text and "10.9.8.7" not in response.text


def test_the_saml_detail_is_still_logged_with_its_traceback(saml_failing, caplog):
    with caplog.at_level(logging.ERROR, logger=saml.logger.name):
        _client(saml.router).get("/auth/saml/login")
    assert "SAML login error" in caplog.text and "/etc/saml/certs/sp.key" in caplog.text


def test_the_missing_dependency_is_still_a_501_with_its_own_clear_message(monkeypatch):
    for name in ("onelogin", "onelogin.saml2", "onelogin.saml2.auth"):
        monkeypatch.setitem(sys.modules, name, None)  # makes `import` raise ImportError
    response = _client(saml.router).get("/auth/saml/login")
    assert response.status_code == 501 and "python3-saml" in response.json()["detail"]
