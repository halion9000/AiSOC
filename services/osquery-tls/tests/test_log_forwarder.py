"""The osquery -> ingest forwarder, run for real (every earlier test replaced forward_events with a mock).

Three independent bugs meant NO osquery event had ever been accepted by the ingest service, and the forwarder swallows failures into a
log line, so nothing ever said so:
  1. it posted to http://ingest:8080, but the compose service is `ingest-worker` (there is no host `ingest`);
  2. compose set AISOC_INGEST_BASE_URL, which this service's settings (prefix AISOC_OSQUERY_TLS_) never read;
  3. the body was {"events": [...]}; ingest answers 400 unless connector_id and connector_type are present.
It must also send the ingest service's bearer token, which the service now requires.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import httpx
import pytest
import respx
import yaml
from app.core.config import Settings, settings
from app.services import log_forwarder

COMPOSE = yaml.safe_load((Path(__file__).resolve().parents[3] / "docker-compose.yml").read_text(encoding="utf-8"))["services"]
BASE = "http://ingest-worker:8080"
URL = f"{BASE}/v1/ingest/batch"
EVENTS = [{"event_type": "process", "hostname": "web-1"}]


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setattr(settings, "ingest_url", BASE)
    monkeypatch.setenv("AISOC_INGEST_SERVICE_TOKEN", "ingest-token-123")


def _run(tenant="tenant-a"):
    asyncio.run(log_forwarder.forward_events(EVENTS, tenant))


@respx.mock
def test_the_body_has_what_the_ingest_handler_requires():
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={"accepted": 1, "rejected": 0}))
    _run()
    body = json.loads(route.calls[0].request.content)
    assert body["connector_id"] and body["connector_type"], "ingest answers 400 without both"
    assert body["events"] == EVENTS


@respx.mock
def test_the_tenant_and_the_ingest_token_are_sent():
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={}))
    _run("tenant-a")
    sent = route.calls[0].request.headers
    assert sent["x-tenant-id"] == "tenant-a" and sent["authorization"] == "Bearer ingest-token-123"


@respx.mock
def test_without_a_token_configured_no_authorization_header_is_sent(monkeypatch):
    monkeypatch.delenv("AISOC_INGEST_SERVICE_TOKEN")
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={}))
    _run()
    assert "authorization" not in route.calls[0].request.headers


@respx.mock
def test_a_failed_forward_is_logged_with_the_url_and_does_not_break_the_agents_log_submission(caplog):
    respx.post(URL).mock(return_value=httpx.Response(401, json={"detail": "invalid or missing service token"}))
    with caplog.at_level(logging.ERROR):
        _run()  # must not raise
    assert "Failed to forward 1 events" in caplog.text and URL in caplog.text


def test_an_empty_batch_makes_no_request():
    with respx.mock:
        route = respx.post(URL).mock(return_value=httpx.Response(200, json={}))
        asyncio.run(log_forwarder.forward_events([], "tenant-a"))
        assert not route.called


# ------------------------------------------------------------------- the settings ----
def _clear(monkeypatch):
    for key in ("AISOC_OSQUERY_TLS_INGEST_URL", "AISOC_INGEST_BASE_URL"):
        monkeypatch.delenv(key, raising=False)


def test_the_default_is_the_real_compose_hostname(monkeypatch):
    _clear(monkeypatch)
    assert Settings().ingest_url == BASE
    assert "ingest-worker" in COMPOSE and "ingest" not in COMPOSE, "the host the default names must be a real compose service"


def test_the_variable_compose_actually_sets_is_read(monkeypatch):
    """compose sets AISOC_INGEST_BASE_URL; the settings class has prefix AISOC_OSQUERY_TLS_ and used to ignore it."""
    _clear(monkeypatch)
    env = COMPOSE["osquery-tls"]["environment"]
    env = env if isinstance(env, dict) else dict(x.split("=", 1) for x in env if "=" in x)
    ingest_vars = {k: v for k, v in env.items() if "INGEST" in k and "URL" in k}
    assert ingest_vars, "compose gives osquery-tls no ingest URL at all"
    for name, value in ingest_vars.items():
        _clear(monkeypatch)
        monkeypatch.setenv(name, "http://sentinel.example:1234")
        assert Settings().ingest_url == "http://sentinel.example:1234", f"compose sets {name} but the settings never read it"
        assert value == BASE, f"compose points osquery-tls at {value}, not the real ingest service"


def test_either_name_works_and_the_prefixed_one_wins(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("AISOC_INGEST_BASE_URL", "http://a:1")
    assert Settings().ingest_url == "http://a:1"
    monkeypatch.setenv("AISOC_OSQUERY_TLS_INGEST_URL", "http://b:2")
    assert Settings().ingest_url == "http://b:2"


def test_constructing_by_field_name_still_works():
    assert Settings(ingest_url="http://c:3").ingest_url == "http://c:3"
