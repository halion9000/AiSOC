"""GET /health/services: one honest row per internal service, down when it does not answer, never a URL."""

from __future__ import annotations

import httpx
import pytest
from app.api.v1.endpoints import health


@pytest.mark.asyncio
async def test_a_service_that_answers_200_is_up_and_anything_else_is_down(monkeypatch):
    monkeypatch.setattr(
        health, "_SERVICE_PROBES", {"fusion": "http://fusion/readyz", "agents": "http://agents/readyz", "ueba": "http://ueba/readyz"}
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "agents":
            return httpx.Response(503)
        if request.url.host == "ueba":
            raise httpx.ConnectError("refused")
        return httpx.Response(200)

    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    out = await health.platform_services(user=object(), db=_Db(("app_user", False, False)))
    assert out["overall"] == "degraded"
    assert sorted(out["down"]) == ["agents", "ueba"]
    by = {r["service"]: r for r in out["services"]}
    assert by["fusion"]["status"] == "up"
    assert by["agents"]["detail"] == "HTTP 503" and by["ueba"]["detail"] == "ConnectError"
    assert "http://" not in str(out["services"])  # no internal URL leaks


@pytest.mark.asyncio
async def test_an_env_override_replaces_a_url_and_empty_omits_the_service(monkeypatch):
    monkeypatch.setattr(health, "_SERVICE_PROBES", {"fusion": "http://fusion/readyz", "ueba": "http://ueba/readyz"})
    monkeypatch.setenv("AISOC_SERVICE_HEALTH_FUSION", "http://elsewhere/ok")
    monkeypatch.setenv("AISOC_SERVICE_HEALTH_UEBA", "")
    assert health._service_probes() == {"fusion": "http://elsewhere/ok"}


class _Result:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _Db:
    def __init__(self, row=None, error=None):
        self._row, self._error = row, error

    async def execute(self, *_a, **_k):
        if self._error:
            raise self._error
        return _Result(self._row[1:] if self._row else None)


@pytest.mark.asyncio
async def test_a_superuser_connection_is_reported_as_not_enforcing_row_security():
    out = await health.database_row_security(_Db(("aisoc", True, False)))
    assert out["enforced"] is False and "superuser" in out["reason"] and "fix" in out


@pytest.mark.asyncio
async def test_a_bypassrls_role_is_reported_too():
    out = await health.database_row_security(_Db(("app", False, True)))
    assert out["enforced"] is False and "BYPASSRLS" in out["reason"]


@pytest.mark.asyncio
async def test_an_ordinary_role_is_enforced_and_an_unreadable_one_is_unknown_not_an_error():
    assert (await health.database_row_security(_Db(("app", False, False))))["enforced"] is True
    assert (await health.database_row_security(_Db(error=RuntimeError("no catalog access"))))["enforced"] is None
    assert (await health.database_row_security(_Db(None)))["enforced"] is None


@pytest.mark.asyncio
async def test_a_service_that_is_up_but_has_consumed_no_events_says_so(monkeypatch):
    monkeypatch.setattr(health, "_SERVICE_PROBES", {"ueba": "http://ueba/health", "fusion": "http://fusion/readyz"})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "ueba":
            return httpx.Response(200, json={"status": "ok", "events_consumed": 0})
        return httpx.Response(200, json={"status": "ready"})

    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    out = await health.platform_services(user=object(), db=_Db(("app_user", False, False)))
    by = {r["service"]: r for r in out["services"]}
    assert by["ueba"]["status"] == "up" and "no events" in by["ueba"]["detail"]
    assert by["fusion"]["detail"] == ""
    assert out["overall"] == "ok"  # up is up: this is information, not an outage


def test_the_deployed_extras_are_probed_at_the_addresses_compose_gives_the_api(monkeypatch):
    """Honeytokens and Purple Team are probed, on the same host:port the API is configured to call them on."""
    import re
    from pathlib import Path

    for name in ("honeytokens", "purple-team"):
        monkeypatch.delenv(f"AISOC_SERVICE_HEALTH_{name.upper()}", raising=False)
    probes = health._service_probes()
    compose = (Path(__file__).resolve().parents[3] / "docker-compose.yml").read_text(encoding="utf-8")
    for name, var in (("honeytokens", "HONEYTOKENS_SERVICE_URL"), ("purple-team", "PURPLE_TEAM_SERVICE_URL")):
        configured = re.search(rf"{var}:\s*(http://[\w.-]+:\d+)", compose)
        assert configured, f"{var} is not set in compose"
        assert probes[name].startswith(configured.group(1)), f"{name} is probed somewhere other than where the API calls it"
