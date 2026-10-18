"""GET /health/services: one honest row per internal service, down when it does not answer, never a URL."""

from __future__ import annotations

import httpx
import pytest
from app.api.v1.endpoints import health


@pytest.mark.asyncio
async def test_a_service_that_answers_200_is_up_and_anything_else_is_down(monkeypatch):
    monkeypatch.setattr(health, "_SERVICE_PROBES", {"fusion": "http://fusion/readyz", "agents": "http://agents/readyz", "ueba": "http://ueba/readyz"})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "agents":
            return httpx.Response(503)
        if request.url.host == "ueba":
            raise httpx.ConnectError("refused")
        return httpx.Response(200)

    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    out = await health.platform_services(user=object())
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
