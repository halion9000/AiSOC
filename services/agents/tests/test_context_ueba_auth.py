"""The context bundle's UEBA baselines call reaches the UEBA service and authenticates to it.

It defaulted to ``http://ueba:8086`` (the service listens on 8004) and sent no token (the service answers 401/503 without one), and a failure was only a debug line, so baselines were silently always empty.
"""

from __future__ import annotations

import httpx
import pytest
from app.context.bundle import ContextBundleBuilder, EntityRef


class _Recorder:
    def __init__(self):
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, json=[{"entity_id": "alice", "baseline_features": {"logins": 3}, "deviation_score": 0.5}])


@pytest.fixture
def recorder(monkeypatch):
    rec = _Recorder()
    real = httpx.AsyncClient

    def client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(rec.handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    return rec


@pytest.mark.asyncio
async def test_baselines_call_sends_the_ueba_service_token(recorder, monkeypatch):
    monkeypatch.setenv("AISOC_UEBA_URL", "http://ueba:8004")
    monkeypatch.setenv("AISOC_UEBA_SERVICE_TOKEN", "ueba-secret")
    out = await ContextBundleBuilder()._fetch_baselines("t1", [EntityRef(type="user", value="alice")])  # noqa: SLF001
    assert recorder.requests[0].headers["authorization"] == "Bearer ueba-secret"
    assert "user:alice" in out or any(k.endswith("alice") for k in out)


@pytest.mark.asyncio
async def test_default_url_is_the_port_the_ueba_service_listens_on(recorder, monkeypatch):
    monkeypatch.delenv("AISOC_UEBA_URL", raising=False)
    monkeypatch.delenv("AISOC_UEBA_SERVICE_TOKEN", raising=False)
    await ContextBundleBuilder()._fetch_baselines("t1", [EntityRef(type="user", value="alice")])  # noqa: SLF001
    assert recorder.requests[0].url.host == "ueba" and recorder.requests[0].url.port == 8004
    assert "authorization" not in recorder.requests[0].headers  # no token configured: none is invented
