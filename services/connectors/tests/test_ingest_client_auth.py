"""The connectors service's ingest client sends the ingest service's bearer token (the service now requires it)."""
from __future__ import annotations

import asyncio
import json
import uuid

import httpx
import respx
from app.ingest_client import IngestClient

BASE = "http://ingest-worker:8080"
URL = f"{BASE}/v1/ingest/batch"


def _push(monkeypatch, *, token):
    monkeypatch.delenv("AISOC_INGEST_SERVICE_TOKEN", raising=False)
    if token is not None:
        monkeypatch.setenv("AISOC_INGEST_SERVICE_TOKEN", token)

    async def go():
        client = IngestClient(BASE)
        try:
            return await client.push_events(tenant_id=uuid.UUID(int=1), connector_id=uuid.UUID(int=2), connector_type="okta", events=[{"a": 1}])
        finally:
            await client.aclose()

    return asyncio.run(go())


@respx.mock
def test_the_token_the_tenant_and_the_connector_identity_are_sent(monkeypatch):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={"accepted": 1, "rejected": 0}))
    assert _push(monkeypatch, token="ingest-token-123") == {"accepted": 1, "rejected": 0}
    sent = route.calls[0].request
    assert sent.headers["authorization"] == "Bearer ingest-token-123" and sent.headers["x-tenant-id"] == str(uuid.UUID(int=1))
    assert json.loads(sent.content)["connector_type"] == "okta"


@respx.mock
def test_without_a_token_no_authorization_header_is_sent(monkeypatch):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={"accepted": 1, "rejected": 0}))
    _push(monkeypatch, token=None)
    assert "authorization" not in route.calls[0].request.headers
    _push(monkeypatch, token="   ")
    assert "authorization" not in route.calls[1].request.headers


@respx.mock
def test_a_refused_token_surfaces_as_an_error_not_a_silent_drop(monkeypatch):
    import pytest
    from app.ingest_client import IngestClientError

    respx.post(URL).mock(return_value=httpx.Response(401, json={"detail": "invalid or missing service token"}))
    with pytest.raises(IngestClientError, match="401"):
        _push(monkeypatch, token="wrong")
