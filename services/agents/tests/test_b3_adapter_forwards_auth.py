"""The Investigate adapter must forward the caller's own credentials to the API.

In production the API refuses anonymous requests; before this the adapter's
alert lookup sent no credentials, so the Investigate button 502'd in production.
"""
import types

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

import app.api.investigate as inv


class _FakeLaunch:
    def __init__(self):
        self.case_id = None

    async def __call__(self, *, case_id, body, background_tasks):
        self.case_id = case_id
        inv._runs["run-1"] = {"started_at": "2026-10-06T00:00:00"}  # what the real launch records
        return types.SimpleNamespace(run_id="run-1", case_id=case_id, status="running", message="started")


@pytest.fixture(autouse=True)
def _dev(monkeypatch):
    # The middleware is tested separately; here we test only what the adapter forwards.
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("API_URL", "http://api:8000")


@respx.mock
@pytest.mark.parametrize("auth", ["Bearer user-jwt-abc", "Bearer aisoc_apikey"])
def test_adapter_forwards_the_callers_authorization(monkeypatch, auth):
    fake = _FakeLaunch()
    monkeypatch.setattr(inv, "launch_investigation", fake)
    route = respx.get("http://api:8000/api/v1/alerts/a-1").mock(
        return_value=httpx.Response(200, json={"id": "a-1", "caseId": "c-9", "title": "t"})
    )
    from app.main import app
    resp = TestClient(app).post("/api/v1/agents/investigate", json={"alertId": "a-1"}, headers={"Authorization": auth})
    assert route.called, resp.text
    assert route.calls[0].request.headers.get("authorization") == auth
    assert fake.case_id == "c-9"


@respx.mock
def test_adapter_sends_no_authorization_when_caller_sent_none(monkeypatch):
    monkeypatch.setattr(inv, "launch_investigation", _FakeLaunch())
    route = respx.get("http://api:8000/api/v1/alerts/a-2").mock(return_value=httpx.Response(200, json={"id": "a-2"}))
    from app.main import app
    TestClient(app).post("/api/v1/agents/investigate", json={"alertId": "a-2"})
    assert route.called
    assert "authorization" not in route.calls[0].request.headers
