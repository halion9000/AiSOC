"""POST /api/v1/agents/investigate when the alert cannot be fetched from the core API.

It used to answer 502 with `detail=f"Could not fetch alert {alert_id} from core API: {exc}"`, which put the HTTP client's own error in the response: for a
connection failure that is the core API's internal host and port, for a status error the upstream URL. The caller has no use for it and an attacker does, so
the response is now generic and the cause is only LOGGED (and chained, so a traceback still shows it). These tests keep it that way.
"""

import httpx
import pytest
from app.api import investigate as inv
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

ALERT = "alert-4711"
INTERNAL = "http://10.9.8.7:8000/api/v1/alerts/alert-4711"
GENERIC = f"Could not fetch alert {ALERT} from the core API"


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(inv.router)
    return TestClient(app, raise_server_exceptions=False)


def fail_with(monkeypatch, exc, seen=None):
    async def get(self, url, **kwargs):
        if seen is not None:
            seen.append((url, kwargs.get("headers", {})))
        raise exc

    monkeypatch.setattr(httpx.AsyncClient, "get", get)


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectError(f"All connection attempts failed to {INTERNAL}"),
        httpx.ReadTimeout(f"timed out reading {INTERNAL}"),
        RuntimeError("psycopg2 password authentication failed for user aisoc_app at 10.9.8.7"),
    ],
    ids=["connect-error", "timeout", "unexpected-error"],
)
def test_a_failed_fetch_answers_502_with_a_generic_message_and_none_of_the_errors_text(client, monkeypatch, exc):
    fail_with(monkeypatch, exc)
    r = client.post("/api/v1/agents/investigate", json={"alertId": ALERT})
    assert r.status_code == 502
    assert r.json() == {"detail": GENERIC}
    for leaked in ("10.9.8.7", "8000", "ConnectError", "ReadTimeout", "All connection attempts", "password", "aisoc_app", "RuntimeError"):
        assert leaked not in r.text, f"the response leaks {leaked!r}: {r.text}"


def test_an_upstream_error_status_is_handled_the_same_way(client, monkeypatch):
    async def get(self, url, **kwargs):
        return httpx.Response(500, request=httpx.Request("GET", INTERNAL), text="Traceback ... secret internal detail")

    monkeypatch.setattr(httpx.AsyncClient, "get", get)
    r = client.post("/api/v1/agents/investigate", json={"alertId": ALERT})
    assert r.status_code == 502 and r.json() == {"detail": GENERIC}
    assert "10.9.8.7" not in r.text and "internal detail" not in r.text


async def test_the_cause_is_still_chained_so_a_traceback_shows_it(monkeypatch):
    cause = httpx.ConnectError("boom")
    fail_with(monkeypatch, cause)
    request = type("R", (), {"headers": {}})()
    with pytest.raises(HTTPException) as caught:
        await inv.legacy_investigate(inv._LegacyInvestigateRequest(alertId=ALERT), background_tasks=None, request=request)  # noqa: SLF001
    assert caught.value.status_code == 502
    assert caught.value.__cause__ is cause  # `raise ... from exc`, not a bare raise that hides it


def test_the_callers_own_credentials_are_forwarded_and_anonymous_calls_send_none(client, monkeypatch):
    seen: list = []
    fail_with(monkeypatch, httpx.ConnectError("x"), seen)
    client.post("/api/v1/agents/investigate", json={"alertId": ALERT}, headers={"Authorization": "Bearer caller-token"})
    client.post("/api/v1/agents/investigate", json={"alertId": ALERT})
    assert seen[0][1] == {"Authorization": "Bearer caller-token"}  # the alert belongs to whoever clicked Investigate
    assert seen[1][1] == {}  # nothing is invented for an anonymous caller
    assert all(url.endswith(f"/api/v1/alerts/{ALERT}") for url, _ in seen)
