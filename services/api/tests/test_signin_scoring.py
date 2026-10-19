"""Sign-in features for the UEBA service, and the call that scores them."""

import json
from datetime import UTC, datetime

import httpx
import pytest
from app.services.signin_scoring import History, score_events, signin_features

NOON = datetime(2026, 10, 19, 12, 30, tzinfo=UTC)


def feats(history=None, **over):
    base = {
        "occurred_at": NOON,
        "success": True,
        "mfa": True,
        "interactive": True,
        "risk": None,
        "country": "US",
        "ip": "1.1.1.1",
        "history": history or History(),
    }
    base.update(over)
    return signin_features(**base)


def test_an_ordinary_sign_in_is_all_zeros_but_the_hour():
    assert feats() == {
        "hour_of_day": 12.0,
        "failed": 0.0,
        "no_mfa": 0.0,
        "non_interactive": 0.0,
        "risk": 0.0,
        "new_country": 0.0,
        "new_ip": 0.0,
    }


def test_failure_missing_mfa_non_interactive_and_risk_each_set_their_feature():
    assert feats(success=False)["failed"] == 1.0
    assert feats(mfa=False)["no_mfa"] == 1.0
    assert feats(success=False, mfa=False)["no_mfa"] == 0.0, "a refused sign-in did not get in, so lacking MFA is not the point"
    assert feats(mfa=None)["no_mfa"] == 0.0, "unknown is not missing"
    assert feats(interactive=False)["non_interactive"] == 1.0
    assert [feats(risk=r)["risk"] for r in (None, "none", "low", "medium", "HIGH", "weird")] == [0.0, 0.0, 1.0, 2.0, 3.0, 0.0]


def test_new_country_and_address_only_count_for_a_person_already_seen():
    assert feats(country="CH", ip="9.9.9.9")["new_country"] == 0.0, "the first sign-in collected for anyone is not 'new'"
    seen = History()
    seen.remember("US", "1.1.1.1")
    assert feats(seen, country="CH", ip="9.9.9.9")["new_country"] == 1.0
    assert feats(seen, country="CH", ip="9.9.9.9")["new_ip"] == 1.0
    assert feats(seen, country="US", ip="1.1.1.1")["new_country"] == 0.0
    assert feats(seen, country=None, ip=None)["new_country"] == 0.0, "no location is not a new location"


def event(key, user="a@x.com"):
    return {
        "key": key,
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "entity_id": user,
        "event_type": "login",
        "features": {"hour_of_day": 3.0},
        "source_event_id": key,
    }


def client_for(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_each_event_is_posted_to_score_with_the_bearer_token_and_anomalies_are_counted(monkeypatch):
    monkeypatch.setenv("AISOC_UEBA_SERVICE_TOKEN", "tok")
    monkeypatch.setenv("AISOC_UEBA_URL", "http://ueba.test:8004/")
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append((str(request.url), request.headers["authorization"], body))
        return httpx.Response(200, json={"anomaly_score": 4.2}) if body["source_event_id"] == "e2" else httpx.Response(200, content=b"null")

    out = await score_events([event("e1"), event("e2")], client=client_for(handler))
    assert out.status == "ok" and out.anomalies == 1
    assert out.scored == {"e1": None, "e2": 4.2}
    url, auth, body = seen[0]
    assert url == "http://ueba.test:8004/api/v1/ueba/score" and auth == "Bearer tok"
    assert body["entity_type"] == "user" and body["event_type"] == "login" and body["features"] == {"hour_of_day": 3.0}


@pytest.mark.asyncio
async def test_without_a_token_nothing_is_sent(monkeypatch):
    monkeypatch.delenv("AISOC_UEBA_SERVICE_TOKEN", raising=False)
    called = []
    out = await score_events([event("e1")], client=client_for(lambda r: called.append(r) or httpx.Response(200, content=b"null")))
    assert out.status == "not_configured" and out.scored == {} and called == []


@pytest.mark.asyncio
async def test_a_refusal_or_an_unreachable_service_marks_the_batch_unavailable_and_stops_asking(monkeypatch):
    monkeypatch.setenv("AISOC_UEBA_SERVICE_TOKEN", "tok")
    for handler in (lambda r: httpx.Response(401, json={"detail": "no"}), lambda r: (_ for _ in ()).throw(httpx.ConnectError("down"))):
        out = await score_events([event(f"e{i}") for i in range(20)], client=client_for(handler))
        assert out.status == "unavailable"
        assert len(out.scored) < 20, "it stopped asking once the service failed"


@pytest.mark.asyncio
async def test_no_events_is_fine(monkeypatch):
    monkeypatch.setenv("AISOC_UEBA_SERVICE_TOKEN", "tok")
    assert (await score_events([])).status == "ok"
