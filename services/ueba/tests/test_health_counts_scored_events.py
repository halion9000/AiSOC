"""The API scores sign-ins by calling /score directly, not through Kafka: those events must count as the service being fed, or /health says it has consumed nothing forever."""

import asyncio
import uuid
from contextlib import asynccontextmanager

from app.api import routes as routes_module
from app.services import kafka_consumer as kc


class FakeDb:
    def begin(self):
        @asynccontextmanager
        async def cm():
            yield

        return cm()


class FakeScoring:
    def __init__(self, db):
        pass

    async def score_event(self, **kwargs):
        return None


def body():
    return routes_module.ScoreEventRequest(tenant_id=uuid.uuid4(), entity_type="user", entity_id="a@b.example", event_type="login", features={"hour_of_day": 3})


def test_record_event_counts_and_stamps_the_time():
    kc.STATS["consumed"], kc.STATS["last_message_at"] = 0, None
    kc.record_event()
    assert kc.STATS["consumed"] == 1
    assert kc.STATS["last_message_at"]


def test_an_event_scored_over_http_counts_as_consumed(monkeypatch):
    kc.STATS["consumed"], kc.STATS["last_message_at"] = 0, None
    monkeypatch.setattr(routes_module, "ScoringService", FakeScoring)
    assert asyncio.run(routes_module.score_event(body(), FakeDb())) is None
    assert kc.STATS["consumed"] == 1
    assert kc.STATS["last_message_at"]


def test_a_scoring_failure_is_not_counted(monkeypatch):
    kc.STATS["consumed"], kc.STATS["last_message_at"] = 0, None

    class Broken(FakeScoring):
        async def score_event(self, **kwargs):
            raise RuntimeError("db down")

    monkeypatch.setattr(routes_module, "ScoringService", Broken)
    try:
        asyncio.run(routes_module.score_event(body(), FakeDb()))
    except RuntimeError:
        pass
    assert kc.STATS["consumed"] == 0
