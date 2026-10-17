"""The consume loop must never commit past a message it did not handle, and never wedge on a bad one.

Before: a message whose processing raised was logged and skipped, and the NEXT successful message's commit moved the offset past it: the alert was gone, with no retry and
no dead letter. A payload that was not JSON raised inside the Kafka iterator itself and ended the loop for good.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.core.config import settings
from app.services.dlq import InMemoryDLQ
from app.workers import consumer as consumer_mod
from app.workers.consumer import FusionWorker

pytestmark = pytest.mark.asyncio

TOPIC = settings.kafka_topic_alerts_raw


class _FakeConsumer:
    def __init__(self, values):
        self._msgs = [SimpleNamespace(value=v, topic=TOPIC) for v in values]
        self.commits = 0

    def __aiter__(self):
        async def gen():
            for m in self._msgs:
                yield m

        return gen()

    async def commit(self):
        self.commits += 1


def _worker(values, process):
    worker = FusionWorker(engine=SimpleNamespace(), sink=None, dlq=InMemoryDLQ())
    worker._consumer = _FakeConsumer(values)  # noqa: SLF001
    worker._producer = AsyncMock()  # noqa: SLF001
    worker._running = True  # noqa: SLF001
    worker._process_message = process  # type: ignore[method-assign]  # noqa: SLF001
    return worker


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    monkeypatch.setattr(consumer_mod, "_RETRY_BACKOFF_SECONDS", 0.0)


async def test_a_message_that_always_fails_is_dead_lettered_not_skipped():
    seen = []

    async def process(payload, topic=None):
        seen.append(payload)
        raise RuntimeError("redis down")

    worker = _worker([{"n": 1}], process)
    await worker._consume_loop()  # noqa: SLF001
    assert len(seen) == consumer_mod._MAX_ATTEMPTS  # retried before giving up  # noqa: SLF001
    assert len(worker._dlq.records) == 1 and "redis down" in worker._dlq.records[0].reason  # noqa: SLF001
    assert worker._consumer.commits == 1  # committed only because it is now safely in the DLQ  # noqa: SLF001


async def test_a_transient_failure_is_retried_and_processed_once():
    calls = {"n": 0}

    async def process(payload, topic=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("blip")

    worker = _worker([{"n": 1}], process)
    await worker._consume_loop()  # noqa: SLF001
    assert calls["n"] == 2
    assert worker._dlq.records == [] and worker._consumer.commits == 1  # noqa: SLF001


async def test_an_undecodable_payload_is_dead_lettered_and_the_loop_keeps_going():
    handled = []

    async def process(payload, topic=None):
        handled.append(payload)

    bad = consumer_mod.decode_message(b"\xff not json")
    worker = _worker([bad, {"n": 2}], process)
    await worker._consume_loop()  # noqa: SLF001
    assert handled == [{"n": 2}], "the good message after the bad one is still processed"
    assert len(worker._dlq.records) == 1 and "undecodable" in worker._dlq.records[0].reason  # noqa: SLF001


async def test_valid_json_decodes_normally():
    assert consumer_mod.decode_message(b'{"a": 1}') == {"a": 1}


async def test_an_unpersisted_alert_is_not_committed_and_can_be_retried(monkeypatch):
    """persist() answering UNAVAILABLE used to be only a counter: the offset was committed, and the dedup fingerprint fusion had already registered made any redelivery a 'duplicate' that persist() skips. Both must be undone: raise so the retry/DLQ path runs, and forget the fingerprint."""
    from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
    from app.services.alert_sink import PersistOutcome, PersistResult

    alert = RawAlert(tenant_id="00000000-0000-0000-0000-000000000001", source="s", title="t", severity=AlertSeverity.HIGH)
    fused = FusedAlert(id=alert.id, tenant_id=alert.tenant_id, fusion_decision=FusionDecision.NEW_INCIDENT, alert=alert)
    forgotten = []
    engine = SimpleNamespace(process=AsyncMock(return_value=fused), forget=AsyncMock(side_effect=lambda a: forgotten.append(a)))
    sink = SimpleNamespace(persist=AsyncMock(return_value=PersistResult(PersistOutcome.UNAVAILABLE, str(fused.id))))
    worker = FusionWorker(engine=engine, sink=sink, dlq=InMemoryDLQ())
    worker._producer = AsyncMock()  # noqa: SLF001
    with pytest.raises(RuntimeError, match="not persisted"):
        await worker._fuse_and_persist(alert)  # noqa: SLF001
    assert forgotten == [alert]
    worker._producer.send.assert_not_awaited()  # noqa: SLF001


async def test_dead_letters_go_to_kafka_as_well_as_the_log():
    """main.py never passed a KafkaDLQ, so a dead letter was only a log line, which is not durable."""
    from app.services.dlq import DeadLetter, KafkaDLQ, TeeDLQ

    first, second = InMemoryDLQ(), InMemoryDLQ()
    letter = DeadLetter.build(topic="t", reason="r", schema_version="v1", payload={"a": 1}, source_event_id=None, tenant_id=None)
    await TeeDLQ(first, second).record(letter)
    assert first.records == [letter] and second.records == [letter]

    class _Broken:
        async def record(self, _letter):
            raise RuntimeError("kafka down")

    survivor = InMemoryDLQ()
    await TeeDLQ(_Broken(), survivor).record(letter)  # one sink failing must not stop the other
    assert survivor.records == [letter]

    producer = AsyncMock()
    await KafkaDLQ(producer).record(letter)
    producer.send.assert_awaited_once()


async def test_worker_without_an_explicit_dlq_uses_kafka_once_started(monkeypatch):
    from app.services.dlq import TeeDLQ

    worker = FusionWorker(engine=SimpleNamespace(), sink=None)
    worker._producer = AsyncMock()  # noqa: SLF001
    worker._install_default_dlq()  # noqa: SLF001
    assert isinstance(worker._dlq, TeeDLQ)  # noqa: SLF001
    explicit = InMemoryDLQ()
    other = FusionWorker(engine=SimpleNamespace(), sink=None, dlq=explicit)
    other._install_default_dlq()  # noqa: SLF001
    assert other._dlq is explicit  # noqa: SLF001
