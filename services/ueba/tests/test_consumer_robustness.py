"""One bad message must not end UEBA's consumer, and a non-finite number must not reach a baseline.

Before: nothing wrapped ``_process_message`` in the consume loop, so any database error ended the consumer for good while the service kept reporting healthy; and ``float("nan")``
or ``float("inf")`` was accepted as a feature value, which poisons a running mean permanently.
"""

from __future__ import annotations

import json
import math

import pytest
from app.services.kafka_consumer import UEBAKafkaConsumer, clean_features


def test_non_finite_and_non_numeric_features_are_dropped():
    out = clean_features({"a": 1, "b": "2.5", "nan": "nan", "inf": float("inf"), "ninf": "-inf", "text": "x", "none": None, "flag": True})
    assert out == {"a": 1.0, "b": 2.5, "flag": 1.0}
    assert all(math.isfinite(v) for v in out.values())


@pytest.mark.asyncio
async def test_a_failing_message_is_logged_and_the_next_one_still_runs():
    consumer = UEBAKafkaConsumer()
    consumer._running = True  # noqa: SLF001
    seen: list[str] = []

    async def process(raw, producer):
        seen.append(raw)
        if raw == b"boom":
            raise RuntimeError("db down")

    consumer._process_message = process  # type: ignore[method-assign]  # noqa: SLF001

    async def messages():
        for value in (b"boom", b"ok"):
            yield type("M", (), {"value": value})()

    await consumer._consume(messages(), producer=None)  # noqa: SLF001
    assert seen == [b"boom", b"ok"]
    assert json  # keep the import used


@pytest.mark.asyncio
async def test_the_health_endpoint_reports_how_many_events_the_consumer_has_seen():
    """'Ready' used to be the whole story: a UEBA service that has never received an event looked identical to one that is learning. The count is on /health."""
    from app.main import health
    from app.services import kafka_consumer as kc

    kc.STATS["consumed"], kc.STATS["last_message_at"] = 0, None
    assert (await health())["events_consumed"] == 0

    class _Msgs:
        def __init__(self, n):
            self._n = n

        def __aiter__(self):
            return self

        async def __anext__(self):
            if self._n == 0:
                raise StopAsyncIteration
            self._n -= 1
            return type("M", (), {"value": b"{}"})()

    consumer = kc.UEBAKafkaConsumer()
    consumer._running = True

    async def _noop(*_a, **_k):
        return None

    consumer._process_message = _noop  # type: ignore[method-assign]
    await consumer._consume(_Msgs(3), None)
    out = await health()
    assert out["events_consumed"] == 3 and out["last_event_at"]
    kc.STATS["consumed"], kc.STATS["last_message_at"] = 0, None
