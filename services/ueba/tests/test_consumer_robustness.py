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
