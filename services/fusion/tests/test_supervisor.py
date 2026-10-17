"""A consumer task that dies must be restarted and must stop reporting ready meanwhile.

Before: ``mark_ready()`` ran right after ``create_task(worker.start())`` and the task was never watched, so a broker outage at boot (or one bad message) killed the consumer
silently while /health kept answering 200.
"""

from __future__ import annotations

import pytest
from app.workers.supervisor import supervise

pytestmark = pytest.mark.asyncio


async def test_a_crashing_consumer_is_restarted_and_readiness_follows():
    events: list[str] = []
    runs = {"n": 0}

    async def start():
        runs["n"] += 1
        events.append(f"start{runs['n']}")
        if runs["n"] < 3:
            raise RuntimeError("broker down")

    async def stop():
        events.append("stop")

    await supervise(start, stop, on_failure=lambda e: events.append(f"fail:{e}"), backoff=0.0)
    assert runs["n"] == 3
    assert events.count("stop") == 2, "the half-started worker is torn down before each retry"
    assert [e for e in events if e.startswith("fail")] == ["fail:broker down", "fail:broker down"]


async def test_a_clean_exit_is_not_restarted():
    runs = {"n": 0}

    async def start():
        runs["n"] += 1

    async def stop():
        raise AssertionError("nothing to tear down after a clean exit")

    await supervise(start, stop, on_failure=lambda e: None, backoff=0.0)
    assert runs["n"] == 1


async def test_cancellation_passes_through():
    import asyncio

    async def start():
        await asyncio.sleep(60)

    async def stop():
        pass

    task = asyncio.create_task(supervise(start, stop, on_failure=lambda e: None, backoff=0.0))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
