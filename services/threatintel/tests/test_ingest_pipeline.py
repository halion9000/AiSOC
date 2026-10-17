"""Threat-intel ingestion: an IOC is only 'seen' once it is really stored, and feeds poll at startup.

Before: each IOC went into the Bloom filter BEFORE the OpenSearch write, so a failed bulk index left them marked as seen and they were never retried. The Bloom key ignored the
source, so a second feed's copy of an IOC was dropped. And the scheduler's first run was a full day after start (a restart reset the timer), so the IOC index stayed empty.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from app.feeds.pipeline import ThreatIntelPipeline
from app.feeds.scheduler import FeedScheduler


class _Bloom:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    async def contains(self, key: str) -> bool:
        return key in self.seen

    async def add(self, key: str) -> None:
        self.seen.add(key)


class _Sink:
    def __init__(self, indexed: int | None = None) -> None:
        self.indexed = indexed
        self.batches: list[list[dict[str, Any]]] = []

    async def bulk_index_iocs(self, iocs):
        self.batches.append(list(iocs))
        return len(iocs) if self.indexed is None else self.indexed

    async def upsert_iocs(self, iocs):
        return None


def _pipeline(os_sink: _Sink, bloom: _Bloom) -> ThreatIntelPipeline:
    return ThreatIntelPipeline(bloom=bloom, os_store=os_sink, qdrant_store=_Sink(), neo4j_store=_Sink())  # type: ignore[arg-type]


def _ioc(value: str = "1.2.3.4", source: str = "otx") -> dict[str, Any]:
    return {"type": "ip", "value": value, "source": source}


@pytest.mark.asyncio
async def test_iocs_whose_index_write_failed_are_retried_not_marked_seen():
    bloom, sink = _Bloom(), _Sink(indexed=0)
    pipeline = _pipeline(sink, bloom)
    first = await pipeline.ingest_iocs([_ioc()], source="otx")
    assert first["new"] == 1 and bloom.seen == set(), "a failed write must not mark the IOC as seen"
    sink.indexed = None  # OpenSearch recovers
    second = await pipeline.ingest_iocs([_ioc()], source="otx")
    assert second["new"] == 1 and second["duplicate"] == 0
    assert len(bloom.seen) == 1
    third = await pipeline.ingest_iocs([_ioc()], source="otx")
    assert third["new"] == 0 and third["duplicate"] == 1


@pytest.mark.asyncio
async def test_the_same_ioc_from_a_second_feed_is_not_dropped():
    bloom, sink = _Bloom(), _Sink()
    pipeline = _pipeline(sink, bloom)
    await pipeline.ingest_iocs([_ioc(source="otx")], source="otx")
    again = await pipeline.ingest_iocs([_ioc(source="misp")], source="misp")
    assert again["new"] == 1, "a different source is a different record (its OpenSearch id includes the source)"


@pytest.mark.asyncio
async def test_a_repeat_inside_one_batch_is_stored_once():
    bloom, sink = _Bloom(), _Sink()
    result = await _pipeline(sink, bloom).ingest_iocs([_ioc(), _ioc()], source="otx")
    assert result["new"] == 1 and result["duplicate"] == 1
    assert len(sink.batches[0]) == 1


@pytest.mark.asyncio
async def test_feeds_poll_at_startup_not_a_day_later():
    ran = asyncio.Event()

    async def handler() -> None:
        ran.set()

    scheduler = FeedScheduler(pipeline=None)  # type: ignore[arg-type]
    scheduler.register("demo", handler, interval_seconds=86400)
    scheduler.start()
    try:
        await asyncio.wait_for(ran.wait(), timeout=5)
    finally:
        scheduler.stop()
