"""CrowdStrike detections beyond the first 100 in a window were silently dropped (``limit: 100`` with no offset, ``ids[:100]``)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from app.connectors.crowdstrike import CrowdStrikeConnector

_BASE = "https://api.crowdstrike.com"


def _connector() -> CrowdStrikeConnector:
    c = CrowdStrikeConnector("id", "secret")
    c._access_token = "tok"  # noqa: SLF001 — skip the OAuth round trip
    return c


@pytest.mark.asyncio
@respx.mock
async def test_every_page_of_detections_is_fetched():
    all_ids = [f"d{i:03d}" for i in range(230)]

    def queries(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params.get("offset", 0))
        limit = int(request.url.params["limit"])
        return httpx.Response(200, json={"resources": all_ids[offset : offset + limit], "meta": {"pagination": {"total": len(all_ids)}}})

    batches: list[int] = []

    def summaries(request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["ids"]
        batches.append(len(ids))
        assert len(ids) <= 100, "the summaries endpoint takes at most 100 ids per call"
        return httpx.Response(200, json={"resources": [{"detection_id": i, "max_severity_displayname": "High"} for i in ids]})

    respx.get(f"{_BASE}/detects/queries/detects/v1").mock(side_effect=queries)
    respx.post(f"{_BASE}/detects/entities/summaries/GET/v1").mock(side_effect=summaries)

    events = await _connector().fetch_alerts(since_seconds=300)
    assert len(events) == 230
    assert sorted(batches) == [30, 100, 100]


@pytest.mark.asyncio
@respx.mock
async def test_a_quiet_window_is_one_query_and_no_summaries_call():
    q = respx.get(f"{_BASE}/detects/queries/detects/v1").mock(return_value=httpx.Response(200, json={"resources": []}))
    s = respx.post(f"{_BASE}/detects/entities/summaries/GET/v1")
    assert await _connector().fetch_alerts(since_seconds=300) == []
    assert q.call_count == 1 and not s.called
