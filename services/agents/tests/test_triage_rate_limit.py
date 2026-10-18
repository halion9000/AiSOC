"""POST /cases/{id}/triage is limited per tenant, because each run is an LLM conversation."""

from __future__ import annotations

import pytest
from app.api import triage
from fastapi import BackgroundTasks, HTTPException
from starlette.requests import Request


def _req() -> Request:
    return Request({"type": "http", "headers": [], "method": "POST", "path": "/"})


@pytest.mark.asyncio
async def test_a_tenant_over_its_burst_gets_429_and_another_tenant_does_not(monkeypatch):
    monkeypatch.setenv("AISOC_TRIAGE_PER_MINUTE", "1")
    monkeypatch.setenv("AISOC_TRIAGE_BURST", "2")
    triage._reset_triage_limiter()
    monkeypatch.setattr(triage, "authenticated_tenant", lambda request: None)

    async def launch(tenant):
        return await triage.launch_triage("case-1", triage.TriageRequest(tenant_id=tenant, alert_summary="x"), BackgroundTasks(), _req())

    await launch("acme")
    await launch("acme")
    with pytest.raises(HTTPException) as exc:
        await launch("acme")
    assert exc.value.status_code == 429 and "Retry-After" in exc.value.headers
    await launch("globex")  # a different tenant has its own bucket
    triage._reset_triage_limiter()


def test_zero_turns_the_limit_off(monkeypatch):
    monkeypatch.setenv("AISOC_TRIAGE_PER_MINUTE", "0")
    triage._reset_triage_limiter()
    assert triage._get_triage_limiter() is None
