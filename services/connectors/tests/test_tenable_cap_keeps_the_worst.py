"""Tenable: when more findings come back than the per-poll cap, the cap drops the least severe ones, not an arbitrary tail."""

from __future__ import annotations

import httpx
import pytest
from app.connectors import tenable


@pytest.mark.asyncio
async def test_the_cap_keeps_the_most_severe_findings(monkeypatch):
    items = [{"plugin_id": i, "plugin_name": f"p{i}", "severity": 4 if i == 250 else 1} for i in range(300)]
    monkeypatch.setattr(tenable, "_MAX_ITEMS", 10)
    real = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"vulnerabilities": items})), **kw),
    )
    cls = next(v for v in vars(tenable).values() if isinstance(v, type) and hasattr(v, "fetch_alerts") and v.__module__ == tenable.__name__)
    conn = cls.__new__(cls)
    conn._base, conn._access, conn._secret = "https://t.invalid", "a", "s"
    out = await conn.fetch_alerts()
    assert len(out) == 10
    assert out[0]["severity"] == "critical"  # plugin 250 sat beyond the cap and is now first
