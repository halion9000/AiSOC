"""When the fusion service is unreachable the entity-risk endpoints answer with the same promotion threshold fusion itself uses (80)."""

import asyncio
import uuid
from types import SimpleNamespace

from app.api.v1.endpoints import fusion as ep


def _no_upstream(monkeypatch):
    async def none(*_a, **_k):
        return None

    monkeypatch.setattr(ep, "_proxy_get", none)
    monkeypatch.setattr(ep, "_effective_tenant", lambda _tenant, _user: str(uuid.uuid4()))


def test_queue_fallback_threshold_matches_fusions_default(monkeypatch):
    _no_upstream(monkeypatch)
    out = asyncio.run(ep.entity_risk_queue(SimpleNamespace(), None, 25, False))
    assert out["entities"] == [] and out["threshold"] == 80.0


def test_stats_fallback_threshold_matches_fusions_default(monkeypatch):
    _no_upstream(monkeypatch)
    out = asyncio.run(ep.entity_risk_stats(SimpleNamespace(), None))
    assert out["threshold"] == 80.0
