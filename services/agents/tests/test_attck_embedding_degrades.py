"""ATT&CK embedding: configurable model, and one warning (not one per batch) when the model is unavailable."""

from __future__ import annotations

import pytest
from app.tools import mitre_full


def test_model_comes_from_the_environment(monkeypatch):
    monkeypatch.delenv("AISOC_EMBEDDING_MODEL", raising=False)
    assert mitre_full.embedding_model() == "text-embedding-3-large"
    monkeypatch.setenv("AISOC_EMBEDDING_MODEL", "bge-m3")
    assert mitre_full.embedding_model() == "bge-m3"
    assert mitre_full._embed_kwargs("bge-m3") == {}
    for off in ("", "off", "OFF", "none"):
        monkeypatch.setenv("AISOC_EMBEDDING_MODEL", off)
        assert mitre_full.embedding_model() == ""


@pytest.mark.asyncio
async def test_disabled_embedding_touches_nothing(monkeypatch):
    monkeypatch.setenv("AISOC_EMBEDDING_MODEL", "off")
    assert await mitre_full.embed_techniques_into_qdrant("http://qdrant.invalid:6333", "k") is None
    assert await mitre_full.semantic_technique_search("phishing", "http://qdrant.invalid:6333", "k") == []
