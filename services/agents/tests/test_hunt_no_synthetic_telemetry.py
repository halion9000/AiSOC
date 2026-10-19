"""Hunting never runs against, or reports, invented telemetry unless the benchmark dataset is asked for by name.

Two defects, both fabricating security data:
  1. POST /api/v1/hunt/search called _synthetic_hits() UNCONDITIONALLY. It queried no event store; every hunt, for any query, returned invented events: a `cmd.exe /c <your query>` process
     on "WS-DEV-01", a sign-in for user@corp.example, an AWS AssumeRole on an Admin role. A hunter could not tell them from real telemetry. It now answers 501: no event store is connected.
  2. The hunt scheduler's telemetry provider DEFAULTED to "synthetic", the benchmark dataset in tests/eval_data, so in any checkout containing that folder scheduled hunts recorded findings from
     benchmark data as if they were the tenant's. The default is now "ingest" (the live path, not wired yet: an empty stream, an empty run). "synthetic" must be requested explicitly.
"""

import importlib

import pytest
from app.hunt import scheduler
from fastapi.testclient import TestClient


class TestHuntSearchIsNotHere:
    """Hunt search lives in the core API (it searches the tenant's own alerts). This service used to carry a second route that answered 501 and that nothing called; it, and the invented
    events it once returned for every query, are gone, so nothing here can hand a hunter fabricated telemetry again."""

    def test_the_module_that_held_the_route_and_the_fake_events_is_gone(self):
        with pytest.raises(ImportError):
            importlib.import_module("app.api.hunt_search")

    def test_the_agents_service_does_not_serve_hunt_search_or_saved_searches(self):
        from app.main import app

        client = TestClient(app)
        assert client.post("/api/v1/hunt/search", json={"query": "powershell -enc"}).status_code in (404, 405)
        assert client.get("/api/v1/hunt/saved").status_code in (404, 405)


class TestSchedulerTelemetry:
    def test_by_default_there_is_no_telemetry_and_so_no_findings(self, monkeypatch):
        monkeypatch.delenv("HUNT_TELEMETRY_PROVIDER", raising=False)
        assert scheduler._load_telemetry() == []

    def test_the_live_provider_is_an_empty_stream_until_it_is_wired(self, monkeypatch):
        monkeypatch.setenv("HUNT_TELEMETRY_PROVIDER", "ingest")
        assert scheduler._load_telemetry() == []

    def test_an_unknown_provider_is_empty_not_synthetic(self, monkeypatch):
        monkeypatch.setenv("HUNT_TELEMETRY_PROVIDER", "somethingelse")
        assert scheduler._load_telemetry() == []

    def test_the_benchmark_dataset_is_used_only_when_asked_for_by_name(self, monkeypatch):
        if scheduler._resolve_synthetic_path() is None:
            pytest.skip("the benchmark dataset is not present in this checkout")
        monkeypatch.setenv("HUNT_TELEMETRY_PROVIDER", "synthetic")
        events = scheduler._load_telemetry()
        assert len(events) > 0
        monkeypatch.setenv("HUNT_TELEMETRY_PROVIDER", " Synthetic ")  # case and spaces are tolerated, as before
        assert len(scheduler._load_telemetry()) == len(events)

    def test_a_default_scheduler_run_scans_nothing(self, monkeypatch):
        monkeypatch.delenv("HUNT_TELEMETRY_PROVIDER", raising=False)
        from app.hunt.engine import HuntEngine

        corpus = scheduler.get_scheduler()._corpus
        corpus.reload()
        hunts = list(corpus.list())
        assert hunts, "the hunt corpus loaded no hunts, so this test would prove nothing"
        events = scheduler._load_telemetry()
        for hunt in hunts[:5]:
            result = HuntEngine().run(hunt, events)
            assert result.events_scanned == 0
            assert len(result.findings) == 0
