"""Hunting never runs against, or reports, invented telemetry unless the benchmark dataset is asked for by name.

Two defects, both fabricating security data:
  1. POST /api/v1/hunt/search called _synthetic_hits() UNCONDITIONALLY. It queried no event store; every hunt, for any query, returned invented events: a `cmd.exe /c <your query>` process
     on "WS-DEV-01", a sign-in for user@corp.example, an AWS AssumeRole on an Admin role. A hunter could not tell them from real telemetry. It now answers 501: no event store is connected.
  2. The hunt scheduler's telemetry provider DEFAULTED to "synthetic", the benchmark dataset in tests/eval_data, so in any checkout containing that folder scheduled hunts recorded findings from
     benchmark data as if they were the tenant's. The default is now "ingest" (the live path, not wired yet: an empty stream, an empty run). "synthetic" must be requested explicitly.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import hunt_search
from app.hunt import scheduler

INVENTED = ["WS-DEV-01", "corp.example", "192.0.2.42", "AssumeRole", "arn:aws:iam::123456789:role/Admin", "DOMAIN\\\\analyst", "explorer.exe"]


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(hunt_search.router)
    yield TestClient(app)


class TestHuntSearch:
    @pytest.mark.parametrize("query", ["powershell -enc", "process.name: cmd.exe", "*", "user:admin AND src_ip:10.0.0.5"])
    def test_it_says_no_event_store_is_connected_for_any_query(self, client, query):
        response = client.post("/api/v1/hunt/search", json={"query": query, "language": "lucene"})
        assert response.status_code == 501
        assert "not connected to an event store" in response.json()["detail"]
        for value in INVENTED:
            assert value not in response.text, f"invented telemetry is back: {value}"
        assert "hits" not in response.json()

    def test_the_query_is_not_echoed_back_into_fake_events(self, client):
        response = client.post("/api/v1/hunt/search", json={"query": "UNIQUE-MARKER-12345"})
        assert response.status_code == 501
        assert "UNIQUE-MARKER-12345" not in response.text  # it used to appear as `cmd.exe /c UNIQUE-MARKER-12345` and as a highlight

    def test_the_synthetic_generator_no_longer_exists(self):
        assert not hasattr(hunt_search, "_synthetic_hits")

    def test_the_agents_service_no_longer_serves_saved_searches(self, client):
        """They were one in-memory dict here: lost on restart and returned to EVERY tenant. They live in the core API (tenant-scoped, persisted); the web rewrite sends /api/v1/hunt/saved* there."""
        assert not hasattr(hunt_search, "_SAVED_SEARCHES")
        assert client.get("/api/v1/hunt/saved").status_code in (404, 405)
        assert client.post("/api/v1/hunt/saved", json={"name": "n", "query": "q", "language": "lucene"}).status_code in (404, 405)
        assert client.delete("/api/v1/hunt/saved/1").status_code in (404, 405)


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
