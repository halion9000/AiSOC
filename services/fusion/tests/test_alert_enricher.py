"""Wave 1 — fuse-time enrichment maps enrichment-service results into the
schema the confidence scorer + vuln boost read, and stays honest (no TI without
a real match) and fail-soft."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from app.models.alert import RawAlert
from app.services.alert_enricher import AlertEnricher
from app.services.confidence import _ti_contribution


class _FakeResp:
    def __init__(self, status: int, payload: dict[str, Any]) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def _fake_client_factory(resp=None, *, error: Exception | None = None):
    class _FakeClient:
        def __init__(self, *a, **k) -> None:
            self.captured: dict[str, Any] = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None):
            if error is not None:
                raise error
            _fake_client_factory.last = {"url": url, "json": json}
            return resp

    return _FakeClient


def _alert(**kw) -> RawAlert:
    base = {"tenant_id": uuid4(), "source": "detection", "title": "t"}
    base.update(kw)
    return RawAlert(**base)


def _enricher() -> AlertEnricher:
    return AlertEnricher(base_url="http://enrich.test:8082", timeout_seconds=1.0, malicious_risk_floor=50.0)


def test_extract_iocs_deduplicates_and_types():
    alert = _alert(src_ip="1.2.3.4", dst_ip="1.2.3.4", domain="evil.test", file_hash="abcd")
    items = AlertEnricher.extract_iocs(alert)
    # src_ip and dst_ip are the same value -> one ip entry.
    assert {"ioc_type": "ip", "value": "1.2.3.4"} in items
    assert {"ioc_type": "domain", "value": "evil.test"} in items
    assert {"ioc_type": "hash", "value": "abcd"} in items
    assert sum(1 for i in items if i["value"] == "1.2.3.4") == 1


def test_to_enrichments_malicious_result_produces_ti_hit_and_fires_scorer():
    results = [
        {
            "value": "45.9.148.99",
            "risk_score": 88.0,
            "malicious_votes": 7,
            "sources": [{"name": "VirusTotal"}, {"name": "OTX"}],
            "classification": {"threat_actors": ["FIN7"]},
            "vulnerabilities": [{"cve": "CVE-2024-1234", "kev": True, "cvss": 9.8, "exploited": True}],
        }
    ]
    enr = _enricher().to_enrichments(results)
    # Source-keyed hits the confidence scorer reads.
    assert enr["virustotal"]["hit"] is True
    assert "45.9.148.99" in enr["virustotal"]["matches"]
    assert enr["otx"]["hit"] is True
    assert enr["kev"]["matches"] == ["CVE-2024-1234"]
    # vuln_boost schema.
    assert enr["vulnerabilities"][0]["cve_id"] == "CVE-2024-1234"
    assert enr["vulnerabilities"][0]["is_exploited"] is True
    # threat_intel summary for the rail.
    assert enr["threat_intel"]["threat_actors"] == ["FIN7"]
    # The confidence TI factor now fires positive (was -0.3 "no TI match").
    contrib, _ = _ti_contribution(enr)
    assert contrib > 0


def test_to_enrichments_benign_result_is_empty_no_fake_ti():
    results = [{"value": "10.0.0.1", "risk_score": 2.0, "malicious_votes": 0, "sources": [{"name": "GreyNoise"}]}]
    enr = _enricher().to_enrichments(results)
    # No malicious signal -> no source-hit keys -> scorer keeps its honest prior.
    assert "virustotal" not in enr
    assert _ti_contribution(enr)[0] < 0


@pytest.mark.asyncio
async def test_enrich_calls_bulk_endpoint(monkeypatch):
    resp = _FakeResp(
        200,
        {"results": [{"value": "1.2.3.4", "risk_score": 90, "malicious_votes": 3, "sources": [{"name": "VirusTotal"}]}]},
    )
    monkeypatch.setattr("app.services.alert_enricher.httpx.AsyncClient", _fake_client_factory(resp))
    enr = await _enricher().enrich(_alert(src_ip="1.2.3.4"))
    assert _fake_client_factory.last["url"].endswith("/enrich/bulk")
    assert enr["virustotal"]["hit"] is True


@pytest.mark.asyncio
async def test_enrich_is_fail_soft_on_error(monkeypatch):
    monkeypatch.setattr("app.services.alert_enricher.httpx.AsyncClient", _fake_client_factory(error=RuntimeError("boom")))
    assert await _enricher().enrich(_alert(src_ip="1.2.3.4")) == {}


@pytest.mark.asyncio
async def test_enrich_no_iocs_short_circuits():
    assert await _enricher().enrich(_alert()) == {}


def test_private_and_loopback_ips_are_never_sent_to_the_enrichment_service():
    """Internal addresses went out to third-party TI providers (and can never be in a feed anyway)."""
    alert = _alert(src_ip="10.1.2.3", dst_ip="8.8.8.8", domain="evil.test")
    values = {i["value"] for i in AlertEnricher.extract_iocs(alert)}
    assert values == {"8.8.8.8", "evil.test"}
    for private in ("192.168.0.9", "172.16.5.5", "127.0.0.1", "169.254.1.1", "::1", "fd00::1"):
        assert AlertEnricher.extract_iocs(_alert(src_ip=private)) == []


@pytest.mark.asyncio
async def test_enrich_authenticates_to_the_service(monkeypatch):
    """The enrichment service requires a bearer token and the enricher sent none: every call was a silent 401, so no alert ever got threat-intel."""
    seen: dict[str, Any] = {}
    ok = _FakeResp(200, {"results": []})

    class _Client:
        def __init__(self, *a, **k) -> None:
            seen["client_kwargs"] = k

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None):
            return ok

    monkeypatch.setattr("app.services.alert_enricher.httpx.AsyncClient", _Client)
    enricher = AlertEnricher(base_url="http://enrich.test:8082", timeout_seconds=1.0, malicious_risk_floor=50.0, token="s3cret")
    await enricher.enrich(_alert(src_ip="8.8.8.8"))
    assert seen["client_kwargs"]["headers"] == {"Authorization": "Bearer s3cret"}


@pytest.mark.asyncio
async def test_enrich_failures_are_logged_above_debug(monkeypatch, caplog):
    """Both failure modes (unreachable URL, 401) were logged at DEBUG, so they were invisible."""
    import structlog.testing

    monkeypatch.setattr("app.services.alert_enricher.httpx.AsyncClient", _fake_client_factory(error=RuntimeError("boom")))
    with structlog.testing.capture_logs() as logs:
        assert await _enricher().enrich(_alert(src_ip="8.8.8.8")) == {}
    assert any(entry["event"] == "fuse_enrichment.failed" and entry["log_level"] in ("warning", "error") for entry in logs)
