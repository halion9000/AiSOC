"""The enrichment gateway: authenticated, correct against the Go service's real API, honest.

The console's IOC lookup never worked: the service was unreachable from the web container,
it listens on 8082 (the console assumed 8083), GET /lookup?ioc= hit a POST-only endpoint,
and the bulk body {iocs: []} is not the service's {items: []}. And it was unauthenticated.
"""
import json
import uuid

import httpx
import pytest
import respx
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import enrichment
from app.core.security import ROLE_PERMISSIONS
from app.main import app
from route_introspect import required_permissions

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
BASE = "http://enrichment:8082"
SHA256 = "a" * 64

# What the Go service really returns (internal/enricher/types.go EnrichmentResult)
RESULT = {
    "ioc_type": "ip", "value": "8.8.8.8", "risk_score": 82.5, "confidence": 91, "malicious_votes": 12, "harmless_votes": 60,
    "total_engines": 90, "tags": ["scanner", "tor"], "reputation": -5, "threat_category": "malware-c2",
    "classification": {"mitre_techniques": ["T1071"], "mitre_tactics": ["command-and-control"]},
    "geo_location": {"country": "Germany", "asn": 24940, "as_org": "Hetzner"},
    "sources": [{"name": "virustotal", "cached": False}, {"name": "abuseipdb", "cached": True}],
    "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z", "enriched_at": "2026-10-06T00:00:00Z",
}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ENRICHMENT_URL", BASE)
    yield
    app.dependency_overrides.clear()


def _client(role="viewer", scopes=None, anonymous=False) -> TestClient:
    async def fake_db():
        yield None

    app.dependency_overrides[deps.get_db] = fake_db
    if not anonymous:
        app.dependency_overrides[deps.get_current_user] = lambda: CurrentUser(
            user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email="t@example.com", scopes=scopes)
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------- classification ----
@pytest.mark.parametrize("raw,expected", [
    ("8.8.8.8", ("ip", "8.8.8.8")), ("  1.2.3.4  ", ("ip", "1.2.3.4")), ("2001:db8::1", ("ip", "2001:db8::1")),
    ("example.com", ("domain", "example.com")), ("Sub.Example.CO.UK", ("domain", "sub.example.co.uk")),
    ("https://evil.example/path?x=1", ("url", "https://evil.example/path?x=1")),
    ("alice@example.com", ("email", "alice@example.com")),
    ("d41d8cd98f00b204e9800998ecf8427e", ("hash", "d41d8cd98f00b204e9800998ecf8427e")),
    ("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", ("hash", "da39a3ee5e6b4b0d3255bfef95601890afd80709")),
    (SHA256, ("hash", SHA256)),
])
def test_classify_recognises_each_indicator_type(raw, expected):
    assert enrichment.classify_ioc(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "example", "not an ioc", "a" * 33, "g" * 32, "999.1.1.1", "foo@bar", "x" * 3000, "-bad-.com", "has space.com"])
def test_classify_refuses_what_it_cannot_identify(raw):
    assert enrichment.classify_ioc(raw) is None


def test_an_ip_is_not_mistaken_for_a_domain():
    assert enrichment.classify_ioc("10.0.0.1")[0] == "ip"


# ------------------------------------------------------------------------- lookup ----
@respx.mock
def test_lookup_sends_the_service_exactly_what_its_handler_accepts():
    route = respx.post(f"{BASE}/enrich").mock(return_value=httpx.Response(200, json=RESULT))
    r = _client().get("/api/v1/enrichment/lookup", params={"ioc": " 8.8.8.8 "})
    assert r.status_code == 200, r.text
    sent = route.calls[0].request
    assert sent.method == "POST"
    assert json.loads(sent.content) == {"ioc_type": "ip", "value": "8.8.8.8", "force": False}


@respx.mock
def test_the_callers_credentials_are_never_forwarded_to_the_enrichment_service():
    route = respx.post(f"{BASE}/enrich").mock(return_value=httpx.Response(200, json=RESULT))
    _client().get("/api/v1/enrichment/lookup", params={"ioc": "8.8.8.8"}, headers={"Authorization": "Bearer secret-user-token", "Cookie": "s=1"})
    assert "authorization" not in route.calls[0].request.headers
    assert "cookie" not in route.calls[0].request.headers


@respx.mock
def test_lookup_maps_the_result_to_the_consoles_indicator_shape():
    respx.post(f"{BASE}/enrich").mock(return_value=httpx.Response(200, json=RESULT))
    d = _client().get("/api/v1/enrichment/lookup", params={"ioc": "8.8.8.8"}).json()
    assert (d["id"], d["type"], d["value"]) == ("ip:8.8.8.8", "ip", "8.8.8.8")
    assert (d["severity"], d["malicious"], d["confidence"]) == ("critical", True, 91)
    assert d["tags"] == ["scanner", "tor"] and d["sources"] == ["virustotal", "abuseipdb"]
    assert (d["country"], d["asn"], d["mitre"], d["description"]) == ("Germany", "AS24940", ["T1071"], "malware-c2")
    assert (d["firstSeen"], d["lastSeen"]) == ("2026-01-01T00:00:00Z", "2026-10-01T00:00:00Z")
    assert d["raw"]["malicious_votes"] == 12, "the provider's own data is kept for power users"


@pytest.mark.parametrize("score,severity,malicious", [
    (0, "info", False), (19.9, "info", False), (20, "low", False), (39.9, "low", False), (40, "medium", False),
    (59.9, "medium", False), (60, "high", True), (79.9, "high", True), (80, "critical", True), (100, "critical", True),
])
def test_severity_bands_and_the_malicious_line(score, severity, malicious):
    out = enrichment.to_indicator({**RESULT, "risk_score": score})
    assert (out.severity, out.malicious) == (severity, malicious)


@pytest.mark.parametrize("confidence,expected", [(150, 100), (-5, 0), (0, 0), (55.5, 55.5)])
def test_confidence_is_clamped_to_0_100(confidence, expected):
    assert enrichment.to_indicator({**RESULT, "confidence": confidence}).confidence == expected


def test_a_sparse_result_does_not_crash_or_invent_fields():
    out = enrichment.to_indicator({"ioc_type": "domain", "value": "x.example", "sources": []})
    assert (out.country, out.asn, out.mitre, out.sources, out.severity, out.malicious) == (None, None, [], [], "info", False)


# ---------------------------------------------------------------- honest failures ----
@respx.mock
@pytest.mark.parametrize("failure", [httpx.ConnectError("down"), httpx.Response(500, json={"error": "boom"}), httpx.Response(200, text="not json"), httpx.Response(200, json=["a list"])])
def test_upstream_trouble_is_a_502_never_made_up_data(failure):
    if isinstance(failure, Exception):
        respx.post(f"{BASE}/enrich").mock(side_effect=failure)
    else:
        respx.post(f"{BASE}/enrich").mock(return_value=failure)
    assert _client().get("/api/v1/enrichment/lookup", params={"ioc": "8.8.8.8"}).status_code == 502


@respx.mock
def test_an_unconfigured_service_is_a_503(monkeypatch):
    monkeypatch.delenv("ENRICHMENT_URL")
    route = respx.post(f"{BASE}/enrich").mock(return_value=httpx.Response(200, json=RESULT))
    assert _client().get("/api/v1/enrichment/lookup", params={"ioc": "8.8.8.8"}).status_code == 503
    assert not route.called


@respx.mock
def test_junk_is_refused_before_the_service_is_called():
    route = respx.post(f"{BASE}/enrich").mock(return_value=httpx.Response(200, json=RESULT))
    c = _client()
    assert c.get("/api/v1/enrichment/lookup", params={"ioc": "not an ioc"}).status_code == 422
    assert c.get("/api/v1/enrichment/lookup").status_code == 422
    assert c.get("/api/v1/enrichment/lookup", params={"ioc": "x" * 3000}).status_code == 422
    assert not route.called


# ---------------------------------------------------------------------------- bulk ----
@respx.mock
def test_bulk_translates_iocs_into_the_services_items_and_skips_junk():
    route = respx.post(f"{BASE}/enrich/bulk").mock(return_value=httpx.Response(200, json={"results": [RESULT], "total": 1, "errors": 0}))
    r = _client().post("/api/v1/enrichment/bulk", json={"iocs": ["8.8.8.8", "not an ioc", SHA256.upper()]})
    assert r.status_code == 200, r.text
    assert json.loads(route.calls[0].request.content) == {"items": [
        {"ioc_type": "ip", "value": "8.8.8.8", "force": False}, {"ioc_type": "hash", "value": SHA256, "force": False}]}
    body = r.json()
    assert len(body["results"]) == 1 and body["results"][0]["id"] == "ip:8.8.8.8"
    assert body["errors"] == [{"ioc": "not an ioc", "error": "Not a recognisable IP, domain, URL, hash or email"}]


@respx.mock
def test_bulk_with_nothing_recognisable_never_calls_the_service():
    route = respx.post(f"{BASE}/enrich/bulk").mock(return_value=httpx.Response(200, json={"results": []}))
    r = _client().post("/api/v1/enrichment/bulk", json={"iocs": ["nope", "also nope"]})
    assert r.status_code == 200 and r.json()["results"] == [] and len(r.json()["errors"]) == 2
    assert not route.called


@respx.mock
def test_bulk_size_limits():
    respx.post(f"{BASE}/enrich/bulk").mock(return_value=httpx.Response(200, json={"results": []}))
    c = _client()
    assert c.post("/api/v1/enrichment/bulk", json={"iocs": []}).status_code == 422
    assert c.post("/api/v1/enrichment/bulk", json={"iocs": ["1.1.1.1"] * 101}).status_code == 422
    assert c.post("/api/v1/enrichment/bulk", json={"iocs": ["1.1.1.1"] * 100}).status_code == 200


@respx.mock
def test_bulk_credentials_are_not_forwarded_either():
    route = respx.post(f"{BASE}/enrich/bulk").mock(return_value=httpx.Response(200, json={"results": []}))
    _client().post("/api/v1/enrichment/bulk", json={"iocs": ["1.1.1.1"]}, headers={"Authorization": "Bearer secret"})
    assert "authorization" not in route.calls[0].request.headers


# -------------------------------------------------------------------- permissions ----
def test_both_routes_require_threat_intel_read():
    routes = [r for r in enrichment.router.routes if isinstance(r, APIRoute)]
    assert len(routes) == 2
    assert all(required_permissions(r) == ["threat_intel:read"] for r in routes)


@respx.mock
@pytest.mark.parametrize("role", [r for r, perms in ROLE_PERMISSIONS.items() if "threat_intel:read" in perms or "*" in perms])
def test_every_role_that_may_read_threat_intel_can_look_up(role):
    respx.post(f"{BASE}/enrich").mock(return_value=httpx.Response(200, json=RESULT))
    assert _client(role).get("/api/v1/enrichment/lookup", params={"ioc": "8.8.8.8"}).status_code == 200


@respx.mock
def test_an_api_key_without_the_scope_is_refused_and_the_service_is_not_called():
    route = respx.post(f"{BASE}/enrich").mock(return_value=httpx.Response(200, json=RESULT))
    assert _client("admin", scopes=["alerts:read"]).get("/api/v1/enrichment/lookup", params={"ioc": "8.8.8.8"}).status_code == 403
    assert _client("admin", scopes=["alerts:read"]).post("/api/v1/enrichment/bulk", json={"iocs": ["8.8.8.8"]}).status_code == 403
    assert not route.called
    assert _client("admin", scopes=["threat_intel:read"]).get("/api/v1/enrichment/lookup", params={"ioc": "8.8.8.8"}).status_code != 403


@respx.mock
def test_anonymous_callers_in_production_never_reach_the_service(monkeypatch):
    monkeypatch.setattr(deps, "is_dev_mode", lambda: False)
    route = respx.post(f"{BASE}/enrich").mock(return_value=httpx.Response(200, json=RESULT))
    c = _client(anonymous=True)
    assert c.get("/api/v1/enrichment/lookup", params={"ioc": "8.8.8.8"}).status_code == 401
    assert c.post("/api/v1/enrichment/bulk", json={"iocs": ["8.8.8.8"]}).status_code == 401
    assert not route.called
