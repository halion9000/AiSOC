"""What a domain's website shows: certificate, HTTP-to-HTTPS, headers. The rules are pure; the probe is faked; nothing here touches the network."""

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.api.v1.endpoints import client_posture as cp
from app.services import web_posture as wp

NOW = datetime(2026, 10, 24, tzinfo=UTC)


def probe(**over):
    base = {"answered": True, "cert_not_after": NOW + timedelta(days=200), "http_answered": True, "http_redirect_to": "https://acme.com/", "headers": {}}
    return wp.ProbeResult(**{**base, **over})


def test_certificate_valid_expiring_expired_unverifiable_and_absent():
    assert wp.assess_certificate(probe(), NOW).status == "good"
    soon = wp.assess_certificate(probe(cert_not_after=NOW + timedelta(days=9)), NOW)
    assert soon.status == "needs_work" and "9 days" in soon.summary
    gone = wp.assess_certificate(probe(cert_not_after=NOW - timedelta(days=3)), NOW)
    assert gone.status == "needs_work" and "expired 3 days ago" in gone.summary
    bad = wp.assess_certificate(probe(cert_error="certificate has expired", cert_not_after=None), NOW)
    assert bad.status == "needs_work" and "browser warning" in bad.summary
    assert wp.assess_certificate(probe(cert_not_after=None, http_redirect_to=None), NOW).status == "missing"


def test_a_certificate_30_days_out_still_warns_and_31_does_not():
    assert wp.assess_certificate(probe(cert_not_after=NOW + timedelta(days=30, hours=1)), NOW).status == "needs_work"
    assert wp.assess_certificate(probe(cert_not_after=NOW + timedelta(days=31, hours=1)), NOW).status == "good"


def test_https_redirect_present_missing_and_no_plain_http_at_all():
    assert wp.assess_https_redirect(probe()).status == "good"
    assert wp.assess_https_redirect(probe(http_redirect_to="http://www.acme.com/")).status == "needs_work"
    assert wp.assess_https_redirect(probe(http_redirect_to=None)).status == "needs_work"
    assert wp.assess_https_redirect(probe(http_answered=False, http_redirect_to=None)).status == "good"


def test_headers_all_present_and_each_missing_one_is_named():
    full = {"Strict-Transport-Security": "max-age=31536000", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"}
    assert wp.assess_headers(full).status == "good"
    assert wp.assess_headers({**full, "X-Frame-Options": ""} | {"Content-Security-Policy": "frame-ancestors 'none'"}).status == "good", "CSP frame-ancestors also stops framing"
    f = wp.assess_headers({})
    assert f.status == "needs_work" and len(f.issues) == 3
    assert any("Strict-Transport-Security" in i for i in wp.assess_headers({k: v for k, v in full.items() if k != "Strict-Transport-Security"}).issues)
    assert wp.assess_headers({**full, "X-Content-Type-Options": "sniff"}).status == "needs_work"


def test_a_domain_with_no_website_has_no_web_section():
    assert wp.web_posture(wp.ProbeResult(answered=False), NOW) is None
    out = wp.web_posture(probe(), NOW)
    assert out is not None and out.certificate.status == "good"


def test_the_endpoint_attaches_the_websites_findings_to_each_domain(monkeypatch):
    from tests.test_domain_posture import FakeResolver

    owner = uuid.uuid4()
    monkeypatch.setattr(cp, "acting_as_tenant", lambda db, tid: contextlib.nullcontext())
    monkeypatch.setattr(cp, "get_resolver", lambda: FakeResolver(txt={"acme.com": ["v=spf1 -all"]}, mx={"acme.com": ["mx.acme.com"]}))

    class FakeProbe:
        async def probe(self, domain):
            return probe(cert_not_after=datetime.now(UTC) + timedelta(days=5))

    monkeypatch.setattr(cp, "get_probe", lambda: FakeProbe())

    class DB:
        async def execute(self, statement, params=None):
            rows = ["amy@acme.com"] if "identity" in str(statement) else []
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))

    out = asyncio.run(cp.client_domains(owner, SimpleNamespace(tenant_id=owner, user_id=uuid.uuid4()), DB()))
    web = out.domains[0].web
    assert web is not None and web.certificate.status == "needs_work" and "5 days" in web.certificate.summary
