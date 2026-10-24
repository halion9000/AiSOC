"""E-mail and DNS posture of a client's domains: the assessments are pure, the resolver is faked, the endpoint is called with a stub database."""

import asyncio
import contextlib
import uuid
from types import SimpleNamespace

import httpx

from app.api.v1.endpoints import client_posture as cp
from app.services import domain_posture as dp


def test_candidate_domains_are_the_clients_own_most_used_first_and_not_providers():
    emails = ["a@acme.com", "b@acme.com", "c@acme.net", "x@gmail.com", "y@acme.onmicrosoft.com", "bad", "", "d@Acme.com"]
    assert dp.candidate_domains(emails) == ["acme.com", "acme.net"]
    assert len(dp.candidate_domains([f"u@d{i}.com" for i in range(9)])) == dp.MAX_DOMAINS


def test_spf_missing_good_soft_weak_and_broken():
    assert dp.assess_spf([]).status == "missing"
    assert dp.assess_spf(["v=spf1 include:spf.protection.outlook.com -all"]).status == "good"
    soft = dp.assess_spf(["v=spf1 include:spf.protection.outlook.com ~all"])
    assert soft.status == "good" and "soft fail" in soft.summary
    assert dp.assess_spf(["v=spf1 include:x.com +all"]).status == "needs_work"
    assert dp.assess_spf(["v=spf1 include:x.com ?all"]).status == "needs_work"
    assert dp.assess_spf(["v=spf1 include:x.com"]).status == "needs_work"
    assert dp.assess_spf(["v=spf1 -all", "v=spf1 ~all"]).issues == ["multiple SPF records"]
    many = "v=spf1 " + " ".join(f"include:s{i}.com" for i in range(11)) + " -all"
    assert "11 DNS lookups" in dp.assess_spf([many]).summary
    assert dp.assess_spf(["google-site-verification=abc"]).status == "missing", "other TXT records are not SPF"


def test_dmarc_missing_monitoring_partial_and_enforcing():
    assert dp.assess_dmarc([]).status == "missing"
    none = dp.assess_dmarc(["v=DMARC1; p=none; rua=mailto:r@x.com"])
    assert none.status == "needs_work" and "monitoring only" in none.summary
    assert dp.assess_dmarc(["v=DMARC1; p=reject; pct=50; rua=mailto:r@x.com"]).status == "needs_work"
    assert dp.assess_dmarc(["v=DMARC1; p=reject"]).status == "needs_work", "no report address"
    assert dp.assess_dmarc(["v=DMARC1; p=quarantine; rua=mailto:r@x.com"]).status == "good"
    assert dp.assess_dmarc(["v=DMARC1; rua=mailto:r@x.com"]).status == "needs_work", "no policy"


class FakeResolver:
    def __init__(self, txt=None, cname=None, mx=None):
        self.t, self.c, self.m = txt or {}, cname or {}, mx or {}

    async def txt(self, name):
        return self.t.get(name, [])

    async def cname(self, name):
        return self.c.get(name, [])

    async def mx(self, name):
        return self.m.get(name, [])


def test_a_domain_with_everything_is_good_and_names_its_mail_provider():
    r = FakeResolver(
        txt={"acme.com": ["v=spf1 include:spf.protection.outlook.com -all"], "_dmarc.acme.com": ["v=DMARC1; p=reject; rua=mailto:r@acme.com"]},
        cname={"selector1._domainkey.acme.com": ["selector1-acme-com._domainkey.acme.onmicrosoft.com"]},
        mx={"acme.com": ["acme-com.mail.protection.outlook.com"]},
    )
    out = asyncio.run(dp.check_domain("acme.com", r))
    assert (out.status, out.mail_provider, out.dkim.status) == ("good", "Microsoft 365", "good")
    assert "selector1" in out.dkim.summary


def test_a_domain_with_mail_and_no_spf_or_dmarc_is_missing_and_one_with_only_spf_needs_work():
    mx = {"a.com": ["mx.a.com"], "b.com": ["mx.b.com"]}
    bad = asyncio.run(dp.check_domain("a.com", FakeResolver(mx=mx)))
    assert (bad.status, bad.spf.status, bad.dmarc.status) == ("missing", "missing", "missing")
    half = asyncio.run(dp.check_domain("b.com", FakeResolver(txt={"b.com": ["v=spf1 -all"]}, mx=mx)))
    assert half.status == "needs_work"


def test_missing_dkim_never_fails_a_domain():
    r = FakeResolver(txt={"a.com": ["v=spf1 -all"], "_dmarc.a.com": ["v=DMARC1; p=reject; rua=mailto:r@a.com"]}, mx={"a.com": ["mx.a.com"]})
    out = asyncio.run(dp.check_domain("a.com", r))
    assert (out.status, out.dkim.status) == ("good", "missing")


def test_doh_resolver_joins_split_txt_strings_and_reads_failures_as_no_records():
    def handler(request: httpx.Request) -> httpx.Response:
        name, rtype = request.url.params["name"], request.url.params["type"]
        if name == "broken.com":
            return httpx.Response(500)
        if rtype == "TXT":
            return httpx.Response(200, json={"Answer": [{"data": '"v=spf1 include:a.com " "-all"'}]})
        if rtype == "MX":
            return httpx.Response(200, json={"Answer": [{"data": "10 Mail.A.com."}]})
        return httpx.Response(200, json={})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            r = dp.DohResolver(c)
            return await r.txt("a.com"), await r.mx("a.com"), await r.cname("a.com"), await r.txt("broken.com"), await r.txt("not a domain")

    txt, mx, cname, broken, junk = asyncio.run(run())
    assert txt == ["v=spf1 include:a.com -all"]
    assert mx == ["mail.a.com"]
    assert (cname, broken, junk) == ([], [], [])


def test_the_endpoint_looks_up_the_domains_of_the_clients_people(monkeypatch):
    owner = uuid.uuid4()
    monkeypatch.setattr(cp, "acting_as_tenant", lambda db, tid: contextlib.nullcontext())
    monkeypatch.setattr(cp, "get_resolver", lambda: FakeResolver(txt={"acme.com": ["v=spf1 -all"]}, mx={"acme.com": ["mx.acme.com"]}))
    monkeypatch.setattr(cp, "get_probe", lambda: type("P", (), {"probe": staticmethod(lambda d: _no_site())})())

    class DB:
        async def execute(self, statement, params=None):
            text = str(statement)
            rows = ["amy@acme.com", "bo@acme.com", "z@gmail.com"] if "identity_sources" in text or "identity_mfa_users" in text else []
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))

    out = asyncio.run(cp.client_domains(owner, SimpleNamespace(tenant_id=owner, user_id=uuid.uuid4()), DB()))
    assert [d.domain for d in out.domains] == ["acme.com"], "the same domain from both lists is looked up once"
    assert out.domains[0].spf.status == "good"


async def _no_site():
    from app.services.web_posture import ProbeResult

    return ProbeResult(answered=False)
