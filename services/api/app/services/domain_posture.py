"""E-mail and DNS posture of a client's domains: SPF, DMARC, DKIM, MX. Read-only and from public DNS only.

A client's domains are not typed in anywhere; they are the domains of the people A.C.O.R.N already holds for it (``candidate_domains``). The assessments are pure functions of the DNS records
(``assess_spf`` / ``assess_dmarc`` / ``assess_dkim``), so every rule is testable without a network. ``check_domain`` does the lookups through a ``Resolver`` (DNS over HTTPS by default).
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter
from collections.abc import Iterable
from typing import Literal, Protocol

import httpx
from pydantic import BaseModel

Status = Literal["good", "needs_work", "missing"]

# Mail providers and Microsoft's own tenant domains are not a client's domain.
IGNORED_DOMAINS = frozenset(
    {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com", "aol.com", "msn.com", "protonmail.com", "me.com"}
)
MAX_DOMAINS = 5
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# Mechanisms that cost a DNS lookup when a receiver evaluates SPF (RFC 7208: at most 10).
_LOOKUP = re.compile(r"^[+\-~?]?(include:|a(:|/|$)|mx(:|/|$)|ptr(:|$)|exists:|redirect=)", re.I)
DKIM_SELECTORS = ("selector1", "selector2", "google", "default", "k1", "s1", "s2")


def candidate_domains(emails: Iterable[str]) -> list[str]:
    """The domains the client's people use, most used first. Provider and ``*.onmicrosoft.com`` domains are left out; at most MAX_DOMAINS."""
    counts: Counter[str] = Counter()
    for e in emails:
        _, _, dom = (e or "").strip().lower().rpartition("@")
        if _DOMAIN.match(dom) and dom not in IGNORED_DOMAINS and not dom.endswith(".onmicrosoft.com"):
            counts[dom] += 1
    return [d for d, _ in counts.most_common(MAX_DOMAINS)]


class Finding(BaseModel):
    status: Status
    summary: str
    record: str | None = None
    issues: list[str] = []


def assess_spf(txt: list[str]) -> Finding:
    records = [t.strip() for t in txt if t.strip().lower().startswith("v=spf1")]
    if not records:
        return Finding(status="missing", summary="No SPF record: anyone can send mail as this domain without failing SPF.")
    if len(records) > 1:
        return Finding(status="needs_work", summary="More than one SPF record: receivers treat that as an error.", record=records[0], issues=["multiple SPF records"])
    rec = records[0]
    terms = rec.split()[1:]
    issues: list[str] = []
    lookups = sum(1 for t in terms if _LOOKUP.match(t))
    if lookups > 10:
        issues.append(f"{lookups} DNS lookups (the limit is 10, so SPF fails for every sender)")
    all_term = next((t for t in terms if re.fullmatch(r"[+\-~?]?all", t, re.I)), None)
    if all_term is None and not any(t.lower().startswith("redirect=") for t in terms):
        issues.append("no 'all' at the end, so nothing is ruled out")
    elif all_term is not None and (all_term[0] in "+?" or all_term.lower() == "all"):
        issues.append(f"'{all_term}' allows any sender")
    if any(t.lower().startswith("ptr") or t.lower().startswith("+ptr") for t in terms):
        issues.append("uses 'ptr', which is deprecated and slow")
    if issues:
        return Finding(status="needs_work", summary="SPF is published but weak: " + "; ".join(issues) + ".", record=rec, issues=issues)
    soft = all_term is not None and all_term.startswith("~")
    return Finding(status="good", summary="SPF is published" + (" (soft fail '~all', which is common with DMARC)." if soft else " and rejects other senders."), record=rec)


def _tags(record: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in record.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            out[k.strip().lower()] = v.strip()
    return out


def assess_dmarc(txt: list[str]) -> Finding:
    records = [t.strip() for t in txt if t.strip().lower().startswith("v=dmarc1")]
    if not records:
        return Finding(status="missing", summary="No DMARC record: spoofed mail from this domain is not told to be rejected, and no one is sent reports.")
    rec = records[0]
    tags = _tags(rec)
    policy = tags.get("p", "").lower()
    issues: list[str] = []
    if policy not in ("none", "quarantine", "reject"):
        issues.append("no valid policy (p=)")
    elif policy == "none":
        issues.append("policy is 'none' (monitoring only: spoofed mail is still delivered)")
    pct = tags.get("pct", "100")
    if pct.isdigit() and int(pct) < 100 and policy in ("quarantine", "reject"):
        issues.append(f"applies to only {pct}% of mail")
    if not tags.get("rua"):
        issues.append("no report address (rua=), so no one sees abuse")
    if issues:
        return Finding(status="needs_work", summary="DMARC is published but not enforcing fully: " + "; ".join(issues) + ".", record=rec, issues=issues)
    return Finding(status="good", summary=f"DMARC enforces '{policy}' and sends reports.", record=rec)


def assess_dkim(found: dict[str, str]) -> Finding:
    """``found`` maps each selector that has a record to that record's text."""
    if not found:
        return Finding(status="missing", summary="No DKIM key found at the common selectors (selector1/2 for Microsoft 365, google). Another selector may be in use.")
    return Finding(status="good", summary="DKIM key published at: " + ", ".join(sorted(found)) + ".", record=next(iter(found.values())))


class Resolver(Protocol):
    async def txt(self, name: str) -> list[str]: ...
    async def cname(self, name: str) -> list[str]: ...
    async def mx(self, name: str) -> list[str]: ...


class DohResolver:
    """DNS over HTTPS (Cloudflare's JSON API). A name that does not exist, or any failure, reads as no records."""

    def __init__(self, client: httpx.AsyncClient | None = None, url: str = "https://cloudflare-dns.com/dns-query") -> None:
        self._client = client
        self._url = url

    async def _answers(self, name: str, rtype: str) -> list[str]:
        if not _DOMAIN.match(name.lower().replace("_", "a")):
            return []
        try:
            if self._client is not None:
                res = await self._client.get(self._url, params={"name": name, "type": rtype}, headers={"Accept": "application/dns-json"}, timeout=8.0)
            else:
                async with httpx.AsyncClient() as c:
                    res = await c.get(self._url, params={"name": name, "type": rtype}, headers={"Accept": "application/dns-json"}, timeout=8.0)
            if res.status_code != 200:
                return []
            return [str(a.get("data", "")) for a in (res.json().get("Answer") or []) if isinstance(a, dict)]
        except (httpx.HTTPError, ValueError):
            return []

    async def txt(self, name: str) -> list[str]:
        # A long TXT value comes back as quoted pieces: "v=spf1 ..." "more"
        return ["".join(re.findall(r'"([^"]*)"', a)) or a for a in await self._answers(name, "TXT")]

    async def cname(self, name: str) -> list[str]:
        return [a.rstrip(".") for a in await self._answers(name, "CNAME")]

    async def mx(self, name: str) -> list[str]:
        return [a.split()[-1].rstrip(".").lower() for a in await self._answers(name, "MX") if a.split()]


class DomainPosture(BaseModel):
    domain: str
    status: Status
    mx: list[str]
    mail_provider: str | None
    spf: Finding
    dmarc: Finding
    dkim: Finding


def mail_provider(mx: list[str]) -> str | None:
    joined = " ".join(mx)
    if "mail.protection.outlook.com" in joined:
        return "Microsoft 365"
    if "google.com" in joined or "googlemail.com" in joined:
        return "Google Workspace"
    if "mimecast" in joined:
        return "Mimecast"
    if "pphosted" in joined or "proofpoint" in joined:
        return "Proofpoint"
    if "barracuda" in joined:
        return "Barracuda"
    return None


def overall(spf: Finding, dmarc: Finding, has_mx: bool) -> Status:
    """A domain that receives mail is judged on SPF and DMARC; DKIM is shown but its selector cannot be known, so it never fails a domain."""
    if not has_mx:
        return "good" if spf.status == "good" or dmarc.status == "good" else "needs_work"
    if spf.status == "good" and dmarc.status == "good":
        return "good"
    if spf.status == "missing" and dmarc.status == "missing":
        return "missing"
    return "needs_work"


async def check_domain(domain: str, resolver: Resolver) -> DomainPosture:
    spf_txt, dmarc_txt, mx = await asyncio.gather(resolver.txt(domain), resolver.txt(f"_dmarc.{domain}"), resolver.mx(domain))

    async def selector(sel: str) -> tuple[str, str] | None:
        name = f"{sel}._domainkey.{domain}"
        recs = await resolver.cname(name) or [t for t in await resolver.txt(name) if "p=" in t.lower()]
        return (sel, recs[0]) if recs else None

    found = {s: r for s, r in (x for x in await asyncio.gather(*(selector(s) for s in DKIM_SELECTORS)) if x)}
    spf, dmarc = assess_spf(spf_txt), assess_dmarc(dmarc_txt)
    return DomainPosture(domain=domain, status=overall(spf, dmarc, bool(mx)), mx=mx, mail_provider=mail_provider(mx), spf=spf, dmarc=dmarc, dkim=assess_dkim(found))


async def check_domains(domains: list[str], resolver: Resolver) -> list[DomainPosture]:
    return list(await asyncio.gather(*(check_domain(d, resolver) for d in domains[:MAX_DOMAINS])))
