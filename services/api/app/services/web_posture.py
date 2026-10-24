"""What a domain's own website shows: its certificate, whether plain HTTP is sent to HTTPS, and the basic response headers. Read-only, from public responses.

The assessments are pure functions of a ``ProbeResult`` (so every rule is testable without a network); ``LiveProbe`` makes the three requests. The result is shown for information next to the
mail checks of ``domain_posture`` and never changes a domain's mail verdict.
"""

from __future__ import annotations

import asyncio
import ssl
from datetime import UTC, datetime
from typing import Protocol

import httpx
from pydantic import BaseModel

from app.services.domain_posture import Finding

CERT_WARN_DAYS = 30


class ProbeResult(BaseModel):
    """What one look at a domain's website saw. A certificate that fails verification sets ``cert_error`` (the site answered, but visitors get a warning)."""

    answered: bool
    cert_error: str | None = None
    cert_not_after: datetime | None = None
    # Where plain http:// sent the visitor, if it answered with a redirect.
    http_redirect_to: str | None = None
    http_answered: bool = False
    headers: dict[str, str] = {}


class WebPosture(BaseModel):
    certificate: Finding
    https_redirect: Finding
    headers: Finding


def assess_certificate(probe: ProbeResult, now: datetime) -> Finding:
    if probe.cert_error:
        return Finding(status="needs_work", summary=f"The certificate does not verify ({probe.cert_error}): visitors get a browser warning.", issues=[probe.cert_error])
    if probe.cert_not_after is None:
        return Finding(status="missing", summary="No HTTPS: nothing answered on port 443.")
    days = (probe.cert_not_after - now).days
    if days < 0:
        return Finding(status="needs_work", summary=f"The certificate expired {-days} day{'s' if days != -1 else ''} ago.", issues=["expired"])
    if days <= CERT_WARN_DAYS:
        return Finding(status="needs_work", summary=f"The certificate expires in {days} day{'s' if days != 1 else ''}: renew it.", issues=["expires soon"])
    return Finding(status="good", summary=f"The certificate is valid for another {days} days.")


def assess_https_redirect(probe: ProbeResult) -> Finding:
    if not probe.http_answered:
        return Finding(status="good", summary="Nothing answers on plain HTTP, so no one is served an unencrypted page.")
    if probe.http_redirect_to and probe.http_redirect_to.lower().startswith("https://"):
        return Finding(status="good", summary="Plain HTTP is sent to HTTPS.")
    return Finding(status="needs_work", summary="Plain HTTP answers and is not sent to HTTPS: pages can be read or changed in transit.", issues=["no https redirect"])


def assess_headers(headers: dict[str, str]) -> Finding:
    h = {k.lower(): v for k, v in headers.items()}
    issues: list[str] = []
    if "strict-transport-security" not in h:
        issues.append("no Strict-Transport-Security (browsers are not told to insist on HTTPS)")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        issues.append("no X-Content-Type-Options: nosniff")
    csp = h.get("content-security-policy", "").lower()
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        issues.append("nothing stops other sites framing this one (X-Frame-Options or CSP frame-ancestors)")
    if issues:
        return Finding(status="needs_work", summary="Missing basic security headers: " + "; ".join(issues) + ".", issues=issues)
    return Finding(status="good", summary="The basic security headers are present.")


def web_posture(probe: ProbeResult, now: datetime) -> WebPosture | None:
    """None when no website answered at all (a mail-only domain), which is normal."""
    if not probe.answered:
        return None
    return WebPosture(certificate=assess_certificate(probe, now), https_redirect=assess_https_redirect(probe), headers=assess_headers(probe.headers))


class WebProbe(Protocol):
    async def probe(self, domain: str) -> ProbeResult: ...


class LiveProbe:
    """Looks at a domain's website from this server: a TLS handshake for the certificate, one GET of https:// for the headers, one GET of http:// to see where it leads. Nothing is stored."""

    def __init__(self, timeout: float = 8.0) -> None:
        self._timeout = timeout

    async def _certificate(self, domain: str) -> tuple[bool, str | None, datetime | None]:
        """(answered, error, not_after). A certificate that fails verification is an error, not an unreachable site."""
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(domain, 443, ssl=ssl.create_default_context(), server_hostname=domain), self._timeout)
        except ssl.SSLCertVerificationError as exc:
            return True, (exc.verify_message or "certificate verification failed"), None
        except (OSError, TimeoutError, ssl.SSLError):
            return False, None, None
        try:
            cert = writer.get_extra_info("peercert") or {}
            not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), UTC) if cert.get("notAfter") else None
            return True, None, not_after
        finally:
            writer.close()

    async def probe(self, domain: str) -> ProbeResult:
        answered, cert_error, not_after = await self._certificate(domain)
        headers: dict[str, str] = {}
        redirect: str | None = None
        http_answered = False
        async with httpx.AsyncClient(follow_redirects=False, timeout=self._timeout, headers={"User-Agent": "aisoc-posture-check"}) as client:
            if answered and cert_error is None:
                try:
                    headers = {k.lower(): v for k, v in (await client.get(f"https://{domain}/")).headers.items()}
                except httpx.HTTPError:
                    pass
            try:
                res = await client.get(f"http://{domain}/")
                http_answered = True
                if 300 <= res.status_code < 400:
                    redirect = res.headers.get("location")
            except httpx.HTTPError:
                pass
        return ProbeResult(answered=answered or http_answered, cert_error=cert_error, cert_not_after=not_after, http_redirect_to=redirect, http_answered=http_answered, headers=headers)
