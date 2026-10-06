"""Authenticated gateway to the enrichment service (VirusTotal, AbuseIPDB, GreyNoise, ...).

Why this exists. The web console used to reach the enrichment service through a direct
Next.js rewrite. That path never worked (the compose web container could not reach the
service, it listens on 8082 not 8083, the console sent GET /lookup?ioc= to an endpoint that
only accepts POST, and its bulk body {iocs: [...]} is not the service's {items: [...]}), and
it would have been dangerous had it worked: the enrichment service has NO authentication, so
anyone able to reach the console could spend your threat-intel provider quotas.

Now the console talks to the API, which requires a login and `threat_intel:read`, works out
the indicator type, calls the service, and translates the answer to the console's
ThreatIndicator shape. Failures are reported as failures; nothing is ever invented.
The caller's credentials are NOT forwarded to the enrichment service (it has no use for them).

Every indicator sent upstream spends the owner's threat-intel provider quota (VirusTotal, AbuseIPDB, ...)
and every role may read threat intel, so lookups are rate limited PER TENANT with a token bucket (burst 100,
refilling 12 a minute; override with AISOC_ENRICHMENT_RATE_CAPACITY / AISOC_ENRICHMENT_RATE_REFILL). One
token per indicator actually sent. Requests refused before reaching a provider (no permission, junk input)
cost nothing. Note the buckets are per tenant but the provider keys are shared by the whole install.
"""
import ipaddress
import os
import re
from typing import Any
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, require_permission
from app.services.explain_rate_limit import ExplainRateLimiter

router = APIRouter(prefix="/enrichment", tags=["enrichment"])

MAX_BULK = 100  # the enrichment service refuses more
MAX_IOC_LENGTH = 2048

_HASH_LENGTHS = {32, 40, 64}  # md5, sha1, sha256
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)
_URL_RE = re.compile(r"^[a-z][a-z0-9+.\-]{1,15}://\S+$", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)


def classify_ioc(raw: str) -> tuple[str, str] | None:
    """(type, cleaned value) for an indicator, or None if it is not one we can look up."""
    value = (raw or "").strip()
    if not value or len(value) > MAX_IOC_LENGTH:
        return None
    try:
        ipaddress.ip_address(value)
        return "ip", value
    except ValueError:
        pass
    if _URL_RE.match(value):
        return "url", value
    if _EMAIL_RE.match(value):
        return "email", value
    if len(value) in _HASH_LENGTHS and _HEX_RE.match(value):
        return "hash", value.lower()
    if _DOMAIN_RE.match(value):
        return "domain", value.lower()
    return None


def _severity(risk_score: float) -> str:
    if risk_score >= 80:
        return "critical"
    if risk_score >= 60:
        return "high"
    if risk_score >= 40:
        return "medium"
    if risk_score >= 20:
        return "low"
    return "info"


class IndicatorOut(BaseModel):
    """The web console's ThreatIndicator (apps/web/src/lib/api.ts), plus the raw provider result."""

    id: str
    type: str
    value: str
    confidence: float
    severity: str
    malicious: bool
    tags: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    firstSeen: str | None = None
    lastSeen: str | None = None
    description: str | None = None
    country: str | None = None
    asn: str | None = None
    mitre: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


def to_indicator(result: dict[str, Any]) -> IndicatorOut:
    ioc_type = str(result.get("ioc_type") or "")
    value = str(result.get("value") or "")
    risk = float(result.get("risk_score") or 0)
    geo = result.get("geo_location") or {}
    asn = geo.get("asn")
    classification = result.get("classification") or {}
    return IndicatorOut(
        id=f"{ioc_type}:{value}",
        type=ioc_type,
        value=value,
        confidence=max(0.0, min(100.0, float(result.get("confidence") or 0))),
        severity=_severity(risk),
        malicious=risk >= 60,  # the same line as "high"
        tags=list(result.get("tags") or []),
        sources=[str(s.get("name")) for s in (result.get("sources") or []) if isinstance(s, dict) and s.get("name")],
        firstSeen=result.get("first_seen"),
        lastSeen=result.get("last_seen"),
        description=result.get("threat_category") or None,
        country=geo.get("country") or None,
        asn=f"AS{asn}" if asn else None,
        mitre=list(classification.get("mitre_techniques") or []),
        raw=result,
    )



def _env_float(name: str, default: float) -> float:
    try:
        value = float((os.getenv(name) or "").strip())
    except ValueError:
        return default
    return value if value > 0 else default


# Same machinery as the alert-explain limiter, with its own numbers and its own state.
_limiter = ExplainRateLimiter(
    capacity=_env_float("AISOC_ENRICHMENT_RATE_CAPACITY", 100.0),
    refill_per_second=_env_float("AISOC_ENRICHMENT_RATE_REFILL", 0.2),
)


async def _charge(tenant_id: UUID, cost: float, response: Response) -> None:
    """Spend `cost` tokens for this tenant or raise 429; always report where the caller stands."""
    try:
        decision = await _limiter.acquire(tenant_id, cost=cost)
    except ValueError as exc:  # more indicators than the bucket can ever hold
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Too many indicators for the configured rate limit: {exc}") from exc
    headers = decision.to_headers()
    for name, value in headers.items():
        response.headers[name] = value
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Enrichment rate limit exceeded", headers=headers)


def _base_url() -> str:
    url = (os.getenv("ENRICHMENT_URL") or "").strip().rstrip("/")
    if not url:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Enrichment service is not configured")
    return url


async def _post(path: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    url = f"{_base_url()}{path}"
    try:
        # No Authorization header: the enrichment service does no authentication, and the
        # caller's token has no business leaving the API.
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Enrichment service unavailable") from exc
    if resp.status_code != 200:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Enrichment service error")
    try:
        body = resp.json()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Enrichment service returned an invalid response") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Enrichment service returned an invalid response")
    return body


@router.get("/lookup", response_model=IndicatorOut, dependencies=[Depends(require_permission("threat_intel:read"))])
async def lookup(
    response: Response,
    current_user: AuthUser,
    ioc: str = Query(..., min_length=1, max_length=MAX_IOC_LENGTH, description="IP, domain, URL, hash or email"),
) -> IndicatorOut:
    classified = classify_ioc(ioc)
    if classified is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Not a recognisable IP, domain, URL, hash or email")
    ioc_type, value = classified
    _base_url()  # an unconfigured service must not cost the caller any quota
    await _charge(current_user.tenant_id, 1.0, response)
    result = await _post("/enrich", {"ioc_type": ioc_type, "value": value, "force": False}, timeout=30.0)
    return to_indicator(result)


class BulkRequest(BaseModel):
    iocs: list[str] = Field(..., min_length=1, max_length=MAX_BULK)


class BulkError(BaseModel):
    ioc: str
    error: str


class BulkResponse(BaseModel):
    results: list[IndicatorOut]
    errors: list[BulkError] = Field(default_factory=list)


@router.post("/bulk", response_model=BulkResponse, dependencies=[Depends(require_permission("threat_intel:read"))])
async def bulk(body: BulkRequest, response: Response, current_user: AuthUser) -> BulkResponse:
    items: list[dict[str, Any]] = []
    errors: list[BulkError] = []
    for raw in body.iocs:
        classified = classify_ioc(raw)
        if classified is None:
            errors.append(BulkError(ioc=str(raw)[:200], error="Not a recognisable IP, domain, URL, hash or email"))
            continue
        items.append({"ioc_type": classified[0], "value": classified[1], "force": False})
    if not items:
        return BulkResponse(results=[], errors=errors)
    _base_url()
    await _charge(current_user.tenant_id, float(len(items)), response)  # one token per indicator actually sent
    upstream = await _post("/enrich/bulk", {"items": items}, timeout=60.0)
    results = [to_indicator(r) for r in (upstream.get("results") or []) if isinstance(r, dict)]
    return BulkResponse(results=results, errors=errors)
