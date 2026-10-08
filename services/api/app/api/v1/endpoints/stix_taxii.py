"""STIX/TAXII threat intelligence publishing endpoints.

Stage 3 #20 — When ``MISP_URL`` + ``MISP_API_KEY`` are configured (and
the target host is allowed by the air-gap policy), POSTs to
``/indicators`` and ``/bundles`` can mirror published STIX into a
downstream MISP instance via :mod:`app.services.misp_push`. The push
is opt-in per request (``?push_to_misp=true``) unless ``MISP_PUSH_AUTO``
is enabled.
"""

import logging
import uuid
from datetime import UTC, datetime
from enum import Enum

from fastapi import APIRouter, HTTPException, Query, status, Depends
from pydantic import BaseModel, Field

from app.core.airgap import AirgapViolation
from app.core.config import settings
from app.services.misp_push import (
    MispNotConfigured,
    MispPushError,
    get_push_client,
    stix_bundle_to_misp_event,
    stix_indicator_to_misp_event,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser, get_current_user, get_db, require_permission
from app.models.stix_object import StixObject

logger = logging.getLogger("aisoc.stix_taxii")

router = APIRouter(prefix="/threatintel/stix", tags=["Threat Intelligence"])


# ── Pydantic models ──────────────────────────────────────────────────────────


class IndicatorPattern(str, Enum):
    ipv4_addr = "ipv4-addr"
    domain_name = "domain-name"
    file_hash = "file:hashes"
    url = "url"
    email_addr = "email-addr"


class STIXIndicator(BaseModel):
    type: str = "indicator"
    spec_version: str = "2.1"
    id: str
    created: str
    modified: str
    name: str
    description: str | None = None
    indicator_types: list[str] = []
    pattern: str
    pattern_type: str = "stix"
    valid_from: str
    valid_until: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    labels: list[str] = []


class STIXIndicatorCreate(BaseModel):
    name: str
    description: str | None = None
    indicator_types: list[str] = []
    pattern: str
    pattern_type: str = "stix"
    valid_from: str | None = None
    valid_until: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    labels: list[str] = []


class STIXBundle(BaseModel):
    type: str = "bundle"
    id: str
    spec_version: str = "2.1"
    created: str
    objects: list[dict]


class STIXBundleCreate(BaseModel):
    objects: list[dict]


class TAXIICollection(BaseModel):
    id: str
    title: str
    description: str
    can_read: bool = True
    can_write: bool = False
    media_types: list[str] = ["application/stix+json;version=2.1"]


class IndicatorListResponse(BaseModel):
    items: list[STIXIndicator]
    total: int


class BundleListResponse(BaseModel):
    items: list[STIXBundle]
    total: int


class TAXIICollectionListResponse(BaseModel):
    items: list[TAXIICollection]
    total: int


class MispPushResult(BaseModel):
    """Embedded in a STIX response when ``push_to_misp=true``."""

    pushed: bool
    misp_event_id: str | None = None
    misp_event_uuid: str | None = None
    url: str | None = None
    pushed_attributes: int | None = None
    skipped_attributes: int | None = None
    error: str | None = None


class STIXIndicatorWithPush(STIXIndicator):
    misp: MispPushResult | None = None


class STIXBundleWithPush(STIXBundle):
    misp: MispPushResult | None = None


class MispPushHealth(BaseModel):
    configured: bool
    airgapped: bool
    auto_push: bool
    url: str | None = None
    user: str | None = None
    role: str | None = None
    ok: bool
    error: str | None = None


class MispDryRunRequest(BaseModel):
    """Either ``indicator`` or ``bundle`` must be provided."""

    indicator: STIXIndicatorCreate | None = None
    bundle: STIXBundleCreate | None = None
    distribution: int | None = Field(default=None, ge=0, le=4)
    threat_level: int | None = Field(default=None, ge=1, le=4)
    analysis: int | None = Field(default=None, ge=0, le=2)


class MispDryRunResponse(BaseModel):
    event: dict
    attribute_count: int
    skipped_count: int
    would_push_to: str | None = None
    airgap_blocked: bool = False
    airgap_message: str | None = None


# ── Published STIX store (database, one per tenant) ───────────────────────────────────────────────────
#
# What a tenant publishes is stored in the stix_objects table (app/models/stix_object.py, migrations/053_stix_objects.sql), so it survives an API restart.
#
# History: this used to be two module-level in-memory lists, SEEDED with invented indicators ("Malicious IP - C2 Server ... associated with APT-42", a "LockBit 3.0 ransomware"
# hash that is actually the SHA-256 of an empty file, confidence 95), shared by every tenant, and listed three TAXII collections that had no endpoints behind them.
# A feed that serves invented indicators as threat intelligence is dangerous: pasted into a blocklist, the empty-file hash blocks every zero-byte file.
#
# Now a tenant sees only what it published itself, nothing is pre-loaded, and what it published is stored in the database (table stix_objects), so it survives an API restart.


# ── Endpoints ────────────────────────────────────────────────────────────────


async def _documents(db: AsyncSession, user: CurrentUser, kind: str) -> list[dict]:
    """The STIX documents THIS tenant published of this kind, in publish order."""
    result = await db.execute(
        select(StixObject)
        .where(StixObject.tenant_id == user.tenant_id, StixObject.kind == kind)
        .order_by(StixObject.created_at, StixObject.id)
    )
    return [row.document for row in result.scalars().all()]


async def _store(db: AsyncSession, user: CurrentUser, kind: str, stix_id: str, document: dict) -> None:
    db.add(StixObject(tenant_id=user.tenant_id, kind=kind, stix_id=stix_id, document=document))
    await db.commit()


@router.get("/indicators", response_model=IndicatorListResponse, dependencies=[Depends(require_permission("threat_intel:read"))])
async def list_indicators(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    label: str | None = Query(default=None),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> IndicatorListResponse:
    """List the STIX 2.1 indicators THIS tenant has published (none until it publishes some)."""
    items = [STIXIndicator(**doc) for doc in await _documents(db, current_user, "indicator")]
    if label:
        items = [i for i in items if label in i.labels]
    return IndicatorListResponse(items=items, total=len(items))


def _should_push(explicit: bool | None) -> bool:
    """Resolve whether this request should mirror to MISP.

    Precedence: explicit query param > ``MISP_PUSH_AUTO`` env > False.
    """
    if explicit is not None:
        return explicit
    return bool(settings.MISP_PUSH_AUTO)


async def _push_indicator_or_swallow(indicator: STIXIndicator) -> MispPushResult | None:
    """Push the indicator to MISP, converting errors to a structured result.

    Returns ``None`` if the push wasn't attempted (e.g. no client config
    AND auto-push is off — that's the "silent" path used when the
    operator just wants demo behavior). Any other failure surfaces as
    ``MispPushResult(pushed=False, error=...)`` so the API consumer
    gets the publish acknowledgment AND knows the mirror failed.
    """
    client = get_push_client()
    if not client.configured:
        return MispPushResult(
            pushed=False,
            error="MISP push not configured (set MISP_URL and MISP_API_KEY).",
        )
    try:
        result = await client.push_indicator(indicator.model_dump())
    except AirgapViolation as exc:
        logger.warning("misp_push.airgap_blocked", extra={"err": str(exc)})
        return MispPushResult(pushed=False, error=f"Air-gap policy blocked push: {exc}")
    except MispNotConfigured as exc:
        return MispPushResult(pushed=False, error=str(exc))
    except MispPushError as exc:
        logger.warning("misp_push.failed", extra={"err": str(exc)})
        return MispPushResult(pushed=False, error=str(exc))
    return MispPushResult(
        pushed=True,
        misp_event_id=str(result.get("misp_event_id") or "") or None,
        misp_event_uuid=str(result.get("misp_event_uuid") or "") or None,
        url=str(result.get("url") or "") or None,
    )


async def _push_bundle_or_swallow(bundle: STIXBundle) -> MispPushResult | None:
    client = get_push_client()
    if not client.configured:
        return MispPushResult(
            pushed=False,
            error="MISP push not configured (set MISP_URL and MISP_API_KEY).",
        )
    try:
        result = await client.push_bundle(bundle.model_dump())
    except AirgapViolation as exc:
        logger.warning("misp_push.airgap_blocked", extra={"err": str(exc)})
        return MispPushResult(pushed=False, error=f"Air-gap policy blocked push: {exc}")
    except MispNotConfigured as exc:
        return MispPushResult(pushed=False, error=str(exc))
    except MispPushError as exc:
        logger.warning("misp_push.failed", extra={"err": str(exc)})
        return MispPushResult(pushed=False, error=str(exc))
    return MispPushResult(
        pushed=True,
        misp_event_id=str(result.get("misp_event_id") or "") or None,
        misp_event_uuid=str(result.get("misp_event_uuid") or "") or None,
        url=str(result.get("url") or "") or None,
        pushed_attributes=int(result.get("pushed_attributes") or 0),
        skipped_attributes=int(result.get("skipped_attributes") or 0),
    )


@router.post(
    "/indicators",
    response_model=STIXIndicatorWithPush,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("threat_intel:write"))],
)
async def create_indicator(
    body: STIXIndicatorCreate,
    push_to_misp: bool | None = Query(
        default=None,
        description=("Mirror this indicator to the configured MISP instance. Defaults to the value of MISP_PUSH_AUTO."),
    ),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> STIXIndicatorWithPush:
    """Publish a new STIX 2.1 indicator and optionally mirror it to MISP."""
    now_iso = datetime.now(UTC).isoformat()
    indicator = STIXIndicator(
        id=f"indicator--{uuid.uuid4()}",
        created=now_iso,
        modified=now_iso,
        name=body.name,
        description=body.description,
        indicator_types=body.indicator_types,
        pattern=body.pattern,
        pattern_type=body.pattern_type,
        valid_from=body.valid_from or now_iso,
        valid_until=body.valid_until,
        confidence=body.confidence,
        labels=body.labels,
    )
    await _store(db, current_user, "indicator", indicator.id, indicator.model_dump(mode="json"))

    push_result: MispPushResult | None = None
    if _should_push(push_to_misp):
        push_result = await _push_indicator_or_swallow(indicator)

    return STIXIndicatorWithPush(**indicator.model_dump(), misp=push_result)


@router.get("/bundles", response_model=BundleListResponse, dependencies=[Depends(require_permission("threat_intel:read"))])
async def list_bundles(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> BundleListResponse:
    """List the STIX 2.1 bundles THIS tenant has published (none until it publishes some)."""
    items = [STIXBundle(**doc) for doc in await _documents(db, current_user, "bundle")]
    return BundleListResponse(items=items, total=len(items))


@router.post(
    "/bundles",
    response_model=STIXBundleWithPush,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("threat_intel:write"))],
)
async def create_bundle(
    body: STIXBundleCreate,
    push_to_misp: bool | None = Query(
        default=None,
        description=(
            "Mirror this bundle to the configured MISP instance as a single "
            "MISP event (one attribute per translatable indicator). Defaults "
            "to MISP_PUSH_AUTO."
        ),
    ),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> STIXBundleWithPush:
    """Create a new STIX 2.1 bundle and optionally mirror it to MISP."""
    if not body.objects:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bundle must contain at least one STIX object.",
        )
    bundle = STIXBundle(
        id=f"bundle--{uuid.uuid4()}",
        created=datetime.now(UTC).isoformat(),
        objects=body.objects,
    )
    await _store(db, current_user, "bundle", bundle.id, bundle.model_dump(mode="json"))

    push_result: MispPushResult | None = None
    if _should_push(push_to_misp):
        push_result = await _push_bundle_or_swallow(bundle)

    return STIXBundleWithPush(**bundle.model_dump(), misp=push_result)


@router.get("/taxii/collections", response_model=TAXIICollectionListResponse, dependencies=[Depends(require_permission("threat_intel:read"))])
async def list_taxii_collections() -> TAXIICollectionListResponse:
    """List TAXII 2.1 collections. No TAXII collection is served yet (there is no per-collection objects endpoint), so there are none to list.

    It used to list three that did not exist ("AiSOC Threat Feed", "Community IOCs", "MITRE ATT&CK Mapping"), which a TAXII client would try to read and fail.
    """
    return TAXIICollectionListResponse(items=[], total=0)


# ── MISP push admin endpoints ───────────────────────────────────────────────


@router.get("/misp/health", response_model=MispPushHealth, tags=["MISP push"], dependencies=[Depends(require_permission("threat_intel:read"))])
async def misp_push_health() -> MispPushHealth:
    """Check whether MISP push is configured and reachable.

    Surfaces enough state for an operator to debug a misconfigured
    deployment without leaking the API key. Calls ``/users/view/me``
    against MISP only when the client is configured.
    """
    client = get_push_client()
    base = MispPushHealth(
        configured=client.configured,
        airgapped=bool(settings.AISOC_AIRGAPPED),
        auto_push=bool(settings.MISP_PUSH_AUTO),
        url=settings.MISP_URL or None,
        ok=False,
    )
    if not client.configured:
        base.error = "MISP_URL and/or MISP_API_KEY not set."
        return base
    try:
        result = await client.health_check()
    except AirgapViolation as exc:
        base.error = f"Air-gap policy blocked health check: {exc}"
        return base
    except (MispNotConfigured, MispPushError) as exc:
        base.error = str(exc)
        return base
    base.ok = True
    base.user = str(result.get("user") or "") or None
    base.role = str(result.get("role") or "") or None
    return base


@router.post("/misp/dry-run", response_model=MispDryRunResponse, tags=["MISP push"], dependencies=[Depends(require_permission("threat_intel:write"))])
async def misp_push_dry_run(body: MispDryRunRequest) -> MispDryRunResponse:
    """Show the MISP event payload that *would* be pushed, without sending it.

    Useful for operators tuning STIX → MISP mappings, and for proving
    that an air-gapped deployment will refuse to send. The endpoint
    runs the air-gap check against the configured MISP URL and reports
    the result, but never opens an HTTP connection.
    """
    if (body.indicator is None) == (body.bundle is None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide exactly one of `indicator` or `bundle`.",
        )

    if body.indicator is not None:
        now_iso = datetime.now(UTC).isoformat()
        ind = STIXIndicator(
            id=f"indicator--dry-run-{uuid.uuid4()}",
            created=now_iso,
            modified=now_iso,
            name=body.indicator.name,
            description=body.indicator.description,
            indicator_types=body.indicator.indicator_types,
            pattern=body.indicator.pattern,
            pattern_type=body.indicator.pattern_type,
            valid_from=body.indicator.valid_from or now_iso,
            valid_until=body.indicator.valid_until,
            confidence=body.indicator.confidence,
            labels=body.indicator.labels,
        )
        event = stix_indicator_to_misp_event(
            ind.model_dump(),
            distribution=body.distribution,
            threat_level=body.threat_level,
            analysis=body.analysis,
        )
        if event is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"STIX pattern {ind.pattern!r} is not currently translatable "
                    "to a MISP attribute. Supported observable prefixes: "
                    "ipv4-addr, ipv6-addr, domain-name, url, email-addr, "
                    "file:hashes (MD5/SHA1/SHA256/SHA512), file:name."
                ),
            )
        attribute_count = len(event.get("Event", {}).get("Attribute", []))
        skipped = 0
    else:
        assert body.bundle is not None  # narrow for type checker
        bundle = STIXBundle(
            id=f"bundle--dry-run-{uuid.uuid4()}",
            created=datetime.now(UTC).isoformat(),
            objects=body.bundle.objects,
        )
        raw = stix_bundle_to_misp_event(
            bundle.model_dump(),
            distribution=body.distribution,
            threat_level=body.threat_level,
            analysis=body.analysis,
        )
        skipped = int(raw.pop("_skipped", 0))
        attribute_count = int(raw.pop("_attribute_count", 0))
        event = raw

    would_push_to: str | None = None
    airgap_blocked = False
    airgap_message: str | None = None
    misp_url = (settings.MISP_URL or "").rstrip("/")
    if misp_url:
        would_push_to = f"{misp_url}/events/add"
        try:
            from app.core.airgap import enforce_airgap_for_url  # local import keeps top tidy

            enforce_airgap_for_url(would_push_to)
        except AirgapViolation as exc:
            airgap_blocked = True
            airgap_message = str(exc)

    return MispDryRunResponse(
        event=event,
        attribute_count=attribute_count,
        skipped_count=skipped,
        would_push_to=would_push_to,
        airgap_blocked=airgap_blocked,
        airgap_message=airgap_message,
    )
