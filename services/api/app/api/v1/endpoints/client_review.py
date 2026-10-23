"""A client review on one page: tool coverage, Multi-Factor, Microsoft Secure Score, the last 30 days of alerts and cases, and a cyber-insurance readiness checklist. Read-only; every number comes
from data AiSOC already holds, and what it does not hold is reported as unknown rather than guessed.

``GET /api/v1/client-review/{client_id}``. For a quarterly business review or a cyber-insurance questionnaire; the checklist answers are evidence from the connected tools, not a certification.
``POST /api/v1/inbox/core-feed/{token}/vcio-reviews``: CORE's daily summary of a client's vCIO Toolbox recommendations and risks (authenticated by the secret in the path, like the other core-feed routes).
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import and_, bindparam, func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.alerts import FINISHED_STATUSES
from app.api.v1.endpoints.client_posture import devices_part
from app.api.v1.endpoints.devices import UnmappedClient, _load_cached, _master_of, _scope, rollup_of
from app.api.v1.endpoints.identity import counts_for_mfa
from app.api.v1.endpoints.inbox_core_feed import _verify_core_feed_token
from app.api.v1.endpoints.signins import targets_by_tenant
from app.db.rls_scope import acting_as_tenant
from app.db.rls_sessions import adopt_tenant
from app.models.alert import Alert
from app.models.client_alias import ClientAlias
from app.models.signin import ClientM365Check, ClientVcioReview, IdentityMfaUser, IdentitySecureScore
from app.models.tenant import Tenant
from app.services.client_review import DeviceFacts, Readiness, device_facts, readiness
from app.services.m365_review import M365Answer, m365_answers
from app.services.sat_review import SAT_SOURCE
from app.services.tech_stack import TechAnswer, tech_stack

router = APIRouter(prefix="/client-review", tags=["posture"])
ingest_router = APIRouter(prefix="/inbox", tags=["inbox-core-feed"])

WINDOW_DAYS = 30
_CASE_FINISHED = ("resolved", "closed")


class ReviewAlerts(BaseModel):
    open: int
    critical_open: int
    high_open: int
    opened_30d: int
    closed_30d: int


class ReviewCases(BaseModel):
    open: int
    opened_30d: int
    resolved_30d: int


class ReviewScore(BaseModel):
    percent: float
    current: float
    max: float
    average: float | None = None
    taken_at: datetime


class VcioRecommendation(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    priority: str | None = Field(default=None, max_length=20)
    adoption: str = Field(max_length=40)
    due: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    on_roadmap: bool = False


class VcioRecommendations(BaseModel):
    total: int = Field(ge=0, le=100000)
    pending: int = Field(ge=0, le=100000)
    adopted: int = Field(ge=0, le=100000)
    declined: int = Field(ge=0, le=100000)
    top: list[VcioRecommendation] = Field(default_factory=list, max_length=15)


class VcioRisk(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    category: str | None = Field(default=None, max_length=60)
    priority: str | None = Field(default=None, max_length=20)
    impact: float | None = None
    likelihood: float | None = None
    score: float | None = None
    inherent: str | None = Field(default=None, max_length=20)


class VcioReviewReport(BaseModel):
    vendor: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")
    vendor_client_id: str = Field(min_length=1, max_length=200)
    recommendations: VcioRecommendations
    risks: list[VcioRisk] = Field(default_factory=list, max_length=30)


class VcioReviewResponse(BaseModel):
    accepted: int
    unmapped: int = 0
    ignored: int = 0
    unmapped_clients: list[UnmappedClient] = Field(default_factory=list)


class _VcioView:
    """Lets the shared client mapping place a report that belongs to one client, as a list of one item."""

    def __init__(self, report: VcioReviewReport) -> None:
        self.vendor = report.vendor
        self.items = [report]


async def apply_vcio_review(db: Any, owner: uuid.UUID, report: VcioReviewReport, now: datetime | None = None) -> VcioReviewResponse:
    """Replace the client's vCIO Toolbox summary with this report. The caller owns the transaction."""
    now = now or datetime.now(UTC)
    by_tenant, unmapped, ignored, waiting = await targets_by_tenant(db, owner, _VcioView(report))
    accepted = 0
    for tid in by_tenant:
        async with acting_as_tenant(db, tid):
            values = {
                "tenant_id": tid,
                "source": report.vendor,
                "recommendations": report.recommendations.model_dump(),
                "risks": [r.model_dump() for r in report.risks],
                "refreshed_at": now,
            }
            stmt = pg_insert(ClientVcioReview).values(values)
            update = {c: stmt.excluded[c] for c in values if c not in ("tenant_id", "source")}
            await db.execute(stmt.on_conflict_do_update(index_elements=["tenant_id", "source"], set_=update))
            accepted += 1
    return VcioReviewResponse(accepted=accepted, unmapped=unmapped, ignored=ignored, unmapped_clients=waiting)


@ingest_router.post("/core-feed/{tenant_token}/vcio-reviews", response_model=VcioReviewResponse)
async def report_core_feed_vcio_review(tenant_token: str, body: VcioReviewReport, db: DBSession) -> VcioReviewResponse:
    """Record one client's vCIO Toolbox recommendations and risks (replacing the last summary)."""
    owner = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, owner)
    result = await apply_vcio_review(db, owner, body)
    await db.commit()
    return result


class M365CheckIn(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9_]{1,60}$")
    status: str = Field(pattern=r"^(met|partly|not_met)$")
    evidence: str = Field(default="", max_length=300)


class M365ChecksReport(BaseModel):
    vendor: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")
    vendor_client_id: str = Field(min_length=1, max_length=200)
    checks: list[M365CheckIn] = Field(default_factory=list, max_length=80)


class _M365View:
    """Lets the shared client mapping place a report that belongs to one client, as a list of one item."""

    def __init__(self, report: M365ChecksReport) -> None:
        self.vendor = report.vendor
        self.items = [report]


async def apply_m365_checks(db: Any, owner: uuid.UUID, report: M365ChecksReport, now: datetime | None = None) -> VcioReviewResponse:
    """Replace the client's Microsoft 365 baseline checks with this report. The caller owns the transaction."""
    now = now or datetime.now(UTC)
    by_tenant, unmapped, ignored, waiting = await targets_by_tenant(db, owner, _M365View(report))
    accepted = 0
    for tid in by_tenant:
        async with acting_as_tenant(db, tid):
            values = {"tenant_id": tid, "source": report.vendor, "checks": [c.model_dump() for c in report.checks], "refreshed_at": now}
            stmt = pg_insert(ClientM365Check).values(values)
            update = {c: stmt.excluded[c] for c in values if c not in ("tenant_id", "source")}
            await db.execute(stmt.on_conflict_do_update(index_elements=["tenant_id", "source"], set_=update))
            accepted += 1
    return VcioReviewResponse(accepted=accepted, unmapped=unmapped, ignored=ignored, unmapped_clients=waiting)


@ingest_router.post("/core-feed/{tenant_token}/m365-checks", response_model=VcioReviewResponse)
async def report_core_feed_m365_checks(tenant_token: str, body: M365ChecksReport, db: DBSession) -> VcioReviewResponse:
    """Record one client's Microsoft 365 baseline checks (replacing the last report)."""
    owner = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, owner)
    result = await apply_m365_checks(db, owner, body)
    await db.commit()
    return result


class ReviewVcio(BaseModel):
    recommendations: VcioRecommendations
    risks: list[VcioRisk]
    refreshed_at: datetime


class ClientReview(BaseModel):
    client_id: uuid.UUID
    client_name: str | None
    generated_at: datetime
    window_days: int
    devices: DeviceFacts
    # The people counts (see /identity/mfa-summary); None when no multi-factor data has arrived for this client.
    mfa: dict[str, int] | None
    secure_score: ReviewScore | None
    alerts: ReviewAlerts
    cases: ReviewCases
    readiness: Readiness
    # What vCIO Toolbox holds for the client (recommendations by adoption, the pending ones that matter most, risks); None when CORE has not sent it.
    vcio: ReviewVcio | None = None
    # Suggested answers to the vCIO Toolbox review template's technology questions, from what A.C.O.R.N can see (nothing is sent to vCIO Toolbox).
    tech_stack: list[TechAnswer] = Field(default_factory=list)
    # Suggested answers to the template's Microsoft 365 questions (checks CORE read through CIPP, plus the multi-factor list); the rest are needs_person.
    m365: list[M365Answer] = Field(default_factory=list)
    m365_refreshed_at: datetime | None = None


@router.get(
    "/{client_id}",
    response_model=ClientReview,
    summary="One client's coverage, identity, alerts and cases for a review, with a cyber-insurance readiness checklist",
)
async def client_review(
    client_id: uuid.UUID, current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))], db: DBSession
) -> ClientReview:
    owner = current_user.tenant_id
    if client_id != owner:
        found = (await db.execute(select(Tenant.id).where(Tenant.id == client_id, Tenant.parent_tenant_id == owner))).scalar_one_or_none()
        if found is None:
            raise HTTPException(status_code=404, detail="Client not found")
    scope, clients = await _scope(db, owner, client_id)
    master = _master_of(await db.get(Tenant, owner))
    shown = [d for d in await _load_cached(db, owner, scope, clients, master) if d.hidden_since is None]
    rolled = devices_part(rollup_of(shown), client_id)
    # Which tools this client is mapped to an organization in (a tool with no mapped client at all cannot say).
    aliases = (
        await db.execute(
            select(ClientAlias.vendor, ClientAlias.child_tenant_id).where(
                ClientAlias.tenant_id == owner, ClientAlias.ignored.is_(False), ClientAlias.child_tenant_id.is_not(None)
            )
        )
    ).all()
    facts = device_facts(
        shown,
        stale_agents=rolled.stale_agents,
        offline=rolled.offline,
        enrolled_in={v for v, tid in aliases if tid == client_id},
        mapped_tools={v for v, _ in aliases},
    )

    now = datetime.now(UTC)
    since = now - timedelta(days=WINDOW_DAYS)
    async with contextlib.nullcontext() if client_id == owner else acting_as_tenant(db, client_id):
        users = (await db.execute(select(IdentityMfaUser).where(IdentityMfaUser.tenant_id == client_id))).scalars().all()
        score_row = (await db.execute(select(IdentitySecureScore).where(IdentitySecureScore.tenant_id == client_id))).scalars().first()
        vcio_row = (await db.execute(select(ClientVcioReview).where(ClientVcioReview.tenant_id == client_id))).scalars().first()
        m365_row = (
            (await db.execute(select(ClientM365Check).where(ClientM365Check.tenant_id == client_id, ClientM365Check.source != SAT_SOURCE)))
            .scalars()
            .first()
        )
        sat_row = (
            (await db.execute(select(ClientM365Check).where(ClientM365Check.tenant_id == client_id, ClientM365Check.source == SAT_SOURCE)))
            .scalars()
            .first()
        )
        a = (
            await db.execute(
                select(
                    func.count().filter(Alert.status.notin_(FINISHED_STATUSES)),
                    func.count().filter(and_(Alert.status.notin_(FINISHED_STATUSES), Alert.severity == "critical")),
                    func.count().filter(and_(Alert.status.notin_(FINISHED_STATUSES), Alert.severity == "high")),
                    func.count().filter(Alert.created_at >= since),
                    func.count().filter(and_(Alert.status.in_(FINISHED_STATUSES), Alert.updated_at >= since)),
                ).where(Alert.tenant_id == client_id)
            )
        ).one()
        c = (
            await db.execute(
                text(
                    "SELECT count(*) FILTER (WHERE status NOT IN :done), count(*) FILTER (WHERE created_at >= :since), "
                    "count(*) FILTER (WHERE status IN :done AND updated_at >= :since) FROM cases WHERE tenant_id = :t"
                ).bindparams(bindparam("done", expanding=True)),
                {"t": client_id, "since": since, "done": list(_CASE_FINISHED)},
            )
        ).one()

    mfa = counts_for_mfa(list(users)) if users else None
    score = (
        ReviewScore(
            percent=round(100 * float(score_row.current_score) / float(score_row.max_score), 1) if float(score_row.max_score) > 0 else 0.0,
            current=float(score_row.current_score),
            max=float(score_row.max_score),
            average=float(score_row.average_score) if score_row.average_score is not None else None,
            taken_at=score_row.taken_at,
        )
        if score_row is not None
        else None
    )
    sat_checks = [c for c in (sat_row.checks if sat_row is not None else []) if isinstance(c, dict)]
    return ClientReview(
        client_id=client_id,
        client_name=clients.get(client_id),
        generated_at=now,
        window_days=WINDOW_DAYS,
        devices=facts,
        mfa=mfa,
        secure_score=score,
        alerts=ReviewAlerts(open=a[0], critical_open=a[1], high_open=a[2], opened_30d=a[3], closed_30d=a[4]),
        cases=ReviewCases(open=c[0], opened_30d=c[1], resolved_30d=c[2]),
        readiness=readiness(facts, mfa, score.percent if score else None, sat=sat_checks),
        tech_stack=tech_stack(shown, facts, has_microsoft_365=bool(users), sat=sat_checks),
        m365=m365_answers([c for c in (m365_row.checks if m365_row is not None else []) if isinstance(c, dict)], list(users)),
        m365_refreshed_at=m365_row.refreshed_at if m365_row is not None else None,
        vcio=(
            ReviewVcio(
                recommendations=VcioRecommendations(**(vcio_row.recommendations or {})),
                risks=[VcioRisk(**r) for r in (vcio_row.risks or []) if isinstance(r, dict)],
                refreshed_at=vcio_row.refreshed_at,
            )
            if vcio_row is not None
            else None
        ),
    )
