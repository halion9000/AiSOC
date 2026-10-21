"""A client review on one page: tool coverage, Multi-Factor, Microsoft Secure Score, the last 30 days of alerts and cases, and a cyber-insurance readiness checklist. Read-only; every number comes
from data AiSOC already holds, and what it does not hold is reported as unknown rather than guessed.

``GET /api/v1/client-review/{client_id}``. For a quarterly business review or a cyber-insurance questionnaire; the checklist answers are evidence from the connected tools, not a certification.
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, bindparam, func, select, text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.alerts import FINISHED_STATUSES
from app.api.v1.endpoints.client_posture import devices_part
from app.api.v1.endpoints.devices import _load_cached, _master_of, _scope, rollup_of
from app.api.v1.endpoints.identity import counts_for_mfa
from app.db.rls_scope import acting_as_tenant
from app.models.alert import Alert
from app.models.signin import IdentityMfaUser, IdentitySecureScore
from app.models.tenant import Tenant
from app.services.client_review import DeviceFacts, Readiness, device_facts, readiness

router = APIRouter(prefix="/client-review", tags=["posture"])

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


@router.get("/{client_id}", response_model=ClientReview, summary="One client's coverage, identity, alerts and cases for a review, with a cyber-insurance readiness checklist")
async def client_review(client_id: uuid.UUID, current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))], db: DBSession) -> ClientReview:
    owner = current_user.tenant_id
    if client_id != owner:
        found = (await db.execute(select(Tenant.id).where(Tenant.id == client_id, Tenant.parent_tenant_id == owner))).scalar_one_or_none()
        if found is None:
            raise HTTPException(status_code=404, detail="Client not found")
    scope, clients = await _scope(db, owner, client_id)
    master = _master_of(await db.get(Tenant, owner))
    shown = [d for d in await _load_cached(db, owner, scope, clients, master) if d.hidden_since is None]
    rolled = devices_part(rollup_of(shown), client_id)
    facts = device_facts(shown, stale_agents=rolled.stale_agents, offline=rolled.offline)

    now = datetime.now(UTC)
    since = now - timedelta(days=WINDOW_DAYS)
    async with contextlib.nullcontext() if client_id == owner else acting_as_tenant(db, client_id):
        users = (await db.execute(select(IdentityMfaUser).where(IdentityMfaUser.tenant_id == client_id))).scalars().all()
        score_row = (await db.execute(select(IdentitySecureScore).where(IdentitySecureScore.tenant_id == client_id))).scalars().first()
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
        readiness=readiness(facts, mfa, score.percent if score else None),
    )
