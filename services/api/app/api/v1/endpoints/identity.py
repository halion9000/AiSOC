"""Identity data CORE collects through CIPP: directory audit entries (scored for unusual behaviour) and each person's multi-factor state. COLLECTING AND SCORING ONLY: nothing here raises an alert.

- ``POST /api/v1/inbox/core-feed/{token}/directory-audits`` and ``.../mfa-users``: authenticated by the secret in the path, like the other core-feed endpoints; placed under the client the CIPP customer
  is mapped to (a customer not mapped yet is counted and skipped, and arrives again after the mapping).
- ``GET /api/v1/identity/mfa-summary`` and ``GET /api/v1/identity/mfa-users``: who has no Multi-Factor, per client.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.devices import UnmappedClient
from app.api.v1.endpoints.inbox_core_feed import _verify_core_feed_token
from app.api.v1.endpoints.signins import targets_by_tenant
from app.db.rls_scope import acting_as_tenant
from app.db.rls_sessions import adopt_tenant
from app.models.signin import DirectoryAuditEvent, IdentityMfaUser
from app.models.tenant import Tenant
from app.services.directory_scoring import directory_features, sensitivity_of
from app.services.signin_scoring import HISTORY_DAYS, score_events

LOG = logging.getLogger(__name__)

ingest_router = APIRouter(prefix="/inbox", tags=["inbox-core-feed"])
router = APIRouter(prefix="/identity", tags=["identity"])

_VENDOR = r"^[a-z0-9][a-z0-9_-]{0,39}$"
MAX_AUDITS = 500
MAX_MFA_USERS = 1000
MAX_BACKLOG = 100
PRUNE_BATCH = 2000


def _utc(t: datetime) -> datetime:
    return t if t.tzinfo else t.replace(tzinfo=UTC)


# ---- directory audit entries ---------------------------------------------------------------------------------------------------------------------------


class DirectoryAuditIn(BaseModel):
    vendor_client_id: str | None = Field(default=None, max_length=200)
    id: str = Field(min_length=1, max_length=200)
    at: datetime
    actor: str = Field(min_length=1, max_length=320)
    actor_is_app: bool = False
    actor_ip: str | None = Field(default=None, max_length=64)
    activity: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=60)
    service: str | None = Field(default=None, max_length=80)
    success: bool = True
    reason: str | None = Field(default=None, max_length=200)
    target: str | None = Field(default=None, max_length=320)
    target_type: str | None = Field(default=None, max_length=40)


class DirectoryAuditsReport(BaseModel):
    vendor: str = Field(pattern=_VENDOR)
    items: list[DirectoryAuditIn] = Field(max_length=MAX_AUDITS)


class DirectoryAuditsResponse(BaseModel):
    accepted: int
    duplicates: int = 0
    unmapped: int = 0
    ignored: int = 0
    scored: int = 0
    anomalies: int = 0
    scoring: str = "ok"
    unmapped_clients: list[UnmappedClient] = Field(default_factory=list)


def _event_for(row: DirectoryAuditEvent) -> dict[str, Any]:
    return {
        "key": row.source_id,
        "tenant_id": row.tenant_id,
        "entity_id": row.actor.lower(),
        "event_type": "directory_change",
        "features": directory_features(
            occurred_at=_utc(row.occurred_at), activity=row.activity, success=row.success, actor=row.actor, target=row.target
        ),
        "source_event_id": row.source_id,
    }


async def apply_directory_audits(
    db: Any, owner: uuid.UUID, report: DirectoryAuditsReport, now: datetime | None = None
) -> DirectoryAuditsResponse:
    """Store the new entries under their clients and score the people's. The caller owns the transaction."""
    now = now or datetime.now(UTC)
    by_tenant, unmapped, ignored, waiting = await targets_by_tenant(db, owner, report)
    accepted = duplicates = scored = anomalies = 0
    statuses: list[str] = []
    for tid, items in by_tenant.items():
        async with acting_as_tenant(db, tid):
            ids = [i.id for i in items]
            existing = set(
                (
                    await db.execute(
                        select(DirectoryAuditEvent.source_id).where(
                            DirectoryAuditEvent.tenant_id == tid,
                            DirectoryAuditEvent.source == report.vendor,
                            DirectoryAuditEvent.source_id.in_(ids),
                        )
                    )
                )
                .scalars()
                .all()
            )
            rows: list[DirectoryAuditEvent] = []
            seen: set[str] = set()
            for it in sorted(items, key=lambda x: _utc(x.at)):
                if it.id in existing or it.id in seen:
                    duplicates += 1
                    continue
                seen.add(it.id)
                on_others = bool(it.target) and (it.target or "").lower() != it.actor.lower()
                rows.append(
                    DirectoryAuditEvent(
                        tenant_id=tid,
                        source=report.vendor,
                        source_id=it.id,
                        actor=it.actor,
                        actor_is_app=it.actor_is_app,
                        actor_ip=it.actor_ip,
                        activity=it.activity,
                        category=it.category,
                        service=it.service,
                        success=it.success,
                        reason=it.reason,
                        target=it.target,
                        target_type=it.target_type,
                        sensitivity=sensitivity_of(it.activity, on_others=on_others),
                        occurred_at=_utc(it.at),
                    )
                )
            db.add_all(rows)
            await db.flush()
            accepted += len(rows)
            people = [r for r in rows if not r.actor_is_app]
            outcome = await score_events([_event_for(r) for r in people])
            statuses.append(outcome.status)
            if outcome.status == "ok":
                by_id = {r.source_id: r for r in people}
                for sid, score in outcome.scored.items():
                    by_id[sid].scored_at = now
                    by_id[sid].anomaly_score = score
                for r in rows:
                    if r.actor_is_app:
                        r.scored_at = now  # an app has nothing to score: counted as handled
                scored += len(outcome.scored)
                anomalies += outcome.anomalies
                await _rescore_backlog(db, tid, report.vendor, now)
            await db.flush()
            await _prune_audits(db, tid, now)
    status = "ok" if all(s == "ok" for s in statuses) else ("not_configured" if "not_configured" in statuses else "unavailable")
    return DirectoryAuditsResponse(
        accepted=accepted,
        duplicates=duplicates,
        unmapped=unmapped,
        ignored=ignored,
        scored=scored,
        anomalies=anomalies,
        scoring=status,
        unmapped_clients=waiting,
    )


async def _rescore_backlog(db: Any, tid: uuid.UUID, source: str, now: datetime) -> None:
    """Score entries stored earlier that the UEBA service could not take at the time (oldest first, a few per request)."""
    pending = (
        (
            await db.execute(
                select(DirectoryAuditEvent)
                .where(
                    DirectoryAuditEvent.tenant_id == tid,
                    DirectoryAuditEvent.source == source,
                    DirectoryAuditEvent.scored_at.is_(None),
                    DirectoryAuditEvent.actor_is_app.is_(False),
                )
                .order_by(DirectoryAuditEvent.occurred_at)
                .limit(MAX_BACKLOG)
            )
        )
        .scalars()
        .all()
    )
    if not pending:
        return
    outcome = await score_events([{**_event_for(r), "key": str(r.id)} for r in pending])
    if outcome.status != "ok":
        return
    by_id = {str(r.id): r for r in pending}
    for key, score in outcome.scored.items():
        by_id[key].scored_at = now
        by_id[key].anomaly_score = score


async def _prune_audits(db: Any, tid: uuid.UUID, now: datetime) -> None:
    """Forget entries older than the history window (a bounded number per request)."""
    old = (
        (
            await db.execute(
                select(DirectoryAuditEvent.id)
                .where(DirectoryAuditEvent.tenant_id == tid, DirectoryAuditEvent.occurred_at < now - timedelta(days=HISTORY_DAYS))
                .limit(PRUNE_BATCH)
            )
        )
        .scalars()
        .all()
    )
    if old:
        await db.execute(delete(DirectoryAuditEvent).where(DirectoryAuditEvent.id.in_(old)))


@ingest_router.post("/core-feed/{tenant_token}/directory-audits", response_model=DirectoryAuditsResponse)
async def report_core_feed_directory_audits(tenant_token: str, body: DirectoryAuditsReport, db: DBSession) -> DirectoryAuditsResponse:
    """Record the identity-related directory audit entries a tool reports, under the client each belongs to, and have the UEBA service score the actors' new ones."""
    owner = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, owner)
    result = await apply_directory_audits(db, owner, body)
    await db.commit()
    return result


# ---- multi-factor state --------------------------------------------------------------------------------------------------------------------------------


class MfaUserIn(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    upn: str = Field(min_length=1, max_length=320)
    display_name: str | None = Field(default=None, max_length=255)
    enabled: bool = True
    user_type: str | None = Field(default=None, max_length=20)
    admin: bool = False
    licensed: bool = False
    registered: bool = False
    capable: bool = False
    per_user: str | None = Field(default=None, max_length=20)
    ca_enforced: bool = False
    security_defaults: bool = False
    methods: list[str] = Field(default_factory=list, max_length=8)


class MfaUsersReport(BaseModel):
    vendor: str = Field(pattern=_VENDOR)
    vendor_client_id: str = Field(min_length=1, max_length=200)
    snapshot_id: uuid.UUID = Field(description="One id for every chunk of one tenant's snapshot.")
    last: bool = Field(default=True, description="True on the final chunk: people not in this snapshot are then removed.")
    items: list[MfaUserIn] = Field(max_length=MAX_MFA_USERS)


class _MfaView:
    """Lets the shared client mapping place a report that belongs to one client, as a list of one item."""

    def __init__(self, report: MfaUsersReport) -> None:
        self.vendor = report.vendor
        self.items = [report]


class MfaUsersResponse(BaseModel):
    accepted: int
    unmapped: int = 0
    ignored: int = 0
    removed: int = 0
    unmapped_clients: list[UnmappedClient] = Field(default_factory=list)


async def apply_mfa_users(db: Any, owner: uuid.UUID, report: MfaUsersReport, now: datetime | None = None) -> MfaUsersResponse:
    """Store one client's snapshot (or a chunk of it); on the last chunk, people who are no longer listed are removed. The caller owns the transaction."""
    now = now or datetime.now(UTC)
    by_tenant, unmapped, ignored, waiting = await targets_by_tenant(db, owner, _MfaView(report))
    accepted = removed = 0
    for tid in by_tenant:
        async with acting_as_tenant(db, tid):
            if report.items:
                values = [
                    {
                        "tenant_id": tid,
                        "source": report.vendor,
                        "user_id": u.id,
                        "upn": u.upn.lower(),
                        "display_name": u.display_name,
                        "enabled": u.enabled,
                        "user_type": u.user_type,
                        "admin": u.admin,
                        "licensed": u.licensed,
                        "registered": u.registered,
                        "capable": u.capable,
                        "per_user": u.per_user,
                        "ca_enforced": u.ca_enforced,
                        "security_defaults": u.security_defaults,
                        "methods": ", ".join(u.methods)[:400] or None,
                        "snapshot_id": report.snapshot_id,
                        "refreshed_at": now,
                    }
                    for u in report.items
                ]
                stmt = pg_insert(IdentityMfaUser).values(values)
                update = {c: stmt.excluded[c] for c in values[0] if c not in ("tenant_id", "source", "user_id")}
                await db.execute(stmt.on_conflict_do_update(index_elements=["tenant_id", "source", "user_id"], set_=update))
                accepted += len(values)
            if report.last:
                res = await db.execute(
                    delete(IdentityMfaUser).where(
                        IdentityMfaUser.tenant_id == tid,
                        IdentityMfaUser.source == report.vendor,
                        IdentityMfaUser.snapshot_id != report.snapshot_id,
                    )
                )
                removed += res.rowcount or 0
    return MfaUsersResponse(accepted=accepted, unmapped=unmapped, ignored=ignored, removed=removed, unmapped_clients=waiting)


@ingest_router.post("/core-feed/{tenant_token}/mfa-users", response_model=MfaUsersResponse)
async def report_core_feed_mfa_users(tenant_token: str, body: MfaUsersReport, db: DBSession) -> MfaUsersResponse:
    """Record one client's multi-factor state (a snapshot, in chunks): people missing from the final chunk are removed."""
    owner = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, owner)
    result = await apply_mfa_users(db, owner, body)
    await db.commit()
    return result


def _counted(users: list[Any]) -> list[Any]:
    """The people who count: enabled member accounts with a licence (shared mailboxes and service accounts have none)."""
    return [u for u in users if u.enabled and u.licensed and (u.user_type or "Member").lower() == "member"]


def _required(u: Any) -> bool:
    """Something makes this person use their second factor: a conditional access policy, security defaults, or the per-user setting."""
    return bool(u.ca_enforced or u.security_defaults or (u.per_user or "").lower() in ("enforced", "enabled"))


def counts_for_mfa(users: list[Any]) -> dict[str, int]:
    """The numbers shown for one client's people: those with a second factor that is required, those who registered one that nothing requires, and those with none."""
    counted = _counted(users)
    with_mfa = [u for u in counted if u.registered and _required(u)]
    not_required = [u for u in counted if u.registered and not _required(u)]
    without = [u for u in counted if not u.registered]
    return {
        "people": len(counted),
        "with_mfa": len(with_mfa),
        "not_required": len(not_required),
        "without_mfa": len(without),
        "admins_without_mfa": len([u for u in without if u.admin]),
    }


class MfaClientSummary(BaseModel):
    client_id: uuid.UUID
    client_name: str | None
    people: int
    with_mfa: int
    # Registered a second factor, but nothing requires it: no conditional access policy, no per-user setting, no security defaults.
    not_required: int
    without_mfa: int
    admins_without_mfa: int
    refreshed_at: datetime | None = None


@router.get(
    "/mfa-summary", response_model=list[MfaClientSummary], summary="Per client: how many people have a Multi-Factor, and how many do not"
)
async def mfa_summary(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))], db: DBSession
) -> list[MfaClientSummary]:
    owner = current_user.tenant_id
    names = {r.id: r.name for r in (await db.execute(select(Tenant.id, Tenant.name).where(Tenant.parent_tenant_id == owner))).all()}
    out: list[MfaClientSummary] = []
    for tid in [owner, *names]:
        async with contextlib.nullcontext() if tid == owner else acting_as_tenant(db, tid):
            users = (await db.execute(select(IdentityMfaUser).where(IdentityMfaUser.tenant_id == tid))).scalars().all()
        if not users:
            continue
        out.append(
            MfaClientSummary(
                client_id=tid, client_name=names.get(tid), refreshed_at=max(u.refreshed_at for u in users), **counts_for_mfa(list(users))
            )
        )
    out.sort(key=lambda s: (-s.admins_without_mfa, -s.without_mfa, (s.client_name or "").lower()))
    return out


class MfaUserOut(BaseModel):
    upn: str
    display_name: str | None
    admin: bool
    registered: bool
    required: bool
    methods: str | None


@router.get(
    "/mfa-users",
    response_model=list[MfaUserOut],
    summary="The people of one client who have no Multi-Factor (or one that nothing requires)",
)
async def mfa_users(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
    client_id: uuid.UUID = Query(),
    which: str = Query(default="without", pattern="^(without|not_required)$"),
) -> list[MfaUserOut]:
    owner = current_user.tenant_id
    clients = set((await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == owner))).scalars().all())
    if client_id != owner and client_id not in clients:
        return []
    async with contextlib.nullcontext() if client_id == owner else acting_as_tenant(db, client_id):
        users = (
            (await db.execute(select(IdentityMfaUser).where(IdentityMfaUser.tenant_id == client_id).order_by(IdentityMfaUser.upn)))
            .scalars()
            .all()
        )
    picked = [u for u in _counted(list(users)) if (not u.registered if which == "without" else (u.registered and not _required(u)))]
    picked.sort(key=lambda u: (not u.admin, u.upn))
    return [
        MfaUserOut(upn=u.upn, display_name=u.display_name, admin=u.admin, registered=u.registered, required=_required(u), methods=u.methods)
        for u in picked[:500]
    ]


class IdentitySummary(BaseModel):
    audits_last_24h: int
    audits_scored_last_24h: int
    audits_unscored: int
    newest_received: datetime | None = None


@router.get("/summary", response_model=IdentitySummary, summary="How many identity changes were collected and scored in the last 24 hours")
async def identity_summary(current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))], db: DBSession) -> IdentitySummary:
    owner = current_user.tenant_id
    tenants = [owner, *(await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == owner))).scalars().all()]
    since = datetime.now(UTC) - timedelta(hours=24)
    total = scored = unscored = 0
    newest: datetime | None = None
    for tid in tenants:
        async with contextlib.nullcontext() if tid == owner else acting_as_tenant(db, tid):
            row = (
                await db.execute(
                    select(
                        func.count(),
                        func.count().filter(DirectoryAuditEvent.scored_at.is_not(None)),
                        func.max(DirectoryAuditEvent.received_at),
                    ).where(and_(DirectoryAuditEvent.tenant_id == tid, DirectoryAuditEvent.occurred_at >= since))
                )
            ).one()
            pending = (
                await db.execute(
                    select(func.count())
                    .select_from(DirectoryAuditEvent)
                    .where(DirectoryAuditEvent.tenant_id == tid, DirectoryAuditEvent.scored_at.is_(None))
                )
            ).scalar_one()
        total += row[0]
        scored += row[1]
        unscored += pending
        if row[2] is not None and (newest is None or row[2] > newest):
            newest = row[2]
    return IdentitySummary(audits_last_24h=total, audits_scored_last_24h=scored, audits_unscored=unscored, newest_received=newest)


class ScoredChange(BaseModel):
    client_id: uuid.UUID
    client_name: str | None
    actor: str
    actor_is_app: bool
    activity: str
    category: str
    target: str | None
    success: bool
    sensitivity: int
    occurred_at: datetime
    score: float


@router.get(
    "/top",
    response_model=list[ScoredChange],
    summary="The highest-scoring identity changes of the last days, across clients (nothing alerts on these yet)",
)
async def top_changes(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
    days: int = Query(default=7, ge=1, le=45),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[ScoredChange]:
    owner = current_user.tenant_id
    children = (await db.execute(select(Tenant.id, Tenant.name).where(Tenant.parent_tenant_id == owner))).all()
    names: dict[uuid.UUID, str | None] = {owner: None, **dict(children)}
    since = datetime.now(UTC) - timedelta(days=days)
    found: list[ScoredChange] = []
    for tid, name in names.items():
        async with contextlib.nullcontext() if tid == owner else acting_as_tenant(db, tid):
            rows = (
                (
                    await db.execute(
                        select(DirectoryAuditEvent)
                        .where(
                            DirectoryAuditEvent.tenant_id == tid,
                            DirectoryAuditEvent.occurred_at >= since,
                            DirectoryAuditEvent.anomaly_score.is_not(None),
                        )
                        .order_by(DirectoryAuditEvent.anomaly_score.desc())
                        .limit(limit)
                    )
                )
                .scalars()
                .all()
            )
        found.extend(
            ScoredChange(
                client_id=tid,
                client_name=name,
                actor=r.actor,
                actor_is_app=r.actor_is_app,
                activity=r.activity,
                category=r.category,
                target=r.target,
                success=r.success,
                sensitivity=r.sensitivity,
                occurred_at=r.occurred_at,
                score=float(r.anomaly_score or 0),
            )
            for r in rows
        )
    found.sort(key=lambda c: (-c.score, c.occurred_at))
    return found[:limit]
