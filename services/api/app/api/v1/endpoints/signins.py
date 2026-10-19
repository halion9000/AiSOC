"""Sign-in events: CORE posts the sign-ins it read through CIPP; AiSOC stores each once and has the UEBA service score it. COLLECTING AND SCORING ONLY: nothing here raises an alert.

``POST /api/v1/inbox/core-feed/{token}/signins`` (authenticated by the secret in the path, like the other core-feed endpoints). A sign-in is placed under the client its vendor client id
(the CIPP customer id) is mapped to; one whose client is not mapped yet is counted and skipped, and arrives again after the mapping.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.devices import UnmappedClient
from app.api.v1.endpoints.inbox_core_feed import _verify_core_feed_token
from app.db.rls_scope import acting_as_tenant
from app.db.rls_sessions import adopt_tenant
from app.models.client_alias import ClientAlias
from app.models.signin import SigninEvent
from app.models.tenant import Tenant
from app.services.signin_scoring import HISTORY_DAYS, History, score_events, signin_features

LOG = logging.getLogger(__name__)

ingest_router = APIRouter(prefix="/inbox", tags=["inbox-core-feed"])
router = APIRouter(prefix="/signins", tags=["signins"])

_VENDOR = r"^[a-z0-9][a-z0-9_-]{0,39}$"
MAX_ITEMS = 500
# Scored per request: the new ones, then older ones that an earlier request could not get scored (the service was down), oldest first.
MAX_BACKLOG = 100
PRUNE_BATCH = 2000


class SignInIn(BaseModel):
    vendor_client_id: str | None = Field(
        default=None,
        max_length=200,
        description="The tool's id for the person's client (CIPP: the customer id); mapped to a client tenant like alerts are.",
    )
    id: str = Field(min_length=1, max_length=200, description="The sign-in's own id; the same one posted twice is stored once.")
    at: datetime
    user: str = Field(min_length=1, max_length=320)
    display_name: str | None = Field(default=None, max_length=255)
    ip: str | None = Field(default=None, max_length=64)
    country: str | None = Field(default=None, max_length=16)
    city: str | None = Field(default=None, max_length=120)
    app: str | None = Field(default=None, max_length=160)
    client_app: str | None = Field(default=None, max_length=100)
    success: bool = True
    error_code: int | None = None
    interactive: bool = True
    mfa: bool | None = None
    risk: str | None = Field(default=None, max_length=20)
    conditional_access: str | None = Field(default=None, max_length=40)


class SignInsReport(BaseModel):
    vendor: str = Field(pattern=_VENDOR, description="The source, e.g. ``cipp``.")
    items: list[SignInIn] = Field(max_length=MAX_ITEMS)


class SignInsResponse(BaseModel):
    accepted: int
    duplicates: int = 0
    unmapped: int = 0
    ignored: int = 0
    scored: int = 0
    anomalies: int = 0
    # ok / unavailable (the UEBA service could not be reached: what was stored stays, unscored) / not_configured (no UEBA token set)
    scoring: str = "ok"
    unmapped_clients: list[UnmappedClient] = Field(default_factory=list)


def _utc(t: datetime) -> datetime:
    return t if t.tzinfo else t.replace(tzinfo=UTC)


async def targets_by_tenant(
    db: Any, owner: uuid.UUID, report: SignInsReport
) -> tuple[dict[uuid.UUID, list[SignInIn]], int, int, list[UnmappedClient]]:
    """The tenant each sign-in belongs to, with counts of the ones left out because their client is ignored or not mapped yet."""
    rows = (await db.execute(select(ClientAlias).where(ClientAlias.tenant_id == owner))).scalars().all()
    known = {(a.vendor, a.vendor_client_id): a for a in rows}
    children = set((await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == owner))).scalars().all())
    by_tenant: dict[uuid.UUID, list[SignInIn]] = {}
    waiting: dict[str, int] = {}
    unmapped = ignored = 0
    for item in report.items:
        if item.vendor_client_id:
            alias = known.get((report.vendor, item.vendor_client_id))
            if alias is not None and alias.ignored:
                ignored += 1
                continue
            target = alias.child_tenant_id if alias is not None else None
            if target is None or target not in children:
                unmapped += 1
                waiting[item.vendor_client_id] = waiting.get(item.vendor_client_id, 0) + 1
                continue
        else:
            target = owner
        by_tenant.setdefault(target, []).append(item)
    waiting_list = [
        UnmappedClient(
            vendor_client_id=vid, name=known[(report.vendor, vid)].vendor_client_name if (report.vendor, vid) in known else None, devices=n
        )
        for vid, n in sorted(waiting.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    ]
    return by_tenant, unmapped, ignored, waiting_list


async def _history(db: Any, tenant_id: uuid.UUID, source: str, users: set[str], now: datetime) -> dict[str, History]:
    """What is already stored about these people: the countries and addresses of their sign-ins in the last HISTORY_DAYS days."""
    out: dict[str, History] = {u: History() for u in users}
    if not users:
        return out
    cutoff = now - timedelta(days=HISTORY_DAYS)
    rows = (
        await db.execute(
            select(SigninEvent.user_principal, SigninEvent.country, SigninEvent.ip_address)
            .where(
                SigninEvent.tenant_id == tenant_id,
                SigninEvent.source == source,
                SigninEvent.user_principal.in_(users),
                SigninEvent.occurred_at >= cutoff,
            )
            .distinct()
        )
    ).all()
    for user, country, ip in rows:
        out[user].remember(country, ip)
    return out


async def apply_signins(db: Any, owner: uuid.UUID, report: SignInsReport, now: datetime | None = None) -> SignInsResponse:
    """Store the new sign-ins under their clients and score them. The caller owns the transaction; scoring marks rows scored inside it."""
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
                        select(SigninEvent.source_id).where(
                            SigninEvent.tenant_id == tid, SigninEvent.source == report.vendor, SigninEvent.source_id.in_(ids)
                        )
                    )
                )
                .scalars()
                .all()
            )
            fresh: dict[str, SignInIn] = {}
            for it in sorted(items, key=lambda x: _utc(x.at)):
                if it.id in existing or it.id in fresh:
                    duplicates += 1
                else:
                    fresh[it.id] = it
            history = await _history(db, tid, report.vendor, {i.user.lower() for i in fresh.values()}, now)
            rows: list[SigninEvent] = []
            to_score: list[dict[str, Any]] = []
            for it in fresh.values():
                user = it.user.lower()
                h = history[user]
                features = signin_features(
                    occurred_at=_utc(it.at),
                    success=it.success,
                    mfa=it.mfa,
                    interactive=it.interactive,
                    risk=it.risk,
                    country=it.country,
                    ip=it.ip,
                    history=h,
                )
                row = SigninEvent(
                    tenant_id=tid,
                    source=report.vendor,
                    source_id=it.id,
                    user_principal=user,
                    display_name=it.display_name,
                    ip_address=it.ip,
                    country=it.country,
                    city=it.city,
                    app=it.app,
                    client_app=it.client_app,
                    success=it.success,
                    error_code=it.error_code,
                    interactive=it.interactive,
                    mfa=it.mfa,
                    risk=it.risk,
                    conditional_access=it.conditional_access,
                    occurred_at=_utc(it.at),
                )
                rows.append(row)
                to_score.append(
                    {
                        "key": it.id,
                        "tenant_id": tid,
                        "entity_id": user,
                        "event_type": "login",
                        "features": features,
                        "source_event_id": it.id,
                    }
                )
                h.remember(it.country, it.ip)
            db.add_all(rows)
            await db.flush()
            accepted += len(rows)
            outcome = await score_events(to_score)
            statuses.append(outcome.status)
            if outcome.status == "ok":
                by_source = {r.source_id: r for r in rows}
                for sid, score in outcome.scored.items():
                    by_source[sid].scored_at = now
                    by_source[sid].anomaly_score = score
                scored += len(outcome.scored)
                anomalies += outcome.anomalies
                await _rescore_backlog(db, tid, report.vendor, now)
            await db.flush()
            await _prune(db, tid, now)
    status = "ok" if all(s == "ok" for s in statuses) else ("not_configured" if "not_configured" in statuses else "unavailable")
    return SignInsResponse(
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
    """Score sign-ins stored earlier that the UEBA service could not take at the time (oldest first, a few per request), judged against what was known about the person then is not possible, so
    only their own features are used with the history as of now; they are rare, and this is only to keep the baseline complete."""
    pending = (
        (
            await db.execute(
                select(SigninEvent)
                .where(SigninEvent.tenant_id == tid, SigninEvent.source == source, SigninEvent.scored_at.is_(None))
                .order_by(SigninEvent.occurred_at)
                .limit(MAX_BACKLOG)
            )
        )
        .scalars()
        .all()
    )
    if not pending:
        return
    events = [
        {
            "key": str(r.id),
            "tenant_id": tid,
            "entity_id": r.user_principal,
            "event_type": "login",
            "features": signin_features(
                occurred_at=_utc(r.occurred_at),
                success=r.success,
                mfa=r.mfa,
                interactive=r.interactive,
                risk=r.risk,
                country=r.country,
                ip=r.ip_address,
                history=History(),
            ),
            "source_event_id": r.source_id,
        }
        for r in pending
    ]
    outcome = await score_events(events)
    if outcome.status != "ok":
        return
    by_id = {str(r.id): r for r in pending}
    for key, score in outcome.scored.items():
        by_id[key].scored_at = now
        by_id[key].anomaly_score = score


async def _prune(db: Any, tid: uuid.UUID, now: datetime) -> None:
    """Forget sign-ins older than the history window (a bounded number per request)."""
    old = (
        (
            await db.execute(
                select(SigninEvent.id)
                .where(SigninEvent.tenant_id == tid, SigninEvent.occurred_at < now - timedelta(days=HISTORY_DAYS))
                .limit(PRUNE_BATCH)
            )
        )
        .scalars()
        .all()
    )
    if old:
        await db.execute(delete(SigninEvent).where(SigninEvent.id.in_(old)))


@ingest_router.post("/core-feed/{tenant_token}/signins", response_model=SignInsResponse)
async def report_core_feed_signins(tenant_token: str, body: SignInsReport, db: DBSession) -> SignInsResponse:
    """Record the sign-ins a tool reports, under the client each belongs to, and have the UEBA service score the new ones."""
    owner = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, owner)
    result = await apply_signins(db, owner, body)
    await db.commit()
    return result


class SigninSummary(BaseModel):
    last_24h: int
    failed_last_24h: int
    scored_last_24h: int
    unscored: int
    users_last_24h: int
    newest_received: datetime | None = None


@router.get("/summary", response_model=SigninSummary, summary="How many sign-ins were collected and scored in the last 24 hours")
async def signin_summary(current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))], db: DBSession) -> SigninSummary:
    owner = current_user.tenant_id
    tenants = [owner, *(await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == owner))).scalars().all()]
    since = datetime.now(UTC) - timedelta(hours=24)
    total = failed = scored = unscored = users = 0
    newest: datetime | None = None
    for tid in tenants:
        async with contextlib.nullcontext() if tid == owner else acting_as_tenant(db, tid):
            row = (
                await db.execute(
                    select(
                        func.count(),
                        func.count().filter(SigninEvent.success.is_(False)),
                        func.count().filter(SigninEvent.scored_at.is_not(None)),
                        func.count(func.distinct(SigninEvent.user_principal)),
                        func.max(SigninEvent.received_at),
                    ).where(SigninEvent.tenant_id == tid, SigninEvent.occurred_at >= since)
                )
            ).one()
            pending = (
                await db.execute(
                    select(func.count()).select_from(SigninEvent).where(SigninEvent.tenant_id == tid, SigninEvent.scored_at.is_(None))
                )
            ).scalar_one()
        total += row[0]
        failed += row[1]
        scored += row[2]
        users += row[3]
        unscored += pending
        if row[4] is not None and (newest is None or row[4] > newest):
            newest = row[4]
    return SigninSummary(
        last_24h=total, failed_last_24h=failed, scored_last_24h=scored, unscored=unscored, users_last_24h=users, newest_received=newest
    )
