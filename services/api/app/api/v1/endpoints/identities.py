"""The Identities page: every person (e-mail identity) the connected tools know, one row each, with the tools that know them, their multi-factor state and the alerts that name them.

``GET /identities`` lists them (filters and sorting), ``GET /identities/detail`` is one person with their alerts and recent sign-ins, and ``POST /inbox/core-feed/{token}/identities`` is where CORE reports the
people of each tool (Datto SaaS Protection, Dropsuite, Huntress SAT, HaloPSA...). Microsoft 365 people come from the list CIPP already fills. Read only; nothing here changes a person in any tool.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.alerts import FINISHED_STATUSES
from app.api.v1.endpoints.devices import DevicesResponse, UnmappedClient, _scope
from app.api.v1.endpoints.inbox_core_feed import _verify_core_feed_token
from app.db.rls_scope import acting_as_tenant, cross_tenant_reads
from app.db.rls_sessions import adopt_tenant
from app.models.alert import Alert
from app.models.identity_source import IdentitySource
from app.models.signin import IdentityMfaUser, SigninEvent
from app.services.identity_people import (
    MICROSOFT,
    SORTS,
    Person,
    attach_alerts,
    build_people,
    filter_people,
    normalize_email,
    sort_people,
)

router = APIRouter(prefix="/identities", tags=["identities"])
ingest_router = APIRouter(prefix="/inbox", tags=["inbox-core-feed"])

ALERT_LOOKBACK_DAYS = 90
MAX_ALERTS_READ = 20000


# ---- reading -----------------------------------------------------------------------------------------------------------------------------------------------


class SourceOut(BaseModel):
    vendor: str
    external_id: str
    enabled: bool | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class PersonOut(BaseModel):
    key: str
    client_id: uuid.UUID
    client_name: str | None = None
    email: str
    display_name: str | None = None
    kind: str
    enabled: bool | None = None
    admin: bool = False
    licensed: bool | None = None
    mfa: str
    mfa_methods: str | None = None
    tools: list[str]
    sources: list[SourceOut] = Field(default_factory=list)
    open_alerts: int = 0
    top_severity: str | None = None


class IdentitySummary(BaseModel):
    total: int
    with_alerts: int
    without_mfa: int
    admins: int
    disabled: int
    # People known to only one tool (so no other tool has them): the ones to look at when a tool is missing someone.
    in_one_tool: int
    tools: dict[str, int] = Field(default_factory=dict)


class IdentityList(BaseModel):
    summary: IdentitySummary
    items: list[PersonOut]
    total: int
    page: int
    page_size: int
    pages: int


def _out(p: Person, with_sources: bool = False) -> PersonOut:
    return PersonOut(
        key=p.key,
        client_id=p.tenant_id,
        client_name=p.client_name,
        email=p.email,
        display_name=p.display_name,
        kind=p.kind,
        enabled=p.enabled,
        admin=p.admin,
        licensed=p.licensed,
        mfa=p.mfa,
        mfa_methods=p.mfa_methods,
        tools=p.vendors,
        sources=[SourceOut(vendor=s.vendor, external_id=s.external_id, enabled=s.enabled, details=s.details) for s in p.sources] if with_sources else [],
        open_alerts=p.open_alerts,
        top_severity=p.top_severity,
    )


async def _people(db: Any, owner: uuid.UUID, client_id: uuid.UUID | None) -> tuple[list[Person], dict[str, list[Any]]]:
    """Every person in scope with alerts attached, and the alerts by person."""
    scope, clients = await _scope(db, owner, client_id)
    names = dict(clients)
    names.setdefault(owner, "This organization")
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=ALERT_LOOKBACK_DAYS)
    async with cross_tenant_reads(db):
        users = (await db.execute(select(IdentityMfaUser).where(IdentityMfaUser.tenant_id.in_(scope), IdentityMfaUser.source == MICROSOFT))).scalars().all()
        sources = (await db.execute(select(IdentitySource).where(IdentitySource.tenant_id.in_(scope)))).scalars().all()
        alerts = (
            (
                await db.execute(
                    select(Alert)
                    .where(Alert.tenant_id.in_(scope), Alert.status.notin_(FINISHED_STATUSES), Alert.created_at >= cutoff)
                    .order_by(Alert.created_at.desc())
                    .limit(MAX_ALERTS_READ)
                )
            )
            .scalars()
            .all()
        )
    people = build_people(names, list(users), list(sources), now)
    return people, attach_alerts(people, [a for a in alerts if a.affected_users])


def summarize(people: list[Person]) -> IdentitySummary:
    tools: dict[str, int] = {}
    for p in people:
        for v in p.vendors:
            tools[v] = tools.get(v, 0) + 1
    return IdentitySummary(
        total=len(people),
        with_alerts=sum(1 for p in people if p.open_alerts > 0),
        without_mfa=sum(1 for p in people if p.mfa == "none" and p.enabled is not False),
        admins=sum(1 for p in people if p.admin),
        disabled=sum(1 for p in people if p.enabled is False),
        in_one_tool=sum(1 for p in people if len(p.vendors) == 1),
        tools=dict(sorted(tools.items())),
    )


@router.get("", response_model=IdentityList, dependencies=[Depends(require_permission("alerts:read"))])
async def list_identities(
    user: AuthUser,
    db: DBSession,
    page: int = Query(default=1, ge=1, le=100_000),
    page_size: int = Query(default=50, ge=1, le=200),
    client_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    source: str | None = Query(default=None, pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$", description="Only people this tool knows."),
    only_in: str | None = Query(default=None, pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$", description="Only people known to this one tool and no other."),
    has_alerts: bool = Query(default=False),
    mfa: str | None = Query(default=None, pattern="^(covered|registered_not_required|none|unknown)$"),
    admin: bool = Query(default=False),
    disabled: bool = Query(default=False),
    kind: str | None = Query(default=None, pattern="^(user|guest|shared|other)$"),
    sort: str = Query(default="alerts"),
) -> IdentityList:
    """The people across the connected tools, with the tools that know each, their multi-factor state and their open alerts. The summary counts everyone in scope, whatever the filters."""
    if sort not in SORTS:
        raise HTTPException(status_code=422, detail=f"sort must be one of: {', '.join(SORTS)}")
    people, _ = await _people(db, user.tenant_id, client_id)
    rows = sort_people(
        filter_people(people, search=search, source=source, only_in=only_in, has_alerts=has_alerts, mfa=mfa, admin=admin, disabled=disabled, kind=kind),
        sort,
    )
    total = len(rows)
    start = (page - 1) * page_size
    return IdentityList(
        summary=summarize(people),
        items=[_out(p) for p in rows[start : start + page_size]],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


class AlertBrief(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    status: str
    source: str | None = None
    created_at: datetime | None = None


class SigninBrief(BaseModel):
    last_30_days: int = 0
    failed: int = 0
    unusual: int = 0
    countries: list[str] = Field(default_factory=list)
    last_at: datetime | None = None


class PersonDetail(BaseModel):
    person: PersonOut
    alerts: list[AlertBrief]
    signins: SigninBrief


@router.get("/detail", response_model=PersonDetail, dependencies=[Depends(require_permission("alerts:read"))])
async def identity_detail(user: AuthUser, db: DBSession, client_id: uuid.UUID, email: Annotated[str, Query(max_length=320)]) -> PersonDetail:
    """One person: every tool's record of them, the open alerts that name them, and a summary of their recent sign-ins."""
    wanted = normalize_email(email)
    if wanted is None:
        raise HTTPException(status_code=422, detail="That is not an e-mail address")
    people, alerts = await _people(db, user.tenant_id, client_id)
    found = next((p for p in people if p.email == wanted and p.tenant_id == client_id), None)
    if found is None:
        raise HTTPException(status_code=404, detail="No such person")
    since = datetime.now(UTC) - timedelta(days=30)
    async with cross_tenant_reads(db):
        events = (
            (await db.execute(select(SigninEvent).where(SigninEvent.tenant_id == client_id, SigninEvent.user_principal.ilike(wanted), SigninEvent.occurred_at >= since)))
            .scalars()
            .all()
        )
    brief = SigninBrief(
        last_30_days=len(events),
        failed=sum(1 for e in events if not e.success),
        unusual=sum(1 for e in events if e.anomaly_score is not None),
        countries=sorted({e.country for e in events if e.country})[:12],
        last_at=max((e.occurred_at for e in events), default=None),
    )
    rows = alerts.get(found.key, [])[:25]
    return PersonDetail(
        person=_out(found, with_sources=True),
        alerts=[
            AlertBrief(
                id=a.id,
                title=a.title,
                severity=a.severity,
                status=a.status,
                source=(a.raw_event or {}).get("source") if isinstance(a.raw_event, dict) else None,
                created_at=a.created_at,
            )
            for a in rows
        ],
        signins=brief,
    )


# ---- CORE reports the people of each tool ------------------------------------------------------------------------------------------------------------------


class IdentityIn(BaseModel):
    vendor_client_id: str | None = Field(default=None, max_length=200)
    external_id: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=320)
    display_name: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None
    kind: str = Field(default="user", pattern="^(user|guest|shared|other)$")
    details: dict[str, Any] = Field(default_factory=dict)


class IdentitiesReport(BaseModel):
    vendor: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")
    items: list[IdentityIn] = Field(max_length=1000)


class _View:
    """Lets the shared client mapping place a report's people (it reads ``vendor`` and ``items``)."""

    def __init__(self, report: IdentitiesReport) -> None:
        self.vendor = report.vendor
        self.items = report.items


async def apply_identities(db: Any, owner: uuid.UUID, report: IdentitiesReport) -> DevicesResponse:
    """Store each person under the client their tool client id is mapped to; skip (and count) those whose client is not mapped yet. The caller owns the transaction."""
    from app.api.v1.endpoints.signins import targets_by_tenant

    by_tenant, unmapped, ignored, waiting = await targets_by_tenant(db, owner, _View(report))  # type: ignore[arg-type]
    now = datetime.now(UTC)
    accepted = 0
    for tid, items in by_tenant.items():
        async with acting_as_tenant(db, tid):
            for it in items:
                email = normalize_email(it.email)
                if email is None:
                    continue
                values = {
                    "tenant_id": tid,
                    "vendor": report.vendor,
                    "external_id": it.external_id,
                    "email": email,
                    "display_name": it.display_name,
                    "enabled": it.enabled,
                    "kind": it.kind,
                    "details": it.details,
                    "refreshed_at": now,
                }
                stmt = pg_insert(IdentitySource).values(values)
                update = {c: stmt.excluded[c] for c in values if c not in ("tenant_id", "vendor", "external_id")}
                await db.execute(stmt.on_conflict_do_update(index_elements=["tenant_id", "vendor", "external_id"], set_=update))
                accepted += 1
    return DevicesResponse(
        accepted=accepted,
        unmapped=unmapped,
        ignored=ignored,
        unmapped_clients=[UnmappedClient(vendor_client_id=w.vendor_client_id, name=w.name, devices=w.devices) for w in waiting],
    )


@ingest_router.post("/core-feed/{tenant_token}/identities", response_model=DevicesResponse)
async def report_core_feed_identities(tenant_token: str, body: IdentitiesReport, db: DBSession) -> DevicesResponse:
    """Record the people a tool reports, under the client each belongs to."""
    owner = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, owner)
    result = await apply_identities(db, owner, body)
    await db.commit()
    return result

