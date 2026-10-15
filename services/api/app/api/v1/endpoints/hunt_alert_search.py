"""Hunt search over the alerts AiSOC already holds: POST /hunt/search.

This used to be served by the agents service, which has no event store and answered every search with a 501. The only real telemetry here is the
alerts CORE forwards, so the search runs over those: the caller's own tenant and its client tenants. It is not KQL/Lucene/SPL. It understands plain
words, "quoted phrases", ``field:value`` and a leading ``-`` for "not". Fields: severity, status, source (the tool), host, user, ip, tag, title, client.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import Text, and_, cast, func, not_, or_, select

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.db.rls_scope import acting_as_tenant
from app.models.alert import Alert
from app.models.tenant import Tenant

router = APIRouter(prefix="/hunt", tags=["hunt"])

FIELDS = ("severity", "status", "source", "host", "user", "ip", "tag", "title", "client")
_TOKEN = re.compile(r'(?P<neg>-)?(?:(?P<field>[A-Za-z_]+):)?(?:"(?P<quoted>[^"]*)"|(?P<word>\S+))')
MAX_TERMS = 12
PER_TENANT_CAP = 300


@dataclass(frozen=True)
class Term:
    value: str
    field: str | None = None
    negate: bool = False


def parse_query(query: str) -> list[Term]:
    """Split a search into terms. An unknown ``field:`` is kept as plain text, so ``C:\\Windows`` still searches for what was typed."""
    terms: list[Term] = []
    for m in _TOKEN.finditer(query or ""):
        value = m.group("quoted") if m.group("quoted") is not None else m.group("word")
        if not value:
            continue
        field = (m.group("field") or "").lower() or None
        if field is not None and field not in FIELDS:
            value, field = f"{m.group('field')}:{value}", None
        if field is None and value.upper() in {"AND"}:
            continue
        terms.append(Term(value=value, field=field, negate=bool(m.group("neg"))))
    return terms[:MAX_TERMS]


def _like(column: Any, value: str) -> Any:
    return cast(column, Text).ilike(f"%{value}%")


def condition(term: Term) -> Any:
    v = term.value
    if term.field == "severity":
        cond = func.lower(Alert.severity) == v.lower()
    elif term.field == "status":
        cond = func.lower(Alert.status) == v.lower()
    elif term.field == "source":
        cond = or_(_like(Alert.connector_type, v), _like(Alert.raw_event["source"], v))
    elif term.field == "host":
        cond = _like(Alert.affected_hosts, v)
    elif term.field == "user":
        cond = _like(Alert.affected_users, v)
    elif term.field == "ip":
        cond = _like(Alert.affected_ips, v)
    elif term.field == "tag":
        cond = _like(Alert.tags, v)
    elif term.field == "title":
        cond = Alert.title.ilike(f"%{v}%")
    else:
        cond = or_(
            Alert.title.ilike(f"%{v}%"),
            Alert.description.ilike(f"%{v}%"),
            _like(Alert.affected_hosts, v),
            _like(Alert.affected_users, v),
            _like(Alert.affected_ips, v),
            _like(Alert.tags, v),
            _like(Alert.connector_type, v),
        )
    return not_(cond) if term.negate else cond


class HuntQuery(BaseModel):
    query: str = Field(default="", max_length=2000)
    language: str | None = None  # accepted so the existing client works; the syntax is the same whatever is chosen
    startTime: datetime | None = None
    endTime: datetime | None = None
    limit: int = Field(default=100, ge=1, le=500)


class HuntHit(BaseModel):
    id: str
    timestamp: str
    source: str
    severity: str | None = None
    fields: dict[str, Any]
    highlight: str | None = None


class HuntResponse(BaseModel):
    total: int
    took: int
    hits: list[HuntHit]


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=UTC)


def _hit(a: Alert, client_name: str | None) -> HuntHit:
    raw = a.raw_event if isinstance(a.raw_event, dict) else {}
    source = str(raw.get("source") or a.connector_type or "alert")
    return HuntHit(
        id=str(a.id),
        timestamp=(a.event_time or a.created_at).isoformat(),
        source=source,
        severity=a.severity,
        highlight=a.title,
        fields={
            "title": a.title,
            "status": a.status,
            "client": client_name,
            "hosts": a.affected_hosts or [],
            "users": a.affected_users or [],
            "ips": a.affected_ips or [],
            "tags": a.tags or [],
        },
    )


@router.post("/search", response_model=HuntResponse, dependencies=[Depends(require_permission("alerts:read"))])
async def hunt_search(body: HuntQuery, user: AuthUser, db: TenantDBSession) -> HuntResponse:
    """Search the caller's alerts, and those of the caller's client tenants, newest first."""
    started = time.monotonic()
    children = (await db.execute(select(Tenant.id, Tenant.name).where(Tenant.parent_tenant_id == user.tenant_id))).all()
    names: dict[uuid.UUID, str] = {c.id: c.name for c in children}
    own = (await db.execute(select(Tenant.name).where(Tenant.id == user.tenant_id))).scalar_one_or_none()
    names[user.tenant_id] = own or "this workspace"
    terms = parse_query(body.query)
    start, end = _aware(body.startTime), _aware(body.endTime)

    hits: list[tuple[datetime, HuntHit]] = []
    total = 0
    for tid in names:
        clauses = [Alert.tenant_id == tid]
        for t in terms:
            if t.field == "client":
                match = [i for i, n in names.items() if t.value.lower() in n.lower()]
                clauses.append((not_ if t.negate else (lambda c: c))(Alert.tenant_id.in_(match)))
            else:
                clauses.append(condition(t))
        if start:
            clauses.append(Alert.event_time >= start)
        if end:
            clauses.append(Alert.event_time <= end)
        async with acting_as_tenant(db, tid):
            count = await db.scalar(select(func.count()).select_from(Alert).where(and_(*clauses)))
            if not count:
                continue
            total += int(count)
            rows = (
                (
                    await db.execute(
                        select(Alert).where(and_(*clauses)).order_by(Alert.event_time.desc()).limit(min(body.limit, PER_TENANT_CAP))
                    )
                )
                .scalars()
                .all()
            )
            for a in rows:
                hits.append((_aware(a.event_time or a.created_at) or datetime.min.replace(tzinfo=UTC), _hit(a, names.get(tid))))
    hits.sort(key=lambda x: x[0], reverse=True)
    return HuntResponse(total=total, took=int((time.monotonic() - started) * 1000), hits=[h for _, h in hits[: body.limit]])
