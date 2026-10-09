"""Strawberry GraphQL root Query type for AiSOC.

All resolvers authenticate via the same ``get_current_user`` dependency
used by the REST layer, and use the shared SQLAlchemy ``AsyncSession``.
The session is RLS-scoped via ``get_tenant_db`` (see ``schema.py``), so
Postgres enforces tenant isolation. Resolvers also apply explicit
``where(tenant_id == user.tenant_id)`` filters as defense-in-depth.

Playbook data is fetched from the agents service (HTTP proxy – same as
the REST /playbooks endpoints).
"""

from __future__ import annotations

import math
import os
import uuid

import httpx
import strawberry
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select
from strawberry.types import Info

from app.graphql.types import (
    AlertPage,
    AlertType,
    CasePage,
    CaseType,
    ConnectorPage,
    ConnectorType,
    DetectionRulePage,
    DetectionRuleType,
    PlaybookRunType,
    PlaybookType,
    SocStatsType,
)
from app.models.alert import Alert
from app.models.connector import Connector
from app.models.detection_rule import DetectionRule
from app.core.internal_auth import internal_service_headers

_AGENTS_URL = os.getenv("AGENTS_SERVICE_URL") or os.getenv("AGENTS_API_URL", "http://agents:8084")

# ─── helpers ──────────────────────────────────────────────────────────────────


def _escape_like(value: str) -> str:
    """Escape SQL LIKE/ILIKE wildcard metacharacters in a user-supplied
    search string.

    Without this, a user can pass ``%`` or ``_`` and turn an ``ILIKE``
    intended as substring search into a wildcard scan (mild data-exposure
    risk and a DoS surface on large tables). We escape ``%``, ``_`` and the
    escape character ``\\`` itself, and rely on the resolver to pass
    ``escape="\\"`` to the SQLAlchemy ``ilike`` call.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _db(info: Info) -> AsyncSession:
    """Pull the async session injected by the Strawberry FastAPI integration."""
    return info.context["db"]


def _tenant_id(info: Info) -> uuid.UUID | None:
    """Return the current user's tenant UUID (or None for unauthenticated)."""
    user = info.context.get("user")
    return getattr(user, "tenant_id", None)


def _scope(stmt: Select, info: Info, model) -> Select:
    """Apply ``where(model.tenant_id == user.tenant_id)`` to ``stmt``.

    Acts as defense-in-depth alongside Postgres RLS. If the user has no
    tenant_id (unauthenticated, which should not reach here), an empty
    UUID is used so the query returns no rows rather than leaking.
    """
    tid = _tenant_id(info)
    if tid is None:
        # Block — no anonymous access to tenant data
        return stmt.where(model.tenant_id == uuid.UUID("00000000-0000-0000-0000-000000000000"))
    return stmt.where(model.tenant_id == tid)


def _orm_to_alert(row: Alert) -> AlertType:
    return AlertType(
        id=row.id,
        tenant_id=row.tenant_id,
        title=row.title,
        description=row.description,
        severity=row.severity,
        status=row.status,
        priority=row.priority,
        category=row.category,
        mitre_tactics=row.mitre_tactics or [],
        mitre_techniques=row.mitre_techniques or [],
        connector_type=row.connector_type,
        ai_score=row.ai_score,
        ai_summary=row.ai_summary,
        ai_recommendations=row.ai_recommendations or [],
        affected_ips=row.affected_ips or [],
        affected_hosts=row.affected_hosts or [],
        affected_users=row.affected_users or [],
        case_id=row.case_id,
        tags=row.tags or [],
        event_time=row.event_time,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


# Cases live in `aisoc_cases` (the table the cases REST API reads and writes). These resolvers used to read the old `cases` table, which never receives a case, so GraphQL saw none:
# after a case was created through REST (201, and REST listed it) `cases` returned total 0, `case(id)` returned null and `socStats.openCases` was 0.
# aisoc_cases has no priority, case_type, tactics, ticket refs, summary or resolution, and its assignee is free text. The schema is unchanged: severity doubles as priority (as in the shift handoff),
# case_number falls back to the case's real id, assigned_to_id is the assignee only if it parses as a UUID, and the fields with no source stay empty rather than being invented.
_CASE_COLUMNS = "id, tenant_id, case_number, title, description, severity, status, assignee, mitre_techniques, alert_ids, tags, sla_due_at, resolved_at, created_at, updated_at"
_FINISHED_STATUSES = ("resolved", "closed")
_MAX_PAGE_SIZE = 200


def _uuid_or_none(value) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value)) if value else None
    except ValueError:
        return None


def _technique_ids(values) -> list[str]:
    """mitre_techniques as a list of technique ids (older fixtures stored {"id": ..., "name": ...} objects)."""
    out: list[str] = []
    for item in values or []:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict) and item.get("id"):
            out.append(str(item["id"]))
    return out


def _sla_breached(due, resolved_at, status: str, now: datetime) -> bool:
    """No deadline is never a breach; a resolved case breached only if it was resolved after the deadline; an open one once the deadline has passed."""
    if due is None:
        return False
    if resolved_at is not None:
        return resolved_at > due
    return status not in _FINISHED_STATUSES and now > due


def _aisoc_case_to_type(row, now: datetime | None = None) -> CaseType:
    return CaseType(
        id=row.id,
        tenant_id=row.tenant_id,
        case_number=row.case_number or str(row.id),
        title=row.title,
        description=row.description,
        status=row.status,
        priority=row.severity,
        severity=row.severity,
        case_type="unspecified",
        mitre_tactics=[],
        mitre_techniques=_technique_ids(row.mitre_techniques),
        assigned_to_id=_uuid_or_none(row.assignee),
        sla_deadline=row.sla_due_at,
        sla_breached=_sla_breached(row.sla_due_at, row.resolved_at, row.status, now or datetime.now(UTC)),
        alert_ids=[str(a) for a in (row.alert_ids or [])],
        tags=row.tags if isinstance(row.tags, dict) else {},
        ticket_refs=[],
        summary=None,
        resolution=None,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _fetch_case(db: AsyncSession, tid: uuid.UUID, case_id: str) -> CaseType | None:
    try:
        wanted = uuid.UUID(str(case_id))
    except ValueError:
        return None
    row = (await db.execute(text(f"SELECT {_CASE_COLUMNS} FROM aisoc_cases WHERE id = :id AND tenant_id = :tid"), {"id": wanted, "tid": tid})).first()
    return _aisoc_case_to_type(row) if row else None


async def _list_cases(db: AsyncSession, tid: uuid.UUID, *, page: int, page_size: int, status: str | None, priority: str | None, search: str | None):
    """(rows as CaseType, total). Only fixed SQL fragments are assembled; every user-supplied value is a bound parameter."""
    page, page_size = max(1, page), min(max(1, page_size), _MAX_PAGE_SIZE)
    where, params = ["tenant_id = :tid"], {"tid": tid}
    if status:
        where.append("status = :status")
        params["status"] = status
    if priority:
        where.append("severity = :priority")
        params["priority"] = priority
    if search:
        where.append("title ILIKE :search ESCAPE '\\'")
        params["search"] = f"%{_escape_like(search)}%"
    clause = " AND ".join(where)
    total = (await db.execute(text(f"SELECT count(*) FROM aisoc_cases WHERE {clause}"), params)).scalar_one()
    rows = (await db.execute(text(f"SELECT {_CASE_COLUMNS} FROM aisoc_cases WHERE {clause} ORDER BY created_at DESC LIMIT :limit OFFSET :offset"), {**params, "limit": page_size, "offset": (page - 1) * page_size})).fetchall()
    return [_aisoc_case_to_type(r) for r in rows], total, page, page_size


async def _count_open_cases(db: AsyncSession, tid: uuid.UUID) -> int:
    return (await db.execute(text("SELECT count(*) FROM aisoc_cases WHERE tenant_id = :tid AND status NOT IN ('resolved', 'closed')"), {"tid": tid})).scalar_one()


def _orm_to_rule(row: DetectionRule) -> DetectionRuleType:
    return DetectionRuleType(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        description=row.description,
        rule_type=row.rule_language,
        severity=row.severity,
        status=row.status,
        enabled=True,  # DetectionRule uses status field; treat non-archived as enabled
        tags=row.tags or [],
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _orm_to_connector(row: Connector) -> ConnectorType:
    return ConnectorType(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        connector_type=row.connector_type,
        description=None,
        enabled=row.is_enabled,
        status=row.health_status,
        last_sync_at=row.last_sync,
        total_events_processed=row.events_ingested,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _proxy_get(path: str, params: dict | None = None):  # noqa: ANN201
    """Call the agents service and return JSON, or raise on failure."""
    url = f"{_AGENTS_URL}/api/v1/playbooks{path}"
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(url, params=params or {}, headers=internal_service_headers())
    r.raise_for_status()
    return r.json()


# ─── Query ────────────────────────────────────────────────────────────────────


@strawberry.type
class Query:
    # ── Alerts ────────────────────────────────────────────────────────────────

    @strawberry.field(description="Fetch a single alert by ID (tenant-scoped).")
    async def alert(self, info: Info, id: strawberry.ID) -> AlertType | None:
        db = _db(info)
        tid = _tenant_id(info)
        if tid is None:
            return None
        result = await db.execute(select(Alert).where(Alert.id == id, Alert.tenant_id == tid))
        row = result.scalar_one_or_none()
        return _orm_to_alert(row) if row else None

    @strawberry.field(description="Paginated list of alerts with optional filters.")
    async def alerts(
        self,
        info: Info,
        page: int = 1,
        page_size: int = 25,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> AlertPage:
        db = _db(info)
        q = _scope(select(Alert), info, Alert)

        if severity:
            q = q.where(Alert.severity == severity)
        if status:
            q = q.where(Alert.status == status)
        if search:
            safe = _escape_like(search)
            q = q.where(Alert.title.ilike(f"%{safe}%", escape="\\"))

        total_result = await db.execute(select(func.count()).select_from(q.subquery()))
        total = total_result.scalar_one()

        offset = (page - 1) * page_size
        rows_result = await db.execute(q.order_by(Alert.created_at.desc()).offset(offset).limit(page_size))
        rows = rows_result.scalars().all()

        return AlertPage(
            items=[_orm_to_alert(r) for r in rows],
            total=total,
            page=page,
            page_size=page_size,
            pages=max(1, math.ceil(total / page_size)),
        )

    # ── Cases ─────────────────────────────────────────────────────────────────

    @strawberry.field(description="Fetch a single case by ID (tenant-scoped).")
    async def case(self, info: Info, id: strawberry.ID) -> CaseType | None:
        db = _db(info)
        tid = _tenant_id(info)
        if tid is None:
            return None
        return await _fetch_case(db, tid, str(id))

    @strawberry.field(description="Paginated list of cases with optional filters.")
    async def cases(
        self,
        info: Info,
        page: int = 1,
        page_size: int = 25,
        status: str | None = None,
        priority: str | None = None,
        search: str | None = None,
    ) -> CasePage:
        db = _db(info)
        tid = _tenant_id(info)
        if tid is None:
            return CasePage(items=[], total=0, page=1, page_size=page_size, pages=1)
        items, total, page, page_size = await _list_cases(db, tid, page=page, page_size=page_size, status=status, priority=priority, search=search)
        return CasePage(items=items, total=total, page=page, page_size=page_size, pages=max(1, math.ceil(total / page_size)))

    # ── Detection Rules ────────────────────────────────────────────────────────

    @strawberry.field(description="Paginated list of detection rules.")
    async def detection_rules(
        self,
        info: Info,
        page: int = 1,
        page_size: int = 25,
        severity: str | None = None,
        status: str | None = None,
    ) -> DetectionRulePage:
        db = _db(info)
        q = _scope(select(DetectionRule), info, DetectionRule)

        if severity:
            q = q.where(DetectionRule.severity == severity)
        if status:
            q = q.where(DetectionRule.status == status)

        total_result = await db.execute(select(func.count()).select_from(q.subquery()))
        total = total_result.scalar_one()

        offset = (page - 1) * page_size
        rows_result = await db.execute(q.order_by(DetectionRule.created_at.desc()).offset(offset).limit(page_size))
        rows = rows_result.scalars().all()

        return DetectionRulePage(
            items=[_orm_to_rule(r) for r in rows],
            total=total,
            page=page,
            page_size=page_size,
            pages=max(1, math.ceil(total / page_size)),
        )

    # ── Connectors ────────────────────────────────────────────────────────────

    @strawberry.field(description="Paginated list of connectors.")
    async def connectors(
        self,
        info: Info,
        page: int = 1,
        page_size: int = 25,
        enabled: bool | None = None,
    ) -> ConnectorPage:
        db = _db(info)
        q = _scope(select(Connector), info, Connector)

        if enabled is not None:
            q = q.where(Connector.is_enabled == enabled)

        total_result = await db.execute(select(func.count()).select_from(q.subquery()))
        total = total_result.scalar_one()

        offset = (page - 1) * page_size
        rows_result = await db.execute(q.order_by(Connector.created_at.desc()).offset(offset).limit(page_size))
        rows = rows_result.scalars().all()

        return ConnectorPage(
            items=[_orm_to_connector(r) for r in rows],
            total=total,
            page=page,
            page_size=page_size,
            pages=max(1, math.ceil(total / page_size)),
        )

    # ── Playbooks (agents service proxy) ──────────────────────────────────────

    @strawberry.field(description="List automation playbooks from the agents service.")
    async def playbooks(self, info: Info, enabled_only: bool = False) -> list[PlaybookType]:
        try:
            data = await _proxy_get("", {"enabled_only": enabled_only})
        except Exception:
            return []

        items = data if isinstance(data, list) else data.get("items", [])
        return [
            PlaybookType(
                id=p.get("id", ""),
                name=p.get("name", ""),
                description=p.get("description"),
                enabled=p.get("enabled", True),
                trigger=p.get("trigger", {}),
                steps=p.get("steps", []),
                tags=p.get("tags", []),
                created_at=p.get("created_at"),
                updated_at=p.get("updated_at"),
            )
            for p in items
        ]

    @strawberry.field(description="List recent playbook execution runs.")
    async def playbook_runs(self, info: Info, limit: int = 50) -> list[PlaybookRunType]:
        try:
            data = await _proxy_get("/runs", {"limit": limit})
        except Exception:
            return []

        items = data if isinstance(data, list) else data.get("items", [])
        return [
            PlaybookRunType(
                id=r.get("id", ""),
                playbook_id=r.get("playbook_id", ""),
                status=r.get("status", ""),
                trigger_event=r.get("trigger_event", {}),
                steps_executed=r.get("steps_executed", 0),
                steps_total=r.get("steps_total", 0),
                error=r.get("error"),
                started_at=r.get("started_at", ""),
                completed_at=r.get("completed_at"),
            )
            for r in items
        ]

    # ── SOC Stats ─────────────────────────────────────────────────────────────

    @strawberry.field(description="High-level SOC statistics for the current tenant.")
    async def soc_stats(self, info: Info) -> SocStatsType:
        from datetime import UTC, datetime, timedelta

        db = _db(info)
        tid = _tenant_id(info)
        if tid is None:
            return SocStatsType(
                total_alerts=0,
                open_cases=0,
                critical_alerts=0,
                alerts_last_24h=0,
                mean_time_to_detect_hours=None,
                mean_time_to_respond_hours=None,
            )

        total_alerts = (await db.execute(select(func.count()).select_from(Alert).where(Alert.tenant_id == tid))).scalar_one()
        open_cases = await _count_open_cases(db, tid)
        critical_alerts = (
            await db.execute(select(func.count()).select_from(Alert).where(Alert.tenant_id == tid, Alert.severity == "critical"))
        ).scalar_one()
        cutoff = datetime.now(UTC) - timedelta(hours=24)
        alerts_24h = (
            await db.execute(select(func.count()).select_from(Alert).where(Alert.tenant_id == tid, Alert.created_at >= cutoff))
        ).scalar_one()

        return SocStatsType(
            total_alerts=total_alerts,
            open_cases=open_cases,
            critical_alerts=critical_alerts,
            alerts_last_24h=alerts_24h,
            mean_time_to_detect_hours=None,
            mean_time_to_respond_hours=None,
        )
