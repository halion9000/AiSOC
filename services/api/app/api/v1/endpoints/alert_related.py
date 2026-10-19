"""Other alerts about the same device or person: GET /api/v1/alerts/{alert_id}/related.

An analyst looking at one alert needs to know whether the same machine or user has been in trouble before, and in which tool (a Petra incident for a person, a Huntress incident for their laptop).
This lists the alerts AiSOC holds in the same tenant, from the last 30 days, that name a host or user the alert names, from any tool, newest first. It matches the names exactly as stored; it does
not guess at similar spellings.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import array

from app.api.v1.deps import AuthUser, require_permission
from app.api.v1.endpoints.alerts import _tool_of
from app.db.rls import TenantDBSession
from app.models.alert import Alert
from app.services.alert_scope import alert_scope

router = APIRouter(prefix="/alerts", tags=["alerts"])

LOOKBACK_DAYS = 30
MAX_RELATED = 20
MAX_NAMES = 20


class RelatedAlert(BaseModel):
    id: uuid.UUID
    title: str
    severity: str | None = None
    status: str | None = None
    source: str | None = None
    created_at: datetime
    matched: Literal["device", "user", "device and user"]


class RelatedAlerts(BaseModel):
    items: list[RelatedAlert]
    # How many more matched than are listed.
    more: int = 0


def names_of(value: Any) -> list[str]:
    """The distinct, non-empty text names in a stored list (host or user names), at most MAX_NAMES."""
    if not isinstance(value, list):
        return []
    seen: list[str] = []
    for v in value:
        if isinstance(v, str) and v.strip() and v.strip() not in seen:
            seen.append(v.strip())
    return seen[:MAX_NAMES]


def match_label(hosts: list[str], users: list[str], other_hosts: Any, other_users: Any) -> str | None:
    """Whether the other alert shares a device, a user or both with this one; None when it shares neither."""
    device = bool(set(hosts) & set(names_of(other_hosts)))
    user = bool(set(users) & set(names_of(other_users)))
    if device and user:
        return "device and user"
    return "device" if device else ("user" if user else None)


@router.get("/{alert_id}/related", response_model=RelatedAlerts, summary="Other recent alerts about the same device or user")
async def related_alerts(
    alert_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: TenantDBSession,
) -> RelatedAlerts:
    async with alert_scope(db, current_user.tenant_id, alert_id) as tid:
        alert = (await db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tid))).scalar_one_or_none()
        hosts, users = names_of(alert.affected_hosts), names_of(alert.affected_users)
        if not hosts and not users:
            return RelatedAlerts(items=[])
        conditions = []
        if hosts:
            conditions.append(Alert.affected_hosts.has_any(array(hosts)))
        if users:
            conditions.append(Alert.affected_users.has_any(array(users)))
        since = datetime.now(UTC) - timedelta(days=LOOKBACK_DAYS)
        rows = (
            (
                await db.execute(
                    select(Alert)
                    .where(Alert.tenant_id == tid, Alert.id != alert_id, Alert.created_at >= since, or_(*conditions))
                    .order_by(Alert.created_at.desc())
                    .limit(MAX_RELATED + 1)
                )
            )
            .scalars()
            .all()
        )
        items = []
        for r in rows:
            label = match_label(hosts, users, r.affected_hosts, r.affected_users)
            if label is not None:
                items.append(
                    RelatedAlert(
                        id=r.id,
                        title=r.title,
                        severity=r.severity,
                        status=r.status,
                        source=_tool_of(r),
                        created_at=r.created_at,
                        matched=label,
                    )  # type: ignore[arg-type]
                )
        return RelatedAlerts(items=items[:MAX_RELATED], more=1 if len(items) > MAX_RELATED else 0)
