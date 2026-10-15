"""Which detections the connected tools have actually raised.

The tools CORE connects (Huntress, Blumira, Petra, NinjaOne, ...) run their own detections and send the results as alerts. This groups the last 30 days of
those alerts by tool and detection name, so an analyst can see what each tool is catching, how often, and for how many clients. It reads alerts only:
no catalogue of what a tool *could* detect is invented.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, select

from app.db.rls_scope import acting_as_tenant
from app.models.alert import Alert
from app.models.tenant import Tenant

WINDOW = timedelta(days=30)
MAX_ALERTS = 5000
FINISHED = ("resolved", "closed", "fp", "false_positive")
_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def source_of(raw_event: Any, connector_type: str | None) -> str:
    if isinstance(raw_event, dict) and raw_event.get("source"):
        return str(raw_event["source"])
    return connector_type or "unknown"


def _ensure_aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def _scan(db: Any, tenant_id: uuid.UUID, since: datetime, groups: dict[tuple[str, str], dict[str, Any]]) -> None:
    rows = (
        await db.execute(
            select(Alert.title, Alert.rule_name, Alert.severity, Alert.status, Alert.raw_event, Alert.connector_type, Alert.created_at)
            .where(and_(Alert.tenant_id == tenant_id, Alert.created_at >= since))
            .order_by(Alert.created_at.desc())
            .limit(MAX_ALERTS)
        )
    ).all()
    for title, rule_name, severity, status, raw_event, connector_type, created_at in rows:
        source = source_of(raw_event, connector_type)
        name = (rule_name or title or "Untitled").strip()
        group = groups.setdefault(
            (source, name), {"source": source, "name": name, "count": 0, "open": 0, "severity": "info", "last_seen": None, "tenants": set()}
        )
        group["count"] += 1
        group["tenants"].add(tenant_id)
        if status not in FINISHED:
            group["open"] += 1
        if _RANK.get(str(severity).lower(), 0) > _RANK[group["severity"]]:
            group["severity"] = str(severity).lower()
        seen = _ensure_aware(created_at)
        if group["last_seen"] is None or seen > group["last_seen"]:
            group["last_seen"] = seen


async def vendor_detections(
    db: Any,
    tenant_id: uuid.UUID,
    *,
    now: datetime | None = None,
    scope: Callable[[Any, uuid.UUID], Any] = acting_as_tenant,
) -> list[dict[str, Any]]:
    """Detections raised in the last 30 days on this tenant's alerts and its clients', most-raised first."""
    since = (now or datetime.now(UTC)) - WINDOW
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    await _scan(db, tenant_id, since, groups)
    children = (await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == tenant_id))).scalars().all()
    for child_id in children:
        async with scope(db, child_id):
            await _scan(db, child_id, since, groups)
    out = [
        {
            "source": g["source"],
            "name": g["name"],
            "count": g["count"],
            "open": g["open"],
            "severity": g["severity"],
            "clients": len(g["tenants"]),
            "last_seen": g["last_seen"].isoformat() if g["last_seen"] else None,
        }
        for g in groups.values()
    ]
    out.sort(key=lambda g: (-g["count"], g["source"], g["name"]))
    return out
