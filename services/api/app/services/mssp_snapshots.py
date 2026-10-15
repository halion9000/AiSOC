"""Per-client metrics snapshots for the MSSP overview.

``mssp_tenant_metrics`` was read by the MSSP pages but nothing wrote it, so every client showed dashes. This computes one snapshot per child
tenant from data that really exists there (its alerts, its cases, the tools mapped to it) and stores it. Nothing is invented: a figure with no
source is left empty (``health_score`` is ``None`` for a client with no tools mapped), and ``raw_data`` says how each figure was worked out.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, select

from app.db.rls_scope import acting_as_tenant
from app.models.alert import Alert
from app.models.client_alias import ClientAlias
from app.models.mssp import MSSPTenantMetrics
from app.models.tenant import Tenant
from app.services import case_metrics

logger = logging.getLogger(__name__)

FINISHED_ALERT = ("resolved", "closed", "fp", "false_positive")
OPEN_CASES = case_metrics.OPEN + case_metrics.IN_PROGRESS
MTTR_WINDOW = timedelta(days=30)
REUSE_WITHIN = timedelta(hours=1)  # a snapshot newer than this is updated in place, so history is hourly, not one row per push
MIN_INTERVAL_SECONDS = 300.0

_last_run: dict[uuid.UUID, float] = {}


# Health score: 100 minus capped penalties for what is going wrong right now. A client with no tools mapped has no score, because nothing is watching it.
CRITICAL_PENALTY, CRITICAL_CAP = 10, 50
HIGH_PENALTY, HIGH_CAP = 3, 20
SLA_PENALTY, SLA_CAP = 5, 30


def health_score(critical_open: int, high_open: int, sla_breaches: int, tools: int) -> int | None:
    if tools <= 0:
        return None
    penalty = (
        min(critical_open * CRITICAL_PENALTY, CRITICAL_CAP)
        + min(high_open * HIGH_PENALTY, HIGH_CAP)
        + min(sla_breaches * SLA_PENALTY, SLA_CAP)
    )
    return max(0, 100 - penalty)


async def compute_child_metrics(db: Any, child_id: uuid.UUID, mapped_tools: int, now: datetime) -> dict[str, Any]:
    """The figures for one client. The caller has already put ``db`` in that client's row-level-security scope."""
    open_alerts = await db.scalar(select(func.count()).where(and_(Alert.tenant_id == child_id, Alert.status.notin_(FINISHED_ALERT))))
    critical = await db.scalar(
        select(func.count()).where(and_(Alert.tenant_id == child_id, Alert.severity == "critical", Alert.status.notin_(FINISHED_ALERT)))
    )
    high = await db.scalar(
        select(func.count()).where(and_(Alert.tenant_id == child_id, Alert.severity == "high", Alert.status.notin_(FINISHED_ALERT)))
    )
    resolved = (
        await db.execute(
            select(Alert.created_at, Alert.resolved_at).where(
                and_(Alert.tenant_id == child_id, Alert.resolved_at.isnot(None), Alert.created_at >= now - MTTR_WINDOW)
            )
        )
    ).all()
    minutes = [(r.resolved_at - r.created_at).total_seconds() / 60 for r in resolved if r.resolved_at and r.created_at]
    open_cases = await case_metrics.count_with_status(db, child_id, OPEN_CASES)
    case_rows = await case_metrics.digest_rows(db, child_id, now - MTTR_WINDOW)
    breaches = sum(1 for r in case_rows if r.sla_breached)
    return {
        "open_alerts": int(open_alerts or 0),
        "critical_alerts": int(critical or 0),
        "open_cases": open_cases,
        "mttr_minutes": round(sum(minutes) / len(minutes), 1) if minutes else None,
        "sla_breaches": breaches,
        "connector_count": mapped_tools,
        "health_score": health_score(int(critical or 0), int(high or 0), breaches, mapped_tools),
        "raw_data": {
            "open_alerts": "alerts not resolved/closed/false-positive",
            "mttr_minutes": f"mean created-to-resolved of alerts resolved in the last {MTTR_WINDOW.days} days",
            "sla_breaches": f"cases from the last {MTTR_WINDOW.days} days past their SLA due time",
            "connector_count": "tools with a client mapped to this tenant",
            "health_score": (
                f"100 minus {CRITICAL_PENALTY} per open critical alert (max {CRITICAL_CAP}), {HIGH_PENALTY} per open high alert (max {HIGH_CAP}) "
                f"and {SLA_PENALTY} per SLA breach (max {SLA_CAP}); empty when no tool is mapped to the client"
            ),
        },
    }


async def snapshot_children(
    db: Any,
    parent_id: uuid.UUID,
    *,
    now: datetime | None = None,
    scope: Callable[[Any, uuid.UUID], Any] = acting_as_tenant,
) -> int:
    """Write (or refresh) one snapshot per child tenant of ``parent_id``. Returns how many were written. The caller commits."""
    now = now or datetime.now(UTC)
    children = (await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == parent_id))).scalars().all()
    if not children:
        return 0
    tools: dict[uuid.UUID, set[str]] = {}
    for child_id, vendor in (
        await db.execute(
            select(ClientAlias.child_tenant_id, ClientAlias.vendor).where(
                ClientAlias.tenant_id == parent_id, ClientAlias.child_tenant_id.in_(children), ClientAlias.ignored.is_(False)
            )
        )
    ).all():
        tools.setdefault(child_id, set()).add(vendor)

    written = 0
    for child_id in children:
        try:
            async with scope(db, child_id), db.begin_nested():
                values = await compute_child_metrics(db, child_id, len(tools.get(child_id, ())), now)
                existing = (
                    await db.execute(
                        select(MSSPTenantMetrics)
                        .where(MSSPTenantMetrics.tenant_id == child_id)
                        .order_by(MSSPTenantMetrics.snapshot_at.desc())
                        .limit(1)
                    )
                ).scalar_one_or_none()
                snapshot_at = existing.snapshot_at if existing is not None else None
                if snapshot_at is not None and snapshot_at.tzinfo is None:
                    snapshot_at = snapshot_at.replace(tzinfo=UTC)
                if existing is not None and snapshot_at is not None and now - snapshot_at < REUSE_WITHIN:
                    for key, value in values.items():
                        setattr(existing, key, value)
                    existing.snapshot_at = now
                else:
                    db.add(MSSPTenantMetrics(tenant_id=child_id, snapshot_at=now, **values))
                await db.flush()
            written += 1
        except Exception:  # one client's failure must not stop the rest
            logger.exception("mssp.snapshot_failed", extra={"tenant_id": str(child_id)})
    return written


async def snapshot_children_throttled(db: Any, parent_id: uuid.UUID, **kwargs: Any) -> int:
    """``snapshot_children`` at most once per ``MIN_INTERVAL_SECONDS`` per parent, so a burst of CORE reports does the work once."""
    last = _last_run.get(parent_id)
    if last is not None and time.monotonic() - last < MIN_INTERVAL_SECONDS:
        return 0
    _last_run[parent_id] = time.monotonic()
    return await snapshot_children(db, parent_id, **kwargs)
