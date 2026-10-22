"""Open a case for each new alert CORE forwards (any severity, from every tool it feeds), so the Cases, Team Analytics and SLA pages have something to show.

CORE only pushes alerts; nothing opened cases from them, so those pages stayed empty. Each run looks at the workspace and its client tenants for recent
alerts from CORE's tools that no case holds yet, and opens one case per alert, linked both ways (the same shape ``POST /cases`` writes).
A kill switch (``AISOC_AUTO_CASES=false``), a 24-hour look-back and a per-run cap keep a first run from opening a case for every old alert.

The other half: ``close_finished_cases`` closes a case AiSOC opened itself once every alert in it is closed (resolved, closed or a false positive) and nobody has taken it. Cases a person opened, and
cases somebody is assigned to, are never closed this way; nothing is pushed to a PSA ticket (that stays a person's decision). A kill switch (``AISOC_AUTO_CLOSE_CASES=false``) turns it off.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text

from app.db.rls_scope import acting_as_tenant

logger = logging.getLogger(__name__)

SEVERITIES = ("critical", "high", "medium", "low", "info")
# Every tool CORE forwards alerts from (CORE's FEED_ADAPTERS). An alert a tool has already closed is not 'new', so it never gets a case.
VENDORS = ("huntress", "petra", "blumira", "ninjaone", "fieldeffect", "threatmate", "addigy")
LOOK_BACK = timedelta(hours=24)
PER_RUN_CAP = 50


FINISHED_ALERT = ("resolved", "closed", "false_positive", "fp")
CLOSE_PER_RUN_CAP = 1000
AUTO_CLOSE_NOTE = "Closed automatically: every alert in this case is closed, and nobody had taken it."


def auto_close_enabled() -> bool:
    return os.getenv("AISOC_AUTO_CLOSE_CASES", "true").strip().lower() not in {"0", "false", "no", "off"}


def enabled() -> bool:
    return os.getenv("AISOC_AUTO_CASES", "true").strip().lower() not in {"0", "false", "no", "off"}


async def open_cases_in_scope(db: Any, tenant_id: uuid.UUID, now: datetime, limit: int) -> int:
    """Open cases for this tenant's qualifying alerts. The caller has already put ``db`` in the tenant's row-level-security scope."""
    rows = (
        await db.execute(
            text(
                "SELECT id, title, description, severity, mitre_techniques, raw_event->>'source' AS vendor FROM alerts "
                "WHERE tenant_id = :t AND case_id IS NULL AND severity = ANY(CAST(:sev AS TEXT[])) AND status = 'new' "
                "AND created_at >= :since AND raw_event->>'source' = ANY(CAST(:vendors AS TEXT[])) ORDER BY created_at LIMIT :n"
            ),
            {"t": tenant_id, "sev": list(SEVERITIES), "since": now - LOOK_BACK, "vendors": list(VENDORS), "n": limit},
        )
    ).all()
    opened = 0
    for alert in rows:
        case_id = uuid.uuid4()
        techniques = alert.mitre_techniques if isinstance(alert.mitre_techniques, list) else []
        await db.execute(
            text(
                "INSERT INTO aisoc_cases (id, tenant_id, title, description, severity, status, mitre_techniques, alert_ids, compliance_frameworks, tags, "
                "opened_at, created_at, updated_at, created_by) VALUES (:id, :t, :title, :description, :sev, 'new', CAST(:mitre AS JSONB), "
                "CAST(:alert_ids AS UUID[]), CAST(:frameworks AS TEXT[]), CAST(:tags AS JSONB), :now, :now, :now, 'system')"
            ),
            {
                "id": case_id,
                "t": tenant_id,
                "title": (alert.title or "Alert from CORE")[:500],
                "description": (alert.description or f"Opened automatically for a {alert.severity} alert from {alert.vendor}.")[:4000],
                "sev": alert.severity,
                "mitre": json.dumps(techniques),
                "alert_ids": [str(alert.id)],
                "frameworks": [],
                "tags": json.dumps({"source": "core-feed", "vendor": alert.vendor, "auto": True}),
                "now": now,
            },
        )
        await db.execute(
            text("UPDATE alerts SET case_id = :c WHERE id = :a AND tenant_id = :t AND case_id IS NULL"),
            {"c": case_id, "a": alert.id, "t": tenant_id},
        )
        opened += 1
    return opened


async def open_cases_for_new_alerts(
    db: Any,
    parent_id: uuid.UUID,
    *,
    now: datetime | None = None,
    scope: Callable[[Any, uuid.UUID], Any] = acting_as_tenant,
) -> int:
    """Run ``open_cases_in_scope`` for the workspace and each client tenant. Returns how many cases were opened. The caller commits."""
    if not enabled():
        return 0
    now = now or datetime.now(UTC)
    ids = [parent_id]
    ids += [r[0] for r in (await db.execute(text("SELECT id FROM tenants WHERE parent_tenant_id = :p"), {"p": parent_id})).all()]
    total = 0
    for tid in ids:
        if total >= PER_RUN_CAP:
            break
        try:
            async with scope(db, tid), db.begin_nested():
                total += await open_cases_in_scope(db, tid, now, PER_RUN_CAP - total)
        except Exception:  # one tenant's failure must not stop the rest
            logger.exception("core_feed_cases.failed", extra={"tenant_id": str(tid)})
    return total


async def close_finished_cases_in_scope(db: Any, tenant_id: uuid.UUID, now: datetime, limit: int = CLOSE_PER_RUN_CAP) -> int:
    """Close this tenant's open, system-opened, unassigned cases whose alerts are all finished. Returns how many were closed. ``db`` is already in the tenant's scope; the caller commits."""
    closed = (
        await db.execute(
            text(
                "WITH due AS ("
                " SELECT c.id FROM aisoc_cases c WHERE c.tenant_id = :t AND c.status NOT IN ('resolved', 'closed') AND c.created_by = 'system' AND c.assignee IS NULL"
                " AND coalesce(cardinality(c.alert_ids), 0) > 0"
                " AND EXISTS (SELECT 1 FROM unnest(c.alert_ids) AS x(aid) JOIN alerts a ON a.id = x.aid WHERE a.tenant_id = :t)"
                " AND NOT EXISTS (SELECT 1 FROM unnest(c.alert_ids) AS x(aid) JOIN alerts a ON a.id = x.aid WHERE a.tenant_id = :t AND a.status <> ALL(CAST(:done AS TEXT[])))"
                " ORDER BY c.updated_at LIMIT :n)"
                " UPDATE aisoc_cases c SET status = 'closed', resolved_at = coalesce(c.resolved_at, :now), closed_at = :now, updated_at = :now, tags = coalesce(c.tags, '{}'::jsonb) || '{\"auto_closed\": true}'::jsonb FROM due WHERE c.id = due.id RETURNING c.id"
            ),
            {"t": tenant_id, "done": list(FINISHED_ALERT), "now": now, "n": limit},
        )
    ).all()
    for (case_id,) in closed:
        await db.execute(
            text("INSERT INTO aisoc_case_comments (id, case_id, tenant_id, author, body, is_system, created_at) VALUES (:id, :c, :t, 'system', :body, true, :now)"),
            {"id": uuid.uuid4(), "c": case_id, "t": tenant_id, "body": AUTO_CLOSE_NOTE, "now": now},
        )
    return len(closed)


async def close_finished_cases(
    db: Any,
    parent_id: uuid.UUID,
    *,
    now: datetime | None = None,
    scope: Callable[[Any, uuid.UUID], Any] = acting_as_tenant,
) -> int:
    """Run ``close_finished_cases_in_scope`` for the workspace and each client tenant. Returns how many cases were closed. The caller commits."""
    if not auto_close_enabled():
        return 0
    now = now or datetime.now(UTC)
    ids = [parent_id]
    ids += [r[0] for r in (await db.execute(text("SELECT id FROM tenants WHERE parent_tenant_id = :p"), {"p": parent_id})).all()]
    total = 0
    for tid in ids:
        try:
            async with scope(db, tid), db.begin_nested():
                total += await close_finished_cases_in_scope(db, tid, now)
        except Exception:  # one tenant's failure must not stop the rest
            logger.exception("core_feed_cases.auto_close_failed", extra={"tenant_id": str(tid)})
    return total
