"""Indicators seen on alerts, for the Threat Intel page.

Threat Intel only held what an analyst typed in or a feed supplied, so it was empty even though alerts carry addresses and file hashes. Each run reads
a tenant's recent alerts and records the public IP addresses (``affected_ips``; private, loopback and link-local ones are skipped) and SHA-256 hashes
(anywhere in the raw event) as indicators with ``source = "alerts"``. They are observations, not verdicts: low confidence, tagged ``from-alert``,
severity "info", linked to the alerts that carried them, and never created for alerts already marked false positive. Seeing an address again refreshes it instead of
adding a duplicate.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text

from app.db.rls_scope import acting_as_tenant

logger = logging.getLogger(__name__)

SOURCE = "alerts"
LOOK_BACK = timedelta(days=7)
PER_TENANT_ALERTS = 500
MIN_INTERVAL_SECONDS = 300.0
_SHA256 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_last_run: dict[uuid.UUID, float] = {}


def indicators_for_alert(affected_ips: Any, raw_event: Any) -> list[tuple[str, str]]:
    """``[(ioc_type, value)]`` for one alert: public IPs (``ip``) and SHA-256 hashes (``file_hash_sha256``), each once."""
    found: dict[tuple[str, str], None] = {}
    for raw in affected_ips if isinstance(affected_ips, list) else []:
        try:
            ip = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue
        if ip.is_global:
            found[("ip", str(ip))] = None
    if raw_event:
        for digest in _SHA256.findall(json.dumps(raw_event, default=str)):
            found[("file_hash_sha256", digest.lower())] = None
    return list(found)


async def sync_in_scope(db: Any, tenant_id: uuid.UUID, now: datetime) -> int:
    """Record this tenant's indicators. The caller has already put ``db`` in the tenant's row-level-security scope. Returns how many were new."""
    alerts = (
        await db.execute(
            text(
                "SELECT id, severity, affected_ips, raw_event, raw_event->>'source' AS vendor FROM alerts WHERE tenant_id = :t AND created_at >= :since "
                "AND status <> 'fp' AND coalesce(disposition, '') NOT IN ('false_positive', 'fp') ORDER BY created_at DESC LIMIT :n"
            ),
            {"t": tenant_id, "since": now - LOOK_BACK, "n": PER_TENANT_ALERTS},
        )
    ).all()
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for alert in alerts:
        for key in indicators_for_alert(alert.affected_ips, alert.raw_event):
            entry = seen.setdefault(key, {"alerts": [], "vendors": set()})
            entry["alerts"].append(str(alert.id))
            if alert.vendor:
                entry["vendors"].add(str(alert.vendor))
    created = 0
    for (kind, value), entry in seen.items():
        existing = (
            await db.execute(
                text("SELECT id FROM threat_intel_iocs WHERE tenant_id = :t AND ioc_type = :k AND value = :v AND source = :s LIMIT 1"),
                {"t": tenant_id, "k": kind, "v": value, "s": SOURCE},
            )
        ).first()
        linked = entry["alerts"][:50]
        if existing is not None:
            await db.execute(
                text(
                    "UPDATE threat_intel_iocs SET last_seen = :now, linked_alerts = CAST(:linked AS UUID[]) WHERE id = :id AND tenant_id = :t"
                ),
                {"now": now, "linked": linked, "id": existing.id, "t": tenant_id},
            )
            continue
        await db.execute(
            text(
                "INSERT INTO threat_intel_iocs (id, tenant_id, ioc_type, value, confidence, severity, tlp, tags, source, source_ref, first_seen, last_seen, "
                "is_active, false_positive, linked_alerts, context, created_at, updated_at) VALUES (:id, :t, :k, :v, 30, :sev, 'amber', CAST(:tags AS TEXT[]), "
                ":s, :ref, :now, :now, true, false, CAST(:linked AS UUID[]), CAST(:ctx AS JSONB), :now, :now)"
            ),
            {
                "id": uuid.uuid4(),
                "t": tenant_id,
                "k": kind,
                "v": value,
                "sev": "info",  # an observation, not a verdict: the Threat Intel page must not show it as malicious
                "tags": ["from-alert", *sorted(entry["vendors"])],
                "s": SOURCE,
                "ref": linked[0],
                "now": now,
                "linked": linked,
                "ctx": json.dumps(
                    {"derived": "observed on an alert; not a confirmed malicious indicator", "alert_count": len(entry["alerts"])}
                ),
            },
        )
        created += 1
    return created


async def sync_children(
    db: Any,
    parent_id: uuid.UUID,
    *,
    now: datetime | None = None,
    scope: Callable[[Any, uuid.UUID], Any] = acting_as_tenant,
) -> int:
    """Run ``sync_in_scope`` for the workspace and each client tenant. Returns how many indicators were new. The caller commits."""
    now = now or datetime.now(UTC)
    ids = [parent_id]
    ids += [r[0] for r in (await db.execute(text("SELECT id FROM tenants WHERE parent_tenant_id = :p"), {"p": parent_id})).all()]
    total = 0
    for tid in ids:
        try:
            async with scope(db, tid), db.begin_nested():
                total += await sync_in_scope(db, tid, now)
        except Exception:  # one tenant's failure must not stop the rest
            logger.exception("iocs_from_alerts.failed", extra={"tenant_id": str(tid)})
    return total


async def sync_children_throttled(db: Any, parent_id: uuid.UUID, *, clock: Callable[[], float] = time.monotonic) -> int:
    """``sync_children`` at most once every few minutes per workspace, since CORE reports every run."""
    mark = clock()
    last = _last_run.get(parent_id)
    if last is not None and mark - last < MIN_INTERVAL_SECONDS:
        return 0
    _last_run[parent_id] = mark
    return await sync_children(db, parent_id)
