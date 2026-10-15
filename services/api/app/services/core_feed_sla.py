"""SLA timing events for alerts the vendor closed.

The SLA page computes time-to-resolve from ``alert_sla_events`` rows, but nothing wrote them for CORE's alerts, so it had no data. When CORE reports an
incident closed in the vendor's portal, ``apply_closed`` resolves the alert and stamps ``enrichment_data.closed_in_vendor``; this adds the two events the
page needs for exactly those alerts: ``detected`` (when AiSOC received the alert) and ``resolved`` (when the closure was reported). Nothing is invented:
there is no ``acknowledged`` event because nobody acknowledged anything, so time-to-detect stays empty for these alerts. Safe to repeat: an alert
that already has an event of a type does not get a second one.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import text


async def record_closure_events(db: Any, tenant_id: uuid.UUID, vendor: str, now: datetime) -> int:
    """Write the missing ``detected`` / ``resolved`` events for this tenant's alerts closed by ``vendor`` at ``now``. Returns how many events were written.

    The caller has already put ``db`` in the tenant's row-level-security scope and owns the transaction.
    """
    result = await db.execute(
        text(
            "INSERT INTO alert_sla_events (id, tenant_id, alert_id, severity, event_type, occurred_at, metadata) "
            "SELECT gen_random_uuid(), a.tenant_id, a.id, a.severity, ev.kind, "
            "CASE ev.kind WHEN 'detected' THEN a.created_at ELSE CAST(:now AS TIMESTAMPTZ) END, CAST(:meta AS JSONB) "
            "FROM alerts a CROSS JOIN (VALUES ('detected'), ('resolved')) AS ev(kind) "
            "WHERE a.tenant_id = :t AND a.enrichment_data->'closed_in_vendor'->>'vendor' = :vendor AND a.enrichment_data->'closed_in_vendor'->>'at' = :at "
            "AND NOT EXISTS (SELECT 1 FROM alert_sla_events e WHERE e.tenant_id = a.tenant_id AND e.alert_id = a.id AND e.event_type = ev.kind)"
        ),
        {
            "t": tenant_id,
            "vendor": vendor,
            "at": now.isoformat(),
            "now": now,
            "meta": json.dumps({"source": "core-feed", "vendor": vendor, "basis": "closed in the vendor's portal, reported by CORE"}),
        },
    )
    return result.rowcount or 0
