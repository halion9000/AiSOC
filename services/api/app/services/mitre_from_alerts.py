"""ATT&CK techniques actually seen on a tenant's alerts.

The coverage pages were fed only by the knowledge graph (Neo4j) and the detection-rule library, so with no graph they showed nothing even
though alerts were arriving. This reads techniques straight from the alerts: the ``mitre_techniques`` / ``mitre_tactics`` the source wrote,
plus any explicit ``T1234`` / ``T1234.001`` id quoted in the title or description. Nothing is guessed from alert wording. Vendors that send
no ATT&CK data (CORE's feeds currently do not) simply contribute nothing.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, select

from app.db.rls_scope import acting_as_tenant
from app.models.alert import Alert
from app.models.tenant import Tenant
from app.services.case_summary import _TECHNIQUE_TO_TACTIC

WINDOW = timedelta(days=90)
MAX_ALERTS = 5000
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _clean(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    found = _TECH_RE.fullmatch(value.strip())
    return value.strip().upper() if found else None


def techniques_for_alert(title: str | None, description: str | None, techniques: Any, tactics: Any) -> dict[str, str | None]:
    """``{technique_id: tactic or None}`` for one alert."""
    ids: list[str] = []
    for raw in techniques if isinstance(techniques, list) else []:
        tid = _clean(raw)
        if tid:
            ids.append(tid)
    for text in (title, description):
        if isinstance(text, str):
            ids.extend(m.upper() for m in _TECH_RE.findall(text))
    given = [str(t) for t in tactics if isinstance(t, str) and t.strip()] if isinstance(tactics, list) else []
    out: dict[str, str | None] = {}
    for tid in ids:
        if tid in out:
            continue
        tactic = given[0] if len(given) == 1 else _TECHNIQUE_TO_TACTIC.get(tid.split(".")[0])
        out[tid] = tactic or (given[0] if given else None)
    return out


async def _scan(db: Any, tenant_id: uuid.UUID, since: datetime, found: dict[str, dict[str, Any]]) -> None:
    rows = (
        await db.execute(
            select(Alert.title, Alert.description, Alert.mitre_techniques, Alert.mitre_tactics)
            .where(and_(Alert.tenant_id == tenant_id, Alert.created_at >= since))
            .order_by(Alert.created_at.desc())
            .limit(MAX_ALERTS)
        )
    ).all()
    for title, description, techniques, tactics in rows:
        for tid, tactic in techniques_for_alert(title, description, techniques, tactics).items():
            cell = found.setdefault(tid, {"alerts": 0, "tactic": None})
            cell["alerts"] += 1
            if cell["tactic"] is None and tactic:
                cell["tactic"] = tactic


async def observed_techniques(
    db: Any,
    tenant_id: uuid.UUID,
    *,
    now: datetime | None = None,
    scope: Callable[[Any, uuid.UUID], Any] = acting_as_tenant,
) -> dict[str, dict[str, Any]]:
    """Techniques seen in the last 90 days on this tenant's alerts and, for an MSSP parent, on each client's alerts too."""
    since = (now or datetime.now(UTC)) - WINDOW
    found: dict[str, dict[str, Any]] = {}
    await _scan(db, tenant_id, since, found)
    children = (await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == tenant_id))).scalars().all()
    for child_id in children:
        async with scope(db, child_id):
            await _scan(db, child_id, since, found)
    return found
