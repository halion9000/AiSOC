"""Case counts for the dashboards, insights and the executive digest, read from aisoc_cases.

These used to count the old `cases` table (the ORM `Case` model), which nothing writes: after cases were created through the cases API, `/metrics/soc` reported `cases_opened_7d: 0` and `cases_closed_7d: 0`, and the dashboard, insights tiles and weekly digest
showed no cases. They also used the old status words ('open', 'in_progress'), which no case in aisoc_cases ever has. The real statuses are new, triaged, investigating, contained, resolved, closed.

Meanings, defined once here so every consumer agrees:
  * OPEN         = status new (nobody has started on it)         * IN_PROGRESS = triaged, investigating, contained (being worked)
  * FINISHED     = resolved or closed
  * finished_at  = COALESCE(resolved_at, closed_at): when a case was FIRST finished, so a case that is resolved and later closed counts once, at the resolve
  * sla breached = no deadline never breaches; a finished case breached only if it was finished after the deadline; an open one once the deadline has passed
Every statement is fixed SQL with bound parameters; the status lists are module constants, never user input.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text

OPEN = ("new",)
IN_PROGRESS = ("triaged", "investigating", "contained")
FINISHED = ("resolved", "closed")

FINISHED_AT = "COALESCE(resolved_at, closed_at)"
SLA_BREACHED = (
    "CASE WHEN sla_due_at IS NULL THEN false "
    "WHEN COALESCE(resolved_at, closed_at) IS NOT NULL THEN COALESCE(resolved_at, closed_at) > sla_due_at "
    "ELSE :now > sla_due_at END"  # :now is bound by the caller (not NOW()) so the rule is the same SQL everywhere and can be evaluated against a truth table in tests
)


def _in(statuses: tuple[str, ...]) -> str:
    return "status IN (" + ", ".join(f"'{s}'" for s in statuses) + ")"


async def count_with_status(db: Any, tenant_id: uuid.UUID, statuses: tuple[str, ...]) -> int:
    """Cases (right now) in any of `statuses`."""
    return int(await db.scalar(text(f"SELECT count(*) FROM aisoc_cases WHERE tenant_id = :tid AND {_in(statuses)}"), {"tid": tenant_id}) or 0)


async def count_created(db: Any, tenant_id: uuid.UUID, start: datetime, end: datetime | None = None, *, statuses: tuple[str, ...] | None = None) -> int:
    """Cases created in [start, end) (open-ended when `end` is None), optionally only those now in `statuses`."""
    where, params = ["tenant_id = :tid", "created_at >= :start"], {"tid": tenant_id, "start": start}
    if end is not None:
        where.append("created_at < :end")
        params["end"] = end
    if statuses:
        where.append(_in(statuses))
    return int(await db.scalar(text(f"SELECT count(*) FROM aisoc_cases WHERE {' AND '.join(where)}"), params) or 0)


async def count_finished_since(db: Any, tenant_id: uuid.UUID, since: datetime) -> int:
    """Cases first resolved or closed at or after `since`."""
    return int(await db.scalar(text(f"SELECT count(*) FROM aisoc_cases WHERE tenant_id = :tid AND {FINISHED_AT} >= :since"), {"tid": tenant_id, "since": since}) or 0)


async def created_timestamps(db: Any, tenant_id: uuid.UUID, start: datetime, end: datetime) -> list[datetime]:
    rows = (await db.execute(text("SELECT created_at FROM aisoc_cases WHERE tenant_id = :tid AND created_at >= :start AND created_at < :end"), {"tid": tenant_id, "start": start, "end": end})).all()
    return [r[0] for r in rows]


async def count_open_before(db: Any, tenant_id: uuid.UUID, at: datetime) -> int:
    """Cases created before `at` and not finished (by their CURRENT status: the table keeps no status history)."""
    return int(await db.scalar(text(f"SELECT count(*) FROM aisoc_cases WHERE tenant_id = :tid AND created_at < :at AND status NOT IN ({', '.join(repr(s) for s in FINISHED)})"), {"tid": tenant_id, "at": at}) or 0)


async def digest_rows(db: Any, tenant_id: uuid.UUID, created_since: datetime) -> list[Any]:
    """(status, created_at, closed_at, sla_breached) per case created since `created_since`; closed_at is the FIRST finish time."""
    sql = f"SELECT status, created_at, {FINISHED_AT} AS closed_at, {SLA_BREACHED} AS sla_breached FROM aisoc_cases WHERE tenant_id = :tid AND created_at >= :since"
    return list((await db.execute(text(sql), {"tid": tenant_id, "since": created_since, "now": datetime.now(UTC)})).all())
