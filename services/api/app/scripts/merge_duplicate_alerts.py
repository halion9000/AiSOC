"""Merge alerts that are the same vendor incident stored more than once.

CORE puts the vendor's own incident id at ``raw_event.finding.uid`` (``huntress:123``, ``petra:<guid>``). When the alert fingerprint changed under incidents that were already
stored (the promoter began extracting a user, then the fingerprint gained the client id), every re-forwarded incident was stored a second time. Fusion now treats (tenant, incident id)
as the alert's identity; this cleans up the rows that were already doubled.

    python -m app.scripts.merge_duplicate_alerts            # dry run: only reports
    python -m app.scripts.merge_duplicate_alerts --apply    # do it
    python -m app.scripts.merge_duplicate_alerts --cross-tenant [--apply]   # also resolve one incident held by a parent AND a client tenant

Nothing is deleted. Per (tenant, incident id) ONE row is kept (one with a case, else an assigned one, else one carrying linked tickets, else the oldest). Each other row that nobody
is working on is closed as ``resolved``, marked ``is_merged`` with ``parent_alert_id`` pointing at the kept row, tagged ``duplicate-of-<id>`` and given an ``enrichment_data.merged_duplicate``
note, so the change is visible and reversible. A duplicate that is assigned or in progress is left as it is and reported. Duplicates of one incident in DIFFERENT tenants (a client mapped
after the incident was first stored under the feed's owner) are reported, not merged, unless ``--cross-tenant`` is given. Then the rule is: when exactly ONE client (child) tenant
holds the incident, the client keeps it and the parent/owner tenant's copy is closed as a duplicate of it (the client's own view is the one analysts work in); when several client
tenants hold it, nothing is touched. Idempotent.
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# Statuses of a duplicate that may be closed without anyone's decision being overridden.
_CLOSABLE = {"new", "resolved", "closed", "false_positive", "fp"}


@dataclass(frozen=True)
class Row:
    id: uuid.UUID
    status: str
    case_id: str | None
    assigned_to_id: uuid.UUID | None
    created_at: datetime
    has_tickets: bool = False


@dataclass
class Plan:
    keeper: uuid.UUID
    close: list[uuid.UUID] = field(default_factory=list)
    leave: list[uuid.UUID] = field(default_factory=list)


def plan_merge(rows: list[Row]) -> Plan:
    """Which row of one (tenant, incident id) group to keep, which duplicates to close, and which to leave alone."""
    ordered = sorted(rows, key=lambda r: (r.case_id is None, r.assigned_to_id is None, not r.has_tickets, r.created_at, str(r.id)))
    keeper, others = ordered[0], ordered[1:]
    plan = Plan(keeper=keeper.id)
    for r in others:
        (plan.close if r.status in _CLOSABLE else plan.leave).append(r.id)
    return plan


def plan_cross_tenant(
    by_tenant: dict[Any, list[Row]], child_tenants: set[Any]
) -> tuple[Any, uuid.UUID, list[tuple[Any, uuid.UUID]]] | None:
    """One incident held by several tenants: ``(client tenant, keeper row id, [(tenant, row id) to close])``, or None when the rule does not apply.

    Applies only when exactly one of the holding tenants is a client (child) tenant. The rows closed are the closable ones in the OTHER (parent/owner) tenants.
    """
    clients = [t for t in by_tenant if t in child_tenants]
    if len(clients) != 1:
        return None
    client = clients[0]
    keeper = plan_merge(by_tenant[client]).keeper
    closing = [(t, r.id) for t, rows in by_tenant.items() if t != client for r in rows if r.status in _CLOSABLE]
    return (client, keeper, closing) if closing else None


_GROUPS_SQL = """
SELECT tenant_id, (raw_event -> 'finding') ->> 'uid' AS uid,
       id, status, case_id, assigned_to_id, created_at,
       (jsonb_typeof(enrichment_data -> 'tickets') = 'array' AND jsonb_array_length(enrichment_data -> 'tickets') > 0) AS has_tickets
FROM alerts
WHERE NOT COALESCE(is_merged, FALSE)
  AND (raw_event -> 'finding') ->> 'uid' IN (
    SELECT (raw_event -> 'finding') ->> 'uid' FROM alerts
    WHERE (raw_event -> 'finding') ->> 'uid' IS NOT NULL AND NOT COALESCE(is_merged, FALSE)
    GROUP BY 1 HAVING count(*) > 1
)
ORDER BY tenant_id, uid, created_at
"""


async def merge(session: Any, *, apply: bool, cross_tenant: bool = False) -> dict[str, int]:
    """Plan (and with ``apply``, perform) the merge. The caller owns the transaction. Returns counts."""
    from sqlalchemy import text  # noqa: PLC0415

    rows = (await session.execute(text(_GROUPS_SQL))).all()
    groups: dict[tuple[Any, str], list[Row]] = {}
    tenants_of_uid: dict[str, set[Any]] = {}
    for tid, uid, rid, status, case_id, assigned, created, has_tickets in rows:
        groups.setdefault((tid, uid), []).append(Row(rid, status, case_id, assigned, created, bool(has_tickets)))
        tenants_of_uid.setdefault(uid, set()).add(tid)

    counts = {"incidents": 0, "closed": 0, "left_alone": 0, "cross_tenant_skipped": 0, "cross_tenant_closed": 0}
    now = datetime.now(UTC).isoformat()
    if cross_tenant:
        children = {r[0] for r in (await session.execute(text("SELECT id FROM tenants WHERE parent_tenant_id IS NOT NULL"))).all()}
    done_uids: set[str] = set()
    for (tid, uid), members in groups.items():
        if len(tenants_of_uid[uid]) > 1:
            if not cross_tenant:
                counts["cross_tenant_skipped"] += 1
                continue
            if uid in done_uids:
                continue
            done_uids.add(uid)
            plan = plan_cross_tenant({t: groups[(t, uid)] for t in tenants_of_uid[uid]}, children)
            if plan is None:
                counts["cross_tenant_skipped"] += 1
                continue
            client, keeper, closing = plan
            counts["cross_tenant_closed"] += len(closing)
            if apply:
                note = {
                    "merged_duplicate": {
                        "of": str(keeper),
                        "tenant": str(client),
                        "at": now,
                        "reason": "same vendor incident held by the client tenant",
                    }
                }
                for other_tenant, row_id in closing:
                    await session.execute(
                        text(
                            """
                            UPDATE alerts
                            SET status = 'resolved', is_merged = TRUE, parent_alert_id = :keeper, updated_at = NOW(),
                                tags = COALESCE(tags, '[]'::jsonb) || to_jsonb(CAST(:tag AS text)),
                                enrichment_data = COALESCE(enrichment_data, '{}'::jsonb) || CAST(:note AS jsonb)
                            WHERE id = :id AND tenant_id = :tenant
                            """
                        ).bindparams(keeper=keeper, tag=f"duplicate-of-{keeper}", note=json.dumps(note), id=row_id, tenant=other_tenant)
                    )
            continue
        if len(members) < 2:
            continue
        plan = plan_merge(members)
        counts["incidents"] += 1
        counts["left_alone"] += len(plan.leave)
        counts["closed"] += len(plan.close)
        if not apply or not plan.close:
            continue
        note = {"merged_duplicate": {"of": str(plan.keeper), "at": now, "reason": "same vendor incident id stored more than once"}}
        await session.execute(
            text(
                """
                UPDATE alerts
                SET status = 'resolved', is_merged = TRUE, parent_alert_id = :keeper, updated_at = NOW(),
                    tags = COALESCE(tags, '[]'::jsonb) || to_jsonb(CAST(:tag AS text)),
                    enrichment_data = COALESCE(enrichment_data, '{}'::jsonb) || CAST(:note AS jsonb)
                WHERE id = ANY(:ids) AND tenant_id = :tenant
                """
            ).bindparams(keeper=plan.keeper, tag=f"duplicate-of-{plan.keeper}", note=json.dumps(note), ids=list(plan.close), tenant=tid)
        )
    return counts


async def _main(apply: bool, cross_tenant: bool = False) -> int:
    from app.db.database import AsyncSessionLocal  # noqa: PLC0415
    from app.db.rls_scope import cross_tenant_reads  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        async with cross_tenant_reads(session):
            counts = await merge(session, apply=apply, cross_tenant=cross_tenant)
            if apply:
                await session.commit()
    mode = "applied" if apply else "dry run (nothing changed; pass --apply)"
    print(f"merge_duplicate_alerts {mode}: {json.dumps(counts)}")
    return 0


def main() -> None:
    sys.exit(asyncio.run(_main("--apply" in sys.argv[1:], "--cross-tenant" in sys.argv[1:])))


if __name__ == "__main__":
    main()
