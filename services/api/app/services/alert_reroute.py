"""Move alerts that CORE forwarded before a client was mapped under the client tenant they belong to.

New alerts are routed to their client's tenant as they arrive (the fusion service, services/fusion/app/services/client_routing.py). An alert that arrived BEFORE its client
was mapped stays under the MSSP parent. This applies the same rule to those: an alert of the parent, from a vendor with a mapped client, whose context names that vendor's
client id, moves to the mapped child tenant. Its auto-opened case and its vendor actions move with it.

An alert that would collide with one already stored under the client (same dedup hash, e.g. it was also pulled again after the mapping) is left where it is and counted.
Needs a database role that may rewrite ``tenant_id`` (row-level security applies the policy's USING expression to the new row too, so the restricted role cannot); a role that
cannot gets a clear error rather than a half-done move.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.models.client_alias import ClientAlias
from app.models.tenant import Tenant

# vendor -> the key in the record's context that holds that vendor's client id. Keep in step with services/fusion/app/services/client_routing.py.
CLIENT_ID_FIELD: dict[str, str] = {
    "huntress": "organization_id",
    "petra": "petra_tenant_id",
    "ninjaone": "organization_id",
    "threatmate": "threatmate_client_id",
    "addigy": "addigy_client_id",
    "blumira": "blumira_account_id",
    "fieldeffect": "fieldeffect_org_id",
}

_MATCH = (
    "a.tenant_id = :parent AND a.raw_event->>'source' = :vendor "
    "AND a.raw_event #>> ARRAY['unmapped', 'context', CAST(:field AS text)] = :vid"
)
_COUNT_SQL = f"SELECT count(*) FROM alerts a WHERE {_MATCH}"
_MOVE_SQL = (
    f"UPDATE alerts a SET tenant_id = :child WHERE {_MATCH} "
    "AND NOT EXISTS (SELECT 1 FROM alerts x WHERE x.tenant_id = :child AND x.dedup_hash IS NOT DISTINCT FROM a.dedup_hash AND x.id <> a.id) "
    "RETURNING a.id"
)
# A case moves only when every alert in it moved: a case spanning clients stays where it is.
_MOVE_CASES_SQL = "UPDATE aisoc_cases SET tenant_id = :child WHERE tenant_id = :parent AND cardinality(alert_ids) > 0 AND alert_ids <@ CAST(:ids AS uuid[])"
_MOVE_ACTIONS_SQL = "UPDATE vendor_actions SET tenant_id = :child WHERE tenant_id = :parent AND alert_id = ANY(CAST(:ids AS uuid[]))"


class RerouteError(Exception):
    pass


@dataclass
class RerouteResult:
    moved: int = 0
    left_duplicates: int = 0
    cases_moved: int = 0
    by_client: dict[str, int] = field(default_factory=dict)


async def reroute_alerts(db: Any, parent_id: uuid.UUID) -> RerouteResult:
    aliases = (
        await db.execute(
            select(ClientAlias.vendor, ClientAlias.vendor_client_id, ClientAlias.child_tenant_id, Tenant.name)
            .join(Tenant, Tenant.id == ClientAlias.child_tenant_id)
            .where(
                ClientAlias.tenant_id == parent_id,
                ClientAlias.ignored.is_(False),
                ClientAlias.child_tenant_id.is_not(None),
                ClientAlias.vendor.in_(list(CLIENT_ID_FIELD)),
                Tenant.parent_tenant_id == parent_id,
            )
        )
    ).all()

    result = RerouteResult()
    try:
        for vendor, vendor_client_id, child_id, child_name in aliases:
            params = {"parent": parent_id, "child": child_id, "vendor": vendor, "field": CLIENT_ID_FIELD[vendor], "vid": vendor_client_id}
            matching = (await db.execute(text(_COUNT_SQL), params)).scalar_one()
            if not matching:
                continue
            moved_ids = [str(r[0]) for r in (await db.execute(text(_MOVE_SQL), params)).all()]
            result.left_duplicates += matching - len(moved_ids)
            if not moved_ids:
                continue
            result.moved += len(moved_ids)
            result.by_client[child_name] = result.by_client.get(child_name, 0) + len(moved_ids)
            ids = {"parent": parent_id, "child": child_id, "ids": moved_ids}
            result.cases_moved += (await db.execute(text(_MOVE_CASES_SQL), ids)).rowcount or 0
            await db.execute(text(_MOVE_ACTIONS_SQL), ids)
    except DBAPIError as exc:
        await db.rollback()
        raise RerouteError(
            "The database refused to move the alerts (its role cannot rewrite an alert's tenant, which row-level security blocks). "
            "Nothing was changed. Run this as the database owner."
        ) from exc
    return result
