"""Which AiSOC tenant a vendor's client belongs to: the database side of client mapping.

``client_matching`` ranks names (pure). This module reads and writes the ``client_aliases`` rows around it: CORE pushes each vendor's client list, a person maps, ignores or creates a tenant for each,
and the Unmapped list is whatever has no tenant yet and has not been ignored.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from app.models.client_alias import ClientAlias
from app.models.tenant import Tenant
from app.services.client_matching import Candidate, Suggestion, is_confident, normalize_name, suggest

SYNC_KEY = "client_sync_vendors"


async def new_child(db: Any, parent_id: uuid.UUID, name: str) -> Tenant:
    """Create a client tenant under ``parent_id`` (and mark the parent as an MSSP parent). The caller owns the transaction."""
    child = Tenant(id=uuid.uuid4(), name=name.strip(), slug=make_slug(name), parent_tenant_id=parent_id, mssp_role="child")
    db.add(child)
    parent = await db.get(Tenant, parent_id)
    if parent is not None and parent.mssp_role != "parent":
        parent.mssp_role = "parent"
    await db.flush()
    return child


async def sync_vendors(db: Any, parent_id: uuid.UUID) -> list[str]:
    """The tools whose clients are added as client tenants automatically (a setting of the MSSP tenant)."""
    parent = await db.get(Tenant, parent_id)
    found = (parent.settings or {}).get(SYNC_KEY) if parent is not None and isinstance(parent.settings, dict) else None
    return sorted({v for v in found if isinstance(v, str)}) if isinstance(found, list) else []


async def set_sync_vendors(db: Any, parent_id: uuid.UUID, vendors: list[str]) -> list[str]:
    parent = await db.get(Tenant, parent_id)
    chosen = sorted(set(vendors))
    if parent is not None:
        parent.settings = {**(parent.settings or {}), SYNC_KEY: chosen}
    return chosen


def make_slug(name: str) -> str:
    """A unique, URL-safe tenant slug for a new client: its name plus a random suffix, so two clients called the same thing never collide."""
    base = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")[:80] or "client"
    return f"{base}-{uuid.uuid4().hex[:6]}"


async def child_candidates(db: Any, parent_id: uuid.UUID) -> list[Candidate]:
    rows = (await db.execute(select(Tenant).where(Tenant.parent_tenant_id == parent_id))).scalars().all()
    return [Candidate(tenant_id=str(t.id), name=t.name) for t in rows]


@dataclass(frozen=True)
class IncomingClient:
    client_id: str
    name: str


async def upsert_clients(db: Any, tenant_id: uuid.UUID, vendor: str, clients: list[IncomingClient]) -> tuple[int, int]:
    """Record the vendor's clients. Returns (new rows, rows linked automatically).

    A client already known keeps whatever a person decided (its tenant, ignored flag); only its display name is refreshed. A NEW client is linked straight away only when its name matches exactly
    one existing client tenant after normalization ("Acme Dental, LLC" = "Acme Dental"); anything less certain waits in the Unmapped list for a person.
    """
    candidates = await child_candidates(db, tenant_id)
    existing = {
        a.vendor_client_id: a
        for a in (await db.execute(select(ClientAlias).where(ClientAlias.tenant_id == tenant_id, ClientAlias.vendor == vendor)))
        .scalars()
        .all()
    }
    created = linked = 0
    for c in clients:
        row = existing.get(c.client_id)
        if row is not None:
            if row.vendor_client_name != c.name:
                row.vendor_client_name = c.name
                row.normalized_name = normalize_name(c.name)
            continue
        suggestions = suggest(c.name, candidates)
        child_id = uuid.UUID(suggestions[0].tenant_id) if is_confident(suggestions) else None
        db.add(
            ClientAlias(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                vendor=vendor,
                vendor_client_id=c.client_id,
                vendor_client_name=c.name,
                normalized_name=normalize_name(c.name),
                child_tenant_id=child_id,
                ignored=False,
                match_source="suggested",
            )
        )
        created += 1
        linked += 1 if child_id else 0
    await db.flush()
    # A tool chosen as a source adds its new clients as tenants straight away (or links them to the tenant you already have by that name).
    if vendor in await sync_vendors(db, tenant_id):
        await import_unmapped(db, tenant_id, vendor, lambda name: new_child(db, tenant_id, name))
    return created, linked


def suggestions_for(alias: ClientAlias, candidates: list[Candidate]) -> list[Suggestion]:
    """Only an unmapped, not-ignored client gets suggestions."""
    if alias.child_tenant_id is not None or alias.ignored:
        return []
    return suggest(alias.vendor_client_name, candidates)


async def import_unmapped(db: Any, parent_id: uuid.UUID, vendor: str, make_child: Any) -> tuple[int, int]:
    """Give every unmapped, not-ignored client of one vendor a tenant. Returns (new tenants created, clients linked to a tenant that already existed).

    A client whose name matches a tenant you already have (after normalization: "ACME Dental, LLC" = "Acme Dental"), including one created a moment ago for the same
    customer from another tool, is linked to it instead of getting a duplicate. ``make_child(name)`` creates the tenant.
    """
    candidates = await child_candidates(db, parent_id)
    pending = (
        (
            await db.execute(
                select(ClientAlias)
                .where(
                    ClientAlias.tenant_id == parent_id,
                    ClientAlias.vendor == vendor,
                    ClientAlias.child_tenant_id.is_(None),
                    ClientAlias.ignored.is_(False),
                )
                .order_by(ClientAlias.vendor_client_name)
            )
        )
        .scalars()
        .all()
    )
    created = linked = 0
    for alias in pending:
        same = [c for c in candidates if normalize_name(c.name) == alias.normalized_name]
        if len(same) == 1:
            alias.child_tenant_id = uuid.UUID(same[0].tenant_id)
            linked += 1
        elif len(same) > 1:
            continue  # two tenants share this name: a person has to choose
        else:
            child = await make_child(alias.vendor_client_name)
            candidates.append(Candidate(tenant_id=str(child.id), name=child.name))
            alias.child_tenant_id = child.id
            created += 1
        alias.match_source = "manual"
    await db.flush()
    return created, linked
