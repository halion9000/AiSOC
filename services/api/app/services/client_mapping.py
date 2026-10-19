"""Which AiSOC tenant a vendor's client belongs to: the database side of client mapping.

``client_matching`` ranks names (pure). This module reads and writes the ``client_aliases`` rows around it: CORE pushes each vendor's client list, a person maps, ignores or creates a tenant for each,
and the Unmapped list is whatever has no tenant yet and has not been ignored.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.models.client_alias import ClientAlias, ClientDeviceHint
from app.models.device import Device
from app.models.tenant import Tenant
from app.services.client_matching import (
    Candidate,
    DeviceOverlap,
    Suggestion,
    device_auto_match,
    device_suggestions,
    is_confident,
    merge_suggestions,
    normalize_name,
    suggest,
    usable_hostnames,
)

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


DISMISSED_KEY = "dismissed_duplicates"


def dismissed_duplicate_sets(parent: Any) -> set[frozenset[str]]:
    """Groups of client tenants the MSSP said are NOT the same customer (a setting of the MSSP tenant). Each is the exact set of tenant ids."""
    found = (getattr(parent, "settings", None) or {}).get(DISMISSED_KEY)
    if not isinstance(found, list):
        return set()
    return {frozenset(x for x in g if isinstance(x, str)) for g in found if isinstance(g, list)}


def dismiss_duplicate_group(parent: Any, tenant_ids: list[str], existing_ids: set[str] | None = None) -> None:
    """Record a dismissed group. When ``existing_ids`` (the MSSP's current client tenants) is given, groups that mention a tenant that no longer exists are dropped, so the setting does not grow forever."""
    sets = dismissed_duplicate_sets(parent) | {frozenset(tenant_ids)}
    if existing_ids is not None:
        sets = {g for g in sets if g <= existing_ids}
    parent.settings = {
        **(parent.settings or {}),
        DISMISSED_KEY: sorted(sorted(g) for g in sets),
    }  # a new dict, so the JSONB column is seen as changed


def without_dismissed(groups: list[list[Candidate]], parent: Any) -> list[list[Candidate]]:
    """Drop the groups that were dismissed. Only an identical set of tenants stays hidden: when a new lookalike joins, the group is shown again."""
    dismissed = dismissed_duplicate_sets(parent)
    return [g for g in groups if frozenset(c.tenant_id for c in g) not in dismissed]


def make_slug(name: str) -> str:
    """A unique, URL-safe tenant slug for a new client: its name plus a random suffix, so two clients called the same thing never collide."""
    base = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")[:80] or "client"
    return f"{base}-{uuid.uuid4().hex[:6]}"


def tenant_hidden(tenant: Any) -> bool:
    """A client tenant the MSSP hid (test clients, say). Kept in the tenant's settings, so no schema change."""
    return bool((getattr(tenant, "settings", None) or {}).get("hidden"))


def set_tenant_hidden(tenant: Any, hidden: bool) -> None:
    settings = dict(getattr(tenant, "settings", None) or {})
    if hidden:
        settings["hidden"] = True
    else:
        settings.pop("hidden", None)
    tenant.settings = settings  # a new dict, so the JSONB column is seen as changed


async def child_candidates(db: Any, parent_id: uuid.UUID, include_hidden: bool = False) -> list[Candidate]:
    """The client tenants a vendor client could be linked to. Hidden ones (test clients, archived ones) are left out unless asked for, so an import never re-links to one."""
    rows = (await db.execute(select(Tenant).where(Tenant.parent_tenant_id == parent_id))).scalars().all()
    return [Candidate(tenant_id=str(t.id), name=t.name) for t in rows if include_hidden or not tenant_hidden(t)]


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


class NameTaken(Exception):
    """A tenant already uses this exact name but is not a link candidate (for example a hidden one)."""


async def import_unmapped(db: Any, parent_id: uuid.UUID, vendor: str, make_child: Any, skipped: list[str] | None = None) -> tuple[int, int]:
    """Give every unmapped, not-ignored client of one vendor a tenant. Returns (new tenants created, clients linked to a tenant that already existed).

    A client whose name matches a tenant you already have (after normalization: "ACME Dental, LLC" = "Acme Dental"), including one created a moment ago for the same
    customer from another tool, is linked to it instead of getting a duplicate. ``make_child(name)`` creates the tenant; if it raises ``NameTaken`` the client is left unmapped
    and its name is added to ``skipped`` (one such client must not fail the whole import).
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
            try:
                child = await make_child(alias.vendor_client_name)
            except NameTaken:
                if skipped is not None:
                    skipped.append(alias.vendor_client_name)
                continue
            candidates.append(Candidate(tenant_id=str(child.id), name=child.name))
            alias.child_tenant_id = child.id
            created += 1
        alias.match_source = "manual"
    await db.flush()
    return created, linked


class MergeError(Exception):
    """A merge that cannot go ahead; ``status`` is the HTTP code to answer with."""

    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


async def merge_clients(db: Any, parent_id: uuid.UUID, source_id: uuid.UUID, target_id: uuid.UUID) -> tuple[Tenant, Tenant, int]:
    """Fold one client tenant into another that is the same customer. The caller audits and commits.

    Every tool client mapped to ``source`` is mapped to ``target`` instead, so what CORE sends from now on lands there, and ``source`` is hidden with ``merged_into`` recording
    where it went. Nothing is deleted and nothing is moved between tenants: alerts and cases already in ``source`` stay in it (tenant data is isolated, and audit records cannot be
    moved), and un-hiding it brings it back. Returns ``(source, target, how many tool clients were re-pointed)``.
    """
    if source_id == target_id:
        raise MergeError("Choose two different clients to merge.")
    found = {
        t.id: t
        for t in (
            await db.execute(select(Tenant).where(Tenant.id.in_([source_id, target_id]), Tenant.parent_tenant_id == parent_id))
        ).scalars()
    }
    if source_id not in found or target_id not in found:
        raise MergeError("Client not found", 404)
    source, target = found[source_id], found[target_id]
    if tenant_hidden(target):
        raise MergeError("The client to keep is hidden; show it first or pick another.")
    result = await db.execute(
        update(ClientAlias)
        .where(ClientAlias.tenant_id == parent_id, ClientAlias.child_tenant_id == source_id)
        .values(child_tenant_id=target_id, ignored=False, match_source="manual")
    )
    set_tenant_hidden(source, True)
    settings = dict(source.settings or {})
    settings["merged_into"] = str(target_id)
    source.settings = settings
    return source, target, result.rowcount or 0


# ---- machine names as evidence ---------------------------------------------------------------------------------------------------------------------------------

HINTS_PER_CLIENT = 300
HINT_KEEP = timedelta(days=14)


async def record_device_hints(db: Any, owner: uuid.UUID, vendor: str, vendor_client_id: str, hostnames: list[str]) -> None:
    """Remember (lower-cased, at most HINTS_PER_CLIENT per client) the machine names a tool reports for a client that is not mapped yet. Refreshes the time on ones already kept and
    forgets those not reported for HINT_KEEP. The caller owns the transaction."""
    keys = sorted({h.strip().lower()[:255] for h in hostnames if h and h.strip()})[:HINTS_PER_CLIENT]
    now = datetime.now(UTC)
    if keys:
        stmt = pg_insert(ClientDeviceHint).values(
            [{"tenant_id": owner, "vendor": vendor, "vendor_client_id": vendor_client_id, "hostname_key": k, "seen_at": now} for k in keys]
        )
        await db.execute(
            stmt.on_conflict_do_update(index_elements=["tenant_id", "vendor", "vendor_client_id", "hostname_key"], set_={"seen_at": now})
        )
    await db.execute(
        delete(ClientDeviceHint).where(
            ClientDeviceHint.tenant_id == owner,
            ClientDeviceHint.vendor == vendor,
            ClientDeviceHint.vendor_client_id == vendor_client_id,
            ClientDeviceHint.seen_at < now - HINT_KEEP,
        )
    )


async def device_overlaps(
    db: Any, owner: uuid.UUID, child_ids: list[uuid.UUID], acting: Any, only: set[tuple[str, str]] | None = None
) -> dict[tuple[str, str], list[DeviceOverlap]]:
    """For each (vendor, vendor client id) with remembered machine names, how many of them are machines under each client tenant.

    ``acting(tenant_id)`` returns the context manager that reads as that tenant (devices are tenant data). Machines are compared by lower-cased name.
    """
    rows = (
        await db.execute(
            select(ClientDeviceHint.vendor, ClientDeviceHint.vendor_client_id, ClientDeviceHint.hostname_key).where(
                ClientDeviceHint.tenant_id == owner
            )
        )
    ).all()
    hints: dict[tuple[str, str], set[str]] = {}
    for vendor, vcid, key in rows:
        hints.setdefault((vendor, vcid), set()).add(key)
    # Generic names ("MacBook-Pro", "Server") are evidence of nothing: leave them out of the comparison and out of the totals.
    usable = {k: usable_hostnames(v) for k, v in hints.items()}
    hints = {k: v for k, v in usable.items() if v}
    if only is not None:
        hints = {k: v for k, v in hints.items() if k in only}
    if not hints:
        return {}
    out: dict[tuple[str, str], list[DeviceOverlap]] = {k: [] for k in hints}
    for tid in child_ids:
        async with acting(tid):
            names = {n.lower() for n in (await db.execute(select(Device.hostname).where(Device.tenant_id == tid))).scalars().all() if n}
        if not names:
            continue
        for key, wanted in hints.items():
            shared = len(wanted & names)
            if shared:
                out[key].append(DeviceOverlap(str(tid), shared, len(wanted)))
    return out


def suggestions_with_devices(
    alias: ClientAlias, candidates: list[Candidate], overlaps: dict[tuple[str, str], list[DeviceOverlap]]
) -> list[Suggestion]:
    """Name suggestions, strengthened (or joined) by machines in common. Only an unmapped, not-ignored client gets any."""
    if alias.child_tenant_id is not None or alias.ignored:
        return []
    names = {c.tenant_id: c.name for c in candidates}
    by_devices = device_suggestions(overlaps.get((alias.vendor, alias.vendor_client_id), []), names)
    return merge_suggestions(suggest(alias.vendor_client_name, candidates), by_devices)


async def auto_link_by_devices(db: Any, owner: uuid.UUID, keys: set[tuple[str, str]], acting: Any) -> int:
    """Link unmapped tool clients to a client without asking when their machines say so (``device_auto_match``: every non-generic machine name is already a machine under ONE client, and
    there are at least three). Never touches a client a person mapped, unmapped or ignored. Returns how many were linked. The caller owns the transaction."""
    if not keys:
        return 0
    aliases = (
        (
            await db.execute(
                select(ClientAlias).where(
                    ClientAlias.tenant_id == owner,
                    ClientAlias.child_tenant_id.is_(None),
                    ClientAlias.ignored.is_(False),
                    ClientAlias.match_source != "manual",
                )
            )
        )
        .scalars()
        .all()
    )
    wanted = [a for a in aliases if (a.vendor, a.vendor_client_id) in keys]
    if not wanted:
        return 0
    candidates = await child_candidates(db, owner)  # hidden clients are never offered
    allowed = {c.tenant_id for c in candidates}
    overlaps = await device_overlaps(db, owner, [uuid.UUID(t) for t in allowed], acting, {(a.vendor, a.vendor_client_id) for a in wanted})
    linked = 0
    for a in wanted:
        tenant = device_auto_match(overlaps.get((a.vendor, a.vendor_client_id), []))
        if tenant is not None and tenant in allowed:
            a.child_tenant_id = uuid.UUID(tenant)
            a.match_source = "suggested"
            linked += 1
    if linked:
        await db.flush()
    return linked
