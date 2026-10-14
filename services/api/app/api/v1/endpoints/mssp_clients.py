"""MSSP console: add a client, and map each vendor's client to one AiSOC tenant.

``POST /mssp/clients/new`` creates a fresh child tenant (nothing is claimed from anyone else, so ``mssp:manage`` is enough; ``mssp:onboard`` stays for claiming an existing tenant).
The ``/mssp/clients`` routes list the clients CORE forwarded from each vendor (Petra, Halo, Huntress, ...), with suggested matches, and let a person map, create-and-map, ignore or unmap each one.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import DBAPIError

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.db.rls_scope import acting_as_tenant
from app.models.alert import Alert
from app.models.client_alias import ClientAlias
from app.models.tenant import Tenant
from app.services.audit import emit_audit
from app.services.client_mapping import (
    child_candidates,
    import_unmapped,
    new_child,
    set_sync_vendors,
    set_tenant_hidden,
    suggestions_for,
    sync_vendors,
    tenant_hidden,
)
from app.services.client_matching import duplicate_groups

router = APIRouter(prefix="/mssp", tags=["mssp"])


class NewClient(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class NewClientOut(BaseModel):
    id: uuid.UUID
    name: str


class SuggestionOut(BaseModel):
    tenant_id: str
    name: str
    score: float


class ClientAliasOut(BaseModel):
    id: uuid.UUID
    vendor: str
    vendor_client_id: str
    vendor_client_name: str
    child_tenant_id: uuid.UUID | None
    child_tenant_name: str | None
    child_tenant_hidden: bool = False
    ignored: bool
    match_source: str
    suggestions: list[SuggestionOut]


class DuplicateTenantOut(BaseModel):
    tenant_id: str
    name: str
    # The tool clients mapped to this tenant, e.g. "Huntress: Acme Dental".
    mapped_from: list[str]


class DuplicateGroupOut(BaseModel):
    tenants: list[DuplicateTenantOut]


class ClientsOut(BaseModel):
    clients: list[ClientAliasOut]
    unmapped: int
    # Client tenants whose names look like the same customer.
    duplicates: list[DuplicateGroupOut] = []
    # Tools whose clients are added as client tenants automatically.
    sync_vendors: list[str] = []


class MapRequest(BaseModel):
    child_tenant_id: uuid.UUID | None = None
    new_tenant_name: str | None = Field(default=None, max_length=255)


class ImportRequest(BaseModel):
    vendor: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")


class ImportOut(BaseModel):
    created: int
    linked: int


class IgnoreRequest(BaseModel):
    ignored: bool = True


async def _make_child(db: TenantDBSession, current_user: AuthUser, name: str) -> Tenant:
    clean = name.strip()
    if not clean:
        raise HTTPException(status_code=422, detail="A client needs a name.")
    taken = (
        await db.execute(
            select(func.count())
            .select_from(Tenant)
            .where(Tenant.parent_tenant_id == current_user.tenant_id, func.lower(Tenant.name) == clean.lower())
        )
    ).scalar_one()
    if taken:
        raise HTTPException(status_code=409, detail=f"You already have a client called {clean}.")
    child = await new_child(db, current_user.tenant_id, clean)
    return child


@router.post("/clients/new", response_model=NewClientOut, status_code=status.HTTP_201_CREATED)
async def create_client(
    body: NewClient,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))],
    db: TenantDBSession,
) -> NewClientOut:
    """Add a client (a new child tenant) by hand."""
    child = await _make_child(db, current_user, body.name)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        action="mssp:client_created",
        resource="tenant",
        resource_id=str(child.id),
        changes={"name": child.name},
        request=request,
    )
    await db.commit()
    return NewClientOut(id=child.id, name=child.name)


async def _alias(db: TenantDBSession, alias_id: uuid.UUID, tenant_id: uuid.UUID) -> ClientAlias:
    row = (await db.execute(select(ClientAlias).where(ClientAlias.id == alias_id, ClientAlias.tenant_id == tenant_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Client not found")
    return row


@router.get("/clients", response_model=ClientsOut)
async def list_clients(current_user: Annotated[AuthUser, Depends(require_permission("mssp:read"))], db: TenantDBSession) -> ClientsOut:
    """Every client CORE has forwarded, with the tenant it is mapped to or the best suggestions."""
    aliases = (
        (
            await db.execute(
                select(ClientAlias)
                .where(ClientAlias.tenant_id == current_user.tenant_id)
                .order_by(ClientAlias.vendor, ClientAlias.vendor_client_name)
            )
        )
        .scalars()
        .all()
    )
    candidates = await child_candidates(db, current_user.tenant_id)
    names = {c.tenant_id: c.name for c in candidates}
    hidden_ids = {
        str(t.id)
        for t in (await db.execute(select(Tenant).where(Tenant.parent_tenant_id == current_user.tenant_id))).scalars().all()
        if tenant_hidden(t)
    }
    candidates = [c for c in candidates if c.tenant_id not in hidden_ids]  # never suggest a hidden test client
    out = [
        ClientAliasOut(
            id=a.id,
            vendor=a.vendor,
            vendor_client_id=a.vendor_client_id,
            vendor_client_name=a.vendor_client_name,
            child_tenant_id=a.child_tenant_id,
            child_tenant_name=names.get(str(a.child_tenant_id)) if a.child_tenant_id else None,
            child_tenant_hidden=str(a.child_tenant_id) in hidden_ids if a.child_tenant_id else False,
            ignored=a.ignored,
            match_source=a.match_source,
            suggestions=[SuggestionOut(tenant_id=s.tenant_id, name=s.name, score=s.score) for s in suggestions_for(a, candidates)],
        )
        for a in aliases
    ]
    sources: dict[str, list[str]] = {}
    for a in aliases:
        if a.child_tenant_id is not None:
            sources.setdefault(str(a.child_tenant_id), []).append(f"{a.vendor}: {a.vendor_client_name}")
    duplicates = [
        DuplicateGroupOut(
            tenants=[
                DuplicateTenantOut(tenant_id=c.tenant_id, name=c.name, mapped_from=sorted(sources.get(c.tenant_id, []))) for c in group
            ]
        )
        for group in duplicate_groups(candidates)
    ]
    return ClientsOut(
        clients=out,
        duplicates=duplicates,
        unmapped=sum(1 for a in aliases if a.child_tenant_id is None and not a.ignored),
        sync_vendors=await sync_vendors(db, current_user.tenant_id),
    )


@router.post("/clients/{alias_id}/map", response_model=ClientAliasOut)
async def map_client(
    alias_id: uuid.UUID,
    body: MapRequest,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))],
    db: TenantDBSession,
) -> ClientAliasOut:
    """Map a vendor client to one of your client tenants, or to a new one created from ``new_tenant_name``. A person's choice is never replaced by a suggestion."""
    if (body.child_tenant_id is None) == (not (body.new_tenant_name or "").strip()):
        raise HTTPException(status_code=422, detail="Choose an existing client or give the name of a new one, not both and not neither.")
    alias = await _alias(db, alias_id, current_user.tenant_id)
    if body.child_tenant_id is not None:
        child = await db.get(Tenant, body.child_tenant_id)
        if child is None or child.parent_tenant_id != current_user.tenant_id:
            raise HTTPException(status_code=404, detail="Client tenant not found")
    else:
        child = await _make_child(db, current_user, body.new_tenant_name or "")
    alias.child_tenant_id = child.id  # type: ignore[assignment]
    alias.ignored = False  # type: ignore[assignment]
    alias.match_source = "manual"  # type: ignore[assignment]
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        action="mssp:client_mapped",
        resource="client_alias",
        resource_id=str(alias.id),
        changes={"vendor": alias.vendor, "vendor_client": alias.vendor_client_name, "tenant": str(child.id)},
        request=request,
    )
    await db.commit()
    return ClientAliasOut(
        id=alias.id,
        vendor=alias.vendor,
        vendor_client_id=alias.vendor_client_id,
        vendor_client_name=alias.vendor_client_name,
        child_tenant_id=child.id,
        child_tenant_name=child.name,
        ignored=False,
        match_source="manual",
        suggestions=[],
    )


@router.post("/clients/{alias_id}/unmap", status_code=status.HTTP_204_NO_CONTENT)
async def unmap_client(
    alias_id: uuid.UUID, current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))], db: TenantDBSession
) -> None:
    alias = await _alias(db, alias_id, current_user.tenant_id)
    alias.child_tenant_id = None  # type: ignore[assignment]
    alias.match_source = "suggested"  # type: ignore[assignment]
    await db.commit()


@router.post("/clients/{alias_id}/ignore", status_code=status.HTTP_204_NO_CONTENT)
async def ignore_client(
    alias_id: uuid.UUID,
    body: IgnoreRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))],
    db: TenantDBSession,
) -> None:
    """Hide a vendor client you do not manage from the Unmapped list (or bring it back with ``ignored: false``)."""
    alias = await _alias(db, alias_id, current_user.tenant_id)
    alias.ignored = body.ignored  # type: ignore[assignment]
    if body.ignored:
        alias.child_tenant_id = None  # type: ignore[assignment]
    await db.commit()


class HiddenRequest(BaseModel):
    hidden: bool


@router.put("/tenants/{tenant_id}/hidden", status_code=status.HTTP_204_NO_CONTENT)
async def set_client_hidden(
    tenant_id: uuid.UUID,
    body: HiddenRequest,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))],
    db: TenantDBSession,
) -> None:
    """Hide a client tenant (a test client, say) from the managed-tenant list and the dashboard totals, or show it again. Nothing is deleted."""
    child = (
        await db.execute(select(Tenant).where(Tenant.id == tenant_id, Tenant.parent_tenant_id == current_user.tenant_id))
    ).scalar_one_or_none()
    if child is None:
        raise HTTPException(status_code=404, detail="Client not found")
    set_tenant_hidden(child, body.hidden)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        action="mssp:client_hidden" if body.hidden else "mssp:client_shown",
        resource="tenant",
        resource_id=str(child.id),
        changes={"name": child.name},
        request=request,
    )
    await db.commit()


class RemoveOut(BaseModel):
    removed: bool
    name: str
    # Why it was kept, when it was.
    reason: str | None = None


# What stops a client tenant being removed. Deleting a tenant cascades to everything it owns, so work a person did there must be checked first, and audit records are
# tamper-proof (a database trigger refuses to delete them), so a tenant that has any cannot be removed at all. Investigation records are not on this list: the triage agent
# writes them for every alert, and migration 085 lets them go with the tenant that owns them (and only then).
_BLOCKERS = (
    ("cases", text("SELECT count(*) FROM cases WHERE tenant_id = :t")),
    ("connectors", text("SELECT count(*) FROM connectors WHERE tenant_id = :t")),
    ("alerts someone worked on", text("SELECT count(*) FROM alerts WHERE tenant_id = :t AND status <> 'new'")),
    ("audit records", text("SELECT count(*) FROM audit_log WHERE tenant_id = :t")),
)


async def _blockers(db: TenantDBSession, tenant_id: uuid.UUID) -> list[str]:
    found: list[str] = []
    async with acting_as_tenant(db, tenant_id):
        for label, stmt in _BLOCKERS:
            if (await db.execute(stmt, {"t": tenant_id})).scalar_one():
                found.append(label)
    return found


@router.post("/tenants/{tenant_id}/remove", response_model=RemoveOut)
async def remove_client(
    tenant_id: uuid.UUID,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))],
    db: TenantDBSession,
) -> RemoveOut:
    """Remove ONE client tenant and its untouched ('new') alerts; every tool client that was mapped to it goes back to Unmapped.

    The console calls this once per client (start over = every client in turn), so no single request runs long enough for the web proxy to give up on it. A client with cases,
    connectors, alerts someone worked on, or audit records is kept and the reason returned: removing it would destroy that work, and audit records cannot be deleted
    at all. If the database cannot take the locks it needs within a few seconds the client is kept too, with that reason, instead of the request hanging.
    """
    child = (
        await db.execute(select(Tenant).where(Tenant.id == tenant_id, Tenant.parent_tenant_id == current_user.tenant_id))
    ).scalar_one_or_none()
    if child is None:
        raise HTTPException(status_code=404, detail="Client not found")
    name = child.name
    blockers = await _blockers(db, tenant_id)
    if blockers:
        return RemoveOut(removed=False, name=name, reason="it has " + ", ".join(blockers))
    try:
        async with db.begin_nested():
            # Fail fast rather than wait behind another process: a request that waits is abandoned by the web proxy after 30 seconds, and the work is lost without a word.
            await db.execute(text("SELECT set_config('lock_timeout', '8s', true), set_config('statement_timeout', '20s', true)"))
            async with acting_as_tenant(db, tenant_id):
                await db.execute(delete(Alert).where(Alert.tenant_id == tenant_id, Alert.status == "new"))
            await db.execute(
                update(ClientAlias)
                .where(ClientAlias.tenant_id == current_user.tenant_id, ClientAlias.child_tenant_id == tenant_id)
                .values(child_tenant_id=None, match_source="suggested")
            )
            await db.execute(delete(Tenant).where(Tenant.id == tenant_id, Tenant.parent_tenant_id == current_user.tenant_id))
    except DBAPIError as exc:  # a lock timeout, a constraint or a trigger refused it: keep the tenant and say why
        detail = " ".join(str(exc.orig or exc).split())[:160]
        return RemoveOut(removed=False, name=name, reason=f"the database would not remove it ({detail})")
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        action="mssp:client_removed",
        resource="tenant",
        resource_id=str(tenant_id),
        changes={"name": name},
        request=request,
    )
    await db.commit()
    return RemoveOut(removed=True, name=name)


@router.post("/clients/import", response_model=ImportOut)
async def import_clients(
    body: ImportRequest,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))],
    db: TenantDBSession,
) -> ImportOut:
    """Add every unmapped client from one tool as a client tenant (or link it to the tenant you already have by that name)."""

    async def make(name: str) -> Tenant:
        return await _make_child(db, current_user, name)

    created, linked = await import_unmapped(db, current_user.tenant_id, body.vendor, make)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        action="mssp:clients_imported",
        resource="client_alias",
        resource_id=body.vendor,
        changes={"vendor": body.vendor, "created": created, "linked": linked},
        request=request,
    )
    await db.commit()
    return ImportOut(created=created, linked=linked)


class SourcesRequest(BaseModel):
    vendors: list[Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")]] = Field(max_length=20)


class SourcesOut(BaseModel):
    sync_vendors: list[str]
    created: int
    linked: int


@router.put("/clients/sources", response_model=SourcesOut)
async def set_client_sources(
    body: SourcesRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))],
    db: TenantDBSession,
) -> SourcesOut:
    """Choose which tools add their clients as client tenants automatically. A tool newly chosen is imported right away; the rest are still mapped by hand."""
    before = set(await sync_vendors(db, current_user.tenant_id))
    chosen = await set_sync_vendors(db, current_user.tenant_id, body.vendors)
    created = linked = 0

    async def make(name: str) -> Tenant:
        return await _make_child(db, current_user, name)

    for vendor in sorted(set(chosen) - before):
        c, linked_now = await import_unmapped(db, current_user.tenant_id, vendor, make)
        created += c
        linked += linked_now
    await db.commit()
    return SourcesOut(sync_vendors=chosen, created=created, linked=linked)
