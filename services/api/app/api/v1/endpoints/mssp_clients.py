"""MSSP console: add a client, and map each vendor's client to one AiSOC tenant.

``POST /mssp/clients/new`` creates a fresh child tenant (nothing is claimed from anyone else, so ``mssp:manage`` is enough; ``mssp:onboard`` stays for claiming an existing tenant).
The ``/mssp/clients`` routes list the clients CORE forwarded from each vendor (Petra, Halo, Huntress, ...), with suggested matches, and let a person map, create-and-map, ignore or unmap each one.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.client_alias import ClientAlias
from app.models.tenant import Tenant
from app.services.audit import emit_audit
from app.services.client_mapping import child_candidates, make_slug, suggestions_for

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
    ignored: bool
    match_source: str
    suggestions: list[SuggestionOut]


class ClientsOut(BaseModel):
    clients: list[ClientAliasOut]
    unmapped: int


class MapRequest(BaseModel):
    child_tenant_id: uuid.UUID | None = None
    new_tenant_name: str | None = Field(default=None, max_length=255)


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
    child = Tenant(id=uuid.uuid4(), name=clean, slug=make_slug(clean), parent_tenant_id=current_user.tenant_id, mssp_role="child")
    db.add(child)
    parent = await db.get(Tenant, current_user.tenant_id)
    if parent is not None and parent.mssp_role != "parent":
        parent.mssp_role = "parent"  # type: ignore[assignment]
    await db.flush()
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
    out = [
        ClientAliasOut(
            id=a.id,
            vendor=a.vendor,
            vendor_client_id=a.vendor_client_id,
            vendor_client_name=a.vendor_client_name,
            child_tenant_id=a.child_tenant_id,
            child_tenant_name=names.get(str(a.child_tenant_id)) if a.child_tenant_id else None,
            ignored=a.ignored,
            match_source=a.match_source,
            suggestions=[SuggestionOut(tenant_id=s.tenant_id, name=s.name, score=s.score) for s in suggestions_for(a, candidates)],
        )
        for a in aliases
    ]
    return ClientsOut(clients=out, unmapped=sum(1 for a in aliases if a.child_tenant_id is None and not a.ignored))


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
