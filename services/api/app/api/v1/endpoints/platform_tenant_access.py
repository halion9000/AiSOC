"""Granting a person EVERY tenant (including ones created later), at `view` or `full`. PLATFORM ADMINISTRATORS ONLY (migration 074).

A customer's own administrators, and an MSP's, can grant a person access to the tenants they manage (`/tenants/{id}/access`); nobody but a platform administrator can hand out "all", because that is the whole customer base. The level must be stated explicitly here (there is no default): a mistaken
default would be far more dangerous than on one tenant. With `full` the person can also WRITE in any tenant, acting with their own role's permissions and never on identity or credential administration (see app.services.view_as); each write is recorded in that tenant's own audit log. These routes
are themselves refused while the caller is working in another tenant (they sit under /platform). The grant and its removal are audited in the platform administrator's own tenant log; what the person then does is audited in each tenant they work in.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.tenant import User
from app.models.tenant_access import AllTenantAccessGrant
from app.services.audit import emit_audit
from app.services.user_lookup import find_user_by_account_name

router = APIRouter(prefix="/platform/all-tenant-access", tags=["platform"])


class AllAccessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access: Literal["view", "full"]  # required: no default


class AllAccessGrantResponse(BaseModel):
    user_id: uuid.UUID
    account_name: str
    email: str | None = None
    username: str | None = None
    home_tenant_id: uuid.UUID
    access: str
    granted_by: str
    created_at: datetime


def _response(grant: AllTenantAccessGrant, user: User) -> AllAccessGrantResponse:
    return AllAccessGrantResponse(
        user_id=user.id, account_name=user.account_name, email=user.email, username=user.username, home_tenant_id=user.tenant_id, access=grant.access, granted_by=grant.granted_by_label, created_at=grant.created_at
    )


@router.get("", response_model=list[AllAccessGrantResponse])
async def list_all_tenant_access(current_user: Annotated[AuthUser, Depends(require_permission("platform:cross_tenant_query"))], db: DBSession) -> list[AllAccessGrantResponse]:
    """Everyone who has been granted every tenant, and at which level."""
    rows = (await db.execute(select(AllTenantAccessGrant, User).join(User, User.id == AllTenantAccessGrant.user_id).order_by(User.account_name))).all()
    return [_response(g, u) for g, u in rows]


@router.put("/{account_name}", response_model=AllAccessGrantResponse)
async def grant_all_tenant_access(
    account_name: str,
    body: AllAccessRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("platform:cross_tenant_query"))],
    db: DBSession,
) -> AllAccessGrantResponse:
    """Let this person work in EVERY tenant, at `view` or `full`. Idempotent; a different level changes the existing grant. Takes effect on their next request."""
    grantee = await find_user_by_account_name(db, account_name)
    if grantee is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No account with that name")
    if grantee.is_active is False:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="That account is deactivated.")
    grantee_id, grantee_name, home = grantee.id, grantee.account_name, str(grantee.tenant_id)
    existing = (await db.execute(select(AllTenantAccessGrant).where(AllTenantAccessGrant.user_id == grantee_id))).scalars().first()
    if existing is not None and existing.access == body.access:
        return _response(existing, grantee)
    before = existing.access if existing is not None else None
    if existing is None:
        grant = AllTenantAccessGrant(user_id=grantee_id, access=body.access, granted_by=current_user.user_id, granted_by_label=current_user.email or str(current_user.user_id))
        db.add(grant)
    else:
        existing.access = body.access
        grant = existing
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="platform:all_tenant_access_granted" if before is None else "platform:all_tenant_access_changed",
        resource="all_tenant_access",
        resource_id=str(grantee_id),
        changes={"account_name": grantee_name, "home_tenant_id": home, "before": before, "after": body.access},
    )
    await db.commit()
    await db.refresh(grant)
    return _response(grant, grantee)


@router.delete("/{account_name}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_all_tenant_access(
    account_name: str,
    current_user: Annotated[AuthUser, Depends(require_permission("platform:cross_tenant_query"))],
    db: DBSession,
) -> None:
    """Take the person's all-tenants access away. Takes effect on their next request. (Grants to individual tenants are separate and are not touched.)"""
    grantee = await find_user_by_account_name(db, account_name)
    grant = None
    if grantee is not None:
        grant = (await db.execute(select(AllTenantAccessGrant).where(AllTenantAccessGrant.user_id == grantee.id))).scalars().first()
    if grantee is None or grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such grant")
    await db.delete(grant)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="platform:all_tenant_access_revoked",
        resource="all_tenant_access",
        resource_id=str(grantee.id),
        changes={"account_name": grantee.account_name, "home_tenant_id": str(grantee.tenant_id), "before": grant.access},
    )
    await db.commit()
