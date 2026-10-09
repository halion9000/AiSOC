"""Tenant and user management endpoints."""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.security import get_password_hash
from app.services.tenant_selection import selectable_tenants
from app.models.tenant import Tenant, User

router = APIRouter(prefix="/tenants", tags=["tenants"])


class TenantHeaderResponse(BaseModel):
    """Minimal tenant identity payload — safe for *any* authenticated user.

    Used by the SOC console TopBar to render the tenant switcher and role
    badge (Workstream 5). Intentionally excludes `plan`, `settings`, and
    `limits` so it does not leak privileged config to viewer/analyst roles.
    """

    id: uuid.UUID
    name: str
    mssp_role: str | None
    parent_tenant_id: uuid.UUID | None

    model_config = {"from_attributes": True}


class TenantResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    plan: str
    is_active: bool
    settings: dict
    limits: dict
    mssp_role: str | None = None
    parent_tenant_id: uuid.UUID | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class UserResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    last_login: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    role: str = "soc_analyst"


class UpdateUserRequest(BaseModel):
    username: str | None = None
    role: str | None = None
    is_active: bool | None = None


class UpdateTenantSettingsRequest(BaseModel):
    settings: dict = {}


class SelectableTenant(BaseModel):
    """Just enough to label a picker entry: the same minimal identity as /me/identity (no plan, settings or limits)."""

    id: uuid.UUID
    name: str
    slug: str


class SelectableTenantsResponse(BaseModel):
    own_tenant_id: uuid.UUID
    can_select_other_tenants: bool
    tenants: list[SelectableTenant]


@router.get("/selectable", response_model=SelectableTenantsResponse)
async def list_selectable_tenants(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
) -> SelectableTenantsResponse:
    """The tenants this caller may choose between in a tenant picker.

    Your own tenant, plus every other tenant if (and only if) you hold platform:cross_tenant_query; anyone else gets exactly one entry, their own, and `can_select_other_tenants: false`. Needs alerts:read (every role holds it), the permission of the pages that offer a picker."""
    can, rows = await selectable_tenants(db, current_user)
    return SelectableTenantsResponse(
        own_tenant_id=current_user.tenant_id,
        can_select_other_tenants=can,
        tenants=[SelectableTenant(id=t.id, name=t.name, slug=t.slug) for t in rows],
    )


@router.get("/me/identity", response_model=TenantHeaderResponse)
async def get_my_tenant_identity(
    current_user: AuthUser,
    db: DBSession,
) -> TenantHeaderResponse:
    """Get minimal tenant identity for the current user.

    Returns only `id`, `name`, `mssp_role`, and `parent_tenant_id`. This is
    safe for **any** authenticated user (analyst, viewer, responder, etc.)
    because it does not expose plan, settings, or limits. Used by the SOC
    console TopBar to render the tenant switcher pill and role badge.
    """
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantHeaderResponse.model_validate(tenant)


@router.get("/me", response_model=TenantResponse)
async def get_my_tenant(
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
    db: DBSession,
) -> TenantResponse:
    """Get the current user's tenant details (full config — requires settings:read)."""
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantResponse.model_validate(tenant)


@router.patch("/me/settings", response_model=TenantResponse)
async def update_tenant_settings(
    request: UpdateTenantSettingsRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> TenantResponse:
    """Update tenant settings."""
    await db.execute(
        update(Tenant)
        .where(Tenant.id == current_user.tenant_id)
        .values(
            settings=request.settings,
            updated_at=datetime.now(UTC),
        )
    )
    await db.commit()

    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    return TenantResponse.model_validate(result.scalar_one())


@router.get("/me/users", response_model=list[UserResponse])
async def list_users(
    current_user: Annotated[AuthUser, Depends(require_permission("users:read"))],
    db: DBSession,
) -> list[UserResponse]:
    """List all users in the current tenant."""
    result = await db.execute(select(User).where(User.tenant_id == current_user.tenant_id).order_by(User.created_at))
    users = result.scalars().all()
    return [UserResponse.model_validate(u) for u in users]


def _require_grantable_role(current_user: Any, role: str) -> None:
    """422 for a role that does not exist, 403 for one the caller may not hand out (see CurrentUser.can_grant_role)."""
    from app.core.security import ROLE_PERMISSIONS  # noqa: PLC0415

    if role not in ROLE_PERMISSIONS:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Unknown role. Known roles: {', '.join(sorted(ROLE_PERMISSIONS))}.")
    if not current_user.can_grant_role(role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You cannot assign a role that grants more than your own.")


@router.post("/me/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: CreateUserRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> UserResponse:
    """Create a new user in the current tenant."""
    _require_grantable_role(current_user, request.role)
    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == request.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists",
        )

    user = User(
        tenant_id=current_user.tenant_id,
        email=request.email,
        username=request.username,
        hashed_password=get_password_hash(request.password),
        role=request.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.patch("/me/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    request: UpdateUserRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> UserResponse:
    """Update a user."""
    result = await db.execute(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Nobody edits a user who holds more power than they do (a tenant_admin could otherwise deactivate or demote a platform_admin of the same tenant), and
    # nobody changes their OWN role (a tenant_admin could otherwise promote itself with one request).
    if not current_user.can_grant_role(user.role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You cannot modify a user whose role grants more than your own.")
    if request.role is not None:
        if user.id == current_user.user_id and request.role != user.role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You cannot change your own role.")
        _require_grantable_role(current_user, request.role)

    updates: dict = {}
    for field in ["username", "role", "is_active"]:
        val = getattr(request, field, None)
        if val is not None:
            updates[field] = val

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        await db.execute(update(User).where(User.id == user_id).values(**updates))
        await db.commit()
        await db.refresh(user)

    return UserResponse.model_validate(user)
