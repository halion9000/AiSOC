"""Tenant and user management endpoints."""

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, model_validator
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.account_names import InvalidAccountName, validate_account_name
from app.core.emails import normalize_email
from app.core.security import get_password_hash
from app.services.account_names import account_name_taken, unique_account_name
from app.services.tenant_selection import selectable_tenants
from app.services.audit import emit_audit
from app.services.user_lookup import find_user_by_account_name
from app.services.tenant_selection import CROSS_TENANT_PERMISSION
from app.services.view_as import home_tenant_of, may_manage_access, viewable_tenants
from app.models.tenant import Tenant, User
from app.models.tenant_access import ACCESS_VIEW, TenantAccessGrant

logger = logging.getLogger(__name__)

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
    email: str | None = None
    account_name: str
    username: str
    role: str
    is_active: bool
    last_login: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    """`account_name` is what the person signs in with (3-32 lower-case letters, digits, '.', '_', '-'; unique across the platform). If it is left out (an older client) one is made from `username`, or from the email, and made unique.
    `email` is optional contact information: it is not verified and not needed to sign in. `username` is a display name and defaults to the account name."""

    account_name: str | None = None
    email: EmailStr | None = None
    username: str | None = None
    password: str
    role: str = "soc_analyst"

    @model_validator(mode="after")
    def _needs_a_name(self) -> "CreateUserRequest":
        if not (self.account_name or self.username or self.email):
            raise ValueError("give an account_name (or a username or email to make one from)")
        return self


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


class ViewableTenant(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    # self: the caller's own tenant. granted: a tenant the caller has been granted (read-only). platform: any tenant, for a holder of the cross-tenant permission.
    relationship: Literal["self", "platform", "granted"]


class ViewableTenantsResponse(BaseModel):
    home_tenant_id: uuid.UUID
    tenants: list[ViewableTenant]


@router.get("/viewable", response_model=ViewableTenantsResponse)
async def list_viewable_tenants(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
) -> ViewableTenantsResponse:
    """The tenants this caller may VIEW (read-only) with the `X-View-As-Tenant` header: their own first, then the tenants they were GRANTED (read-only; see `PUT /tenants/{id}/access/{account_name}`) or every tenant (a platform admin).

    It is the same rule the server applies when the header is sent (app.services.view_as), so the console can only offer what will be honoured. It always answers for the person's own account, whatever is being viewed.
    """
    rows = await viewable_tenants(db, current_user)
    return ViewableTenantsResponse(
        home_tenant_id=home_tenant_of(current_user),
        tenants=[ViewableTenant(id=t.id, name=t.name, slug=t.slug, relationship=rel) for t, rel in rows],
    )


class ManageableTenant(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    # self: the caller's own tenant. child: a tenant whose parent is the caller's. other: any other tenant, for a platform admin.
    relationship: Literal["self", "child", "other"]


class ManageableTenantsResponse(BaseModel):
    home_tenant_id: uuid.UUID
    tenants: list[ManageableTenant]


@router.get("/manageable", response_model=ManageableTenantsResponse)
async def list_manageable_tenants(
    current_user: Annotated[AuthUser, Depends(require_permission("users:read"))],
    db: DBSession,
) -> ManageableTenantsResponse:
    """The tenants whose ACCESS this caller may manage (who may be granted a view of them): the tenants for which `PUT /tenants/{id}/access/{account_name}` would be allowed, own tenant first. It is built from the same rule as those routes
    (`may_manage_access`), so the console can only offer what the server will honour. Empty for a role that cannot manage access."""
    home = home_tenant_of(current_user)
    query = select(Tenant).order_by(Tenant.name).limit(500)
    if not current_user.holds(CROSS_TENANT_PERMISSION):
        query = select(Tenant).where((Tenant.id == home) | (Tenant.parent_tenant_id == home)).order_by(Tenant.name).limit(500)
    candidates = (await db.execute(query)).scalars().all()
    managed = [t for t in candidates if may_manage_access(current_user, t)]
    managed.sort(key=lambda t: (t.id != home, t.name.lower()))
    return ManageableTenantsResponse(
        home_tenant_id=home,
        tenants=[ManageableTenant(id=t.id, name=t.name, slug=t.slug, relationship="self" if t.id == home else "child" if t.parent_tenant_id == home else "other") for t in managed],
    )


class AccessGrantResponse(BaseModel):
    tenant_id: uuid.UUID  # the tenant the access is TO
    user_id: uuid.UUID
    account_name: str
    email: str | None = None
    username: str | None = None
    home_tenant_id: uuid.UUID  # the tenant the person belongs to
    access: str
    granted_by: str
    created_at: datetime


def _grant_response(grant: TenantAccessGrant, user: User) -> AccessGrantResponse:
    return AccessGrantResponse(
        tenant_id=grant.tenant_id,
        user_id=user.id,
        account_name=user.account_name,
        email=user.email,
        username=user.username,
        home_tenant_id=user.tenant_id,
        access=grant.access,
        granted_by=grant.granted_by_label,
        created_at=grant.created_at,
    )


async def _tenant_whose_access_the_caller_manages(db: Any, current_user: Any, tenant_id: uuid.UUID) -> Tenant:
    """The tenant, if the caller may manage who has access to it; otherwise the SAME 404 as for a tenant that does not exist, so this cannot be used to find out which tenants exist."""
    tenant = (await db.execute(select(Tenant).where(Tenant.id == tenant_id))).scalars().first()
    if tenant is None or not may_manage_access(current_user, tenant):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return tenant


@router.get("/{tenant_id}/access", response_model=list[AccessGrantResponse])
async def list_tenant_access(
    tenant_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("users:read"))],
    db: DBSession,
) -> list[AccessGrantResponse]:
    """Who has been GRANTED read-only access to this tenant (people who belong to other tenants). For a platform admin, this tenant's own administrators, or the administrators of its parent."""
    tenant = await _tenant_whose_access_the_caller_manages(db, current_user, tenant_id)
    rows = (
        await db.execute(
            select(TenantAccessGrant, User).join(User, User.id == TenantAccessGrant.user_id).where(TenantAccessGrant.tenant_id == tenant.id).order_by(User.account_name)
        )
    ).all()
    return [_grant_response(g, u) for g, u in rows]


@router.put("/{tenant_id}/access/{account_name}", response_model=AccessGrantResponse)
async def grant_tenant_access(
    tenant_id: uuid.UUID,
    account_name: str,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> AccessGrantResponse:
    """Let the person with this account name VIEW this tenant, read-only. Idempotent. Takes effect on their next request. Recorded in this tenant's own audit log."""
    tenant = await _tenant_whose_access_the_caller_manages(db, current_user, tenant_id)
    grantee = await find_user_by_account_name(db, account_name)
    if grantee is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No account with that name")
    if grantee.tenant_id == tenant.id:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="That account already belongs to this tenant; a grant is for people who belong to another one.")
    if grantee.is_active is False:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="That account is deactivated.")

    # Plain values, taken now: a rollback expires every object loaded in the session, and reading an expired one would try to do IO where it cannot.
    grantee_id, tenant_pk = grantee.id, tenant.id

    def find() -> Any:
        return select(TenantAccessGrant).where(TenantAccessGrant.user_id == grantee_id, TenantAccessGrant.tenant_id == tenant_pk)

    existing = (await db.execute(find())).scalars().first()
    if existing is not None:
        return _grant_response(existing, grantee)
    grant = TenantAccessGrant(user_id=grantee.id, tenant_id=tenant.id, access=ACCESS_VIEW, granted_by=current_user.user_id, granted_by_label=current_user.email or str(current_user.user_id))
    db.add(grant)
    try:
        await emit_audit(
            db=db,
            tenant_id=tenant.id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            action="tenant:access_granted",
            resource="tenant_access",
            resource_id=str(grantee.id),
            changes={"account_name": grantee.account_name, "home_tenant_id": str(grantee.tenant_id), "access": ACCESS_VIEW},
        )
        await db.commit()
    except IntegrityError:
        # Two requests granted the same person at once: the database's unique constraint decided, and this one is the "already granted" case.
        await db.rollback()
        existing = (await db.execute(find())).scalars().first()
        if existing is None:
            raise
        return _grant_response(existing, await find_user_by_account_name(db, account_name))  # the person is read again: the rollback expired the copy loaded above
    await db.refresh(grant)
    return _grant_response(grant, grantee)


@router.delete("/{tenant_id}/access/{account_name}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_tenant_access(
    tenant_id: uuid.UUID,
    account_name: str,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> None:
    """Take the person's access to this tenant away. Takes effect on their next request. Recorded in this tenant's own audit log."""
    tenant = await _tenant_whose_access_the_caller_manages(db, current_user, tenant_id)
    grantee = await find_user_by_account_name(db, account_name)
    grant = None
    if grantee is not None:
        grant = (await db.execute(select(TenantAccessGrant).where(TenantAccessGrant.user_id == grantee.id, TenantAccessGrant.tenant_id == tenant.id))).scalars().first()
    if grantee is None or grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such grant")
    await db.delete(grant)
    await emit_audit(
        db=db,
        tenant_id=tenant.id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="tenant:access_revoked",
        resource="tenant_access",
        resource_id=str(grantee.id),
        changes={"account_name": grantee.account_name, "home_tenant_id": str(grantee.tenant_id)},
    )
    await db.commit()


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

    # The account name. Chosen explicitly: it must be valid and free (a name is not sensitive, so "taken" is said plainly). Not chosen (an older client): made from the username or email and made unique.
    if request.account_name is not None:
        try:
            name = validate_account_name(request.account_name)
        except InvalidAccountName as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from None
        if await account_name_taken(db, name):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="That account name is already taken. Choose another.")
    else:
        name = await unique_account_name(db, request.username or request.email or "")

    # The optional email. Addresses are unique across ALL tenants, so a clash may be with a user of another organisation. Say so only for the caller's own tenant, whose users the caller can list anyway; for another
    # tenant's user do not confirm that the address is registered anywhere (that would tell this admin who uses the platform), and record the attempt so probing can be seen.
    email = normalize_email(request.email) if request.email else None  # stored lower-cased: `Alice@x` and `alice@x` are one address (app/core/emails.py)
    if email is not None:
        owner_tenant = (await db.execute(select(User.tenant_id).where(func.lower(User.email) == email).order_by(User.created_at.asc()).limit(1))).scalar_one_or_none()
        if owner_tenant is not None:
            if owner_tenant == current_user.tenant_id:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A user with this email already exists in your organization.")
            logger.warning(
                "user creation refused: the email belongs to a user of another tenant",
                extra={"acting_tenant": str(current_user.tenant_id), "acting_user": str(current_user.user_id), "email_sha256": hashlib.sha256(email.encode()).hexdigest()[:16]},
            )
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This email address cannot be used. Choose a different one.")

    user = User(
        tenant_id=current_user.tenant_id,
        email=email,
        account_name=name,
        username=request.username or name,
        hashed_password=get_password_hash(request.password),
        role=request.role,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        # Two requests took the same name (or email) at once: the database's unique index decided.
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="That account name (or email) was just taken. Choose another.") from None
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
