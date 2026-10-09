"""FastAPI dependency injection.

Authentication supports two credential types:
  1. JWT Bearer token   – issued by /auth/login
  2. API key Bearer     – prefixed with "aisoc_", validated against the api_keys table

API key auth carries explicit ``scopes``; JWT auth derives permissions from the
user's role via ``ROLE_PERMISSIONS``.

Multi-tenant Row-Level Security (RLS)
--------------------------------------
Use ``TenantDBSession`` (from ``app.db.rls``) instead of ``DBSession`` for
endpoints that must be tenant-isolated at the database level.  It sets the
Postgres session variable ``app.current_tenant_id`` before yielding, which
activates the RLS policies defined in ``migrations/002_rls.sql``.

    from app.db.rls import TenantDBSession

    @router.get("/cases")
    async def list_cases(db: TenantDBSession, user: AuthUser):
        ...
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

import logging
from fastapi import Depends, HTTPException, Request, Response, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.token_revocation import is_revoked
from app.api.v1.dev_auth import (
    DEMO_TENANT_ID,
    DEMO_USER_EMAIL,
    DEMO_USER_ID,
    DEMO_USER_ROLE,
    is_dev_mode,
)
from app.core.security import decode_token, has_permission, hash_api_key, permission_in
from app.db.database import get_db
from app.models.tenant import ApiKey, User
from app.services.view_as import VIEW_AS_HEADER, VIEWING_HEADER, is_account_level, record_view, refuse_api_key, resolve_view_as

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False)

_API_KEY_PREFIX = "aisoc_"


class CurrentUser:
    """Resolved authenticated user context.

    ``scopes`` is only populated when authenticated via an API key; it
    holds the explicit permission strings granted to that key.  When ``None``
    the user's role-based permissions apply.

    Permission resolution order:
      1. API-key scopes (explicit list)
      2. RBAC ``user_roles`` → ``role_permissions`` (database-backed)
      3. Static ``ROLE_PERMISSIONS`` fallback (legacy / bootstrap)
    """

    def __init__(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        role: str,
        email: str,
        scopes: list[str] | None = None,
        home_tenant_id: uuid.UUID | None = None,
    ) -> None:
        self.user_id = user_id
        self.tenant_id = tenant_id
        # The tenant the person BELONGS to. It differs from tenant_id only while they are viewing another tenant (app.services.view_as).
        self.home_tenant_id = home_tenant_id or tenant_id
        self.role = role
        self.email = email
        self.scopes = scopes  # None → role-based; list → API-key scoped

    @property
    def viewing_other_tenant(self) -> bool:
        """True while this request is a read-only view of a tenant other than the person's own."""
        return self.tenant_id != self.home_tenant_id

    @property
    def label(self) -> str:
        """Who this is, as text for an audit field or a log line: the email, else the user id.

        Several endpoints stored `str(user)`, which for this class is "<app.api.v1.deps.CurrentUser object at 0x...>": a meaningless value written to the database (compliance reviewer, phishing submitter, knowledge-base author) that also leaked an in-process memory address through the API."""
        return self.email or str(self.user_id)

    def __str__(self) -> str:
        return self.label

    @property
    def id(self) -> uuid.UUID:
        """Alias for ``user_id``. Fourteen call sites in eight modules (reports, remediation, mssp, posture, insider threat, replay, sla, audit) read ``current_user.id``, the way they would on the ORM ``User``;
        ``CurrentUser`` only had ``user_id``, so every one of those endpoints raised AttributeError (HTTP 500) on any call that reached that line."""
        return self.user_id

    def require_permission(self, permission: str) -> None:
        if self.scopes is not None:
            # API-key path: check explicit scopes list
            allowed = permission_in(self.scopes, permission)
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key missing scope: {permission}",
                )
        else:
            # JWT / role path — static ROLE_PERMISSIONS fallback
            if not has_permission(self.role, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission}",
                )

    def holds(self, permission: str) -> bool:
        """Does this principal hold `permission`? The same test require_permission applies, as a yes/no instead of a 403."""
        try:
            self.require_permission(permission)
        except HTTPException:
            return False
        return True

    def can_grant_role(self, target_role: str) -> bool:
        """May this principal hand out `target_role`? Only a role whose every permission they hold themselves: nobody can grant more power than they have.

        POST/PATCH /tenants/me/users took any `role` string from the request, so a tenant_admin (who holds users:write) could create a platform_admin user, or promote itself to one (shown live: one request each). An unknown role is never grantable."""
        # Imported here: app.core.security imports nothing from the API layer, but keeping the lookup local avoids a module-level cycle.
        from app.core.security import ROLE_PERMISSIONS  # noqa: PLC0415

        perms = ROLE_PERMISSIONS.get(target_role)
        if perms is None:
            return False
        if "*" in perms and not self.holds_wildcard():
            return False
        return all(self.holds(p) for p in perms if p != "*")

    def holds_wildcard(self) -> bool:
        from app.core.security import ROLE_PERMISSIONS  # noqa: PLC0415

        if self.scopes is not None:
            return "*" in self.scopes
        return "*" in ROLE_PERMISSIONS.get(self.role, [])

    async def has_permission_db(self, permission: str, db: AsyncSession) -> bool:
        """Check permission via RBAC tables (granular RBAC).

        Falls back to the static ROLE_PERMISSIONS map when the user has
        no rows in ``user_roles`` (e.g. fresh tenants not yet migrated).
        """
        if self.scopes is not None:
            return permission_in(self.scopes, permission)

        # Query RBAC tables
        from app.models.rbac import Permission as PermModel  # noqa: PLC0415
        from app.models.rbac import Role, RolePermission, UserRole

        result = await db.execute(
            select(PermModel.name)
            .join(RolePermission, RolePermission.permission_id == PermModel.id)
            .join(Role, Role.id == RolePermission.role_id)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == self.user_id, Role.tenant_id == self.tenant_id)
        )
        db_perms: list[str] = [row[0] for row in result.all()]

        if db_perms:
            return permission_in(db_perms, permission)

        # Fallback to static map
        return has_permission(self.role, permission)

    async def require_permission_db(self, permission: str, db: AsyncSession) -> None:
        """Async permission check (RBAC tables then static fallback)."""
        if not await self.has_permission_db(permission, db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}",
            )


async def _resolve_api_key(raw_key: str, db: AsyncSession) -> CurrentUser:
    """Look up and validate an aisoc_ API key; return its CurrentUser."""
    hashed = hash_api_key(raw_key)
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.hashed_key == hashed,
            ApiKey.is_active == True,  # noqa: E712
        )
    )
    api_key: ApiKey | None = result.scalar_one_or_none()
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check expiry
    if api_key.expires_at is not None and api_key.expires_at < datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update last_used_at in background (fire-and-forget style — don't await)
    await db.execute(update(ApiKey).where(ApiKey.id == api_key.id).values(last_used_at=datetime.now(UTC)))

    # Fetch the owning user for context (user_id may be NULL for service keys)
    role = "api_service"
    email = f"api-key:{api_key.key_prefix}"
    user_id = api_key.user_id or api_key.tenant_id  # fallback to tenant UUID

    if api_key.user_id is not None:
        user_res = await db.execute(
            select(User).where(User.id == api_key.user_id, User.is_active == True)  # noqa: E712
        )
        user = user_res.scalar_one_or_none()
        if user is not None:
            role = user.role
            email = user.email
            user_id = user.id

    return CurrentUser(
        user_id=user_id,
        tenant_id=api_key.tenant_id,
        role=role,
        email=email,
        scopes=api_key.scopes or [],
    )


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    db: AsyncSession = Depends(get_db),
    request: Request = None,  # type: ignore[assignment]  # injected by FastAPI; None for a direct call
    response: Response = None,  # type: ignore[assignment]
) -> CurrentUser:
    """The signed-in caller, as the tenant the request is FOR.

    That is the caller's own tenant, unless the request carries `X-View-As-Tenant` and the caller may view that tenant (read-only): see app.services.view_as for the rule, and why a bad or unauthorised value is an error and never ignored.
    """
    user = await _authenticate(credentials, db)
    requested = None if request is None or credentials is None else request.headers.get(VIEW_AS_HEADER)
    if not requested or not requested.strip() or is_account_level(request.url.path):
        return user
    if user.scopes is not None:
        raise refuse_api_key()
    target = await resolve_view_as(db, user, requested, request.method)
    if target is None:
        return user
    await record_view(db, user, target, request)  # in the VIEWED tenant's own audit log; if it cannot be written, the view is not served
    logger.info(
        "viewing another tenant (read-only)",
        extra={"viewer": str(user.user_id), "home_tenant": str(user.tenant_id), "viewed_tenant": str(target), "http_method": request.method, "path": request.url.path},
    )
    if response is not None:
        response.headers[VIEWING_HEADER] = str(target)
    return CurrentUser(user_id=user.user_id, tenant_id=target, role=user.role, email=user.email, home_tenant_id=user.tenant_id)


async def _authenticate(
    credentials: HTTPAuthorizationCredentials | None,
    db: AsyncSession,
) -> CurrentUser:
    """Resolve Bearer token to CurrentUser.

    Accepts both JWT tokens and aisoc_ API keys.

    In development mode an unauthenticated request resolves to a deterministic
    demo user (see ``app.api.v1.dev_auth``). Production requires a bearer token.
    """
    if credentials is None:
        if is_dev_mode():
            return CurrentUser(
                user_id=DEMO_USER_ID,
                tenant_id=DEMO_TENANT_ID,
                role=DEMO_USER_ROLE,
                email=DEMO_USER_EMAIL,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    # --- API key path ---
    if token.startswith(_API_KEY_PREFIX):
        return await _resolve_api_key(token, db)

    # --- JWT path ---
    try:
        payload = decode_token(token)
        user_id: str = payload.get("sub")  # type: ignore[assignment]
        token_type: str = payload.get("type", "access")
        if user_id is None or token_type != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        # A token that was signed out (revoked) is refused even though its signature and expiry are still good.
        if await is_revoked(payload.get("jti")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from e

    # B2 fix: uuid.UUID() raises ValueError on malformed sub claims, which
    # previously surfaced as a 500 instead of a clean 401. Catch it here so
    # any token with a non-UUID subject is rejected as invalid credentials.
    try:
        user_uuid = uuid.UUID(user_id)
    except (ValueError, AttributeError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: malformed user id",
        ) from e

    result = await db.execute(
        select(User).where(User.id == user_uuid, User.is_active == True)  # noqa: E712
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return CurrentUser(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
        email=user.email,
    )


async def require_signed_in_session(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> CurrentUser:
    """Account-level actions (passkeys, push subscriptions, profile preferences) belong to a signed-in person, not to an API key acting as them.

    An API key resolves to the user who owns it, and routes that only ask "who is this?" never look at its scopes, so a key with ANY scopes (even read-only) could manage that
    user's passkeys and notifications. ``scopes`` is None for a session (JWT) and a list, possibly empty, for an API key, so this tests ``is not None``, never truthiness.
    Used as a dependency on the user parameter, so it runs before the database dependency and before body validation.
    """
    if current_user.scopes is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action is only available to a signed-in user, not an API key.",
        )
    return current_user


async def get_current_active_user(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> CurrentUser:
    return current_user


def require_permission(permission: str):
    """Factory for permission-checking dependencies."""

    async def _check(current_user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
        current_user.require_permission(permission)
        return current_user

    return _check


# Type aliases
DBSession = Annotated[AsyncSession, Depends(get_db)]
AuthUser = Annotated[CurrentUser, Depends(get_current_user)]
SessionUser = Annotated[CurrentUser, Depends(require_signed_in_session)]


# Re-export TenantDBSession for convenience so endpoints can import from one place
# Actual implementation lives in app.db.rls to avoid circular imports.
def _get_tenant_db_session() -> "Annotated[AsyncSession, ...]":  # pragma: no cover
    from app.db.rls import TenantDBSession as _T  # noqa: PLC0415

    return _T  # type: ignore[return-value]
