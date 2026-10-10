"""Viewing another tenant ("view as"), read-only, for the people who are entitled to.

WHAT WAS WRONG. The console's tenant switcher stored the chosen tenant and sent it as `X-Tenant-Id`, which the API never read. An MSSP operator who "switched" to a customer kept seeing their OWN data under the customer's name, and
nothing told them. The header is also sent on every request with whatever the console last knew (often a build-time constant), so it cannot carry intent.

THE RULE. A request may ask to view a tenant with the explicit header `X-View-As-Tenant`. The server honours it only for a tenant the caller may view, and only for reading:

  * the caller's OWN tenant: nothing changes.
  * ANY tenant, for a holder of `platform:cross_tenant_query` (the same permission that lets /nl-query and entity risk name another tenant).
  * a tenant the person has been GRANTED (a row in `tenant_access_grants`, migration 072) or ALL tenants (a row in `all_tenant_access_grants`, migration 074, platform administrators only), at level `view` (read-only) or `full`. Grants are checked against the database on every
    request, so a revocation takes effect at once.
  * anything else, including a tenant that does not exist, is 403 (the same answer for both, so it is not a way to find out which tenants exist). In particular being a member of an MSSP parent tenant confers NOTHING over its
    child tenants by itself: that blanket rule (every parent user could view every child, even a `viewer`) was replaced by explicit grants.

WHO MAY GRANT (`may_manage_access`): a holder of the platform-wide permission (any tenant); or a holder of `users:write` whose HOME tenant is the tenant concerned, or is that tenant's PARENT (so an MSP's administrators decide which
of their own staff may see which customers, and a customer's administrators decide who may see theirs).

While viewing, the request acts as the caller's role (a role grants the same permissions everywhere) but on the viewed tenant: `tenant_id` is the viewed tenant, so every query and the row-level-security context follow it, and `home_tenant_id` is still the caller's.
A WRITE is allowed only with FULL access (a grant at level `full`, or an all-tenants grant at `full`): with `view` access it is refused (403 read_only), because a write that quietly landed in the caller's HOME tenant, or in a customer's, while the screen said otherwise would be worse than the bug
being fixed. With full access the person acts with their OWN role's permissions on the viewed tenant, never more, and identity and credential administration stays refused whatever the level (users, roles, API keys, who has access, platform and MSSP administration: see IDENTITY_ADMIN_PATH
and ACTING_DENIED_PERMISSIONS). Every such write is recorded in the VIEWED tenant's own audit log BEFORE it is carried out (record_act_as; if that cannot be written the write is not performed), and the audit middleware adds its outcome to the same log. A bad request is never silently ignored: an unusable value is 400, and an API key
(bound to its own tenant) is refused. Account-level routes (sign in/out, push, passkeys, the tenant list itself) always act as the person's own account and ignore the header.

The listing used by the switcher (`viewable_tenants`) and the check (`may_view_tenant`) are one rule, so the console can only offer what the server will honour.

AUDIT. The audit middleware records only writes, and under the caller's HOME tenant, so without more a customer would have no record at all that an operator looked at their data. A view therefore writes one event (`tenant:viewed`) into the
 VIEWED tenant's own hash-chained log, naming the person, their tenant and role: once per person per viewed tenant per 15 minutes (a screen makes dozens of reads), and if that event cannot be written the view is not served.
"""
from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import HTTPException, status
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.tenant import Tenant
from app.models.tenant_access import ACCESS_FULL, ACCESS_VIEW, AllTenantAccessGrant, TenantAccessGrant
from app.services.audit import emit_audit
from app.services.tenant_selection import CROSS_TENANT_PERMISSION

VIEW_AS_HEADER = "X-View-As-Tenant"
VIEWING_HEADER = "X-Viewing-Tenant"  # on the response: the tenant the data is for
VIEWING_ACCESS_HEADER = "X-Viewing-Access"  # on the response: what the person may do there (view | full)
ERROR_HEADER = "X-View-As-Error"  # on a refusal: invalid | forbidden | read_only | not_allowed_here | session_only
MANAGE_ACCESS_PERMISSION = "users:write"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
LIST_LIMIT = 500
VIEW_AUDIT_ACTION = "tenant:viewed"
VIEW_AUDIT_WINDOW = timedelta(minutes=15)

# Routes about the PERSON's account, not about a tenant: they always act as the signed-in person, whatever is being viewed (a user must be able to sign out, and the tenant list must not change when they switch).
ACCOUNT_LEVEL_PATH = re.compile(r"^/api/v\d+/(auth|push|passkeys)(/|$)|^/api/v\d+/tenants/viewable$")

Relationship = Literal["self", "platform", "granted"]
Access = Literal["view", "full"]
_ACCESS_RANK = {ACCESS_VIEW: 1, ACCESS_FULL: 2}
ACT_AUDIT_ACTION = "tenant:acted"
# Even with FULL access, a person working in another tenant cannot administer IDENTITY or CREDENTIALS there, nor platform or MSSP administration: users, roles, API keys and who has access (by route), and the permissions below (by permission). A stolen technician login must
# not be able to plant a hidden administrator or a long-lived key in every customer; whoever needs those actions uses an account in that tenant. Reads are not affected.
IDENTITY_ADMIN_PATH = re.compile(r"^/api/v\d+/(tenants/(me/users|[^/]+/access)|api-keys|rbac|platform|mssp)(/|$)")
ACTING_DENIED_PERMISSIONS = frozenset({"users:write", "mssp:manage", "mssp:onboard", "platform:cross_tenant_query", "plugins:admin"})


def home_tenant_of(user: Any) -> uuid.UUID:
    """The tenant the PERSON belongs to. Every rule here is relative to it, never to the tenant a request happens to be for: a principal that is already viewing a child must not be able to reason from that child's position."""
    return getattr(user, "home_tenant_id", None) or user.tenant_id


def is_account_level(path: str) -> bool:
    return bool(ACCOUNT_LEVEL_PATH.match(path))


async def granted_tenant_ids(db: Any, user: Any) -> set[uuid.UUID]:
    """The tenants this PERSON has been granted individually, at any level (by their own account, never by the tenant a request happens to be for)."""
    rows = (await db.execute(select(TenantAccessGrant.tenant_id).where(TenantAccessGrant.user_id == user.user_id))).scalars().all()
    return set(rows)


@dataclass(frozen=True)
class Grants:
    """Everything this PERSON has been granted: per tenant (tenant id to level) and, separately, every tenant (a level, or None)."""

    by_tenant: Mapping[uuid.UUID, str]
    all_tenants: str | None = None


async def access_grants(db: Any, user: Any) -> Grants:
    rows = (await db.execute(select(TenantAccessGrant.tenant_id, TenantAccessGrant.access).where(TenantAccessGrant.user_id == user.user_id))).all()
    everywhere = (await db.execute(select(AllTenantAccessGrant.access).where(AllTenantAccessGrant.user_id == user.user_id))).scalars().first()
    return Grants({tenant_id: level for tenant_id, level in rows}, everywhere)


def _stronger(a: str | None, b: str | None) -> str | None:
    return a if _ACCESS_RANK.get(a or "", 0) >= _ACCESS_RANK.get(b or "", 0) else b


def access_level(user: Any, tenant_id: uuid.UUID, grants: Grants) -> Access | None:
    """What `user` may do in `tenant_id`: "full" (their own tenant), the strongest of: "view" for a holder of the platform-wide permission, the level of a grant for that tenant, the level of an all-tenants grant; None for nothing."""
    if tenant_id == home_tenant_of(user):
        return ACCESS_FULL
    level: str | None = ACCESS_VIEW if user.holds(CROSS_TENANT_PERMISSION) else None
    level = _stronger(level, grants.by_tenant.get(tenant_id))
    level = _stronger(level, grants.all_tenants)
    return level  # type: ignore[return-value]


def may_view_tenant(user: Any, tenant: Tenant, granted: Collection[uuid.UUID] | Mapping[uuid.UUID, str] = (), all_access: str | None = None) -> bool:
    """May `user` view `tenant`? Their own: always. Any tenant: a holder of the platform-wide permission. Otherwise only a tenant they have been granted (`granted`: ids, or id-to-level; see access_grants), or all of them (`all_access`)."""
    by_tenant = dict(granted) if isinstance(granted, Mapping) else dict.fromkeys(granted, ACCESS_VIEW)
    return access_level(user, tenant.id, Grants(by_tenant, all_access)) is not None


def may_manage_access(user: Any, tenant: Tenant) -> bool:
    """May `user` grant and revoke other people's access to `tenant`, and see who has it? A holder of the platform-wide permission: any tenant. Otherwise a holder of `users:write` whose home tenant is `tenant`
    (a customer's administrators decide who may see their data) or is its parent (an MSP's administrators decide which of their staff may see which customers). Never from inside a view of another tenant: `home_tenant_of`."""
    if user.holds(CROSS_TENANT_PERMISSION):
        return True
    if not user.holds(MANAGE_ACCESS_PERMISSION):
        return False
    home = home_tenant_of(user)
    return tenant.id == home or (tenant.parent_tenant_id is not None and tenant.parent_tenant_id == home)


async def viewable_access(db: Any, user: Any) -> list[tuple[Tenant, Relationship, Access]]:
    """Every tenant `user` may view, their own first, each with what they may do there. This and `access_level` are the same rule."""
    home = home_tenant_of(user)
    grants = await access_grants(db, user)
    own = (await db.execute(select(Tenant).where(Tenant.id == home))).scalars().first()
    out: list[tuple[Tenant, Relationship, Access]] = [(own, "self", ACCESS_FULL)] if own is not None else []
    platform = bool(user.holds(CROSS_TENANT_PERMISSION))
    if platform or grants.all_tenants:
        candidates = (await db.execute(select(Tenant).where(Tenant.id != home).order_by(Tenant.name).limit(LIST_LIMIT))).scalars().all()
    else:
        candidates = (
            (await db.execute(select(Tenant).join(TenantAccessGrant, TenantAccessGrant.tenant_id == Tenant.id).where(TenantAccessGrant.user_id == user.user_id, Tenant.id != home).order_by(Tenant.name).limit(LIST_LIMIT)))
            .scalars()
            .all()
        )
    for t in candidates:
        level = access_level(user, t.id, grants)
        if level is not None:
            out.append((t, "platform" if platform else "granted", level))
    return out


async def viewable_tenants(db: Any, user: Any) -> list[tuple[Tenant, Relationship]]:
    """Every tenant `user` may view, their own first (see viewable_access for the level of each)."""
    return [(t, rel) for t, rel, _ in await viewable_access(db, user)]


async def record_view(db: Any, user: Any, target: uuid.UUID, request: Any = None) -> bool:
    """Write the `tenant:viewed` event into the VIEWED tenant's audit log, unless this person already has one there within the window. True when a row was written.

    The check is a query, not process memory, so it holds across workers and restarts. An error is NOT swallowed: a view that cannot be recorded is not served (an audit gap on a cross-tenant read is worse than a failed request).
    """
    cutoff = datetime.now(UTC) - VIEW_AUDIT_WINDOW
    recent = (
        select(AuditLog.id)
        .where(AuditLog.tenant_id == target, AuditLog.actor_id == user.user_id, AuditLog.action == VIEW_AUDIT_ACTION, AuditLog.created_at >= cutoff)
        .limit(1)
    )
    if (await db.execute(recent)).first() is not None:
        return False
    await emit_audit(
        db=db,
        tenant_id=target,
        actor_id=user.user_id,
        actor_email=user.email,
        action=VIEW_AUDIT_ACTION,
        resource="tenant",
        resource_id=str(target),
        changes={"viewer_home_tenant_id": str(home_tenant_of(user)), "viewer_role": user.role},
        request=request,
    )
    await db.commit()
    return True


def _refuse(code: int, error: str, detail: str) -> HTTPException:
    return HTTPException(status_code=code, detail=detail, headers={ERROR_HEADER: error})


def refuse_api_key() -> HTTPException:
    return _refuse(status.HTTP_403_FORBIDDEN, "session_only", "Viewing another tenant is only for signed-in sessions; an API key acts on its own tenant.")


@dataclass(frozen=True)
class ViewTarget:
    """The tenant a request is to be served for and what the person may do there: "view" (reading only) or "full" (reading and writing, identity administration excepted)."""

    tenant_id: uuid.UUID
    access: Access


async def resolve_view_as(db: Any, user: Any, requested: str, method: str, path: str | None = None) -> ViewTarget | None:
    """The tenant this request is to be served for (and the person's level there), or None for "no change" (the caller's own). Raises the refusal otherwise.

    A write is allowed only with FULL access, and never on an identity-administration route (IDENTITY_ADMIN_PATH). With view access it is `read_only`."""
    try:
        target = uuid.UUID(requested.strip())
    except (ValueError, AttributeError):
        raise _refuse(status.HTTP_400_BAD_REQUEST, "invalid", f"{VIEW_AS_HEADER} must be a tenant id.") from None
    if target == home_tenant_of(user):
        return None
    tenant = (await db.execute(select(Tenant).where(Tenant.id == target))).scalars().first()
    level = None if tenant is None else access_level(user, tenant.id, await access_grants(db, user))
    if level is None:
        raise _refuse(status.HTTP_403_FORBIDDEN, "forbidden", "You may not view that tenant.")
    if method.upper() not in SAFE_METHODS:
        if level != ACCESS_FULL:
            raise _refuse(status.HTTP_403_FORBIDDEN, "read_only", "You have read-only access to this tenant. Ask for full access, or switch back to your own tenant to make changes.")
        if path is not None and IDENTITY_ADMIN_PATH.match(path):
            raise _refuse(status.HTTP_403_FORBIDDEN, "not_allowed_here", "Users, roles, API keys, access and platform administration are not available while working in another tenant: use an account in that tenant.")
    return ViewTarget(tenant_id=target, access=level)  # type: ignore[arg-type]


async def record_act_as(db: Any, user: Any, target: uuid.UUID, access: str, request: Any) -> None:
    """Write an event into the TARGET tenant's own audit log BEFORE a write made from another tenant is carried out: who, from where, with which role, what method and path. An error is NOT swallowed: a write that cannot be recorded is not performed.
    (The audit middleware adds the outcome afterwards, also in this tenant's log.)"""
    await emit_audit(
        db=db,
        tenant_id=target,
        actor_id=user.user_id,
        actor_email=user.email,
        action=ACT_AUDIT_ACTION,
        resource="tenant",
        resource_id=str(target),
        changes={"acted_from_tenant_id": str(home_tenant_of(user)), "role": user.role, "access": access, "method": request.method, "path": request.url.path},
        request=request,
    )
    await db.commit()
