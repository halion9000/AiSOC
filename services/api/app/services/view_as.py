"""Viewing another tenant ("view as"), read-only, for the people who are entitled to.

WHAT WAS WRONG. The console's tenant switcher stored the chosen tenant and sent it as `X-Tenant-Id`, which the API never read. An MSSP operator who "switched" to a customer kept seeing their OWN data under the customer's name, and
nothing told them. The header is also sent on every request with whatever the console last knew (often a build-time constant), so it cannot carry intent.

THE RULE. A request may ask to view a tenant with the explicit header `X-View-As-Tenant`. The server honours it only for a tenant the caller may view, and only for reading:

  * the caller's OWN tenant: nothing changes.
  * ANY tenant, for a holder of `platform:cross_tenant_query` (the same permission that lets /nl-query and entity risk name another tenant).
  * a tenant that is a CHILD of the caller's own (`parent_tenant_id` = the caller's tenant), for a holder of `mssp:read` (the permission that lists children).
  * anything else, including a tenant that does not exist, is 403 (the same answer for both, so it is not a way to find out which tenants exist).

While viewing, the request acts as the caller's role (a role grants the same permissions everywhere) but on the viewed tenant: `tenant_id` is the viewed tenant, so every query and the row-level-security context follow it, and `home_tenant_id` is still the caller's.
Writes are refused (403): a write that quietly landed in the caller's HOME tenant, or in a customer's, while the screen said otherwise would be worse than the bug being fixed. A bad request is never silently ignored: an unusable value is 400, and an API key
(bound to its own tenant) is refused. Account-level routes (sign in/out, push, passkeys, the tenant list itself) always act as the person's own account and ignore the header.

The listing used by the switcher (`viewable_tenants`) and the check (`may_view_tenant`) are one rule, so the console can only offer what the server will honour.

AUDIT. The audit middleware records only writes, and under the caller's HOME tenant, so without more a customer would have no record at all that an operator looked at their data. A view therefore writes one event (`tenant:viewed`) into the
 VIEWED tenant's own hash-chained log, naming the person, their tenant and role: once per person per viewed tenant per 15 minutes (a screen makes dozens of reads), and if that event cannot be written the view is not served.
"""
from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import HTTPException, status
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.tenant import Tenant
from app.services.audit import emit_audit
from app.services.tenant_selection import CROSS_TENANT_PERMISSION

VIEW_AS_HEADER = "X-View-As-Tenant"
VIEWING_HEADER = "X-Viewing-Tenant"  # on the response: the tenant the data is for
ERROR_HEADER = "X-View-As-Error"  # on a refusal: invalid | forbidden | read_only | session_only
MSSP_READ_PERMISSION = "mssp:read"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
LIST_LIMIT = 500
VIEW_AUDIT_ACTION = "tenant:viewed"
VIEW_AUDIT_WINDOW = timedelta(minutes=15)

# Routes about the PERSON's account, not about a tenant: they always act as the signed-in person, whatever is being viewed (a user must be able to sign out, and the tenant list must not change when they switch).
ACCOUNT_LEVEL_PATH = re.compile(r"^/api/v\d+/(auth|push|passkeys)(/|$)|^/api/v\d+/tenants/viewable$")

Relationship = Literal["self", "child", "platform"]


def home_tenant_of(user: Any) -> uuid.UUID:
    """The tenant the PERSON belongs to. Every rule here is relative to it, never to the tenant a request happens to be for: a principal that is already viewing a child must not be able to reason from that child's position."""
    return getattr(user, "home_tenant_id", None) or user.tenant_id


def is_account_level(path: str) -> bool:
    return bool(ACCOUNT_LEVEL_PATH.match(path))


def may_view_tenant(user: Any, tenant: Tenant) -> bool:
    """May `user` view `tenant`? (Their own: always.)"""
    home = home_tenant_of(user)
    if tenant.id == home:
        return True
    if user.holds(CROSS_TENANT_PERMISSION):
        return True
    return bool(user.holds(MSSP_READ_PERMISSION) and tenant.parent_tenant_id is not None and tenant.parent_tenant_id == home)


async def viewable_tenants(db: Any, user: Any) -> list[tuple[Tenant, Relationship]]:
    """Every tenant `user` may view, their own first. This and `may_view_tenant` are the same rule."""
    home = home_tenant_of(user)
    own = (await db.execute(select(Tenant).where(Tenant.id == home))).scalars().first()
    out: list[tuple[Tenant, Relationship]] = [(own, "self")] if own is not None else []
    if user.holds(CROSS_TENANT_PERMISSION):
        others = (await db.execute(select(Tenant).where(Tenant.id != home).order_by(Tenant.name).limit(LIST_LIMIT))).scalars().all()
        return out + [(t, "platform") for t in others]
    if user.holds(MSSP_READ_PERMISSION):
        children = (await db.execute(select(Tenant).where(Tenant.parent_tenant_id == home).order_by(Tenant.name).limit(LIST_LIMIT))).scalars().all()
        return out + [(t, "child") for t in children]
    return out


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


async def resolve_view_as(db: Any, user: Any, requested: str, method: str) -> uuid.UUID | None:
    """The tenant this request is to be served for, or None for "no change" (the caller's own). Raises the refusal otherwise."""
    try:
        target = uuid.UUID(requested.strip())
    except (ValueError, AttributeError):
        raise _refuse(status.HTTP_400_BAD_REQUEST, "invalid", f"{VIEW_AS_HEADER} must be a tenant id.") from None
    if target == home_tenant_of(user):
        return None
    tenant = (await db.execute(select(Tenant).where(Tenant.id == target))).scalars().first()
    if tenant is None or not may_view_tenant(user, tenant):
        raise _refuse(status.HTTP_403_FORBIDDEN, "forbidden", "You may not view that tenant.")
    if method.upper() not in SAFE_METHODS:
        raise _refuse(status.HTTP_403_FORBIDDEN, "read_only", "This tenant is read-only while you are viewing it as another tenant. Switch back to your own tenant to make changes.")
    return target
