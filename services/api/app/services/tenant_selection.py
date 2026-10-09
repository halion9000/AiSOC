"""Which tenant may a caller read? One rule, used by every endpoint that lets the caller name a tenant.

A caller may always read their OWN tenant. Naming any other tenant needs the platform permission `platform:cross_tenant_query` (held by platform_admin, or by an API key that carries that exact scope; the wildcard `*`, the wildcard `admin` role and `<resource>:*` scopes do not hold it, see app.core.security.PLATFORM_PERMISSIONS).
Before this module fusion checked the role NAME `platform_admin`, osquery_fim checked the role name too (plus a demo-tenant alias), and /nl-query checked the permission: three answers to the same question, so an API key judged by its scopes was allowed in one place and refused in another.

The tenant a request acts on is never taken from a header or a query string on trust: a request may only NAME a tenant, and this decides whether the caller is entitled to it."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select

from app.models.tenant import Tenant

CROSS_TENANT_PERMISSION = "platform:cross_tenant_query"
MISMATCH_DETAIL = "tenant_id does not match your tenant"


def may_select_other_tenants(user: Any) -> bool:
    return bool(user.holds(CROSS_TENANT_PERMISSION))


def resolve_requested_tenant(user: Any, requested: str | UUID | None, *, also_allowed: Iterable[str] = ()) -> str:
    """The tenant (as a string) this request is for.

    Nothing requested -> the caller's own. The caller's own, or one in `also_allowed` (an endpoint-specific alias the caller is entitled to) -> that. Anything else -> only for a holder of the cross-tenant permission; otherwise a 403."""
    own = str(user.tenant_id)
    wanted = ("" if requested is None else str(requested)).strip()
    if not wanted:
        return own
    if wanted == own or wanted in {str(a) for a in also_allowed}:
        return wanted
    if may_select_other_tenants(user):
        return wanted
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=MISMATCH_DETAIL)


async def selectable_tenants(db: Any, user: Any, *, include_others: bool = True) -> tuple[bool, list[Tenant]]:
    """The tenants this caller can choose between in a picker, and whether they may choose any but their own.

    A holder of the cross-tenant permission gets every tenant (ordered by name, capped at 500); everyone else gets exactly their own, and `False`. `include_others=False` forces the own-tenant-only answer for a feature that is not available even to a holder (e.g. NL search when no tenant field is configured)."""
    can = include_others and may_select_other_tenants(user)
    stmt = select(Tenant).order_by(Tenant.name).limit(500) if can else select(Tenant).where(Tenant.id == user.tenant_id)
    return can, list((await db.execute(stmt)).scalars().all())
