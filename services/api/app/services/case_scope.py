"""Let an MSSP parent open and work a case that lives under one of its clients, the way it already can for alerts.

Every case route filters by ``user.tenant_id``. For a case under a client tenant the parent's own id matches nothing, so the page that lists all clients' cases could not open one. ``case_scoped``
is a drop-in for ``require_permission`` on the routes that take a ``{case_id}``: it checks the same permission, then (only when the case belongs to one of the caller's OWN clients) hands the
route a copy of the user whose ``tenant_id`` is that client, with the session acting as the client for the length of the request. A case that is not the caller's own, or a client's of someone else,
is left alone and the route answers 404 as before.
"""

import copy
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import Depends, Request
from sqlalchemy import text

from app.api.v1.deps import CurrentUser, DBSession, require_permission
from app.db.rls_scope import acting_as_tenant, cross_tenant_reads


async def find_case_tenant(db: Any, owner: uuid.UUID, case_ref: str) -> uuid.UUID | None:
    """The tenant holding the case (by id or by its INC-number), when it is the caller's own or one of the caller's clients; None otherwise. The caller's own tenant wins a tie."""
    ref = (case_ref or "").strip()
    if not ref:
        return None
    async with cross_tenant_reads(db):
        row = (
            await db.execute(
                text(
                    "SELECT c.tenant_id FROM aisoc_cases c "
                    "WHERE (c.id::text = lower(:ref) OR upper(c.case_number) = upper(:ref)) "
                    "AND (c.tenant_id = :owner OR c.tenant_id IN (SELECT t.id FROM tenants t WHERE t.parent_tenant_id = :owner)) "
                    "ORDER BY (c.tenant_id = :owner) DESC LIMIT 1"
                ).bindparams(ref=ref, owner=owner)
            )
        ).fetchone()
    return row[0] if row else None


def case_scoped(permission: str):
    """Like ``require_permission(permission)``, but a route with a ``{case_id}`` also works on a case under one of the caller's clients."""
    check = require_permission(permission)

    async def dependency(request: Request, user: Annotated[CurrentUser, Depends(check)], db: DBSession) -> AsyncIterator[CurrentUser]:
        case_ref = request.path_params.get("case_id")
        tenant = await find_case_tenant(db, user.tenant_id, case_ref) if isinstance(case_ref, str) else None
        if tenant is None or tenant == user.tenant_id:
            yield user
            return
        scoped = copy.copy(user)
        scoped.tenant_id = tenant
        async with acting_as_tenant(db, tenant):
            yield scoped

    return dependency
