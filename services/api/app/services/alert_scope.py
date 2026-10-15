"""Find which tenant an alert lives in, for a caller who may be an MSSP parent.

An alert CORE forwarded is stored under its client's tenant, but the person looking at it is often signed in to the parent, where the list shows it (see list_alerts). Opening,
updating or acting on it must work from there too, so the single-alert endpoints use this: the alert is looked for in the caller's own tenant first, then in the caller's client
tenants, and the work is done as that tenant (the same scoping the list uses). Anyone else's alert is not found.
"""

from __future__ import annotations

import contextlib
import uuid
from collections.abc import AsyncIterator
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select

from app.db.rls_scope import acting_as_tenant
from app.models.alert import Alert
from app.models.tenant import Tenant


async def find_alert_tenant(db: Any, own_tenant_id: uuid.UUID, alert_id: uuid.UUID) -> uuid.UUID | None:
    """The tenant (the caller's own, or one of its clients) that holds the alert, else None."""
    if (await db.execute(select(Alert.id).where(Alert.id == alert_id, Alert.tenant_id == own_tenant_id))).first() is not None:
        return own_tenant_id
    clients = [r[0] for r in (await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == own_tenant_id))).all()]
    if not clients:
        return None
    # One query when the session can see across tenants; otherwise ask each client as itself (row-level security shows a tenant only its own rows).
    row = (await db.execute(select(Alert.tenant_id).where(Alert.id == alert_id, Alert.tenant_id.in_(clients)))).first()
    if row is not None:
        return row[0]
    for tid in clients:
        async with acting_as_tenant(db, tid):
            if (await db.execute(select(Alert.id).where(Alert.id == alert_id, Alert.tenant_id == tid))).first() is not None:
                return tid
    return None


@contextlib.asynccontextmanager
async def alert_scope(db: Any, own_tenant_id: uuid.UUID, alert_id: uuid.UUID) -> AsyncIterator[uuid.UUID]:
    """Yield the tenant holding the alert, with the session acting as it for the length of the block. 404 when the caller cannot see the alert."""
    tid = await find_alert_tenant(db, own_tenant_id, alert_id)
    if tid is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    if tid == own_tenant_id:
        yield tid
    else:
        async with acting_as_tenant(db, tid):
            yield tid
