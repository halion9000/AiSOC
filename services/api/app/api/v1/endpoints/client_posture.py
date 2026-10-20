"""One client's security posture on a single page: devices, second-factor coverage, open alerts and cases. Read-only; every number comes from data AiSOC already holds.

``GET /api/v1/client-posture/{client_id}``. The same figures are on the Devices, Multi-factor status, Alerts and Cases pages; this puts them side by side for a client review.
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, bindparam, func, not_, select, text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.alerts import FINISHED_STATUSES, has_ticket_expr
from app.api.v1.endpoints.devices import ClientRollup, _load_cached, _master_of, _scope, rollup_of
from app.api.v1.endpoints.identity import counts_for_mfa
from app.db.rls_scope import acting_as_tenant
from app.models.alert import Alert
from app.models.signin import IdentityMfaUser
from app.models.tenant import Tenant

router = APIRouter(prefix="/client-posture", tags=["posture"])

_CASE_FINISHED = ("resolved", "closed")


class PostureDevices(BaseModel):
    devices: int = 0
    needs_attention: int = 0
    stale_agents: int = 0
    not_in_huntress: int = 0
    offline: int = 0


class PostureIdentity(BaseModel):
    people: int
    with_mfa: int
    not_required: int
    without_mfa: int
    admins_without_mfa: int
    refreshed_at: datetime | None = None


class PostureAlerts(BaseModel):
    open: int
    critical: int
    high: int
    without_ticket: int


class ClientPosture(BaseModel):
    client_id: uuid.UUID
    client_name: str | None
    generated_at: datetime
    devices: PostureDevices
    # None when no multi-factor data has arrived for this client (CIPP not connected or not mapped).
    identity: PostureIdentity | None
    alerts: PostureAlerts
    open_cases: int


def devices_part(rollups: list[ClientRollup], client_id: uuid.UUID) -> PostureDevices:
    """The client's row of the device rollup, or zeros when it has no devices."""
    for r in rollups:
        if r.client_id == client_id:
            return PostureDevices(
                devices=r.devices,
                needs_attention=r.needs_attention,
                stale_agents=r.stale_agents,
                not_in_huntress=r.not_in_huntress,
                offline=r.offline,
            )
    return PostureDevices()


@router.get(
    "/{client_id}", response_model=ClientPosture, summary="One client's devices, second-factor coverage, open alerts and cases side by side"
)
async def client_posture(
    client_id: uuid.UUID, current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))], db: DBSession
) -> ClientPosture:
    owner = current_user.tenant_id
    if client_id != owner:
        found = (await db.execute(select(Tenant.id).where(Tenant.id == client_id, Tenant.parent_tenant_id == owner))).scalar_one_or_none()
        if found is None:
            raise HTTPException(status_code=404, detail="Client not found")
    scope, clients = await _scope(db, owner, client_id)
    master = _master_of(await db.get(Tenant, owner))
    loaded = await _load_cached(db, owner, scope, clients, master)
    devices = devices_part(rollup_of([d for d in loaded if d.hidden_since is None]), client_id)

    async with contextlib.nullcontext() if client_id == owner else acting_as_tenant(db, client_id):
        users = (await db.execute(select(IdentityMfaUser).where(IdentityMfaUser.tenant_id == client_id))).scalars().all()
        row = (
            await db.execute(
                select(
                    func.count(),
                    func.count().filter(Alert.severity == "critical"),
                    func.count().filter(Alert.severity == "high"),
                    func.count().filter(not_(has_ticket_expr())),
                ).where(and_(Alert.tenant_id == client_id, Alert.status.notin_(FINISHED_STATUSES)))
            )
        ).one()
        cases = (
            await db.execute(
                text("SELECT count(*) FROM cases WHERE tenant_id = :t AND status NOT IN :done").bindparams(
                    bindparam("done", expanding=True)
                ),
                {"t": client_id, "done": list(_CASE_FINISHED)},
            )
        ).scalar_one()
    identity = PostureIdentity(refreshed_at=max(u.refreshed_at for u in users), **counts_for_mfa(list(users))) if users else None
    name = clients.get(client_id)
    return ClientPosture(
        client_id=client_id,
        client_name=name,
        generated_at=datetime.now(UTC),
        devices=devices,
        identity=identity,
        alerts=PostureAlerts(open=row[0], critical=row[1], high=row[2], without_ticket=row[3]),
        open_cases=cases,
    )
