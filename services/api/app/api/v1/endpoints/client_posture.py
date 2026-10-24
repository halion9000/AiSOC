"""One client's security posture on a single page: devices, second-factor coverage, open alerts and cases. Read-only; every number comes from data AiSOC already holds.

``GET /api/v1/client-posture/{client_id}``. The same figures are on the Devices, Multi-factor status, Alerts and Cases pages; this puts them side by side for a client review.
"""

from __future__ import annotations

import asyncio
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
from app.models.client_alias import ClientAlias
from app.models.identity_source import IdentitySource
from app.models.signin import ClientM365Check, IdentityMfaUser
from app.models.tenant import Tenant
from app.services.domain_posture import DohResolver, DomainPosture, Resolver, candidate_domains, check_domains
from app.services.web_posture import LiveProbe, WebPosture, WebProbe, web_posture
from app.services.infra_review import saas_products

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


class PostureTool(BaseModel):
    """A tool this client is mapped to, and its id for the client in that tool (the id the tool's own page for the client is addressed by)."""

    vendor: str
    vendor_client_id: str
    vendor_client_name: str | None = None
    # What the tool protects for this client, when it says (Datto SaaS Protection: "microsoft", "google" or "both"), so a link can open the right page.
    product: str | None = None


class ClientPosture(BaseModel):
    client_id: uuid.UUID
    client_name: str | None
    generated_at: datetime
    devices: PostureDevices
    # None when no multi-factor data has arrived for this client (CIPP not connected or not mapped).
    identity: PostureIdentity | None
    alerts: PostureAlerts
    open_cases: int
    # The tools this client is mapped to (Huntress, NinjaOne...), for the page to show and link to the client's page in each.
    tools: list[PostureTool] = []


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
    "/{client_id}", response_model=ClientPosture, summary="One client's devices, Multi-Factor coverage, open alerts and cases side by side"
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
    aliases = (
        await db.execute(
            select(ClientAlias.vendor, ClientAlias.vendor_client_id, ClientAlias.vendor_client_name)
            .where(ClientAlias.tenant_id == owner, ClientAlias.child_tenant_id == client_id, ClientAlias.ignored.is_(False))
            .order_by(ClientAlias.vendor, ClientAlias.vendor_client_name)
        )
    ).all()
    saas_checks: list[dict] = []
    if any(v == "datto-saas" for v, _, _ in aliases):
        async with contextlib.nullcontext() if client_id == owner else acting_as_tenant(db, client_id):
            saas_row = (
                (
                    await db.execute(
                        select(ClientM365Check).where(ClientM365Check.tenant_id == client_id, ClientM365Check.source == "datto-saas")
                    )
                )
                .scalars()
                .first()
            )
        saas_checks = [c for c in (saas_row.checks if saas_row is not None else []) if isinstance(c, dict)]
    tools = [
        PostureTool(
            vendor=v, vendor_client_id=i, vendor_client_name=n or None, product=saas_products(saas_checks) if v == "datto-saas" else None
        )
        for v, i, n in aliases
    ]
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
        tools=tools,
    )


def get_resolver() -> Resolver:
    """The DNS resolver the domain checks use (replaced in tests)."""
    return DohResolver()


def get_probe() -> WebProbe:
    """What looks at a domain's website (replaced in tests)."""
    return LiveProbe()


class DomainWithWeb(DomainPosture):
    # What the domain's website shows; None when no website answered, which is normal for a mail-only domain.
    web: WebPosture | None = None


class ClientDomains(BaseModel):
    client_id: uuid.UUID
    # The domains looked at: those of the people held for the client, most used first.
    domains: list[DomainWithWeb]
    generated_at: datetime


@router.get("/{client_id}/domains", response_model=ClientDomains, summary="SPF, DMARC, DKIM and MX of the domains a client's people use")
async def client_domains(
    client_id: uuid.UUID, current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))], db: DBSession
) -> ClientDomains:
    """Looks the client's e-mail domains up in public DNS right now (nothing is stored). The domains are taken from the e-mail addresses of its people, so a client with none shows none."""
    owner = current_user.tenant_id
    if client_id != owner:
        found = (await db.execute(select(Tenant.id).where(Tenant.id == client_id, Tenant.parent_tenant_id == owner))).scalar_one_or_none()
        if found is None:
            raise HTTPException(status_code=404, detail="Client not found")
    async with contextlib.nullcontext() if client_id == owner else acting_as_tenant(db, client_id):
        upns = (await db.execute(select(IdentityMfaUser.upn).where(IdentityMfaUser.tenant_id == client_id))).scalars().all()
        mails = (await db.execute(select(IdentitySource.email).where(IdentitySource.tenant_id == client_id))).scalars().all()
    checked = await check_domains(candidate_domains([*upns, *mails]), get_resolver())
    probe = get_probe()
    now = datetime.now(UTC)
    webs = await asyncio.gather(*(probe.probe(d.domain) for d in checked))
    domains = [DomainWithWeb(**d.model_dump(), web=web_posture(w, now)) for d, w in zip(checked, webs, strict=True)]
    return ClientDomains(client_id=client_id, domains=domains, generated_at=now)
