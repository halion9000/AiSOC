"""What AiSOC suggests adding to a client's vCIO Toolbox, a person's decision on each, and the hand-off to CORE.

``GET  /client-review/{client_id}/vcio-proposals``                      the suggestions and their states.
``POST /client-review/{client_id}/vcio-proposals/refresh``              work the suggestions out again from the client review's checks.
``POST /client-review/{client_id}/vcio-proposals/{id}/approve|reject``  a person's decision. Approving needs the client mapped to a vCIO Toolbox customer.
``POST /inbox/core-feed/{token}/vcio-proposals/approved``               CORE collects what was approved (authenticated by the secret in the path, like the other core-feed routes).
``POST /inbox/core-feed/{token}/vcio-proposals/{id}/result``            CORE says whether vCIO Toolbox took it.

Nothing is sent to vCIO Toolbox by AiSOC itself, and nothing is sent until a person has approved it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.client_review import client_review
from app.api.v1.endpoints.inbox_core_feed import _scope_ids, _verify_core_feed_token
from app.db.rls_scope import acting_as_tenant, cross_tenant_reads
from app.db.rls_sessions import adopt_tenant
from app.models.client_alias import ClientAlias
from app.models.signin import ClientVcioProposal
from app.models.tenant import Tenant
from app.services.vcio_proposals import SOURCE, drafts_from_readiness, sync_suggestions

router = APIRouter(prefix="/client-review", tags=["posture"])
ingest_router = APIRouter(prefix="/inbox", tags=["inbox-core-feed"])


class ProposalOut(BaseModel):
    id: uuid.UUID
    key: str
    kind: str
    name: str
    description: str
    priority: str
    evidence: str
    status: str
    decided_at: datetime | None = None
    sent_at: datetime | None = None
    result_message: str | None = None
    updated_at: datetime


class ProposalsOut(BaseModel):
    client_id: uuid.UUID
    # False when the client is not mapped to a vCIO Toolbox customer yet: suggestions can be read, but not approved.
    mapped: bool
    proposals: list[ProposalOut]


def _out(row: ClientVcioProposal) -> ProposalOut:
    return ProposalOut(
        id=row.id,
        key=row.key,
        kind=row.kind,
        name=row.name,
        description=row.description,
        priority=row.priority,
        evidence=row.evidence,
        status=row.status,
        decided_at=row.decided_at,
        sent_at=row.sent_at,
        result_message=row.result_message,
        updated_at=row.updated_at,
    )


async def _own_client(db: Any, owner: uuid.UUID, client_id: uuid.UUID) -> None:
    if client_id == owner:
        return
    found = (await db.execute(select(Tenant.id).where(Tenant.id == client_id, Tenant.parent_tenant_id == owner))).scalar_one_or_none()
    if found is None:
        raise HTTPException(status_code=404, detail="Client not found")


async def _vendor_client_id(db: Any, owner: uuid.UUID, client_id: uuid.UUID) -> str | None:
    """The vCIO Toolbox customer this client is mapped to, if any."""
    return (
        (
            await db.execute(
                select(ClientAlias.vendor_client_id).where(
                    ClientAlias.tenant_id == owner,
                    ClientAlias.vendor == SOURCE,
                    ClientAlias.child_tenant_id == client_id,
                    ClientAlias.ignored.is_(False),
                )
            )
        )
        .scalars()
        .first()
    )


async def _rows(db: Any, owner: uuid.UUID, client_id: uuid.UUID) -> list[ClientVcioProposal]:
    async with acting_as_tenant(db, client_id):
        return list(
            (
                await db.execute(
                    select(ClientVcioProposal)
                    .where(ClientVcioProposal.tenant_id == client_id, ClientVcioProposal.source == SOURCE)
                    .order_by(ClientVcioProposal.created_at)
                )
            )
            .scalars()
            .all()
        )


@router.get("/{client_id}/vcio-proposals", response_model=ProposalsOut, summary="What AiSOC suggests adding to this client's vCIO Toolbox")
async def list_proposals(
    client_id: uuid.UUID, user: Annotated[AuthUser, Depends(require_permission("alerts:read"))], db: DBSession
) -> ProposalsOut:
    await _own_client(db, user.tenant_id, client_id)
    rows = await _rows(db, user.tenant_id, client_id)
    return ProposalsOut(
        client_id=client_id, mapped=await _vendor_client_id(db, user.tenant_id, client_id) is not None, proposals=[_out(r) for r in rows]
    )


@router.post(
    "/{client_id}/vcio-proposals/refresh",
    response_model=ProposalsOut,
    summary="Work the suggestions out again from the client review's checks",
)
async def refresh_proposals(
    client_id: uuid.UUID, user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))], db: DBSession
) -> ProposalsOut:
    await _own_client(db, user.tenant_id, client_id)
    review = await client_review(client_id, user, db)
    drafts = drafts_from_readiness(review.readiness)
    async with acting_as_tenant(db, client_id):
        await sync_suggestions(db, client_id, drafts)
    await db.commit()
    rows = await _rows(db, user.tenant_id, client_id)
    return ProposalsOut(
        client_id=client_id, mapped=await _vendor_client_id(db, user.tenant_id, client_id) is not None, proposals=[_out(r) for r in rows]
    )


async def _decide(db: Any, user: AuthUser, client_id: uuid.UUID, proposal_id: uuid.UUID, decision: str) -> ProposalOut:
    await _own_client(db, user.tenant_id, client_id)
    allowed_from = {"approved": ("suggested", "failed"), "rejected": ("suggested", "cleared", "failed")}[decision]
    if decision == "approved" and await _vendor_client_id(db, user.tenant_id, client_id) is None:
        raise HTTPException(status_code=409, detail="Map this client to its vCIO Toolbox customer on the Clients page first.")
    async with acting_as_tenant(db, client_id):
        row = (
            (
                await db.execute(
                    select(ClientVcioProposal).where(ClientVcioProposal.id == proposal_id, ClientVcioProposal.tenant_id == client_id)
                )
            )
            .scalars()
            .first()
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Suggestion not found")
        if row.status not in allowed_from:
            raise HTTPException(status_code=409, detail=f"A suggestion that is {row.status} cannot be {decision}.")
        now = datetime.now(UTC)
        row.status = decision
        row.decided_by = uuid.UUID(str(user.id)) if getattr(user, "id", None) else None
        row.decided_at = now
        row.updated_at = now
        row.result_message = None
    await db.commit()
    return _out(row)


@router.post(
    "/{client_id}/vcio-proposals/{proposal_id}/approve", response_model=ProposalOut, summary="Approve: CORE will add it to vCIO Toolbox"
)
async def approve_proposal(
    client_id: uuid.UUID, proposal_id: uuid.UUID, user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))], db: DBSession
) -> ProposalOut:
    return await _decide(db, user, client_id, proposal_id, "approved")


@router.post(
    "/{client_id}/vcio-proposals/{proposal_id}/reject", response_model=ProposalOut, summary="Reject: it will not be suggested again"
)
async def reject_proposal(
    client_id: uuid.UUID, proposal_id: uuid.UUID, user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))], db: DBSession
) -> ProposalOut:
    return await _decide(db, user, client_id, proposal_id, "rejected")


# ---- CORE's side ----------------------------------------------------------------------------------------------------------------------------------------


class ApprovedItem(BaseModel):
    id: uuid.UUID
    vendor_client_id: str
    kind: str
    key: str
    name: str
    description: str
    priority: str


class ApprovedResponse(BaseModel):
    items: list[ApprovedItem]


class ProposalResult(BaseModel):
    ok: bool
    vendor_id: str | None = Field(default=None, max_length=80)
    message: str | None = Field(default=None, max_length=500)


@ingest_router.post("/core-feed/{tenant_token}/vcio-proposals/approved", response_model=ApprovedResponse)
async def approved_proposals(tenant_token: str, db: DBSession) -> ApprovedResponse:
    """The suggestions a person approved and CORE has not yet sent, with the vCIO Toolbox customer each belongs to."""
    owner = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, owner)
    tenants = await _scope_ids(db, owner)
    async with cross_tenant_reads(db):
        rows = (
            (
                await db.execute(
                    select(ClientVcioProposal)
                    .where(
                        ClientVcioProposal.tenant_id.in_(tenants),
                        ClientVcioProposal.source == SOURCE,
                        ClientVcioProposal.status == "approved",
                    )
                    .limit(50)
                )
            )
            .scalars()
            .all()
        )
        aliases = (
            (
                await db.execute(
                    select(ClientAlias).where(ClientAlias.tenant_id == owner, ClientAlias.vendor == SOURCE, ClientAlias.ignored.is_(False))
                )
            )
            .scalars()
            .all()
        )
    customer_of = {a.child_tenant_id: a.vendor_client_id for a in aliases if a.child_tenant_id is not None}
    items = [
        ApprovedItem(
            id=r.id,
            vendor_client_id=customer_of[r.tenant_id],
            kind=r.kind,
            key=r.key,
            name=r.name,
            description=r.description,
            priority=r.priority,
        )
        for r in rows
        if r.tenant_id in customer_of
    ]
    return ApprovedResponse(items=items)


@ingest_router.post("/core-feed/{tenant_token}/vcio-proposals/{proposal_id}/result", response_model=ProposalOut)
async def proposal_result(tenant_token: str, proposal_id: uuid.UUID, body: ProposalResult, db: DBSession) -> ProposalOut:
    """CORE reports whether vCIO Toolbox took an approved suggestion. Only an approved one can be answered, so a repeated report changes nothing."""
    owner = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, owner)
    tenants = await _scope_ids(db, owner)
    async with cross_tenant_reads(db):
        row = (
            (
                await db.execute(
                    select(ClientVcioProposal).where(ClientVcioProposal.id == proposal_id, ClientVcioProposal.tenant_id.in_(tenants))
                )
            )
            .scalars()
            .first()
        )
    if row is None:
        raise HTTPException(status_code=404, detail="Suggestion not found")
    async with acting_as_tenant(db, row.tenant_id):
        row = (await db.execute(select(ClientVcioProposal).where(ClientVcioProposal.id == proposal_id))).scalars().one()
        if row.status == "approved":
            now = datetime.now(UTC)
            row.status = "sent" if body.ok else "failed"
            row.sent_at = now if body.ok else None
            row.vendor_id = body.vendor_id if body.ok else None
            row.result_message = (body.message or "")[:500] or None
            row.updated_at = now
    await db.commit()
    return _out(row)
