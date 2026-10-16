"""Approve or reject a Huntress remediation plan, or resolve the incident, from the alert in AiSOC.

AiSOC holds no vendor key. These routes only QUEUE the request (a ``vendor_actions`` row, migration 084) after checking it makes sense for the incident's last reported state;
CORE collects it on its next sync (``inbox_core_feed.py``), makes the call at Huntress and reports back. The alert page shows the progress.

Permission: ``connectors:write`` to ask for an action (these change a live security tool), ``alerts:read`` to see them. Every request is audited.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.alert import Alert
from app.models.vendor_action import VendorAction
from app.services.alert_scope import alert_scope
from app.services.audit import emit_audit
from app.services.vendor_actions import (
    PENDING_TTL,
    REJECT_REASONS,
    SUPPORTED_VENDOR,
    alert_vendor_and_uid,
    effective_status,
    problem_with_request,
    problem_with_resolve_only,
    vendor_account_id,
)

router = APIRouter(prefix="/alerts", tags=["alerts"])

_RejectReason = Literal[REJECT_REASONS]  # type: ignore[valid-type]


class VendorActionRequest(BaseModel):
    action: Literal["approve", "reject", "resolve"]
    comment: str | None = Field(
        default=None, max_length=2048, description="Required for ``reject``: why the plan is being rejected (Huntress's SOC reads it)."
    )
    reason: _RejectReason = "unspecified"
    useful: bool = Field(default=True, description="``reject`` only: whether the remediation plan was useful.")
    resolution: int | None = Field(
        default=None,
        description="Blumira only: how to record the resolution (10 Valid, 20 False Positive, 30 No Action Needed, 40 Risk Accepted). ``comment`` is sent as its note.",
    )


class VendorActionItem(BaseModel):
    id: uuid.UUID
    action: str
    status: str
    result_message: str | None
    created_at: datetime
    finished_at: datetime | None


class VendorActionsResponse(BaseModel):
    supported: bool
    vendor: str | None = None
    incident_uid: str | None = None
    vendor_state: dict[str, Any] | None = None
    actions: list[VendorActionItem]
    # PSA tickets (HaloPSA) linked to this alert, as CORE last reported them. Present whether or not the alert supports actions.
    tickets: list[dict[str, Any]] = []


def linked_tickets(enrichment: Any) -> list[dict[str, Any]]:
    """The tickets CORE linked to the alert (``enrichment_data.tickets``), or none. Anything not shaped like a ticket is left out."""
    found = enrichment.get("tickets") if isinstance(enrichment, dict) else None
    return [t for t in found if isinstance(t, dict) and t.get("id")] if isinstance(found, list) else []


def _item(row: VendorAction, now: datetime) -> VendorActionItem:
    return VendorActionItem(
        id=row.id,
        action=row.action,
        status=effective_status(row.status, row.created_at, row.claimed_at, now),
        result_message=row.result_message,
        created_at=row.created_at,
        finished_at=row.finished_at,
    )


async def _alert(db: Any, alert_id: uuid.UUID, tenant_id: uuid.UUID) -> Alert:
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id))).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.get("/{alert_id}/vendor-actions", response_model=VendorActionsResponse)
async def list_vendor_actions(
    alert_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: TenantDBSession,
) -> VendorActionsResponse:
    """The incident's last reported vendor state (remediation plan) and the actions asked for so far. ``supported`` is false for alerts this does not apply to."""
    async with alert_scope(db, current_user.tenant_id, alert_id) as tid:
        alert = await _alert(db, alert_id, tid)
        found = alert_vendor_and_uid(alert.raw_event)
        tickets = linked_tickets(alert.enrichment_data)
        if found is None:
            return VendorActionsResponse(supported=False, actions=[], tickets=tickets)
        vendor, uid = found
        rows = (
            (
                await db.execute(
                    select(VendorAction)
                    .where(VendorAction.alert_id == alert.id, VendorAction.tenant_id == tid)
                    .order_by(VendorAction.created_at.desc())
                    .limit(20)
                )
            )
            .scalars()
            .all()
        )
        now = datetime.now(UTC)
        state = (alert.enrichment_data or {}).get("vendor_state")
        return VendorActionsResponse(
            supported=True,
            vendor=vendor,
            incident_uid=uid,
            vendor_state=state if isinstance(state, dict) else None,
            actions=[_item(r, now) for r in rows],
            tickets=tickets,
        )


@router.post("/{alert_id}/vendor-actions", response_model=VendorActionItem, status_code=status.HTTP_202_ACCEPTED)
async def request_vendor_action(
    alert_id: uuid.UUID,
    body: VendorActionRequest,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: TenantDBSession,
) -> VendorActionItem:
    """Queue an approve / reject / resolve for CORE to carry out at the vendor (Blumira and Field Effect: resolve only). Returns 202: nothing has happened at the vendor yet."""
    async with alert_scope(db, current_user.tenant_id, alert_id) as tid:
        alert = await _alert(db, alert_id, tid)
        found = alert_vendor_and_uid(alert.raw_event)
        if found is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Only a Huntress, Blumira or Field Effect alert that carries its incident id supports this.",
            )
        vendor, uid = found
        if vendor == SUPPORTED_VENDOR:
            problem = problem_with_request(body.action, (alert.enrichment_data or {}).get("vendor_state"))
        else:
            problem = problem_with_resolve_only(vendor, body.action, body.resolution, alert.status)
        if problem:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=problem)
        if body.action == "reject" and not (body.comment or "").strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Say why the plan is being rejected; Huntress's SOC reads it."
            )

        now = datetime.now(UTC)
        in_flight = (
            (
                await db.execute(
                    select(VendorAction).where(
                        VendorAction.alert_id == alert.id,
                        VendorAction.tenant_id == tid,
                        VendorAction.status.in_(("pending", "claimed")),
                        VendorAction.created_at > now - PENDING_TTL,
                    )
                )
            )
            .scalars()
            .all()
        )
        if in_flight:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="An action for this incident is already waiting for CORE; let it finish first."
            )

        params: dict[str, Any] = {}
        if body.action == "reject":
            params = {"comment": (body.comment or "").strip(), "reason": body.reason, "useful": body.useful}
        elif vendor == "blumira":
            params = {"resolution": body.resolution, "notes": (body.comment or "").strip()}
            account = vendor_account_id(alert.raw_event)
            if account:
                params["account_id"] = account
        elif vendor == "fieldeffect":
            params = {"comment": (body.comment or "").strip()}
        row = VendorAction(
            id=uuid.uuid4(),
            tenant_id=tid,
            alert_id=alert.id,
            vendor=vendor,
            incident_uid=uid,
            action=body.action,
            params=params,
            status="pending",
            requested_by=current_user.user_id,
            created_at=now,
        )
        db.add(row)
        await db.flush()
        await emit_audit(
            db=db,
            tenant_id=tid,
            actor_id=current_user.user_id,
            action="alerts:vendor_action_requested",
            resource="alert",
            resource_id=str(alert.id),
            changes={"vendor": vendor, "incident": uid, "action": body.action, "vendor_action_id": str(row.id)},
            request=request,
        )
        await db.commit()
        return _item(row, now)
