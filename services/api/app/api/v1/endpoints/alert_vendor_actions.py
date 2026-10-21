"""Approve or reject a Huntress remediation plan, or resolve the incident, from the alert in AiSOC.

AiSOC holds no vendor key. These routes only QUEUE the request (a ``vendor_actions`` row, migration 084) after checking it makes sense for the incident's last reported state;
CORE collects it on its next sync (``inbox_core_feed.py``), makes the call at Huntress and reports back. The alert page shows the progress.

Permission: ``connectors:write`` to ask for an action (these change a live security tool), ``alerts:read`` to see them. Every request is audited.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import ARRAY, Text, cast, func, select, update

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.alert import Alert
from app.models.connector import Connector
from app.models.tenant import Tenant
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


MAX_MANUAL_TICKETS = 20
_TICKET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$")


def _shaped(found: Any) -> list[dict[str, Any]]:
    return [t for t in found if isinstance(t, dict) and t.get("id")] if isinstance(found, list) else []


def plain_ticket_number(ticket_id: str) -> str:
    """A ticket number without leading zeros when it is all digits ("0555871" is ticket 555871 in HaloPSA); anything else is left as it is."""
    text = str(ticket_id).strip()
    return (text.lstrip("0") or "0") if text.isdigit() else text


def linked_tickets(enrichment: Any) -> list[dict[str, Any]]:
    """The tickets linked to the alert: the ones CORE matched (``enrichment_data.tickets``) and the ones a person entered (``enrichment_data.manual_tickets``, flagged ``manual``). Anything not
    shaped like a ticket is left out. A ticket both CORE and a person named appears once, as CORE reported it (it knows the summary and status)."""
    if not isinstance(enrichment, dict):
        return []
    core = _shaped(enrichment.get("tickets"))
    seen = {(str(t.get("system") or "halopsa"), plain_ticket_number(t["id"])) for t in core}
    manual = [
        {**t, "manual": True}
        for t in _shaped(enrichment.get("manual_tickets"))
        if (str(t.get("system") or "halopsa"), plain_ticket_number(t["id"])) not in seen
    ]
    return core + manual


def with_halo_urls(tickets: list[dict[str, Any]], base: str | None) -> list[dict[str, Any]]:
    """Give a HaloPSA ticket that has no link the link to it in Halo (``<address>/tickets?id=<number>``), when the HaloPSA address is known. A ticket that already has a link keeps it."""
    if not base:
        return tickets
    return [
        {**t, "url": f"{base}/tickets?id={quote(plain_ticket_number(t['id']), safe='')}"}
        if str(t.get("system") or "halopsa") == "halopsa" and not t.get("url")
        else t
        for t in tickets
    ]


async def halo_base_of(db: Any, owner_tenant_id: uuid.UUID) -> str | None:
    """The HaloPSA address CORE's tickets have used, remembered on the organization the feed belongs to. None when CORE has not linked a ticket yet (or on any problem reading it)."""
    try:
        tenant = await db.get(Tenant, owner_tenant_id)
        value = (tenant.settings or {}).get("halopsa_base_url") if tenant is not None else None
    except Exception:  # noqa: BLE001 - a missing link must never fail the page
        return None
    return value if isinstance(value, str) and re.match(r"^https://[a-z0-9][a-z0-9-]*\.halopsa\.com$", value) else None


async def ticket_status_param(db: Any, owner_tenant_id: uuid.UUID, action: str) -> dict[str, str]:
    """For a resolve: the HaloPSA ticket status CORE should move the incident's ticket to (the organization's own choice, else "Tech Updated"). Nothing for approve or reject, which only add a
    note. A problem reading the setting falls back to the default; it never stops the resolve."""
    if action != "resolve":
        return {}
    from app.api.v1.endpoints.tenant_ticket_settings import close_status_of

    try:
        tenant = await db.get(Tenant, owner_tenant_id)
        return {"ticket_status": close_status_of(tenant.settings if tenant is not None else None)}
    except Exception:  # noqa: BLE001
        return {"ticket_status": close_status_of(None)}


class ManualTicketRequest(BaseModel):
    id: str = Field(min_length=1, max_length=41, description="The ticket number, with or without a leading #.")
    system: Literal["halopsa"] = "halopsa"
    summary: str | None = Field(default=None, max_length=300, description="Optional: what the ticket is about, shown on the alert.")
    url: str | None = Field(default=None, max_length=500, description="Optional: a link to the ticket. Only https addresses are kept.")


def clean_manual_ticket(body: ManualTicketRequest, user_id: Any, now: datetime) -> dict[str, Any]:
    """The ticket as it is stored: the number tidied (``#4521`` becomes ``4521``), the link kept only when it is a plain https address, and who added it and when. Raises ``ValueError``
    with a plain message for a number that cannot be one."""
    ticket_id = body.id.strip().lstrip("#").strip()
    if not _TICKET_ID.match(ticket_id):
        raise ValueError("A ticket number is letters, digits, dashes and underscores (up to 40), for example 4521.")
    ticket_id = plain_ticket_number(ticket_id)
    url = (body.url or "").strip()
    out: dict[str, Any] = {"system": body.system, "id": ticket_id, "added_by": str(user_id), "added_at": now.isoformat()}
    if (body.summary or "").strip():
        out["summary"] = body.summary.strip()
    if re.match(r"^https://[^\s]+$", url, re.IGNORECASE):
        out["url"] = url
    return out


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
        tickets = with_halo_urls(linked_tickets(alert.enrichment_data), await halo_base_of(db, current_user.tenant_id))
        if found is None:
            return VendorActionsResponse(supported=False, actions=[], tickets=tickets)
        vendor, uid = found
        rows = (
            (
                await db.execute(
                    select(VendorAction)
                    # Script runs (vendor ``core``) are listed by their own route, so they never appear as an incident action here.
                    .where(VendorAction.alert_id == alert.id, VendorAction.tenant_id == tid, VendorAction.vendor != "core")
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


class TicketsResponse(BaseModel):
    tickets: list[dict[str, Any]]


@router.post("/{alert_id}/tickets", response_model=TicketsResponse)
async def add_manual_ticket(
    alert_id: uuid.UUID,
    body: ManualTicketRequest,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    db: TenantDBSession,
) -> TicketsResponse:
    """Link a ticket to this alert by hand, for the case CORE could not match one. Kept apart from the tickets CORE matched, so its next sync never removes it. Adding a number that is
    already linked updates its summary and link."""
    async with alert_scope(db, current_user.tenant_id, alert_id) as tid:
        alert = await _alert(db, alert_id, tid)
        now = datetime.now(UTC)
        try:
            ticket = clean_manual_ticket(body, current_user.user_id, now)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
        enrichment = dict(alert.enrichment_data) if isinstance(alert.enrichment_data, dict) else {}
        existing = [
            t
            for t in _shaped(enrichment.get("manual_tickets"))
            if not (t.get("system") == ticket["system"] and str(t["id"]) == ticket["id"])
        ]
        if len(existing) >= MAX_MANUAL_TICKETS:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=f"An alert can have at most {MAX_MANUAL_TICKETS} tickets entered by hand."
            )
        enrichment["manual_tickets"] = [*existing, ticket]
        await db.execute(update(Alert).where(Alert.id == alert.id, Alert.tenant_id == tid).values(enrichment_data=enrichment))
        await emit_audit(
            db=db,
            tenant_id=tid,
            actor_id=current_user.user_id,
            action="alerts:ticket_linked",
            resource="alert",
            resource_id=str(alert.id),
            changes={"system": ticket["system"], "ticket": ticket["id"]},
            request=request,
        )
        await db.commit()
        return TicketsResponse(tickets=with_halo_urls(linked_tickets(enrichment), await halo_base_of(db, current_user.tenant_id)))


@router.delete("/{alert_id}/tickets/{ticket_id}", response_model=TicketsResponse)
async def remove_manual_ticket(
    alert_id: uuid.UUID,
    ticket_id: str,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    db: TenantDBSession,
) -> TicketsResponse:
    """Remove a ticket somebody entered by hand. A ticket CORE matched is not removable here (CORE would just report it again)."""
    async with alert_scope(db, current_user.tenant_id, alert_id) as tid:
        alert = await _alert(db, alert_id, tid)
        enrichment = dict(alert.enrichment_data) if isinstance(alert.enrichment_data, dict) else {}
        manual = _shaped(enrichment.get("manual_tickets"))
        kept = [t for t in manual if str(t["id"]) != ticket_id]
        if len(kept) == len(manual):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No ticket with that number was entered by hand on this alert."
            )
        enrichment["manual_tickets"] = kept
        await db.execute(update(Alert).where(Alert.id == alert.id, Alert.tenant_id == tid).values(enrichment_data=enrichment))
        await emit_audit(
            db=db,
            tenant_id=tid,
            actor_id=current_user.user_id,
            action="alerts:ticket_unlinked",
            resource="alert",
            resource_id=str(alert.id),
            changes={"ticket": ticket_id},
            request=request,
        )
        await db.commit()
        return TicketsResponse(tickets=with_halo_urls(linked_tickets(enrichment), await halo_base_of(db, current_user.tenant_id)))


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
        if (
            vendor == SUPPORTED_VENDOR
        ):  # Huntress: CORE knows the incident's ticket. (For the other tools it does not, so there is no ticket to move.)
            params = {**params, **await ticket_status_param(db, current_user.tenant_id, body.action)}
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


class RefreshResponse(BaseModel):
    vendor: str
    requested_at: str


@router.post("/{alert_id}/refresh", response_model=RefreshResponse, status_code=status.HTTP_202_ACCEPTED)
async def refresh_alert_status(
    alert_id: uuid.UUID,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: TenantDBSession,
) -> RefreshResponse:
    """Ask CORE to re-read this alert's tool now, so its status here catches up with the tool's.

    It leaves the same request the Sync button on a connector card leaves, for that one tool only: other tools are not asked, and nothing here reaches the vendor. CORE collects it within about
    15 seconds, reads that tool's changed and open incidents, and reports back; the alert's state then updates by itself. Only an alert that carries its tool's incident id can be re-checked.
    """
    async with alert_scope(db, current_user.tenant_id, alert_id) as tid:
        alert = await _alert(db, alert_id, tid)
        found = alert_vendor_and_uid(alert.raw_event)
    if found is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only a Huntress, Blumira or Field Effect alert that carries its incident id can be re-checked.",
        )
    vendor, uid = found
    now = datetime.now(UTC)
    # The feed is the caller's own (CORE reports to the organization it is connected as), even when the alert sits in one of its clients.
    result = await db.execute(
        update(Connector)
        .where(
            Connector.tenant_id == current_user.tenant_id,
            Connector.connector_type == "core_feed",
            Connector.connector_config["vendor"].astext == vendor,
        )
        .values(
            connector_config=func.jsonb_set(
                Connector.connector_config, cast(["sync_requested_at"], ARRAY(Text)), func.to_jsonb(cast(now.isoformat(), Text)), True
            )
        )
    )
    if (result.rowcount or 0) == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=f"CORE is not feeding {vendor} into this organization, so there is nothing to ask."
        )
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        action="alerts:refresh_requested",
        resource="alert",
        resource_id=str(alert_id),
        changes={"vendor": vendor, "incident": uid},
        request=request,
    )
    await db.commit()
    return RefreshResponse(vendor=vendor, requested_at=now.isoformat())
