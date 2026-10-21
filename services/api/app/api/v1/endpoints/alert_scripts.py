"""Run one of CORE's NinjaOne scripts on the machine an alert is about, from the alert page.

AiSOC runs nothing and holds no NinjaOne or HaloPSA key. These routes only QUEUE a request (a ``vendor_actions`` row for the vendor ``core``, the same queue Approve / Resolve use). CORE
collects it within about 15 seconds, finds the machine, runs the script, waits for the output, adds it as a private note on the HaloPSA ticket and as a comment on the AiSOC case, and reports
back. CORE decides whether to ask its owner first: a script switched to "run at once" there starts straight away, any other waits for an approval card in CORE.

Permission: ``connectors:write`` to ask (it reaches a live machine), ``alerts:read`` to see the options. Every request is audited.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text

from app.api.v1.deps import AuthUser, require_permission
from app.api.v1.endpoints.alert_vendor_actions import _alert, linked_tickets
from app.db.rls import TenantDBSession
from app.models.client_alias import ClientAlias
from app.models.tenant import Tenant
from app.models.vendor_action import VendorAction
from app.services.alert_scope import alert_scope
from app.services.audit import emit_audit
from app.services.vendor_actions import PENDING_TTL

router = APIRouter(prefix="/alerts", tags=["alerts"])

SCRIPT_VENDOR = "core"
SCRIPT_ACTION = "run_script"


class ScriptOption(BaseModel):
    id: int
    name: str
    one_click: bool = False


class ScriptOptions(BaseModel):
    scripts: list[ScriptOption]
    device: str | None = None
    tickets: list[str]
    case_id: uuid.UUID | None = None
    case_number: str | None = None
    # Why nothing can be run from this alert, in plain words; None when it can.
    blocked: str | None = None


def published_scripts(settings: Any) -> list[ScriptOption]:
    """The scripts CORE last said are switched on, shaped and capped. Nothing else is ever offered."""
    found = settings.get("core_scripts") if isinstance(settings, dict) else None
    out: list[ScriptOption] = []
    for s in found if isinstance(found, list) else []:
        if isinstance(s, dict) and isinstance(s.get("id"), int) and isinstance(s.get("name"), str) and s["name"].strip():
            out.append(ScriptOption(id=s["id"], name=s["name"].strip()[:200], one_click=bool(s.get("one_click"))))
    return sorted(out, key=lambda s: s.name.lower())[:200]


def device_of(alert: Any) -> str | None:
    """The machine the alert is about: the first host it names. None when it names none."""
    hosts = alert.affected_hosts if isinstance(getattr(alert, "affected_hosts", None), list) else []
    named = [h.strip() for h in hosts if isinstance(h, str) and h.strip()]
    return named[0][:255] if named else None


async def _case_of(db: Any, tenant_id: uuid.UUID, alert_id: uuid.UUID) -> Any:
    return (
        await db.execute(
            text("SELECT id, case_number FROM aisoc_cases WHERE tenant_id = :t AND :a = ANY(alert_ids) ORDER BY created_at DESC LIMIT 1").bindparams(
                t=tenant_id, a=alert_id
            )
        )
    ).first()


@router.get("/{alert_id}/scripts", response_model=ScriptOptions)
async def alert_script_options(
    alert_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: TenantDBSession,
) -> ScriptOptions:
    """The scripts that can be run from this alert, the machine and tickets it has, and the case it belongs to (if any)."""
    owner = (await db.execute(select(Tenant.settings).where(Tenant.id == current_user.tenant_id))).scalar_one_or_none()
    scripts = published_scripts(owner)
    async with alert_scope(db, current_user.tenant_id, alert_id) as tid:
        alert = await _alert(db, alert_id, tid)
        device = device_of(alert)
        tickets = [str(t["id"]) for t in linked_tickets(alert.enrichment_data) if t.get("system", "halopsa") == "halopsa"]
        case = await _case_of(db, tid, alert_id)
    blocked = None
    if not scripts:
        blocked = "CORE has not shared any scripts. Switch scripts on in CORE under Settings > Manage NinjaOne scripts."
    elif device is None:
        blocked = "This alert does not name a machine, so there is nothing to run a script on."
    return ScriptOptions(
        scripts=scripts,
        device=device,
        tickets=tickets,
        case_id=case.id if case else None,
        case_number=case.case_number if case else None,
        blocked=blocked,
    )


class TicketChoice(BaseModel):
    mode: Literal["link", "create"]
    number: str | None = Field(default=None, max_length=41, description="``link``: the HaloPSA ticket number the result goes on.")


class RunScriptRequest(BaseModel):
    script_id: int = Field(ge=1, le=2_000_000_000)
    ticket: TicketChoice | None = None
    case_id: uuid.UUID | None = Field(default=None, description="The case the output is added to; it must already hold this alert.")


class RunScriptResponse(BaseModel):
    id: uuid.UUID
    status: str
    runs_at_once: bool


@router.post("/{alert_id}/scripts/run", response_model=RunScriptResponse, status_code=status.HTTP_202_ACCEPTED)
async def run_alert_script(
    alert_id: uuid.UUID,
    body: RunScriptRequest,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: TenantDBSession,
) -> RunScriptResponse:
    """Queue the script for CORE. Returns 202: nothing has run yet."""
    if body.ticket is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Choose a HaloPSA ticket (an existing number, or open a new one): the result is put on it.")
    owner = (await db.execute(select(Tenant.settings).where(Tenant.id == current_user.tenant_id))).scalar_one_or_none()
    script = next((s for s in published_scripts(owner) if s.id == body.script_id), None)
    if script is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="CORE has not switched that script on.")
    async with alert_scope(db, current_user.tenant_id, alert_id) as tid:
        alert = await _alert(db, alert_id, tid)
        device = device_of(alert)
        if device is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="This alert does not name a machine to run the script on.")
        params: dict[str, Any] = {"script_id": script.id, "script_name": script.name, "device": device, "alert_title": (alert.title or "")[:300]}
        if body.case_id is not None:
            case = (
                await db.execute(
                    text("SELECT 1 FROM aisoc_cases WHERE id = :c AND tenant_id = :t AND :a = ANY(alert_ids)").bindparams(c=body.case_id, t=tid, a=alert_id)
                )
            ).first()
            if case is None:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="That case does not hold this alert.")
            params["case_id"] = str(body.case_id)
        if body.ticket.mode == "link":
            number = (body.ticket.number or "").strip().lstrip("#").strip()
            if not number.isdigit() or len(number) > 12:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Give the HaloPSA ticket number (digits only).")
            params["ticket_id"] = number.lstrip("0") or "0"
        else:
            halo_client = (
                (
                    await db.execute(
                        select(ClientAlias.vendor_client_id).where(
                            ClientAlias.tenant_id == current_user.tenant_id,
                            ClientAlias.vendor == "halopsa",
                            ClientAlias.child_tenant_id == tid,
                            ClientAlias.ignored.is_(False),
                        )
                    )
                )
                .scalars()
                .first()
            )
            params["create_ticket"] = {
                "summary": f"{script.name}: {(alert.title or 'alert')[:150]}"[:200],
                "details": (alert.description or alert.title or "")[:3000],
                **({"halo_client_id": str(halo_client)} if halo_client else {}),
            }
        raw = alert.raw_event if isinstance(alert.raw_event, dict) else {}
        finding = raw.get("finding") if isinstance(raw.get("finding"), dict) else {}
        uid = finding.get("uid") if isinstance(finding.get("uid"), str) else f"alert:{alert_id}"
        now = datetime.now(UTC)
        in_flight = (
            await db.execute(
                select(VendorAction.id).where(
                    VendorAction.alert_id == alert.id,
                    VendorAction.tenant_id == tid,
                    VendorAction.vendor == SCRIPT_VENDOR,
                    VendorAction.status.in_(("pending", "claimed")),
                    VendorAction.created_at > now - PENDING_TTL,
                )
            )
        ).first()
        if in_flight:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A script request for this alert is already waiting for CORE; let it finish first.")
        row = VendorAction(
            id=uuid.uuid4(),
            tenant_id=tid,
            alert_id=alert.id,
            vendor=SCRIPT_VENDOR,
            incident_uid=uid[:200],
            action=SCRIPT_ACTION,
            params=params,
            status="pending",
            requested_by=current_user.user_id,
        )
        db.add(row)
        await db.flush()
        await emit_audit(
            db=db,
            tenant_id=tid,
            actor_id=current_user.user_id,
            action="alerts:script_requested",
            resource="alert",
            resource_id=str(alert.id),
            changes={"script": script.name, "device": device, "ticket": params.get("ticket_id") or ("create" if "create_ticket" in params else None)},
            request=request,
        )
        await db.commit()
        return RunScriptResponse(id=row.id, status="pending", runs_at_once=script.one_click)
