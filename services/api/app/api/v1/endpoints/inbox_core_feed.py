"""CORE reports what it forwarded, so the Connectors page can show it.

CORE reads the tools it holds credentials for (Huntress, Blumira, ...) and posts the records to the push inbox (``/v1/inbox/{token}``). That path carries the data;
it says nothing about whether each source is healthy, so nothing would ever fill in the ``connectors`` columns the Connectors page reads (health, last sync, events
ingested, errors). After each run CORE therefore posts a short report here, and each source becomes (or updates) one row of type ``core_feed``.

``POST /api/v1/inbox/core-feed/{tenant_token}/status`` is authenticated by the secret in the path, exactly like the ITSM webhooks (``inbox_itsm.py``): no session, no
API key. Only the tenant's ``core-feed`` token (template ``generic-json``, label ``core-feed``, not revoked) is accepted, so a token minted for any other webhook
cannot write here. The report can only create or update this tenant's own ``core_feed`` rows; it cannot touch any other connector.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, literal, select, text, update
from sqlalchemy.dialects.postgresql import JSONB

from app.api.v1.deps import DBSession
from app.core.logging import safe_log_value
from app.db.rls_scope import acting_as_tenant, cross_tenant_reads
from app.db.rls_sessions import adopt_tenant
from app.models.alert import Alert
from app.models.connector import Connector
from app.models.tenant import Tenant
from app.models.vendor_action import VendorAction
from app.services.client_mapping import IncomingClient, upsert_clients
from app.services.core_feed_cases import open_cases_for_new_alerts
from app.services.mssp_snapshots import snapshot_children_throttled
from app.services.vendor_actions import CLAIMED_TTL, PENDING_TTL

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/inbox", tags=["inbox-core-feed"])

CORE_FEED_TYPE = "core_feed"
CORE_FEED_LABEL = "core-feed"
CORE_FEED_TEMPLATE = "generic-json"
_CATEGORIES = ("siem", "edr", "cloud", "iam", "saas", "audit", "vcs", "ndr", "network")


class SourceReport(BaseModel):
    """One source's outcome for CORE's latest run."""

    vendor: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$", description="CORE's id for the source, e.g. ``huntress``.")
    name: str | None = Field(default=None, max_length=120, description="Display name for a new row; ignored for an existing one.")
    category: Literal["siem", "edr", "cloud", "iam", "saas", "audit", "vcs", "ndr", "network"] = "saas"
    status: Literal["ok", "error"]
    fetched: int = Field(default=0, ge=0, le=1_000_000)
    sent: int = Field(default=0, ge=0, le=1_000_000, description="Records AiSOC accepted in this run.")


class StatusReport(BaseModel):
    sources: list[SourceReport] = Field(max_length=50)


class StatusResponse(BaseModel):
    updated: int


async def _verify_core_feed_token(db: Any, token: str) -> Any:
    """The tenant of an active ``core-feed`` token, or 401. A read across tenants by nature (the tenant is learned FROM the token)."""
    async with cross_tenant_reads(db):
        row = (
            await db.execute(
                text(
                    """
                    SELECT tenant_id
                    FROM tenant_inbox_tokens
                    WHERE token = :token AND revoked_at IS NULL AND template_id = :template AND label = :label
                    """
                ).bindparams(token=token, template=CORE_FEED_TEMPLATE, label=CORE_FEED_LABEL)
            )
        ).fetchone()
    if row is None:
        # One answer for "no such token", "revoked" and "a token for something else": don't tell a caller which.
        logger.warning("inbox_core_feed.token_rejected", extra={"token_fingerprint": safe_log_value(f"...{token[-6:]}")})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked inbox token")
    return row.tenant_id


async def _scope_ids(db: Any, owner: Any) -> list[Any]:
    """The tenant that owns the feed, then its client tenants. A mapped client's alerts are stored under the client's own tenant (fusion's client routing), so anything that
    looks for "this feed's alerts" has to look there too. Only real children of the owner qualify: the token never reaches any other tenant."""
    children = (await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == owner))).scalars().all()
    return [owner, *children]


async def _across(db: Any, owner: Any, work: Any) -> list[Any]:
    """Run ``work(tenant_id)`` once per tenant in scope, each inside that tenant's row-level-security scope (restored afterwards). Returns the results in order."""
    results = []
    for tid in await _scope_ids(db, owner):
        async with acting_as_tenant(db, tid):
            results.append(await work(tid))
    return results


async def apply_report(db: Any, tenant_id: Any, report: StatusReport, now: datetime | None = None) -> int:
    """Create or update one ``core_feed`` row per reported source. The caller owns the transaction. Returns how many sources were applied."""
    now = now or datetime.now(UTC)
    applied = 0
    for src in report.sources:
        row = (
            await db.execute(
                select(Connector).where(
                    Connector.tenant_id == tenant_id,
                    Connector.connector_type == CORE_FEED_TYPE,
                    Connector.connector_config["vendor"].astext == src.vendor,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            row = Connector(
                tenant_id=tenant_id,
                name=(src.name or f"{src.vendor.replace('-', ' ').title()}")[:120] + " (via CORE)",
                connector_type=CORE_FEED_TYPE,
                category=src.category,
                is_enabled=True,
                auth_config={},
                connector_config={"vendor": src.vendor, "managed_by": "core"},
                tags=["core-feed"],
                health_status="unknown",
                events_ingested=0,
                events_dropped=0,
                error_count=0,
            )
            db.add(row)
            await db.flush()

        values: dict[str, Any] = {"last_health_check": now, "updated_at": now}
        if src.status == "ok":
            values.update(
                health_status="healthy",
                last_sync=now,
                events_ingested=Connector.events_ingested + src.sent,
                last_outage_at=None,
            )
            if src.sent > 0:
                values.update(last_event_at=now, last_event_kind="core-feed")
        else:
            values.update(
                health_status="unhealthy",
                error_count=Connector.error_count + 1,
                last_outage_at=func.coalesce(Connector.last_outage_at, now),
            )
        await db.execute(update(Connector).where(Connector.id == row.id).values(**values))
        applied += 1
    return applied


@router.post("/core-feed/{tenant_token}/status", response_model=StatusResponse)
async def report_core_feed_status(tenant_token: str, body: StatusReport, db: DBSession) -> StatusResponse:
    """Record CORE's latest run for each source it forwards."""
    tenant_id = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, tenant_id)
    applied = await apply_report(db, tenant_id, body)
    await db.commit()
    # Refresh the per-client numbers the MSSP overview shows. Best effort: it must never fail the status report itself.
    try:
        if await snapshot_children_throttled(db, tenant_id):
            await db.commit()
    except Exception:
        logger.exception("mssp.snapshot_refresh_failed")
        await db.rollback()
    # Open a case for each new high/critical alert that has none. Also best effort.
    try:
        if await open_cases_for_new_alerts(db, tenant_id):
            await db.commit()
    except Exception:
        logger.exception("core_feed.auto_cases_failed")
        await db.rollback()
    return StatusResponse(updated=applied)


# ---- closed in the vendor's own portal --------------------------------------------------------------------------------------------------------------------------------


_UID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9:_.-]{0,120}$"
_CLOSED_CHUNK = 100


class ClosedItem(BaseModel):
    uid: str = Field(pattern=_UID_PATTERN, description="The incident's ``finding.uid`` as CORE sent it, e.g. ``huntress:4821``.")
    state: str | None = Field(
        default=None, max_length=60, description="The vendor's own word for it, e.g. ``resolved`` or ``REMEDIATED``; shown on the alert."
    )


class ClosedReport(BaseModel):
    vendor: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")
    closed: list[ClosedItem] = Field(max_length=500)


class ClosedResponse(BaseModel):
    resolved: int


async def apply_closed(db: Any, tenant_id: Any, report: ClosedReport, now: datetime | None = None) -> int:
    """Resolve this tenant's alerts whose incident the vendor has closed. The caller owns the transaction. Returns how many alerts changed.

    Deliberately narrow: only alerts still ``new`` (nobody has acted on them) are touched, so an analyst's own decision is never overridden; it can only CLOSE, never
    reopen; and an alert is matched on the incident id the inbox template keeps at ``raw_event.finding.uid``, within this tenant. Alerts imported before that was kept have no id and are not matched. The vendor's state is kept on the alert (and as a tag).
    """
    now = now or datetime.now(UTC)
    prefix = f"{report.vendor}:"
    by_uid = {item.uid: item.state for item in report.closed if item.uid.startswith(prefix)}
    uids = sorted(by_uid)
    changed = 0
    for i in range(0, len(uids), _CLOSED_CHUNK):
        chunk = uids[i : i + _CLOSED_CHUNK]
        note = {
            "closed_in_vendor": {
                "vendor": report.vendor,
                "at": now.isoformat(),
                "states": sorted({str(by_uid[u]) for u in chunk if by_uid[u]}),
            }
        }
        result = await db.execute(
            update(Alert)
            .where(
                Alert.tenant_id == tenant_id,
                Alert.status == "new",
                Alert.raw_event["finding"]["uid"].astext.in_(chunk),
            )
            .values(
                status="resolved",
                updated_at=now,
                enrichment_data=Alert.enrichment_data.op("||")(literal(note, type_=JSONB)),
                tags=Alert.tags.op("||")(literal([f"closed-in-{report.vendor}"], type_=JSONB)),
            )
        )
        changed += result.rowcount or 0
    return changed


@router.post("/core-feed/{tenant_token}/closed", response_model=ClosedResponse)
async def report_core_feed_closed(tenant_token: str, body: ClosedReport, db: DBSession) -> ClosedResponse:
    """Mark alerts resolved when CORE reports their incidents closed in the vendor's own portal."""
    tenant_id = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, tenant_id)
    resolved = sum(await _across(db, tenant_id, lambda tid: apply_closed(db, tid, body)))
    await db.commit()
    return ClosedResponse(resolved=resolved)


# --- Incident state and vendor actions -------------------------------------------------------------------------------------------------------------------------
# CORE reports each OPEN incident's current state (status, remediation plan, the ticket the vendor opened in the PSA) so AiSOC can show it; an analyst's approve /
# reject / resolve is queued as a ``vendor_actions`` row (``alert_vendor_actions.py``), CORE collects it here, carries it out at the vendor (CORE holds the key; AiSOC never does)
# and reports the outcome. Same path-token authentication as the routes above.


class _Param(BaseModel):
    name: str = Field(max_length=120)
    description: str | None = Field(default=None, max_length=1000)


class _Remediation(BaseModel):
    id: int
    type: str | None = Field(default=None, max_length=30)
    action: str | None = Field(default=None, max_length=200)
    parameters: list[_Param] = Field(default_factory=list, max_length=20)
    status: str | None = Field(default=None, max_length=30)


class StateItem(BaseModel):
    uid: str = Field(pattern=_UID_PATTERN)
    status: str = Field(max_length=40, description="The vendor's status for the incident, e.g. ``sent``.")
    remediations: list[_Remediation] = Field(default_factory=list, max_length=50)
    psa_ticket_eids: list[str] = Field(
        default_factory=list, max_length=20, description="Ticket ids the vendor opened in the PSA for this incident."
    )


class StateReport(BaseModel):
    vendor: Literal["huntress"]
    items: list[StateItem] = Field(max_length=500)


class StateResponse(BaseModel):
    updated: int


async def apply_state(db: Any, tenant_id: Any, report: StateReport, now: datetime | None = None) -> int:
    """Store each incident's reported state on its alert (``enrichment_data.vendor_state``). The caller owns the transaction. Returns how many alerts were updated."""
    now = now or datetime.now(UTC)
    prefix = f"{report.vendor}:"
    updated = 0
    for item in report.items:
        if not item.uid.startswith(prefix):
            continue
        state = {
            "vendor_state": {
                "vendor": report.vendor,
                "at": now.isoformat(),
                "status": item.status,
                "remediations": [r.model_dump() for r in item.remediations],
                "psa_ticket_eids": [str(t)[:120] for t in item.psa_ticket_eids],
            }
        }
        result = await db.execute(
            update(Alert)
            .where(Alert.tenant_id == tenant_id, Alert.raw_event["finding"]["uid"].astext == item.uid)
            .values(enrichment_data=Alert.enrichment_data.op("||")(literal(state, type_=JSONB)))
        )
        updated += result.rowcount or 0
    return updated


@router.post("/core-feed/{tenant_token}/state", response_model=StateResponse)
async def report_core_feed_state(tenant_token: str, body: StateReport, db: DBSession) -> StateResponse:
    """Record the current state of open vendor incidents, so the alert can show the remediation plan and offer the right actions."""
    tenant_id = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, tenant_id)
    updated = sum(await _across(db, tenant_id, lambda tid: apply_state(db, tid, body)))
    await db.commit()
    return StateResponse(updated=updated)


class ClaimRequest(BaseModel):
    vendor: Literal["huntress"]


class ClaimedAction(BaseModel):
    id: uuid.UUID
    action: Literal["approve", "reject", "resolve"]
    incident_uid: str
    params: dict[str, Any]


class ClaimResponse(BaseModel):
    actions: list[ClaimedAction]


async def claim_actions(db: Any, tenant_id: Any, vendor: str, now: datetime | None = None) -> list[VendorAction]:
    """Hand CORE this tenant's pending actions, each at most once. The caller owns the transaction.

    First the housekeeping that keeps the queue honest: a pending action older than its time-to-live is failed as expired (it must never fire late), and a claimed one CORE never
    answered is failed. Then pending actions are claimed in one statement (``pending`` -> ``claimed``), so two overlapping polls cannot both receive the same row.
    """
    now = now or datetime.now(UTC)
    await db.execute(
        update(VendorAction)
        .where(VendorAction.tenant_id == tenant_id, VendorAction.status == "pending", VendorAction.created_at < now - PENDING_TTL)
        .values(status="failed", result_message="Expired before CORE collected it; request it again.", finished_at=now)
    )
    await db.execute(
        update(VendorAction)
        .where(VendorAction.tenant_id == tenant_id, VendorAction.status == "claimed", VendorAction.claimed_at < now - CLAIMED_TTL)
        .values(status="failed", result_message="CORE did not report a result.", finished_at=now)
    )
    rows = (
        (
            await db.execute(
                update(VendorAction)
                .where(VendorAction.tenant_id == tenant_id, VendorAction.vendor == vendor, VendorAction.status == "pending")
                .values(status="claimed", claimed_at=now)
                .returning(VendorAction)
            )
        )
        .scalars()
        .all()
    )
    return sorted(rows, key=lambda r: r.created_at)


@router.post("/core-feed/{tenant_token}/actions/claim", response_model=ClaimResponse)
async def claim_core_feed_actions(tenant_token: str, body: ClaimRequest, db: DBSession) -> ClaimResponse:
    """CORE collects the actions analysts have asked for. Each is handed out once."""
    tenant_id = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, tenant_id)
    rows = sorted(
        [r for got in await _across(db, tenant_id, lambda tid: claim_actions(db, tid, body.vendor)) for r in got],
        key=lambda r: r.created_at,
    )
    await db.commit()
    return ClaimResponse(
        actions=[ClaimedAction(id=r.id, action=r.action, incident_uid=r.incident_uid, params=r.params or {}) for r in rows]  # type: ignore[arg-type]
    )


class ActionResult(BaseModel):
    status: Literal["done", "failed"]
    message: str | None = Field(default=None, max_length=1000)


class ActionResultResponse(BaseModel):
    recorded: bool


@router.post("/core-feed/{tenant_token}/actions/{action_id}/result", response_model=ActionResultResponse)
async def report_core_feed_action_result(
    tenant_token: str, action_id: uuid.UUID, body: ActionResult, db: DBSession
) -> ActionResultResponse:
    """CORE reports how a claimed action went. Only a claimed action of this tenant can be answered, once."""
    tenant_id = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, tenant_id)
    now = datetime.now(UTC)
    row = None
    for tid in await _scope_ids(db, tenant_id):
        async with acting_as_tenant(db, tid):
            row = (
                await db.execute(
                    update(VendorAction)
                    .where(VendorAction.id == action_id, VendorAction.tenant_id == tid, VendorAction.status == "claimed")
                    .values(status=body.status, result_message=body.message, finished_at=now)
                    .returning(VendorAction.alert_id, VendorAction.action)
                )
            ).first()
            if row is not None:
                if body.status == "done" and row.action == "resolve":
                    # The vendor accepted the resolution: mirror it now rather than waiting for the next closed-incident sweep. Same narrow rule as ``apply_closed``: never override an analyst's decision.
                    await db.execute(
                        update(Alert)
                        .where(Alert.id == row.alert_id, Alert.tenant_id == tid, Alert.status == "new")
                        .values(status="resolved", resolved_at=now, updated_at=now)
                    )
                break
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such claimed action")
    await db.commit()
    return ActionResultResponse(recorded=True)


class ClientItem(BaseModel):
    id: str = Field(min_length=1, max_length=200, description="The vendor's own id for the client.")
    name: str = Field(min_length=1, max_length=300)


class ClientsReport(BaseModel):
    vendor: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")
    clients: list[ClientItem] = Field(max_length=5000)


class ClientsResponse(BaseModel):
    new: int
    linked: int


@router.post("/core-feed/{tenant_token}/clients", response_model=ClientsResponse)
async def report_core_feed_clients(tenant_token: str, body: ClientsReport, db: DBSession) -> ClientsResponse:
    """CORE sends the list of clients one vendor has (Petra tenants, Halo clients, ...), so each can be mapped to an AiSOC tenant on the MSSP page."""
    tenant_id = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, tenant_id)
    created, linked = await upsert_clients(
        db, tenant_id, body.vendor, [IncomingClient(c.id, c.name.strip()) for c in body.clients if c.name.strip()]
    )
    await db.commit()
    return ClientsResponse(new=created, linked=linked)


class LinkedTicket(BaseModel):
    id: str = Field(min_length=1, max_length=120)
    system: Literal["halopsa"] = "halopsa"
    summary: str | None = Field(default=None, max_length=500)
    status: str | None = Field(default=None, max_length=120)
    client: str | None = Field(default=None, max_length=300)
    url: str | None = Field(default=None, max_length=500, pattern=r"^https://")


class TicketsItem(BaseModel):
    uid: str = Field(min_length=1, max_length=200)
    tickets: list[LinkedTicket] = Field(max_length=20)


class TicketsReport(BaseModel):
    vendor: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")
    items: list[TicketsItem] = Field(max_length=500)


class TicketsResponse(BaseModel):
    updated: int


async def apply_tickets(db: Any, tenant_id: Any, report: TicketsReport) -> int:
    """Store the PSA tickets linked to each incident on its alert (``enrichment_data.tickets``), in ``tenant_id``. The caller owns the transaction."""
    prefix = f"{report.vendor}:"
    updated = 0
    for item in report.items:
        if not item.uid.startswith(prefix):
            continue
        value = {"tickets": [t.model_dump(exclude_none=True) for t in item.tickets]}
        result = await db.execute(
            update(Alert)
            .where(Alert.tenant_id == tenant_id, Alert.raw_event["finding"]["uid"].astext == item.uid)
            .values(enrichment_data=Alert.enrichment_data.op("||")(literal(value, type_=JSONB)))
        )
        updated += result.rowcount or 0
    return updated


@router.post("/core-feed/{tenant_token}/tickets", response_model=TicketsResponse)
async def report_core_feed_tickets(tenant_token: str, body: TicketsReport, db: DBSession) -> TicketsResponse:
    """Record the PSA (HaloPSA) tickets linked to open vendor incidents, so each alert shows its tickets."""
    tenant_id = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, tenant_id)
    updated = sum(await _across(db, tenant_id, lambda tid: apply_tickets(db, tid, body)))
    await db.commit()
    return TicketsResponse(updated=updated)
