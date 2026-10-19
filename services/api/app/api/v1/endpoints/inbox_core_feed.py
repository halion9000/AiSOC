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
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator
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
from app.services.connector_run_log import record_if_changed
from app.services.core_feed_cases import open_cases_for_new_alerts
from app.services.core_feed_sla import record_closure_events
from app.services.iocs_from_alerts import sync_children_throttled as sync_iocs_throttled
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
    # "warning": the alerts came through, but a side job (devices, clients, ticket links) failed; ``message`` says which.
    status: Literal["ok", "warning", "error"]
    fetched: int = Field(default=0, ge=0, le=1_000_000)
    sent: int = Field(default=0, ge=0, le=1_000_000, description="Records AiSOC accepted in this run.")
    message: str | None = Field(
        default=None,
        max_length=300,
        description="Why a run failed, in CORE's words (already stripped of tokens and URLs). Shown on the connector card.",
    )


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


async def _across(db: Any, owner: Any, work: Any, tenants: list[Any] | None = None) -> list[Any]:
    """Run ``work(tenant_id)`` once per tenant (the whole scope, or just ``tenants``), each inside that tenant's row-level-security scope (restored afterwards). Returns the results in order."""
    results = []
    for tid in tenants if tenants is not None else await _scope_ids(db, owner):
        async with acting_as_tenant(db, tid):
            results.append(await work(tid))
    return results


async def _tenants_holding(db: Any, owner: Any, uids: list[str]) -> list[tuple[Any, set[str]]]:
    """For each tenant in the feed's scope that has an alert for any of these incident ids, which of the ids it holds (scope order): ONE query.

    A report used to be applied item by item in every client tenant of the owner. With 240 clients, a few hundred items was tens of thousands of statements, each inside its own
    row-level-security scope, and CORE gave up after 30 seconds. An incident normally lives in one tenant, so ask once where each one is and give every tenant only its own items.
    The lookup reads across the scope on purpose (it is what finds the tenants), and returns only tenant ids that are already in it: the token never reaches any other tenant.
    """
    scope = await _scope_ids(db, owner)
    wanted = sorted(set(uids))
    if not wanted:
        return []
    uid_expr = Alert.raw_event["finding"]["uid"].astext
    async with cross_tenant_reads(db):
        rows = (
            await db.execute(select(Alert.tenant_id, uid_expr).where(Alert.tenant_id.in_(scope), uid_expr.in_(wanted)).distinct())
        ).all()
    held: dict[Any, set[str]] = {}
    for tid, uid in rows:
        held.setdefault(tid, set()).add(uid)
    return [(tid, held[tid]) for tid in scope if tid in held]


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
        config = dict(row.connector_config or {})
        if src.status in ("error", "warning") and src.message and src.message.strip():
            config.update(last_error=src.message.strip(), last_error_at=now.isoformat())
        else:
            config.pop("last_error", None)
            config.pop("last_error_at", None)
        if config != (row.connector_config or {}):
            values["connector_config"] = config
        if src.status in ("ok", "warning"):
            values.update(
                health_status="healthy" if src.status == "ok" else "degraded",
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
        # The card keeps only the latest message; the log keeps the history (an entry only when status or message changed).
        await record_if_changed(
            db,
            tenant_id,
            row.id,
            status=src.status,
            message=src.message if src.status != "ok" else None,
            fetched=src.fetched,
            sent=src.sent,
            now=now,
        )
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
    # Record public IPs and file hashes seen on alerts as Threat Intel indicators. Also best effort.
    try:
        if await sync_iocs_throttled(db, tenant_id):
            await db.commit()
    except Exception:
        logger.exception("core_feed.iocs_from_alerts_failed")
        await db.rollback()
    return StatusResponse(updated=applied)


# ---- Sync pressed on a connector card ---------------------------------------------------------------------------------------------------------------------------------

# A request nobody collected (CORE was off) goes stale instead of firing hours later, when the person has long stopped waiting.
SYNC_REQUEST_TTL = timedelta(minutes=10)


class SyncClaimResponse(BaseModel):
    vendors: list[str]


async def claim_sync_requests_for(db: Any, tenant_id: Any, now: datetime | None = None) -> list[str]:
    """The tools whose Sync button was pressed recently, handed over once: the request is cleared as it is collected, so the next check finds nothing. The caller owns the transaction."""
    now = now or datetime.now(UTC)
    rows = (
        await db.execute(
            select(Connector.id, Connector.connector_config).where(
                Connector.tenant_id == tenant_id,
                Connector.connector_type == CORE_FEED_TYPE,
                Connector.connector_config.has_key("sync_requested_at"),  # noqa: W601
            )
        )
    ).all()
    vendors: list[str] = []
    for row in rows:
        config = row.connector_config or {}
        try:
            asked = datetime.fromisoformat(str(config.get("sync_requested_at")))
        except ValueError:
            asked = None
        if asked is not None and asked.tzinfo is None:
            asked = asked.replace(tzinfo=UTC)
        if asked is not None and now - asked <= SYNC_REQUEST_TTL and isinstance(config.get("vendor"), str):
            vendors.append(config["vendor"])
        await db.execute(
            update(Connector).where(Connector.id == row.id).values(connector_config=Connector.connector_config.op("-")("sync_requested_at"))
        )
    return sorted(set(vendors))


@router.post("/core-feed/{tenant_token}/sync-requests/claim", response_model=SyncClaimResponse)
async def claim_core_feed_sync_requests(tenant_token: str, db: DBSession) -> SyncClaimResponse:
    """CORE asks, about every 15 seconds, which tools to sync now."""
    tenant_id = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, tenant_id)
    vendors = await claim_sync_requests_for(db, tenant_id)
    await db.commit()
    return SyncClaimResponse(vendors=vendors)


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
    now = datetime.now(UTC)
    prefix = f"{body.vendor}:"
    holders = await _tenants_holding(db, tenant_id, [i.uid for i in body.closed if i.uid.startswith(prefix)])
    held = dict(holders)
    changed = await _across(
        db,
        tenant_id,
        lambda tid: apply_closed(db, tid, body.model_copy(update={"closed": [i for i in body.closed if i.uid in held[tid]]}), now),
        tenants=[tid for tid, _ in holders],
    )
    resolved = sum(changed)
    if resolved:
        # Give the SLA page the timing for what was just closed. Best effort: it must never undo the closures themselves. Only tenants where something was resolved.
        async def sla(tid: Any) -> int:
            try:
                async with db.begin_nested():
                    return await record_closure_events(db, tid, body.vendor, now)
            except Exception:
                logger.exception("core_feed.sla_events_failed")
                return 0

        await _across(db, tenant_id, sla, tenants=[tid for (tid, _), n in zip(holders, changed, strict=True) if n])
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
    prefix = f"{body.vendor}:"
    holders = await _tenants_holding(db, tenant_id, [i.uid for i in body.items if i.uid.startswith(prefix)])
    held = dict(holders)
    updated = sum(
        await _across(
            db,
            tenant_id,
            lambda tid: apply_state(db, tid, body.model_copy(update={"items": [i for i in body.items if i.uid in held[tid]]})),
            tenants=[tid for tid, _ in holders],
        )
    )
    await db.commit()
    return StateResponse(updated=updated)


class ClaimRequest(BaseModel):
    vendor: Literal["huntress", "blumira", "fieldeffect"]


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


_HALO_BASE = re.compile(r"^(https://[a-z0-9][a-z0-9-]*\.halopsa\.com)/tickets\?id=", re.IGNORECASE)


def halo_base_from(report: TicketsReport) -> str | None:
    """The HaloPSA address (``https://acme.halopsa.com``) the tickets in this report link to, so a ticket someone enters by number alone can be given its link too. Only a HaloPSA address is kept."""
    for item in report.items:
        for t in item.tickets:
            m = _HALO_BASE.match(t.url or "")
            if m:
                return m.group(1).lower()
    return None


@router.post("/core-feed/{tenant_token}/tickets", response_model=TicketsResponse)
async def report_core_feed_tickets(tenant_token: str, body: TicketsReport, db: DBSession) -> TicketsResponse:
    """Record the PSA (HaloPSA) tickets linked to open vendor incidents, so each alert shows its tickets."""
    tenant_id = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, tenant_id)
    halo = halo_base_from(body)
    if halo is not None:
        owner = await db.get(Tenant, tenant_id)
        if owner is not None and (owner.settings or {}).get("halopsa_base_url") != halo:
            owner.settings = {**(owner.settings or {}), "halopsa_base_url": halo}
    prefix = f"{body.vendor}:"
    holders = await _tenants_holding(db, tenant_id, [i.uid for i in body.items if i.uid.startswith(prefix)])
    held = dict(holders)
    updated = sum(
        await _across(
            db,
            tenant_id,
            lambda tid: apply_tickets(db, tid, body.model_copy(update={"items": [i for i in body.items if i.uid in held[tid]]})),
            tenants=[tid for tid, _ in holders],
        )
    )
    await db.commit()
    return TicketsResponse(updated=updated)


class DeviceItem(BaseModel):
    uid: str = Field(min_length=1, max_length=200)
    hostname: str = Field(min_length=1, max_length=255)


class DevicesReport(BaseModel):
    vendor: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")
    items: list[DeviceItem] = Field(max_length=500)


class DevicesResponse(BaseModel):
    updated: int


async def apply_devices(db: Any, tenant_id: Any, report: DevicesReport) -> int:
    """Name the device on stored alerts that have none (``affected_hosts``), in ``tenant_id``. Only an EMPTY host list is filled: what ingestion already set is never overwritten, and nothing is re-scored.
    The caller owns the transaction."""
    prefix = f"{report.vendor}:"
    updated = 0
    for item in report.items:
        host = item.hostname.strip()
        if not host or not item.uid.startswith(prefix):
            continue
        result = await db.execute(
            update(Alert)
            .where(
                Alert.tenant_id == tenant_id,
                Alert.raw_event["finding"]["uid"].astext == item.uid,
                func.jsonb_array_length(func.coalesce(Alert.affected_hosts, literal([], type_=JSONB))) == 0,
            )
            .values(affected_hosts=literal([host], type_=JSONB))
        )
        updated += result.rowcount or 0
    return updated


@router.post("/core-feed/{tenant_token}/device-names", response_model=DevicesResponse)
async def report_core_feed_devices(tenant_token: str, body: DevicesReport, db: DBSession) -> DevicesResponse:
    """Record the device a vendor's incidents were raised on, for stored alerts that were forwarded without one (a Huntress incident names only its agent)."""
    tenant_id = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, tenant_id)
    prefix = f"{body.vendor}:"
    holders = await _tenants_holding(db, tenant_id, [i.uid for i in body.items if i.uid.startswith(prefix)])
    held = dict(holders)
    updated = sum(
        await _across(
            db,
            tenant_id,
            lambda tid: apply_devices(db, tid, body.model_copy(update={"items": [i for i in body.items if i.uid in held[tid]]})),
            tenants=[tid for tid, _ in holders],
        )
    )
    await db.commit()
    return DevicesResponse(updated=updated)


ALERT_LINK_KEYS = ("device_url", "user_url")


class EntityItem(BaseModel):
    uid: str = Field(min_length=1, max_length=200)
    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    src_ip: str | None = Field(default=None, max_length=64)
    # A link to the alert in the vendor's own tool. Only a plain https address; it is set only where the alert has no link yet.
    url: str | None = Field(default=None, max_length=1000, pattern=r"^https://[^\s]+$")
    # Links to the device and the user in the vendor's tool (keys ``device_url`` and ``user_url``), https only. Set only where the alert has no links yet.
    links: dict[str, str] | None = None

    @field_validator("links")
    @classmethod
    def _links_are_safe(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if value is None:
            return None
        clean = {
            k: v
            for k, v in value.items()
            if k in ALERT_LINK_KEYS and isinstance(v, str) and len(v) <= 1000 and re.match(r"^https://[^\s]+$", v)
        }
        return clean or None


class EntitiesReport(BaseModel):
    vendor: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")
    items: list[EntityItem] = Field(max_length=500)


async def apply_entities(db: Any, tenant_id: Any, report: EntitiesReport) -> int:
    """Give stored alerts the host, user and address a vendor's evidence names, and a link to the alert in the vendor's tool, in ``tenant_id``. Each is filled only where it is EMPTY: what ingestion
    already set is never overwritten, and nothing is re-scored. Returns how many alert fields were filled. The caller owns the transaction."""
    prefix = f"{report.vendor}:"
    filled = 0
    for item in report.items:
        if not item.uid.startswith(prefix):
            continue
        for column, value in (
            (Alert.affected_hosts, item.hostname),
            (Alert.affected_users, item.username),
            (Alert.affected_ips, item.src_ip),
        ):
            cleaned = (value or "").strip()
            if not cleaned:
                continue
            result = await db.execute(
                update(Alert)
                .where(
                    Alert.tenant_id == tenant_id,
                    Alert.raw_event["finding"]["uid"].astext == item.uid,
                    func.jsonb_array_length(func.coalesce(column, literal([], type_=JSONB))) == 0,
                )
                .values({column.key: literal([cleaned], type_=JSONB)})
            )
            filled += result.rowcount or 0
        if item.url:
            result = await db.execute(
                update(Alert)
                .where(
                    Alert.tenant_id == tenant_id,
                    Alert.raw_event["finding"]["uid"].astext == item.uid,
                    Alert.raw_event["url"].astext.is_(None),
                )
                .values(raw_event=Alert.raw_event.op("||")(literal({"url": item.url}, type_=JSONB)))
            )
            filled += result.rowcount or 0
        if item.links:
            result = await db.execute(
                update(Alert)
                .where(
                    Alert.tenant_id == tenant_id,
                    Alert.raw_event["finding"]["uid"].astext == item.uid,
                    Alert.raw_event["links"].astext.is_(None),
                )
                .values(raw_event=Alert.raw_event.op("||")(literal({"links": item.links}, type_=JSONB)))
            )
            filled += result.rowcount or 0
    return filled


@router.post("/core-feed/{tenant_token}/entities", response_model=DevicesResponse)
async def report_core_feed_entities(tenant_token: str, body: EntitiesReport, db: DBSession) -> DevicesResponse:
    """Record the user, host and address a vendor's evidence names, for stored alerts that were forwarded without them (a Blumira finding carries none; its evidence does)."""
    tenant_id = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, tenant_id)
    prefix = f"{body.vendor}:"
    holders = await _tenants_holding(db, tenant_id, [i.uid for i in body.items if i.uid.startswith(prefix)])
    held = dict(holders)
    filled = sum(
        await _across(
            db,
            tenant_id,
            lambda tid: apply_entities(db, tid, body.model_copy(update={"items": [i for i in body.items if i.uid in held[tid]]})),
            tenants=[tid for tid, _ in holders],
        )
    )
    await db.commit()
    return DevicesResponse(updated=filled)
