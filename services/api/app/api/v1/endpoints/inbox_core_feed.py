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
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, literal, select, text, update
from sqlalchemy.dialects.postgresql import JSONB

from app.api.v1.deps import DBSession
from app.core.logging import safe_log_value
from app.db.rls_scope import cross_tenant_reads
from app.db.rls_sessions import adopt_tenant
from app.models.alert import Alert
from app.models.connector import Connector

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


def closed_uid_regex(uids: list[str]) -> str:
    """A regular expression matching the record text that carries one of these incident ids as its ``"uid"``. Ids are escaped, so they can only match themselves."""
    return r'"uid"\s*:\s*"(?:' + "|".join(re.escape(u) for u in uids) + ')"'


async def apply_closed(db: Any, tenant_id: Any, report: ClosedReport, now: datetime | None = None) -> int:
    """Resolve this tenant's alerts whose incident the vendor has closed. The caller owns the transaction. Returns how many alerts changed.

    Deliberately narrow: only alerts still ``new`` (nobody has acted on them) are touched, so an analyst's own decision is never overridden; it can only CLOSE, never
    reopen; and an alert is matched on the incident id inside its own original record, within this tenant. The vendor's state is kept on the alert (and as a tag).
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
                Alert.raw_event["raw_data"].astext.op("~")(closed_uid_regex(chunk)),
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
    resolved = await apply_closed(db, tenant_id, body)
    await db.commit()
    return ClosedResponse(resolved=resolved)
