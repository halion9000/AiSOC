"""Forward normalised osquery events to services/ingest /v1/ingest/batch."""

from __future__ import annotations

import logging
import os

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

INGEST_CONNECTOR_ID = "osquery-tls"
INGEST_CONNECTOR_TYPE = "osquery"


async def forward_events(events: list[dict], tenant_id: str) -> None:
    """POST a batch of normalised events to the ingest service.

    Failures are logged but not re-raised so a single bad ingest call
    does not abort a log submission response to the osqueryd agent.
    """
    if not events:
        return
    url = f"{settings.ingest_url}/v1/ingest/batch"
    # The ingest service requires a bearer token and rejects a batch without connector_id and connector_type (a 400 this forwarder
    # never sent, so no osquery event had ever been accepted; the failure was swallowed by the log line below).
    headers = {"X-Tenant-ID": tenant_id}
    token = (os.getenv("AISOC_INGEST_SERVICE_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                json={"connector_id": INGEST_CONNECTOR_ID, "connector_type": INGEST_CONNECTOR_TYPE, "events": events},
                headers=headers,
            )
            resp.raise_for_status()
    except Exception:
        logger.exception(
            "Failed to forward %d events to ingest service (tenant=%s, url=%s)",
            len(events),
            tenant_id,
            url,
        )
