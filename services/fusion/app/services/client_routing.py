"""Send a forwarded alert to the client tenant its vendor client is mapped to.

CORE forwards every tool's alerts into ONE tenant (the MSSP's own). Each record carries the vendor's id for the client it belongs to (the Huntress or NinjaOne organization,
the Petra tenant). When a person has mapped that client to one of their client tenants (MSSP page, ``client_aliases``), the alert is stored under that tenant instead, so each
customer sees only their own. A client that is not mapped, is ignored, or has no id in the record stays where it arrived: nothing is ever dropped, and a lookup failure
leaves the alert with the MSSP.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

logger = structlog.get_logger()

# vendor -> the key in the record's context that holds that vendor's client id. Must match what CORE forwards (hud/src/aisoc-feed.ts, aisoc-ninjaone.ts) and what it lists as
# clients (hud/src/aisoc-clients.ts): Huntress organizations, Petra tenants, NinjaOne organizations.
CLIENT_ID_FIELD: dict[str, str] = {
    "huntress": "organization_id",
    "petra": "petra_tenant_id",
    "ninjaone": "organization_id",
}

Resolver = Callable[[uuid.UUID, str, str], Awaitable[uuid.UUID | None]]


def client_key(raw_event: dict[str, Any] | None) -> tuple[str, str] | None:
    """(vendor, vendor client id) of a forwarded record, or None when it names no client."""
    if not isinstance(raw_event, dict):
        return None
    vendor = raw_event.get("source")
    field = CLIENT_ID_FIELD.get(vendor) if isinstance(vendor, str) else None
    if field is None:
        return None
    unmapped = raw_event.get("unmapped")
    context = unmapped.get("context") if isinstance(unmapped, dict) else None
    value = context.get(field) if isinstance(context, dict) else None
    if isinstance(value, bool) or not isinstance(value, str | int) or str(value).strip() == "":
        return None
    return vendor, str(value).strip()


async def route_to_client_tenant(tenant_id: uuid.UUID, raw_event: dict[str, Any] | None, resolve: Resolver) -> uuid.UUID:
    """The tenant this alert should be stored under: the mapped client tenant, else ``tenant_id`` unchanged."""
    key = client_key(raw_event)
    if key is None:
        return tenant_id
    try:
        child = await resolve(tenant_id, key[0], key[1])
    except Exception as exc:  # noqa: BLE001 — a failed lookup must never lose or delay the alert
        logger.warning("client_routing.lookup_failed", error=str(exc))
        return tenant_id
    return child or tenant_id
