"""Make sure the default tenant has a push-inbox token that CORE can use to forward its connector data into AiSOC.

CORE (the HUD) already holds the vendor credentials (Huntress, DNSFilter, ...) and knows how to call those APIs. Rather than copying every credential into AiSOC and
re-implementing every vendor client, CORE polls its own connectors and posts what it finds to AiSOC's generic JSON push inbox (``POST /v1/inbox/{token}``,
template ``generic-json``). This script creates that one token.

    python -m app.scripts.ensure_core_feed_token

Idempotent: if an active token with the label below already exists it is returned unchanged, otherwise one is created. The last line of output is machine-readable:

    AISOC_CORE_FEED_RESULT {"ok": true, "token": "aitnb_...", "created": false}

The token is a credential (it is the only thing that authenticates a push). It is printed here for CORE to store in AiSOC's ``.env`` and is never logged.
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

DEFAULT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
LABEL = "core-feed"
TEMPLATE_ID = "generic-json"
RESULT_MARKER = "AISOC_CORE_FEED_RESULT "


async def ensure_token(session: Any, tenant_id: uuid.UUID, new_token: str) -> tuple[str, bool]:
    """Return ``(token, created)``: the tenant's active CORE feed token, creating it from ``new_token`` if there is none. The caller owns the transaction."""
    from sqlalchemy import select, text  # noqa: PLC0415

    from app.models.inbox import TenantInboxToken  # noqa: PLC0415

    await session.execute(text("select set_config('app.current_tenant_id', :t, true)"), {"t": str(tenant_id)})
    existing = (
        (
            await session.execute(
                select(TenantInboxToken)
                .where(
                    TenantInboxToken.tenant_id == tenant_id,
                    TenantInboxToken.template_id == TEMPLATE_ID,
                    TenantInboxToken.label == LABEL,
                    TenantInboxToken.revoked_at.is_(None),
                )
                .order_by(TenantInboxToken.created_at)
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    if existing is not None:
        return existing.token, False
    session.add(TenantInboxToken(token=new_token, tenant_id=tenant_id, template_id=TEMPLATE_ID, label=LABEL, created_at=datetime.now(UTC)))
    return new_token, True


async def run() -> dict[str, Any]:
    from app.api.v1.endpoints.inbox import _generate_inbox_token  # noqa: PLC0415
    from app.db.database import AsyncSessionLocal  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        token, created = await ensure_token(session, DEFAULT_TENANT_ID, _generate_inbox_token())
        await session.commit()
    return {"ok": True, "token": token, "created": created}


def main() -> int:
    try:
        result = asyncio.run(run())
    except Exception as exc:  # noqa: BLE001 - report any failure as a machine-readable result, never a traceback that could echo a value
        print(RESULT_MARKER + json.dumps({"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}))
        return 1
    print(RESULT_MARKER + json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
