"""The running log behind a connector card.

A card shows only the latest message. This keeps the history: an entry is written when a source's status or message differs from the last entry, never on a repeat, so a healthy
connector that reports "ok" every five minutes adds nothing. The newest ``LOG_KEEP`` entries per connector are kept.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import delete, select

from app.models.connector_run_log import ConnectorRunLog

LOG_KEEP = 200


def clean_message(message: str | None) -> str | None:
    """The message as stored: trimmed, and ``None`` when there is nothing to say."""
    text = (message or "").strip()
    return text or None


def differs_from_last(last: Any, status: str, message: str | None) -> bool:
    """``True`` when there is no earlier entry or its status or message is not the same as this report's."""
    if last is None:
        return True
    return last.status != status or clean_message(last.message) != clean_message(message)


async def record_if_changed(
    db: Any,
    tenant_id: uuid.UUID,
    connector_id: uuid.UUID,
    *,
    status: str,
    message: str | None,
    fetched: int,
    sent: int,
    now: datetime,
) -> bool:
    """Write one entry when this report differs from the last one, then trim to ``LOG_KEEP``. The caller owns the transaction. Returns whether an entry was written."""
    last = (
        await db.execute(
            select(ConnectorRunLog.status, ConnectorRunLog.message)
            .where(ConnectorRunLog.connector_id == connector_id)
            .order_by(ConnectorRunLog.at.desc(), ConnectorRunLog.id.desc())
            .limit(1)
        )
    ).first()
    if not differs_from_last(last, status, message):
        return False
    db.add(
        ConnectorRunLog(
            tenant_id=tenant_id,
            connector_id=connector_id,
            at=now,
            status=status,
            message=clean_message(message),
            fetched=fetched,
            sent=sent,
        )
    )
    await db.flush()
    keep = (
        select(ConnectorRunLog.id)
        .where(ConnectorRunLog.connector_id == connector_id)
        .order_by(ConnectorRunLog.at.desc(), ConnectorRunLog.id.desc())
        .limit(LOG_KEEP)
    )
    await db.execute(delete(ConnectorRunLog).where(ConnectorRunLog.connector_id == connector_id, ConnectorRunLog.id.not_in(keep)))
    return True
