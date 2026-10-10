"""The platform-wide alert email setting (one row, id = 1): on or off, from which severity, to whom. Edited only by platform administrators."""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.models.alert_email import PlatformAlertEmailSettings

SEVERITIES = ("info", "low", "medium", "high", "critical")
MAX_RECIPIENTS = 20
_EMAIL = re.compile(r"[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


class InvalidSettings(ValueError):
    pass


def normalize_recipients(values: Any) -> list[str]:
    """Trimmed, lower-cased, de-duplicated, order kept. Raises InvalidSettings for anything that is not a plain address (no names, no angle brackets, no control characters) or for too many."""
    if not isinstance(values, (list, tuple)):
        raise InvalidSettings("recipients must be a list of email addresses")
    out: list[str] = []
    for value in values:
        address = str(value).strip().lower()
        if len(address) > 254 or not _EMAIL.fullmatch(address):
            raise InvalidSettings(f"not a plain email address: {address[:60]!r}")
        if address not in out:
            out.append(address)
    if len(out) > MAX_RECIPIENTS:
        raise InvalidSettings(f"at most {MAX_RECIPIENTS} recipients")
    return out


async def get_settings(db: Any) -> PlatformAlertEmailSettings:
    """The settings row, created (everything off) if the table has none."""
    row = (await db.execute(select(PlatformAlertEmailSettings).where(PlatformAlertEmailSettings.id == 1))).scalars().first()
    if row is None:
        row = PlatformAlertEmailSettings(id=1, enabled=False, min_severity="high", recipients=[], consecutive_failures=0)
        db.add(row)
        await db.flush()
    return row


async def update_settings(
    db: Any, *, updated_by: str, enabled: bool | None = None, min_severity: str | None = None, recipients: Any = None, now: datetime | None = None
) -> PlatformAlertEmailSettings:
    """Change any of the three. Turning it ON needs at least one recipient and starts the clock: only alerts created AFTER that moment are ever emailed (switching on never mails a backlog). Commits."""
    now = now or datetime.now(UTC)
    row = await get_settings(db)
    if min_severity is not None:
        if min_severity not in SEVERITIES:
            raise InvalidSettings(f"min_severity must be one of: {', '.join(SEVERITIES)}")
        row.min_severity = min_severity
    if recipients is not None:
        row.recipients = normalize_recipients(recipients)
    if enabled is not None:
        if enabled and not row.recipients:
            raise InvalidSettings("add at least one recipient before switching alert email on")
        if enabled and not row.enabled:
            row.enabled_since = now
        row.enabled = enabled
    row.updated_by_label = updated_by[:200]
    row.updated_at = now
    await db.commit()
    return row
