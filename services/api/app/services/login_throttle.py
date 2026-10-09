"""Guessing a password is no longer free: failed sign-ins are counted, and too many in a window lock further attempts out.

THE RULE. After `LOGIN_MAX_FAILURES_PER_ACCOUNT` (5) FAILED attempts for one address, or `LOGIN_MAX_FAILURES_PER_IP` (20) from one client address, within `LOGIN_FAILURE_WINDOW_MINUTES` (15), further attempts are refused with 429 and a
Retry-After until the oldest of those failures leaves the window. A successful sign-in clears that address's failures (not the client address's). Old rows are purged as new ones arrive.

IT MUST NOT BRING BACK THE ENUMERATION. The address is counted exactly as typed (lower-cased, trimmed) whether or not an account exists, so a made-up address locks after five attempts just like a real one, and the answer while locked is
the same text for an unknown address, a real one, and a client address that has made too many attempts. (A distinguishing lock would let anyone find out which addresses are registered by watching which ones lock.)

IT CHECKS BEFORE THE PASSWORD. While locked even the CORRECT password is refused: otherwise the lock would only slow a guesser down by a request. The cost is that someone who can send five bad passwords for an address can lock that person out for
up to the window (it ends by itself, and `python -m app.scripts.login_lockout clear` ends it at once). The client-address count is the other half: one client cannot try many addresses.

The client address comes from `resolve_client_ip`, which ignores X-Forwarded-For unless trusted proxies are configured (otherwise an attacker could dodge the per-client limit by forging it). A request with no attributable address is limited by
address only.

Counts live in the database (`login_failures`, migration 069), so they hold across workers and restarts. An error here is not swallowed: a store that cannot be read must not silently turn the lock off.
"""
from __future__ import annotations

import hashlib
import logging
import math
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import delete, select

from app.core.config import settings
from app.core.emails import normalize_email
from app.models.login_failure import LoginFailure

logger = logging.getLogger(__name__)


def email_key(email: str) -> str:
    """The address as the lock counts it: trimmed and lower-cased, so `Alice@x` and `alice@x` share one count (the same rule as everywhere else: app/core/emails.py)."""
    return normalize_email(email)


def window() -> timedelta:
    return timedelta(minutes=settings.LOGIN_FAILURE_WINDOW_MINUTES)


def limits() -> tuple[int, int]:
    """(failures per address, failures per client address) in force. One place, so the operator's tool can never disagree with login about them."""
    return settings.LOGIN_MAX_FAILURES_PER_ACCOUNT, settings.LOGIN_MAX_FAILURES_PER_IP


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def too_many_attempts(remaining: timedelta) -> HTTPException:
    """The one answer for every locked case. It names no reason beyond the fact, so it cannot tell a real address from a made-up one."""
    seconds = max(1, math.ceil(remaining.total_seconds()))
    minutes = max(1, math.ceil(seconds / 60))
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"Too many failed sign-in attempts. Try again in about {minutes} minute{'' if minutes == 1 else 's'}.",
        headers={"Retry-After": str(seconds)},
    )


async def _remaining(db: Any, column: Any, value: str, limit: int, now: datetime) -> timedelta | None:
    """None when under the limit; otherwise how long until the count drops below it (the oldest of the latest `limit` failures leaving the window)."""
    cutoff = now - window()
    rows = (
        (await db.execute(select(LoginFailure.created_at).where(column == value, LoginFailure.created_at > cutoff).order_by(LoginFailure.created_at.desc()).limit(limit)))
        .scalars()
        .all()
    )
    if len(rows) < limit:
        return None
    return _aware(rows[-1]) + window() - now


async def ensure_not_locked(db: Any, email: str, client_ip: str | None, *, now: datetime | None = None) -> None:
    """Raise the 429 if this address, or this client address, has failed too often recently. Call BEFORE checking the password."""
    now = now or datetime.now(UTC)
    waits = [await _remaining(db, LoginFailure.email_key, email_key(email), settings.LOGIN_MAX_FAILURES_PER_ACCOUNT, now)]
    if client_ip:
        waits.append(await _remaining(db, LoginFailure.client_ip, client_ip, settings.LOGIN_MAX_FAILURES_PER_IP, now))
    longest = max((w for w in waits if w is not None), default=None)
    if longest is not None:
        raise too_many_attempts(longest)


async def record_failure(db: Any, email: str, client_ip: str | None, *, now: datetime | None = None) -> None:
    """Count one failed attempt (and purge rows older than the window). Committed HERE: the request is about to raise 401, which rolls the session back."""
    now = now or datetime.now(UTC)
    key = email_key(email)
    db.add(LoginFailure(email_key=key, client_ip=client_ip, created_at=now))
    await db.execute(delete(LoginFailure).where(LoginFailure.created_at <= now - window()))
    await db.commit()
    if await _remaining(db, LoginFailure.email_key, key, settings.LOGIN_MAX_FAILURES_PER_ACCOUNT, now) is not None:
        logger.warning(
            "sign-in locked after repeated failures",
            extra={"email_sha256": hashlib.sha256(key.encode()).hexdigest()[:16], "client_ip": client_ip, "failures_limit": settings.LOGIN_MAX_FAILURES_PER_ACCOUNT},
        )


async def clear_failures(db: Any, email: str) -> None:
    """A successful sign-in: forget this address's failures (the client address's stay, so one client still cannot try many addresses). Committed HERE, like record_failure: it must not depend on how the caller's session ends."""
    await db.execute(delete(LoginFailure).where(LoginFailure.email_key == email_key(email)))
    await db.commit()
