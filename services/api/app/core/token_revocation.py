"""Server-side revocation of JWTs, so signing out actually ends the session.

Signing out used to only clear the browser's copy of the tokens: the access token (and the refresh token) stayed valid until they expired, so anyone who had
copied one, or a stolen laptop, kept working access after the user "signed out". Tokens now carry a unique ``jti``; logging out records it here, in Redis, for exactly
as long as the token would have lived (so the list cannot grow without bound), and ``get_current_user`` and ``/auth/refresh`` refuse a token whose ``jti`` is recorded.

Failure policy, deliberately asymmetric:
  * REVOKING (logout) fails loudly: if the store is unreachable the caller is told the session was NOT ended (HTTP 503), never that it was.
  * CHECKING (every authenticated request) fails open: if the store is unreachable the request is allowed and a warning is logged. Failing closed would lock every user
    out of the whole API during any Redis outage, which is worse than the brief window this leaves open.

Tokens issued before this existed have no ``jti`` and cannot be revoked; they simply expire as before.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any

from redis.asyncio import Redis, from_url
from redis.exceptions import RedisError

from app.core.config import settings

logger = logging.getLogger("aisoc.token_revocation")

_KEY_PREFIX = "aisoc:revoked-jti:"
_client: Redis | None = None


class RevocationUnavailable(Exception):
    """The revocation store could not be reached, so a token could not be revoked."""


def _get_client() -> Redis:
    global _client
    if _client is None:
        _client = from_url(
            str(settings.REDIS_URL),
            decode_responses=True,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
        )
    return _client


def _seconds_until(exp: Any) -> int:
    """Seconds from now until `exp` (a datetime or a unix timestamp), never less than 1 (Redis rejects a zero TTL)."""
    exp_ts = exp.timestamp() if isinstance(exp, datetime) else float(exp)
    return max(1, int(exp_ts - time.time()))


async def revoke(jti: str, exp: Any) -> None:
    """Record `jti` as revoked until `exp`. Raises RevocationUnavailable if the store cannot be reached."""
    try:
        await _get_client().set(_KEY_PREFIX + jti, "1", ex=_seconds_until(exp))
    except (RedisError, OSError) as exc:
        logger.warning("token_revocation.revoke_failed", extra={"err": str(exc)})
        raise RevocationUnavailable("the revocation store is unavailable") from exc


async def is_revoked(jti: str | None) -> bool:
    """True if `jti` has been revoked. A token with no jti (issued before revocation existed) is never revoked. Fails OPEN if the store is unreachable."""
    if not jti:
        return False
    try:
        return bool(await _get_client().exists(_KEY_PREFIX + jti))
    except (RedisError, OSError) as exc:
        logger.warning("token_revocation.check_failed_allowing_request", extra={"err": str(exc)})
        return False


# ── Refresh-token rotation ───────────────────────────────────────────────────────────────────────────────────────────────
# A refresh token is single use: ``/auth/refresh`` hands back a NEW pair and the presented token is spent. Two browser tabs refreshing at the same moment present the same
# token, so for a short grace window the second caller is given the pair the first one was issued (rather than being signed out). A spent token presented AFTER the grace
# window is a replay (a copied token, or one tab that missed the rotation) and is refused. Like checking revocation, this fails OPEN when Redis is unreachable.

_USED_PREFIX = "aisoc:refresh-used:"
_PAIR_PREFIX = "aisoc:refresh-pair:"
REFRESH_GRACE_SECONDS = 30
_PAIR_WAIT_ATTEMPTS = 20
_PAIR_WAIT_SECONDS = 0.1


async def claim_refresh(jti: str | None, exp: Any) -> str:
    """Spend a refresh token. Returns ``"fresh"`` (first use: issue a new pair, then ``remember_refresh_pair``), ``"replay"`` (already spent; ``spent_pair`` may return the
    pair issued to the first caller), or ``"unchecked"`` (no jti, or the store is unreachable: issue as before)."""
    if not jti:
        return "unchecked"
    try:
        won = await _get_client().set(_USED_PREFIX + jti, "1", ex=_seconds_until(exp), nx=True)
    except (RedisError, OSError) as exc:
        logger.warning("token_revocation.claim_failed_allowing_refresh", extra={"err": str(exc)})
        return "unchecked"
    return "fresh" if won else "replay"


async def remember_refresh_pair(jti: str | None, pair: str) -> None:
    """Keep the pair issued for a spent token for the grace window, so a concurrent refresh with the same token gets it. Best effort."""
    if not jti:
        return
    try:
        await _get_client().set(_PAIR_PREFIX + jti, pair, ex=REFRESH_GRACE_SECONDS)
    except (RedisError, OSError) as exc:
        logger.warning("token_revocation.remember_pair_failed", extra={"err": str(exc)})


async def spent_pair(jti: str | None) -> str | None:
    """The pair issued to the first caller that spent ``jti``, if still inside the grace window. Waits briefly: the first caller may not have stored it yet."""
    import asyncio

    if not jti:
        return None
    for _ in range(_PAIR_WAIT_ATTEMPTS):
        try:
            pair = await _get_client().get(_PAIR_PREFIX + jti)
        except (RedisError, OSError):
            return None
        if pair:
            return pair
        await asyncio.sleep(_PAIR_WAIT_SECONDS)
    return None
