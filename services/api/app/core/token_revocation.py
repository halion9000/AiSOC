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
