"""Optional shared-secret auth for the threat-actor attribution HTTP surface.

Every route of the ``threatintel`` service except health requires
``Authorization: Bearer <AISOC_THREATINTEL_SERVICE_TOKEN>``, compared in constant
time. This used to be opt-in ("when set"), i.e. OPEN unless an operator remembered
to configure it, and it covered only /api/v1/actors/*, not /api/v1/iocs/search.
It now FAILS CLOSED: with no token configured only a development environment runs
open (so a local stack keeps working); anything else answers 503 instead of
serving unauthenticated.

This mirrors two existing conventions in the codebase:

* the ingest ``k8s-audit`` shared-secret gate — a header token compared with
  ``subtle.ConstantTimeCompare`` (here: :func:`hmac.compare_digest`), and
* the actions->api ``AISOC_API_SERVICE_TOKEN`` inter-service token.

Resolves the ``[#TODO-attribution-rbac]`` caveat in
``docs/threat-actor-attribution.md``.
"""

from __future__ import annotations

import hmac

import structlog
from fastapi import Header, HTTPException, status

from app.config import settings

logger = structlog.get_logger(__name__)

_BEARER_PREFIX = "bearer "

# Warn at most once per process so an exposed-but-unauthenticated deployment
# is visible in logs without flooding them on every request.
_warned_unconfigured = False


_DEV_ENVIRONMENTS = frozenset({"development", "dev", "local", "test"})


def _is_development() -> bool:
    return str(getattr(settings, "ENVIRONMENT", "development")).strip().lower() in _DEV_ENVIRONMENTS


def _expected_token() -> str:
    return (getattr(settings, "AISOC_THREATINTEL_SERVICE_TOKEN", "") or "").strip()


async def require_actor_auth(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency gating the ``/api/v1/actors/*`` endpoints.

    * Token unset, development environment → allow, warning once.
    * Token unset, anything else → ``503`` (fail closed).
    * Token set → require a matching ``Authorization: Bearer <token>``,
      constant-time compared; missing or wrong → ``401``.
    """
    expected = _expected_token()
    if not expected and not _is_development():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="threatintel service auth is not configured",
        )
    if not expected:
        global _warned_unconfigured
        if not _warned_unconfigured:
            logger.warning(
                "actor_auth.unconfigured",
                detail=(
                    "AISOC_THREATINTEL_SERVICE_TOKEN is unset; /api/v1/actors/* "
                    "is unauthenticated. Set it (and configure the investigation "
                    "agent with the same value) before exposing the service "
                    "beyond the private network."
                ),
            )
            _warned_unconfigured = True
        return

    presented = ""
    if authorization and authorization.lower().startswith(_BEARER_PREFIX):
        presented = authorization[len(_BEARER_PREFIX) :].strip()

    if not presented or not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
