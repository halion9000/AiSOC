"""Shared-secret auth for the threatintel HTTP surface.

Every route of the ``threatintel`` service except health requires
``Authorization: Bearer <AISOC_THREATINTEL_SERVICE_TOKEN>``, compared in constant
time. This used to be opt-in ("when set"), i.e. OPEN unless an operator remembered
to configure it, and it covered only /api/v1/actors/*, not /api/v1/iocs/search.

There is no development mode: with no token configured every route answers 503,
and CORE generates the token on every build, so a properly set up stack always has
one. The investigation agent sends the same value.

This mirrors two existing conventions in the codebase:

* the ingest ``k8s-audit`` shared-secret gate: a header token compared with
  ``subtle.ConstantTimeCompare`` (here: :func:`hmac.compare_digest`), and
* the actions->api ``AISOC_API_SERVICE_TOKEN`` inter-service token.

Resolves the ``[#TODO-attribution-rbac]`` caveat in
``docs/threat-actor-attribution.md``.
"""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from app.config import settings

_BEARER_PREFIX = "bearer "


def _expected_token() -> str:
    return (getattr(settings, "AISOC_THREATINTEL_SERVICE_TOKEN", "") or "").strip()


async def require_actor_auth(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency gating the threatintel routes.

    * Token unset → ``503`` (fail closed).
    * Token set → require a matching ``Authorization: Bearer <token>``,
      constant-time compared; missing or wrong → ``401``.
    """
    expected = _expected_token()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="threatintel service auth is not configured",
        )

    presented = ""
    if authorization and authorization.lower().startswith(_BEARER_PREFIX):
        presented = authorization[len(_BEARER_PREFIX) :].strip()

    if not presented or not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
