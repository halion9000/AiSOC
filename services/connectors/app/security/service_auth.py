"""Bearer-token guard for the connectors service's API.

The service makes outbound calls (query a SIEM, push a case to a ticketing tool, fetch a cloud resource
config) using connector configuration and decrypted credentials that its CALLER supplies in each request.
It had no authentication at all, so anything able to reach it could make it call out with arbitrary
configuration. The API is its only caller; it now sends ``Authorization: Bearer <AISOC_CONNECTORS_SERVICE_TOKEN>``.

Fail closed: with no token configured, only a development environment runs open (so a local stack keeps
working). Anything else (production, staging, a typo) answers 503 instead of running unauthenticated.
``AISOC_CONNECTORS_ENVIRONMENT`` follows the stack-wide AISOC_ENVIRONMENT switch in docker-compose.yml.
Read at call time, not import time, so the setting can change without a reload and tests can set it.
"""
from __future__ import annotations

import os
import secrets
from typing import Annotated

from fastapi import Header, HTTPException, status

_DEV_ENVIRONMENTS = frozenset({"development", "dev", "local", "test"})


def _token() -> str:
    return (os.getenv("AISOC_CONNECTORS_SERVICE_TOKEN") or "").strip()


def is_development() -> bool:
    raw = os.getenv("AISOC_CONNECTORS_ENVIRONMENT")
    # Unset means a plain local run (development). Set to an empty or unrecognised value is NOT development: a
    # mistake must fail closed, so `or "development"` (which would treat "" as dev) is deliberately not used.
    return ("development" if raw is None else raw).strip().lower() in _DEV_ENVIRONMENTS


async def require_service_token(authorization: Annotated[str | None, Header()] = None) -> None:
    token = _token()
    if not token:
        if is_development():
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="connectors service auth is not configured",
        )
    scheme, _, supplied = (authorization or "").partition(" ")
    supplied = supplied.strip()
    if scheme.lower() != "bearer" or not supplied or not secrets.compare_digest(supplied.encode(), token.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing service token",
            headers={"WWW-Authenticate": "Bearer"},
        )
