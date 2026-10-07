"""Bearer-token guard for the UEBA service's API.

Every route answered anonymous requests, several for ANY tenant named in the request (anomalies, baselines, peer groups, scoring).
Callers send ``Authorization: Bearer <AISOC_UEBA_SERVICE_TOKEN>``. Fail closed: with no token configured only a development
environment runs open; anything else answers 503. ``AISOC_UEBA_ENVIRONMENT`` follows the stack-wide AISOC_ENVIRONMENT switch in
docker-compose.yml. Unset means a plain local run (development); set-but-empty is NOT development (a mistake must fail closed).
Read at call time so tests and redeploys can change it.
"""
from __future__ import annotations

import os
import secrets
from typing import Annotated

from fastapi import Header, HTTPException, status

_DEV_ENVIRONMENTS = frozenset({"development", "dev", "local", "test"})


def is_development() -> bool:
    raw = os.getenv("AISOC_UEBA_ENVIRONMENT")
    return ("development" if raw is None else raw).strip().lower() in _DEV_ENVIRONMENTS


async def require_service_token(authorization: Annotated[str | None, Header()] = None) -> None:
    token = (os.getenv("AISOC_UEBA_SERVICE_TOKEN") or "").strip()
    if not token:
        if is_development():
            return
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="ueba service auth is not configured")
    scheme, _, supplied = (authorization or "").partition(" ")
    supplied = supplied.strip()
    if scheme.lower() != "bearer" or not supplied or not secrets.compare_digest(supplied.encode(), token.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing service token", headers={"WWW-Authenticate": "Bearer"})
