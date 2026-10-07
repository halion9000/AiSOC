"""Bearer-token guard for the purple-team service's API.

Every route answered anonymous requests, including atomics/run and caldera/run, which LAUNCH adversary simulations.
Callers send ``Authorization: Bearer <AISOC_PURPLE_TEAM_SERVICE_TOKEN>``. There is no development mode: with no token configured every route answers 503, and CORE generates the token on every build, so a properly set
up stack always has one. Read at call time so tests and redeploys can change it.
"""
from __future__ import annotations

import os
import secrets
from typing import Annotated

from fastapi import Header, HTTPException, status


async def require_service_token(authorization: Annotated[str | None, Header()] = None) -> None:
    token = (os.getenv("AISOC_PURPLE_TEAM_SERVICE_TOKEN") or "").strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="purple-team service auth is not configured")
    scheme, _, supplied = (authorization or "").partition(" ")
    supplied = supplied.strip()
    if scheme.lower() != "bearer" or not supplied or not secrets.compare_digest(supplied.encode(), token.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing service token", headers={"WWW-Authenticate": "Bearer"})
