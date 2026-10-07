"""Bearer-token guard for the fusion service's API.

Every route except health and metrics required nothing, and several take a caller-supplied ``tenant_id``, so anything able to
reach the service could read any tenant's entity-risk queue, submit feedback, trigger a retrain or run correlation. Callers
(the agents service's ``/process`` call, the API gateway) now send ``Authorization: Bearer <AISOC_FUSION_SERVICE_TOKEN>``.

Fail closed: with no token configured only a development environment runs open; anything else answers 503. Read at call
time so tests and redeploys can change it. ``/health`` stays open (Docker's healthcheck has no token) as does ``/metrics``
(scraped by Prometheus).
"""
from __future__ import annotations

import os
import secrets
from typing import Annotated

from fastapi import Header, HTTPException, status

from app.core.config import settings

_DEV_ENVIRONMENTS = frozenset({"development", "dev", "local", "test"})


def is_development() -> bool:
    return str(settings.environment).strip().lower() in _DEV_ENVIRONMENTS


async def require_service_token(authorization: Annotated[str | None, Header()] = None) -> None:
    token = (os.getenv("AISOC_FUSION_SERVICE_TOKEN") or "").strip()
    if not token:
        if is_development():
            return
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="fusion service auth is not configured")
    scheme, _, supplied = (authorization or "").partition(" ")
    supplied = supplied.strip()
    if scheme.lower() != "bearer" or not supplied or not secrets.compare_digest(supplied.encode(), token.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing service token", headers={"WWW-Authenticate": "Bearer"})
