"""
Hunt search API.

The console's threat-hunter view posts ad-hoc queries here. This is *distinct* from the hunt-corpus YAML runner (``hunts.py``); this module handles free-form telemetry search.

Endpoints (under ``/api/v1/hunt``):
    POST /search          - execute a hunt query against telemetry

Saved searches (``/api/v1/hunt/saved``) are NOT served here any more. They were one module-level dict in this service: lost on every restart and not tenant-scoped (the docstring said "for the
current tenant", the code never looked at a tenant), so every tenant's saved queries were listed to anyone. They live in the core API (services/api ... hunt_saved_searches.py), persisted and tenant-scoped,
and the web console's Next.js rewrite sends ``/api/v1/hunt/saved*`` there.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/hunt", tags=["hunt-search"])


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


class HuntQuery(BaseModel):
    query: str
    language: str = "lucene"  # lucene | eql | sigma | spl
    timeRange: str | None = "24h"
    indices: list[str] | None = None
    limit: int = 100


class HuntHit(BaseModel):
    id: str
    timestamp: str
    source: str
    event_type: str
    raw: dict[str, Any]
    highlights: list[str] | None = None


class HuntResponse(BaseModel):
    query: str
    total: int
    took_ms: int
    hits: list[HuntHit]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/search", response_model=HuntResponse)
async def hunt_search(query: HuntQuery) -> HuntResponse:
    """Execute a hunt query against telemetry.

    No event store is connected to this endpoint yet (the federated search work it waits on has not landed), so it cannot return results and says so.
    It used to return invented events for EVERY query, unconditionally: a ``cmd.exe /c <your query>`` process on "WS-DEV-01", a sign-in for
    ``user@corp.example``, an AWS ``AssumeRole`` on an ``Admin`` role. A hunter could not tell them from real telemetry.
    """
    raise HTTPException(
        status_code=501,
        detail="Hunt search is not connected to an event store yet, so it cannot return results.",
    )
