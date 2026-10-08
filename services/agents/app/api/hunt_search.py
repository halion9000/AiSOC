"""
Hunt search & saved-searches API.

The console's threat-hunter view posts ad-hoc queries here and saves/retrieves
search bookmarks. This is *distinct* from the hunt-corpus YAML runner
(``hunts.py``); this module handles free-form telemetry search.

Endpoints (under ``/api/v1/hunt``):

    POST /search          — execute a hunt query against telemetry
    GET  /saved           — list saved searches for the current tenant
    POST /saved           — save a new search
    DELETE /saved/{id}    — delete a saved search
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
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


class SavedSearchCreate(BaseModel):
    name: str
    query: str
    language: str = "lucene"


class SavedSearch(BaseModel):
    id: str
    name: str
    query: str
    language: str
    createdAt: str
    pinned: bool = False


# ---------------------------------------------------------------------------
# In-memory store (demo; production would persist to Postgres)
# ---------------------------------------------------------------------------

_SAVED_SEARCHES: dict[str, SavedSearch] = {}


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


@router.get("/saved")
async def list_saved_searches() -> dict[str, list[dict[str, Any]]]:
    """Return all saved searches."""
    return {"searches": [s.model_dump() for s in _SAVED_SEARCHES.values()]}


@router.post("/saved", response_model=SavedSearch, status_code=201)
async def save_search(data: SavedSearchCreate) -> SavedSearch:
    """Persist a new saved search."""
    ss = SavedSearch(
        id=str(uuid.uuid4()),
        name=data.name,
        query=data.query,
        language=data.language,
        createdAt=datetime.now(UTC).isoformat(),
    )
    _SAVED_SEARCHES[ss.id] = ss
    return ss


@router.delete("/saved/{search_id}", status_code=204, response_model=None)
async def delete_saved_search(search_id: str) -> None:
    """Delete a saved search by ID."""
    if search_id not in _SAVED_SEARCHES:
        raise HTTPException(status_code=404, detail="saved search not found")
    del _SAVED_SEARCHES[search_id]
