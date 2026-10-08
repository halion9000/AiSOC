"""Saved hunt SEARCHES (raw query bookmarks on the /hunt page): GET/POST /hunt/saved, DELETE /hunt/saved/{id}.

These used to be served by the AGENTS service from one module-level dict: lost on every restart and NOT tenant-scoped, so every tenant's saved queries (hostnames, usernames, IOCs) were listed to anyone.
The web console reached that service through a Next.js rewrite that bypasses the API, so no tenant identity existed on the path. They live here now: persisted, tenant-scoped (RLS plus an explicit tenant
filter) and permission-checked. Shared across a tenant's analysts, like saved hunts. The response shape is unchanged so the web client needs no change beyond the route.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.saved_hunt_search import SavedHuntSearch

logger = structlog.get_logger()

router = APIRouter(prefix="/hunt/saved", tags=["hunt"])

LANGUAGES = ("lucene", "kql", "sql", "esql", "spl")
MAX_PER_TENANT = 500  # a bookmark list, not a data store: bound it so one tenant cannot grow it without limit


class SavedSearchCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    query: str = Field(..., min_length=1, max_length=8000)
    language: str = "lucene"


class SavedSearchOut(BaseModel):
    id: str
    name: str
    query: str
    language: str
    createdAt: str
    pinned: bool = False


def _out(row: SavedHuntSearch) -> SavedSearchOut:
    return SavedSearchOut(id=str(row.id), name=row.name, query=row.query, language=row.language, createdAt=row.created_at.isoformat(), pinned=bool(row.pinned))


def _coerce_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


@router.get("", dependencies=[Depends(require_permission("lake:query"))])
async def list_saved_searches(user: AuthUser, db: TenantDBSession) -> dict[str, list[SavedSearchOut]]:
    """The caller's tenant's saved searches, newest first."""
    rows = (await db.execute(select(SavedHuntSearch).where(SavedHuntSearch.tenant_id == user.tenant_id).order_by(SavedHuntSearch.created_at.desc()).limit(MAX_PER_TENANT))).scalars().all()
    return {"searches": [_out(r) for r in rows]}


@router.post("", response_model=SavedSearchOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("lake:query"))])
async def save_search(data: SavedSearchCreate, user: AuthUser, db: TenantDBSession) -> SavedSearchOut:
    """Save a search for the caller's tenant."""
    name, query = data.name.strip(), data.query.strip()
    if not name or not query:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="name and query must not be blank")
    if data.language not in LANGUAGES:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"language must be one of {', '.join(LANGUAGES)}")
    existing = (await db.execute(select(func.count()).select_from(SavedHuntSearch).where(SavedHuntSearch.tenant_id == user.tenant_id))).scalar_one()
    if existing >= MAX_PER_TENANT:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"This tenant already has {MAX_PER_TENANT} saved searches; delete some before saving more")
    now = datetime.now(UTC)
    row = SavedHuntSearch(id=uuid.uuid4(), tenant_id=user.tenant_id, created_by=user.user_id, name=name, query=query, language=data.language, pinned=False, created_at=now, updated_at=now)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    logger.info("hunt.saved_search.create", tenant_id=str(user.tenant_id), search_id=str(row.id))
    return _out(row)


@router.delete("/{search_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None, dependencies=[Depends(require_permission("lake:query"))])
async def delete_saved_search(search_id: str, user: AuthUser, db: TenantDBSession) -> None:
    """Delete one of the caller's tenant's saved searches. Another tenant's id is a 404, exactly like an id that does not exist."""
    sid = _coerce_uuid(search_id)
    if sid is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="saved search not found")
    result = await db.execute(delete(SavedHuntSearch).where(SavedHuntSearch.id == sid, SavedHuntSearch.tenant_id == user.tenant_id))
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="saved search not found")
    logger.info("hunt.saved_search.delete", tenant_id=str(user.tenant_id), search_id=str(sid))
