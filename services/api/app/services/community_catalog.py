"""Database-backed store for the community catalog (replaces three in-memory dictionaries that were lost on every restart).

Entries are plain dicts, exactly what the endpoints already built, so the handlers keep their logic: get() returns a COPY, the handler changes it, and save() writes it back.

Read-modify-write paths (install counts, ratings, curation) must call get(..., lock=True): it takes SELECT ... FOR UPDATE, so two concurrent installs cannot both read the same count and
lose one increment, a race the in-memory dictionaries could not have. (SQLite, used in unit tests, has no row locks and ignores it.) Do not hold the lock across a slow network call:
read without it, make the call, then re-read with it to apply the change.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.community_catalog import CommunityCatalogItem


class ItemExists(Exception):
    """An item with this id already exists in this kind: submissions never overwrite an existing entry."""


def _jsonable(entry: dict[str, Any]) -> dict[str, Any]:
    """The entry as plain JSON types (UUIDs, enums and datetimes become strings)."""
    return json.loads(json.dumps(entry, default=str))


def _is_duplicate(exc: IntegrityError) -> bool:
    """True only for a UNIQUE / primary-key violation. An IntegrityError can also be a foreign-key or check violation, which is a different fault and must not be reported as "already exists"."""
    orig = exc.orig
    code = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None) or getattr(getattr(orig, "__cause__", None), "sqlstate", None)
    if code:
        return code == "23505"  # Postgres unique_violation
    return "unique constraint failed" in str(orig).lower()  # SQLite


def _status_of(entry: dict[str, Any]) -> str:
    status = entry["status"]
    return str(getattr(status, "value", status))


class CatalogStore:
    def __init__(self, kind: str) -> None:
        self.kind = kind

    def _select(self, item_id: str | None = None):
        stmt = select(CommunityCatalogItem).where(CommunityCatalogItem.kind == self.kind)
        return stmt if item_id is None else stmt.where(CommunityCatalogItem.item_id == item_id)

    async def get(self, db: AsyncSession, item_id: str, *, lock: bool = False) -> dict[str, Any] | None:
        stmt = self._select(item_id)
        if lock:
            # populate_existing: if this session already loaded the row (e.g. a read before a slow call), a plain locking SELECT would hand back that STALE cached copy and a
            # concurrent change made in between would be lost. Refresh it from the row we now hold the lock on.
            stmt = stmt.with_for_update().execution_options(populate_existing=True)
        row = (await db.execute(stmt)).scalar_one_or_none()
        return None if row is None else dict(row.data)

    async def list(self, db: AsyncSession) -> list[dict[str, Any]]:
        rows = (await db.execute(self._select().order_by(CommunityCatalogItem.created_at, CommunityCatalogItem.item_id))).scalars().all()
        return [dict(r.data) for r in rows]

    async def create(self, db: AsyncSession, item_id: str, entry: dict[str, Any], *, submitter_tenant_id: uuid.UUID | None = None) -> None:
        db.add(CommunityCatalogItem(kind=self.kind, item_id=item_id, status=_status_of(entry), submitter_tenant_id=submitter_tenant_id, data=_jsonable(entry)))
        try:
            await db.commit()
        except IntegrityError as exc:
            await db.rollback()
            if _is_duplicate(exc):
                raise ItemExists(item_id) from exc
            raise  # any other integrity fault (e.g. the submitting tenant does not exist) is not a duplicate id

    async def save(self, db: AsyncSession, item_id: str, entry: dict[str, Any], *, commit: bool = True) -> None:
        row = await db.get(CommunityCatalogItem, (self.kind, item_id))  # already in the session from get(), so no second SELECT
        if row is None:
            raise KeyError(item_id)
        row.data = _jsonable(entry)
        row.status = _status_of(entry)
        row.updated_at = datetime.now(UTC)
        if commit:
            await db.commit()
