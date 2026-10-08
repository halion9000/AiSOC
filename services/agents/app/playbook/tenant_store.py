"""Tenant-owned playbooks, stored in Postgres (table tenant_playbooks, created by services/api/migrations/059_tenant_playbooks.sql).

Playbooks are a shared, read-only library (the shipped fixtures and packs, served by PlaybookStore) plus each tenant's own playbooks, which are here. A tenant creates one from scratch or CLONES a library playbook to
customise it. This repository never touches the library and the library is never writable through the API.

Every operation runs in its own transaction with the tenant's RLS context set INSIDE it (the setting is transaction-local), and every query ALSO filters on tenant_id: two independent layers.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

import asyncpg

from app.investigator import ledger
from app.playbook.models import Playbook

MAX_PER_TENANT = 200  # a library of custom playbooks, not a data store
IMMUTABLE_FIELDS = frozenset({"id", "cloned_from", "created_at", "scope", "editable"})


class PlaybookStoreUnavailable(Exception):
    """No database is configured, so tenant playbooks cannot be stored (the shared library still works)."""


class PlaybookLimitReached(Exception):
    pass


class PlaybookRepo(Protocol):
    async def list(self, tenant_id: UUID, *, enabled_only: bool = False) -> list[Playbook]: ...
    async def get(self, tenant_id: UUID, playbook_id: str) -> Playbook | None: ...
    async def create(self, tenant_id: UUID, playbook: Playbook, *, created_by: UUID | None = None) -> Playbook: ...
    async def update(self, tenant_id: UUID, playbook_id: str, data: dict[str, Any]) -> Playbook | None: ...
    async def delete(self, tenant_id: UUID, playbook_id: str) -> bool: ...


def _to_playbook(row: asyncpg.Record) -> Playbook:
    definition = row["definition"]
    definition = json.loads(definition) if isinstance(definition, str) else dict(definition)
    return Playbook.model_validate({**definition, "id": row["id"], "name": row["name"], "enabled": row["enabled"], "cloned_from": row["cloned_from"]})


class PostgresPlaybookRepo:
    """The production repository."""

    async def _pool(self) -> asyncpg.Pool:
        pool = await ledger.get_pool()
        if pool is None:
            raise PlaybookStoreUnavailable("DATABASE_URL is not configured")
        return pool

    @staticmethod
    async def _scope(conn: asyncpg.Connection, tenant_id: UUID) -> None:
        await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(tenant_id))

    async def list(self, tenant_id: UUID, *, enabled_only: bool = False) -> list[Playbook]:
        pool = await self._pool()
        async with pool.acquire() as conn, conn.transaction():
            await self._scope(conn, tenant_id)
            rows = await conn.fetch(
                "SELECT id, name, enabled, cloned_from, definition FROM tenant_playbooks WHERE tenant_id = $1 AND ($2::boolean IS FALSE OR enabled) ORDER BY created_at DESC LIMIT $3",
                tenant_id, enabled_only, MAX_PER_TENANT,
            )
        return [_to_playbook(r) for r in rows]

    async def get(self, tenant_id: UUID, playbook_id: str) -> Playbook | None:
        pool = await self._pool()
        async with pool.acquire() as conn, conn.transaction():
            await self._scope(conn, tenant_id)
            row = await conn.fetchrow("SELECT id, name, enabled, cloned_from, definition FROM tenant_playbooks WHERE tenant_id = $1 AND id = $2", tenant_id, playbook_id)
        return None if row is None else _to_playbook(row)

    async def create(self, tenant_id: UUID, playbook: Playbook, *, created_by: UUID | None = None) -> Playbook:
        now = datetime.now(UTC).isoformat()
        stored = playbook.model_copy(update={"id": str(uuid.uuid4()), "created_at": now, "updated_at": now})
        pool = await self._pool()
        async with pool.acquire() as conn, conn.transaction():
            await self._scope(conn, tenant_id)
            # Serialise creates for THIS tenant so the cap is exact: count-then-insert would otherwise let concurrent creates overshoot it. (Released automatically at the end of the transaction.)
            await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", f"tenant_playbooks:{tenant_id}")
            count = await conn.fetchval("SELECT count(*) FROM tenant_playbooks WHERE tenant_id = $1", tenant_id)
            if count >= MAX_PER_TENANT:
                raise PlaybookLimitReached(f"This tenant already has {MAX_PER_TENANT} custom playbooks; delete some before adding more")
            await conn.execute(
                "INSERT INTO tenant_playbooks (tenant_id, id, name, enabled, cloned_from, created_by, definition) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)",
                tenant_id, stored.id, stored.name, stored.enabled, stored.cloned_from, created_by, json.dumps(stored.model_dump(mode="json")),
            )
        return stored

    async def update(self, tenant_id: UUID, playbook_id: str, data: dict[str, Any]) -> Playbook | None:
        pool = await self._pool()
        async with pool.acquire() as conn, conn.transaction():
            await self._scope(conn, tenant_id)
            row = await conn.fetchrow(
                "SELECT id, name, enabled, cloned_from, definition FROM tenant_playbooks WHERE tenant_id = $1 AND id = $2 FOR UPDATE", tenant_id, playbook_id
            )
            if row is None:
                return None
            current = _to_playbook(row)
            changes = {k: v for k, v in data.items() if k not in IMMUTABLE_FIELDS}
            merged = Playbook.model_validate({**current.model_dump(mode="json"), **changes, "id": current.id, "cloned_from": current.cloned_from, "updated_at": datetime.now(UTC).isoformat()})
            await conn.execute(
                "UPDATE tenant_playbooks SET name = $3, enabled = $4, definition = $5::jsonb, updated_at = now() WHERE tenant_id = $1 AND id = $2",
                tenant_id, playbook_id, merged.name, merged.enabled, json.dumps(merged.model_dump(mode="json")),
            )
        return merged

    async def delete(self, tenant_id: UUID, playbook_id: str) -> bool:
        pool = await self._pool()
        async with pool.acquire() as conn, conn.transaction():
            await self._scope(conn, tenant_id)
            result = await conn.execute("DELETE FROM tenant_playbooks WHERE tenant_id = $1 AND id = $2", tenant_id, playbook_id)
        return result.endswith(" 1")


_default: PostgresPlaybookRepo | None = None


def get_playbook_repo() -> PlaybookRepo:
    """FastAPI dependency (overridden in tests)."""
    global _default
    if _default is None:
        _default = PostgresPlaybookRepo()
    return _default
