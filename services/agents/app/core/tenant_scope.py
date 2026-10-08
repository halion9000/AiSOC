"""Run database work as ONE tenant, so Postgres row-level security actually applies.

The policies read the setting `app.current_tenant_id` (through current_tenant_id()), and a setting applied with set_config(..., true) lasts only until the end of the CURRENT TRANSACTION. Four modules in this service did neither:
they set `app.tenant_id` (a name no standard policy reads) with a bare `conn.execute`, i.e. in autocommit mode, where the setting is discarded as soon as that statement finishes. So the context was never in effect on any of those
paths, and (because every standard policy also admits "no context") RLS silently admitted everything; the only protection was each query's own `WHERE tenant_id = ...`.

    async with pool.acquire() as conn:
        async with tenant_scope(conn, tenant_id):
            await conn.execute(...)   # runs inside one transaction, scoped to tenant_id

Deliberately NOT a session-level setting: on a pooled connection that would leave one tenant's context on the connection for the NEXT borrower.
Note RLS only constrains a NON-superuser role; the default compose connects as the bootstrap superuser, for which it is bypassed regardless (the explicit tenant filters are what protect those deployments).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import asyncpg

RLS_SETTING = "app.current_tenant_id"


@asynccontextmanager
async def tenant_scope(conn: asyncpg.Connection, tenant_id: uuid.UUID | str) -> AsyncIterator[asyncpg.Connection]:
    async with conn.transaction():
        await conn.execute(f"SELECT set_config('{RLS_SETTING}', $1, true)", str(tenant_id))
        yield conn
