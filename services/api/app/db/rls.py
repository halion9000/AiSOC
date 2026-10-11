"""Row-Level Security (RLS) helpers for multi-tenant isolation.

Usage
-----
Replace ``get_db`` with ``get_tenant_db`` in endpoint signatures that require
tenant-scoped sessions:

    @router.get("/cases")
    async def list_cases(db: TenantDBSession, user: AuthUser):
        ...

The ``get_tenant_db`` dependency wraps ``get_db`` and issues:

    SET LOCAL app.current_tenant_id = '<uuid>';

inside the transaction, which is picked up by the Postgres RLS policies
defined in migrations/002_rls.sql.

For compatibility, ``get_current_user`` also exposes a helper
``set_rls_context(session, tenant_id)`` that can be called manually.
"""

from __future__ import annotations

import contextlib
import inspect
import uuid
from collections.abc import AsyncGenerator, AsyncIterator
from typing import Annotated

from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser, get_current_user
from app.db.database import AsyncSessionLocal


async def set_rls_context(session: AsyncSession, tenant_id: uuid.UUID) -> None:
    """Emit SET LOCAL to scope the session to a single tenant."""
    await session.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, TRUE)"),
        {"tid": str(tenant_id)},
    )


def _is_postgresql(session: AsyncSession) -> bool:
    """True only if the session is clearly bound to PostgreSQL; anything else (SQLite, a mock with a coroutine get_bind) is False."""
    try:
        bind = session.get_bind()
    except Exception:
        return False
    if inspect.iscoroutine(bind):  # an AsyncMock's method: never awaited, so close it to avoid a RuntimeWarning
        bind.close()
        return False
    return getattr(getattr(bind, "dialect", None), "name", None) == "postgresql"


@contextlib.asynccontextmanager
async def cross_tenant_reads(session: AsyncSession) -> AsyncIterator[None]:
    """Deliberately read rows of MORE THAN ONE tenant on this session, for the length of the block.

    Some reads are cross-tenant by design: an MSSP parent's rule packs are applied to its managed tenants, so resolving a child's
    effective rules reads rows the PARENT owns while the session
    belongs to the child (app/services/mssp_rule_resolver.py). Today that works only because a plain get_db session carries no tenant and
    the RLS policies are fail-open, so such a
    session sees every row. Measured on a real Postgres, tagging that session with the child's tenant makes the resolver return NOTHING
    for it (docs/security/rls-fail-closed-plan.md), so
    this makes the intent explicit and survives both changes the plan describes (tagging every session; fail-closed policies).

    Inside the block the tenant setting is cleared (an empty string is the same as unset for current_tenant_id()); a session tagged by the
    plan's hook is also untagged for the block, so the
    hook cannot re-apply the tenant at the next transaction. On exit the setting that was in force is put back, so a tenant-scoped session
    is never left wider than it was; if the block
    failed, only the tag is restored (the failed transaction is rolled back, which resets the setting anyway).

    The caller must still filter by tenant explicitly in its queries: this removes the policy's filter, it does not replace it. With
    fail-closed policies this will need a granted bypass,
    which is the plan's step 4; today it changes nothing for a session that already has no tenant set.
    """
    if not _is_postgresql(session):
        # Row-level security is a PostgreSQL feature: on any other database there is no tenant setting to clear
        # (the unit tests run the resolver on SQLite), so the block is a no-op. It is also a no-op for anything that
        # is not clearly a PostgreSQL session (a mock in a unit test), so it never consumes a scripted response.
        yield
        return
    previous = (await session.execute(text("SELECT current_setting('app.current_tenant_id', TRUE)"))).scalar_one_or_none()
    tag = session.info.pop("rls_tenant_id", None)
    await session.execute(text("SELECT set_config('app.current_tenant_id', '', TRUE)"))
    failed = False
    try:
        yield
    except BaseException:
        failed = True
        raise
    finally:
        if tag is not None:
            session.info["rls_tenant_id"] = tag
        if previous and not failed:
            await session.execute(text("SELECT set_config('app.current_tenant_id', :t, TRUE)"), {"t": previous})


async def get_tenant_db(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> AsyncGenerator[AsyncSession, None]:
    """DB session scoped to the authenticated user's tenant via Postgres RLS.

    Yields an ``AsyncSession`` where ``app.current_tenant_id`` is set to the
    current user's tenant UUID for the duration of the transaction.
    """
    async with AsyncSessionLocal() as session:
        try:
            await set_rls_context(session, current_user.tenant_id)
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# Convenience type alias — use this as the dependency type in route signatures
TenantDBSession = Annotated[AsyncSession, Depends(get_tenant_db)]
