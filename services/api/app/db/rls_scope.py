"""Scoping blocks for row-level security: read or write as another tenant, explicitly, and put the scope back.

They live apart from app/db/rls.py because that module imports app.api.v1.deps (for get_tenant_db), and deps imports
app/services/view_as.py, which needs these blocks: importing them from
rls.py was a circular import. app/db/rls.py re-exports them, so `from app.db.rls import cross_tenant_reads` keeps working. The reasoning
and the measurements are in
docs/security/rls-fail-closed-plan.md.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import uuid
from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


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
async def _rescoped(session: AsyncSession, setting: str, tag: str | None, *, switch_off: bool = False) -> AsyncIterator[None]:
    """Run a block with the session's tenant setting (and its tag) changed, then put both back. The shared body of the two public blocks
    below.

    Two things about the unit of work make this more than a SET: (1) `session.add()` only QUEUES a write, and SQLAlchemy sends it at the
    next query or commit, so pending writes made under the
    OLD scope are flushed before the scope changes (otherwise they would be sent under the new one), and writes made inside the block are
    flushed before it ends (otherwise they would be sent
    under the restored scope and be rejected by the policy); (2) it is a no-op for anything that is not clearly a PostgreSQL session
    (SQLite, a mock), so it never sends SQL there and never
    consumes a scripted response.
    """
    if not _is_postgresql(session):
        yield
        return
    await session.flush()
    previous = (await session.execute(text("SELECT current_setting('app.current_tenant_id', TRUE)"))).scalar_one_or_none()
    previous_switch = (
        (await session.execute(text("SELECT current_setting('app.rls_fail_closed', TRUE)"))).scalar_one_or_none() if switch_off else None
    )
    old_tag = session.info.pop("rls_tenant_id", None)
    if tag is not None:
        session.info["rls_tenant_id"] = tag
    await session.execute(text("SELECT set_config('app.current_tenant_id', :t, TRUE)"), {"t": setting} if setting else {"t": ""})
    if (
        switch_off
    ):  # the granted bypass: for this block a session with no tenant sees every row even when fail-closed is switched on (migration 081)
        await session.execute(text("SELECT set_config('app.rls_fail_closed', 'off', TRUE)"))
    outcome = "ok"
    try:
        yield
    except Exception:
        outcome = "error"
        raise
    except BaseException:  # cancellation and the like: awaiting in `finally` is not safe, so nothing is sent
        outcome = "abort"
        raise
    finally:
        session.info.pop("rls_tenant_id", None)
        if old_tag is not None:
            session.info["rls_tenant_id"] = old_tag
        if outcome != "abort":
            try:
                if outcome == "ok":
                    await session.flush()
                restore = previous or ""
                if restore != setting:
                    await session.execute(text("SELECT set_config('app.current_tenant_id', :t, TRUE)"), {"t": restore})
                if switch_off:
                    await session.execute(text("SELECT set_config('app.rls_fail_closed', :v, TRUE)"), {"v": previous_switch or ""})
            except Exception:
                # After an ordinary error the restore is best-effort: if the transaction is aborted the statement raises, and the rollback
                # resets the setting anyway.
                # After success a failure here is real and propagates. Never flush after an error: the pending writes may be the reason it
                # failed.
                if outcome == "ok":
                    raise


@contextlib.asynccontextmanager
async def cross_tenant_reads(session: AsyncSession) -> AsyncIterator[None]:
    """Deliberately READ rows of more than one tenant on this session, for the length of the block.

    Some reads are cross-tenant by design: an MSSP parent's rule packs are applied to its managed tenants, so resolving a child's
    effective rules reads rows the PARENT owns while the session
    belongs to the child (app/services/mssp_rule_resolver.py). Today that works only because a plain get_db session carries no tenant and
    the RLS policies are fail-open, so such a session sees
    every row. Measured on a real Postgres, tagging that session with the child's tenant makes the resolver return NOTHING for it
    (docs/security/rls-fail-closed-plan.md), so this makes the
    intent explicit and survives both changes the plan describes (tagging every session; fail-closed policies).

    Inside the block the tenant setting is cleared (an empty string is the same as unset for current_tenant_id()); a session tagged by the
    plan's hook is also untagged for the block, so the hook
    cannot re-apply the tenant at the next transaction. On exit the setting that was in force is put back, so a tenant-scoped session is
    never left wider than it was.

    For READS only: the caller must still filter by tenant explicitly in its queries (this removes the policy's filter, it does not
    replace it), and a write inside the block is not what this
    is for (use acting_as_tenant). With fail-closed policies this will need a granted bypass (the plan's step 4); today it changes nothing
    for a session that already has no tenant set.
    """
    async with _rescoped(session, "", None, switch_off=True):
        yield


@contextlib.asynccontextmanager
async def acting_as_tenant(session: AsyncSession, tenant_id: uuid.UUID) -> AsyncIterator[None]:
    """READ and WRITE as another tenant for the length of the block: the tenant setting AND the session tag become `tenant_id`, then both
    are put back.

    For the few places that legitimately write into a tenant that is not the session's own, the clearest being "view another tenant"
    (app/services/view_as.py): the `tenant:viewed` event goes
    into the VIEWED tenant's audit log. Measured on a real Postgres as the restricted role, with the real emit_audit: with no tenant set
    it works; with the session tagged with the viewer's HOME
    tenant the insert is rejected ("new row violates row-level security policy"), because neither the audit_log nor the grants policy has
    a WITH CHECK, so Postgres applies the USING expression
    to writes too; and the chain read (`_resolve_prev_hash`) returns None, which reads as "genesis" and would silently FORK the target's
    audit hash chain if only the insert were let through.
    So the read of the chain head and the insert must share ONE scope, and that is what this gives them.

    Writes queued inside the block are flushed before it ends (see _rescoped), so they are sent under the target's scope. Use it around
    the whole unit (read the chain head, add the row), not
    around part of it.
    """
    async with _rescoped(session, str(tenant_id), str(tenant_id)):
        yield


def acting_as_argument(name: str, *, session: str = "db"):
    """Decorator: run the wrapped coroutine in `acting_as_tenant(<its argument `name`>)`, using its argument `session` (default "db") as
    the session.

    For a handler whose path names the tenant it acts on, and which may legitimately act on a tenant that is not the caller's own: a
    platform holder on any tenant, an MSP parent on its children
    (app/api/v1/endpoints/tenants.py, access management: it reads and writes the TARGET tenant's access grants and writes an audit event
    into the TARGET's log).

    The scope is applied around the whole handler, after FastAPI has authenticated the caller and checked the permission the route
    declares. The handler's own check that the caller may manage
    that tenant runs inside the block; nothing it reads before that check is covered by a tenant policy (the tenants table has none), so
    the scope exposes nothing that check protects.
    `functools.wraps` keeps the signature, so FastAPI still sees the route's parameters and dependencies (checked against the generated
    OpenAPI).
    """

    def decorate(fn):
        signature = inspect.signature(fn)

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            bound = signature.bind(*args, **kwargs).arguments
            async with acting_as_tenant(bound[session], uuid.UUID(str(bound[name]))):
                return await fn(*args, **kwargs)

        return wrapper

    return decorate
