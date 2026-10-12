"""Sessions for code that has no signed-in user (step 4b of docs/security/rls-fail-closed-plan.md).

A request's session is tagged by `get_current_user` / `get_tenant_db` (step 3). Everything that opens its OWN session (the workers, the background jobs, the audit
middleware) has no such tag, and with fail-closed policies (migration 081, switch on) a session with no tenant sees NOTHING. There are only two honest ways
for such code to work, and this module is both of them, explicit and greppable:

  * `tenant_session(tenant_id)`: the code is working FOR one tenant (a per-tenant digest, a scan job, the audit write for a request it knows the tenant of).
    The session is tagged with that tenant, so it sees only that tenant's rows and, because the step-3 listener re-applies the tag at every transaction
    BEGIN, it still does after a `commit()`.
  * `platform_session()`: the code legitimately works ACROSS tenants (oauth_refresh, the retention sweeper, the hunt scheduler's selection of due hunts). The
    session keeps the fail-closed switch OFF for its transactions (the same listener), so it behaves exactly as a tenant-less session does today. This is a
    GRANTED BYPASS in application code, not a database boundary: any session may set a custom setting (see migration 081), so it is defence in depth against
    application bugs, not against SQL injection. Every use is a place a reviewer can read.

Both are opt-in by call site and independent of the AISOC_RLS_TAG_SESSIONS flag, because the code that calls them says what it is doing. With the switch off
(today's default) a platform session sees what a tenant-less session saw before; a tenant session sees only its tenant, which is what its queries filter for.

`factory=` exists so a test can bind the helpers to a particular database; production code passes nothing.
"""

from __future__ import annotations

import contextlib
import uuid
from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import AsyncSessionLocal
from app.db.rls_hook import SETTING, TAG, TAG_PLATFORM
from app.db.rls_scope import _is_postgresql


def mark_tenant(session, tenant_id: uuid.UUID | str) -> None:
    """Tag a session somebody else opened (an injected factory, a test) with the tenant it works for. Takes effect at the next transaction BEGIN."""
    info = getattr(session, "info", None)
    if info is not None:
        info.pop(TAG_PLATFORM, None)
        info[TAG] = str(tenant_id)


def mark_platform(session) -> None:
    """Mark a session somebody else opened as a platform (cross-tenant) session. Takes effect at the next transaction BEGIN."""
    info = getattr(session, "info", None)
    if info is not None:
        info.pop(TAG, None)
        info[TAG_PLATFORM] = True


async def adopt_tenant(session, tenant_id: uuid.UUID | str) -> None:
    """Make `session` work FOR `tenant_id` from now on: in the transaction in progress AND in every later one.

    For code that learns its tenant only by looking something up with no tenant yet: an ITSM webhook's token, an OAuth `state`, a passkey's owner. That first lookup
    is an explicit `cross_tenant_reads` block; the moment the tenant is known and the caller has decided to trust it (the token was valid, the state matched), call
    this, and everything after is tenant-scoped like an authenticated request. Marking alone is not enough, because the tag only takes effect at the NEXT transaction
    BEGIN and a lookup has already begun one (the same lesson as `rls_hook.tag_session`).
    """
    mark_tenant(session, tenant_id)
    in_transaction = getattr(session, "in_transaction", None)
    if callable(in_transaction) and in_transaction() and _is_postgresql(session):
        await session.execute(text(f"SELECT set_config('{SETTING}', :t, TRUE)"), {"t": str(tenant_id)})


@contextlib.asynccontextmanager
async def tenant_session(tenant_id: uuid.UUID | str, *, factory=None) -> AsyncIterator[AsyncSession]:
    """A session for work done FOR one tenant. The caller commits; nothing here does."""
    async with (factory or AsyncSessionLocal)() as session:
        mark_tenant(session, tenant_id)
        yield session


@contextlib.asynccontextmanager
async def platform_session(*, factory=None) -> AsyncIterator[AsyncSession]:
    """A session for work that spans tenants, with the fail-closed switch off for its transactions. The caller commits; nothing here does."""
    async with (factory or AsyncSessionLocal)() as session:
        mark_platform(session)
        yield session
