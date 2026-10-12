"""Tag a database session with its tenant, and keep that tenant in force across transactions (step 3 of docs/security/rls-fail-closed-plan.md).

WHY. `get_tenant_db` sets the tenant with `set_config('app.current_tenant_id', ..., true)` (SET LOCAL), which lasts for ONE transaction: after a handler's
`commit()` the next statement runs with no tenant. Today that does not matter, because the policies are fail-open (a session with no tenant sees every
row). It matters the moment they are fail-closed, and the plan measured it: flipping all 77 policies with nothing else failed 251 of 404 flow steps; the
same flip with this hook failed 0 of 435.

HOW. `tag_session(session, tenant_id)` stores the tenant in `session.info["rls_tenant_id"]`; the listener below runs on every transaction BEGIN of a
PostgreSQL connection and re-applies it. The scoping blocks in app/db/rls_scope.py already know this tag: `cross_tenant_reads` removes it for the length
of its block (so the listener cannot re-apply the tenant inside it) and `acting_as_tenant` replaces it, and both put it back.

FLAG. `AISOC_RLS_TAG_SESSIONS`, default OFF. With it off `tag_session` does nothing, no session ever carries a tag, and the (always installed)
listener finds none: behaviour is identical to before. Installing the listener unconditionally, and gating on the tag, means the flag can change
without re-registering anything.

SCOPE OF THIS CHANGE. Only sessions that pass through `get_current_user` (the plain `get_db` session of every authenticated route) and `get_tenant_db`
are tagged. Code that opens its own session, or has no signed-in user, is NOT tagged and still sees no tenant: the audit middleware, the workers
(oauth_refresh, weekly_digest, the hunt scheduler), login, SSO, signup and webhook ingestion. They need their own explicit mechanism before step 4
(see "Code paths with no signed-in user" in the plan).
"""

from __future__ import annotations

import uuid

from sqlalchemy import event, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.rls_scope import _is_postgresql

TAG = "rls_tenant_id"
SETTING = "app.current_tenant_id"


def tagging_enabled() -> bool:
    return bool(settings.AISOC_RLS_TAG_SESSIONS)


async def tag_session(session, tenant_id: uuid.UUID | str | None) -> None:
    """Tag `session` with the tenant its requests are for, if tagging is on. A no-op when the flag is off or there is no tenant.

    It is a coroutine because the tag alone is not enough: the listener only runs at the NEXT transaction BEGIN, and by the time a route's session is
    tagged it is usually already inside one (`get_current_user` authenticates on the session first). Measured: tagging without applying the tenant to
    that transaction left a handler's FIRST writes with no tenant (199 of 409 flow steps failed against fail-closed policies, where the same flip
    without the hook failed 251 of 404). So the tenant is applied to the transaction in progress as well.
    """
    if tenant_id is None or not tagging_enabled():
        return
    session.info[TAG] = str(tenant_id)
    in_transaction = getattr(session, "in_transaction", None)
    if callable(in_transaction) and in_transaction() and _is_postgresql(session):
        await session.execute(text(f"SELECT set_config('{SETTING}', :t, TRUE)"), {"t": str(tenant_id)})


def _after_begin(session: Session, transaction, connection) -> None:
    tag = session.info.get(TAG)
    if not tag or connection.dialect.name != "postgresql":
        return
    connection.execute(text(f"SELECT set_config('{SETTING}', :t, TRUE)"), {"t": tag})


def install() -> None:
    """Register the listener once for every ORM session (idempotent)."""
    if not event.contains(Session, "after_begin", _after_begin):
        event.listen(Session, "after_begin", _after_begin)


install()
