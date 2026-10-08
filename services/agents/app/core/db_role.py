"""Tell the operator when the database role BYPASSES row-level security.

PostgreSQL superusers (and roles with BYPASSRLS) ignore every RLS policy. The default compose connects every service as `aisoc`, the bootstrap superuser, so in that setup RLS protects nothing and tenant isolation rests
entirely on the application's own `WHERE tenant_id = ...` filters. That is a legitimate thing to know, and nothing said it. This logs it once at startup.

It is best-effort: it never raises, never blocks startup, and does nothing against a non-PostgreSQL database. It reports a fact; it does not change behaviour.
"""

from __future__ import annotations

import asyncpg
import structlog

logger = structlog.get_logger()

_CONSEQUENCE = "PostgreSQL bypasses row-level security for this role, so tenant isolation relies entirely on application-level tenant filters. Connect as a non-superuser role (aisoc_app) to have RLS enforced."
_warned = False


async def warn_if_rls_bypassed(pool: asyncpg.Pool) -> bool | None:
    """True if the connected role bypasses RLS, False if it does not, None if that cannot be determined."""
    global _warned
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT current_user AS name, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
    except Exception as exc:  # noqa: BLE001
        logger.debug("db.role_check_failed", error=type(exc).__name__)
        return None
    if row is None:
        return None
    name, superuser, bypassrls = str(row["name"]), bool(row["rolsuper"]), bool(row["rolbypassrls"])
    if superuser or bypassrls:
        if not _warned:
            _warned = True
            logger.warning("db.rls_bypassed", role=name, superuser=superuser, bypassrls=bypassrls, consequence=_CONSEQUENCE)
        return True
    logger.info("db.rls_enforced", role=name)
    return False
