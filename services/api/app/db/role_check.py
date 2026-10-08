"""Tell the operator when the database role BYPASSES row-level security.

PostgreSQL superusers (and roles with BYPASSRLS) ignore every RLS policy. The default compose connects every service as `aisoc`, the bootstrap superuser, so in that setup RLS protects nothing and tenant isolation rests
entirely on the application's own `WHERE tenant_id = ...` filters. That is a legitimate thing to know, and nothing said it. This logs it once at startup.

It is best-effort: it never raises, never blocks startup, and does nothing against a non-PostgreSQL database. It reports a fact; it does not change behaviour.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import text

logger = structlog.get_logger()

_CONSEQUENCE = "PostgreSQL bypasses row-level security for this role, so tenant isolation relies entirely on application-level tenant filters. Connect as a non-superuser role (aisoc_app) to have RLS enforced."
_warned = False
_tasks: set[asyncio.Task] = set()  # keep a reference so a fire-and-forget task is not garbage collected mid-run


@dataclass(frozen=True)
class DbRole:
    name: str
    superuser: bool
    bypassrls: bool

    @property
    def bypasses_rls(self) -> bool:
        return self.superuser or self.bypassrls


async def check_db_role(engine: Any) -> DbRole | None:
    """Look up the connected role and log whether RLS applies to it. Returns None if it cannot be determined."""
    global _warned
    if getattr(getattr(engine, "dialect", None), "name", "") != "postgresql":
        return None
    try:
        async with engine.connect() as conn:
            row = (await conn.execute(text("SELECT current_user AS name, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"))).one()
    except Exception as exc:  # noqa: BLE001
        logger.debug("db.role_check_failed", error=type(exc).__name__)
        return None
    role = DbRole(name=str(row[0]), superuser=bool(row[1]), bypassrls=bool(row[2]))
    if role.bypasses_rls:
        if not _warned:
            _warned = True
            logger.warning("db.rls_bypassed", role=role.name, superuser=role.superuser, bypassrls=role.bypassrls, consequence=_CONSEQUENCE)
    else:
        logger.info("db.rls_enforced", role=role.name)
    return role


def schedule_role_check(engine: Any, *, timeout: float = 5.0) -> asyncio.Task:
    """Run the check in the background so a slow or unreachable database cannot delay startup."""

    async def _run() -> None:
        try:
            await asyncio.wait_for(check_db_role(engine), timeout)
        except Exception as exc:  # noqa: BLE001  (including the timeout)
            logger.debug("db.role_check_skipped", error=type(exc).__name__)

    task = asyncio.create_task(_run(), name="db_role_check")
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return task
