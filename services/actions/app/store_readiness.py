"""Readiness of the action store: is the database reachable AND has migration 055 been applied?

The actions service accepts actions only if it can store them durably. If it were reported ready without that, a deploy that started the new image before the migration ran (or without DATABASE_URL)
would fail every response action at request time with a bare 500, during whatever incident prompted them. Instead /readyz stays 503, so the deploy visibly fails its healthcheck, and a watcher flips it to
ready as soon as the store answers (no restart needed once the migration is applied).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import structlog
from sqlalchemy import text

from app.db import get_session_factory

logger = structlog.get_logger(__name__)

# Seconds between re-checks while the store is not ready (a module constant so tests can shorten it).
RECHECK_INTERVAL_SECONDS = 5.0


async def check_action_store() -> tuple[bool, str]:
    """(ready, reason). Ready only when DATABASE_URL is set and the response_actions table can be queried."""
    factory = get_session_factory()
    if factory is None:
        return False, "DATABASE_URL is not configured"
    try:
        async with factory() as session:
            await session.execute(text("SELECT 1 FROM response_actions LIMIT 0"))
    except Exception as exc:  # unreachable database, missing table (migration 055 not applied), bad credentials...
        return False, f"{type(exc).__name__}: {str(exc).splitlines()[0][:160] if str(exc) else ''}"
    return True, "ok"


async def mark_ready_when_store_answers(mark_ready: Callable[[], None]) -> None:
    """Re-check until the store answers, then mark the service ready."""
    while True:
        await asyncio.sleep(RECHECK_INTERVAL_SECONDS)
        ready, reason = await check_action_store()
        if ready:
            logger.info("actions.store_ready")
            mark_ready()
            return
        logger.warning("actions.store_not_ready", reason=reason)
