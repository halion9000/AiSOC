"""Keeps "hide this alert type" rules true as alerts keep arriving: every minute it hides new alerts an active rule covers and lifts the rules that have run out (their alerts come back)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import structlog

from app.db.database import AsyncSessionLocal
from app.db.rls_sessions import mark_platform
from app.services.alert_suppression import sweep

logger = structlog.get_logger()

INTERVAL_SECONDS = 60


async def run_suppression_sweeper(*, sleep: Callable[[float], Any] = asyncio.sleep, session_factory: Callable[[], Any] = AsyncSessionLocal) -> None:
    """The long-running loop (started under the scheduler lock from the API lifespan). A failed pass never ends it; cancellation does."""
    await sleep(20)
    while True:
        try:
            async with session_factory() as session:
                mark_platform(session)  # the rules cover the owner's clients, so the pass reads across tenants
                done = await sweep(session)
                if done["hidden"] or done["expired"]:
                    logger.info("alert_suppression.sweep", **done)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("alert_suppression.sweeper_error", error=str(exc))
        await sleep(INTERVAL_SECONDS)
