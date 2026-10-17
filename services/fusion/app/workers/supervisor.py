"""Keep a long-running worker alive: restart it when it dies, with backoff."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable

import structlog

logger = structlog.get_logger()


async def supervise(
    start: Callable[[], Awaitable[None]],
    stop: Callable[[], Awaitable[None]],
    *,
    on_failure: Callable[[Exception], None],
    backoff: float = 1.0,
    max_backoff: float = 60.0,
) -> None:
    """Run ``start`` until it returns. If it raises, call ``on_failure`` (so readiness can drop), tear the worker down with ``stop``, wait, and start it again.

    A clean return ends supervision; cancellation passes through."""
    delay = backoff
    while True:
        try:
            await start()
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("worker_died_restarting", error=str(exc), retry_in=delay, exc_info=True)
            on_failure(exc)
            with contextlib.suppress(Exception):
                await stop()
            await asyncio.sleep(delay)
            delay = min(max(delay * 2, 0.0), max_backoff)
