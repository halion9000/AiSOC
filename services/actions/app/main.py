"""
AiSOC Action Execution Service entry point.

Wires the legacy ``ActionType``-keyed router and the new ``(vendor_id,
capability)``-keyed live-actions router under ``/api/v1``. The two
layers coexist by design: the legacy router still backs the established
human-in-the-loop UI (approvals, blast-radius gates, ChatOps callbacks),
while the live-actions router exposes the generic interface that the
agent loop and plugin SDK consume.

Builtin executor adapters are registered at import time via FastAPI's
startup hook so they're available before the first request lands. We
use the startup hook (rather than module-level execution) so that test
fixtures can reset the registry between tests with
``app.live_actions.reset_for_tests()`` and re-trigger registration
without restarting the process.
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI

import asyncio

from app._health import install_health_routes
from app.api.live_actions_router import router as live_actions_router
from app.api.router import router as legacy_router
from app.db import dispose_engine
from app.live_actions import register_builtin_executors
from app.db_role import warn_if_rls_bypassed
from app.store_readiness import check_action_store, mark_ready_when_store_answers

logger = structlog.get_logger(__name__)

app = FastAPI(
    title="AiSOC Action Execution Service",
    description=(
        "Blast-radius gated response action execution with human-in-the-loop "
        "approvals (legacy router) and the generic (vendor_id, capability) "
        "live-actions interface used by the agent loop and plugin SDK."
    ),
    version="0.2.0",
)

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
# /readyz flips to 200 once the builtin executor registration is
# complete (in the startup hook below).
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-actions")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready

app.include_router(legacy_router, prefix="/api/v1")
app.include_router(live_actions_router, prefix="/api/v1")


@app.on_event("startup")
async def _register_builtin_live_actions() -> None:
    """Register in-tree adapters with the live-action registry on boot.

    ``overwrite=True`` so a hot-reload (uvicorn --reload) doesn't crash
    on duplicate-registration errors. The registry's normal default of
    ``overwrite=False`` still protects plugins from clobbering each
    other.
    """
    count = register_builtin_executors(overwrite=True)
    logger.info("live_actions.bootstrap_complete", builtin_count=count)
    # Phase 2.6 — the registry is now populated. Ready ALSO requires the action store: without a reachable database and migration 055 the service cannot accept actions, so /readyz stays 503
    # (the deploy visibly fails its healthcheck) and a watcher flips it on as soon as the store answers.
    ready, reason = await check_action_store()
    if ready:
        app.state.mark_ready()
        await warn_if_rls_bypassed()  # a fact worth logging once; best-effort, never raises
    else:
        logger.error("actions.store_not_ready", reason=reason, hint="set DATABASE_URL and apply migration 055 (services/api/migrations/055_response_actions.sql); /readyz stays 503 until the store answers")
        app.state.store_watch = asyncio.create_task(mark_ready_when_store_answers(app.state.mark_ready))


@app.on_event("shutdown")
async def _drain_readyz() -> None:
    """Phase 2.6 — drain /readyz at the start of shutdown so the
    orchestrator stops sending new requests while in-flight ones
    finish.
    """
    app.state.mark_not_ready()
    watch = getattr(app.state, "store_watch", None)
    if watch is not None:
        watch.cancel()
    await dispose_engine()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "aisoc-actions"}
