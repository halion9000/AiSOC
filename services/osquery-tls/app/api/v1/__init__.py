"""API v1 router for the osquery TLS service."""

from fastapi import APIRouter, Depends

from app.api.v1.endpoints import (
    config,
    distributed_enqueue,
    distributed_read,
    distributed_status,
    distributed_write,
    enroll,
    fim,
    log,
    packs,
)
from app.core.security import require_api_token

router = APIRouter(prefix="/api/v1/osquery")
router.include_router(enroll.router)
router.include_router(config.router)
router.include_router(log.router)
router.include_router(distributed_read.router)
router.include_router(distributed_write.router)
# INTERNAL routes: queue a query on a host, read its results, manage tenant packs, read FIM events.
# They need the bearer token (see require_api_token); the agent-facing routes above do not.
_internal = [Depends(require_api_token)]
router.include_router(distributed_enqueue.router, dependencies=_internal)
router.include_router(distributed_status.router, dependencies=_internal)
router.include_router(packs.router, dependencies=_internal)
router.include_router(fim.router, dependencies=_internal)
