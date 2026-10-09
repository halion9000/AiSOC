"""
Fusion gateway / fallback for /api/v1/fusion/*.

The fusion microservice (services/fusion) owns Risk-Based Alerting (RBA) —
entity rollups, decayed risk scoring, and ML-assisted ranking. In a full
deployment the web tier proxies /api/v1/fusion/* directly to that service
(see apps/web/next.config.js → FUSION_HOST). When the fusion service is
not deployed (e.g. the demo Fly.io stack), the web rewrite still hits the
core API service via the catch-all, so we expose a thin gateway here that:

  1. Forwards to the upstream fusion service if FUSION_URL is set in the
     api environment, preserving full functionality.
  2. Otherwise returns graceful empty payloads so the console renders an
     empty queue instead of a 500.

Endpoint surface mirrors services/fusion/app/api/router.py:
    GET  /api/v1/fusion/health
    GET  /api/v1/fusion/metrics
    GET  /api/v1/fusion/entity-risk/queue
    GET  /api/v1/fusion/entity-risk/stats
    GET  /api/v1/fusion/entity-risk/{entity_type}/{entity_value}
    GET  /api/v1/fusion/ml/status
"""

from __future__ import annotations

import logging
import os
import re
from typing import Annotated, Any
from urllib.parse import quote
from uuid import UUID

import httpx
from fastapi import APIRouter, HTTPException, Query, Depends

from app.api.v1.deps import AuthUser, require_permission
from app.core.internal_auth import fusion_service_headers
from app.core.logging import safe_log_value
from app.services.tenant_selection import resolve_requested_tenant


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/fusion", tags=["fusion"])

# When set, requests are forwarded to the live fusion service. When unset,
# the gateway returns deterministic, empty fallbacks so the UI degrades
# gracefully instead of bubbling 5xx into the analyst console.
_FUSION_URL = (os.getenv("FUSION_SERVICE_URL") or os.getenv("FUSION_URL") or "").rstrip("/")

# Tight allowlist for proxied request paths. We only ever proxy to a fixed
# upstream (`_FUSION_URL`) on a known set of routes, so the path must be a
# pure relative path with no scheme, host, control characters, or traversal
# sequences. This neutralises partial-SSRF (an attacker cannot redirect the
# request elsewhere) and log-injection (the path can never contain CR/LF).
_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./%]*$")


def _validate_proxy_path(path: str) -> str:
    """Reject any proxied path that isn't a tightly constrained relative path."""
    if (
        not isinstance(path, str) or not _SAFE_PATH_RE.match(path) or ".." in path or path.startswith("//")  # protocol-relative URL
    ):
        raise HTTPException(status_code=400, detail="invalid_request_path")
    return path


async def _proxy_get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Forward GET to fusion if configured. Return None on transport error."""
    if not _FUSION_URL:
        return None
    safe_path = _validate_proxy_path(path)
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=fusion_service_headers()) as client:
            resp = await client.get(f"{_FUSION_URL}{safe_path}", params=params or {})
        if resp.status_code >= 500:
            logger.warning(
                "fusion.upstream_error",
                extra={
                    "status_code": resp.status_code,
                    "path": safe_log_value(safe_path),
                },
            )
            return None
        if resp.status_code == 404:
            # Let caller surface 404 cleanly.
            raise HTTPException(status_code=404, detail="not_found")
        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        return resp.json()
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        logger.warning(
            "fusion.unreachable",
            extra={"err": safe_log_value(str(exc))},
        )
        return None


# ─── Health / metrics ──────────────────────────────────────────────────────


@router.get("/health", summary="Fusion service health", dependencies=[Depends(require_permission("alerts:read"))])
async def fusion_health() -> dict[str, Any]:
    upstream = await _proxy_get("/health")
    if upstream is not None:
        return upstream
    return {
        "status": "stub",
        "service": "aisoc-fusion-gateway",
        "upstream_configured": bool(_FUSION_URL),
    }


@router.get("/metrics", summary="Fusion worker metrics", dependencies=[Depends(require_permission("settings:read"))])
async def fusion_metrics() -> dict[str, Any]:
    upstream = await _proxy_get("/metrics")
    if upstream is not None:
        return upstream
    return {"status": "stub", "metrics": {}}


# ─── ML status ─────────────────────────────────────────────────────────────


@router.get("/ml/status", summary="Fusion ML model status", dependencies=[Depends(require_permission("alerts:read"))])
async def ml_status() -> dict[str, Any]:
    upstream = await _proxy_get("/ml/status")
    if upstream is not None:
        return upstream
    return {
        "status": "stub",
        "model_version": None,
        "trained_at": None,
        "training_samples": 0,
        "feedback_count": 0,
    }


# ─── Entity risk (RBA) ─────────────────────────────────────────────────────

# The threshold here mirrors services/fusion/app/services/entity_risk.py
# default; the UI displays it as "promotion threshold".
_DEFAULT_THRESHOLD = 100.0



def _effective_tenant(tenant_id: UUID | None, user: "AuthUser") -> str:
    """The tenant this request is for. The fusion service trusts the tenant_id it is sent, so the check lives here.

    Omitted: the caller's own tenant (taken from their verified login, never from the request), so a client never has to know or guess it: the console used to send a BUILD-TIME constant here, which is 'default' (not even a UUID: a 422) on a standard build and some other tenant's id elsewhere (a 403).
    Naming a tenant other than your own needs platform:cross_tenant_query (app.services.tenant_selection)."""
    return resolve_requested_tenant(user, tenant_id)


@router.get("/entity-risk/queue", summary="Top entities by risk score")
async def entity_risk_queue(
    user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    tenant_id: UUID | None = None,
    limit: int = Query(default=25, ge=1, le=200),
    promoted_only: bool = False,
) -> dict[str, Any]:
    tenant = _effective_tenant(tenant_id, user)
    upstream = await _proxy_get(
        "/entity-risk/queue",
        params={
            "tenant_id": tenant,
            "limit": limit,
            "promoted_only": str(promoted_only).lower(),
        },
    )
    if upstream is not None:
        return upstream
    return {
        "tenant_id": tenant,
        "threshold": _DEFAULT_THRESHOLD,
        "entities": [],
    }


@router.get("/entity-risk/stats", summary="Entity-risk queue stats")
async def entity_risk_stats(
    user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    tenant_id: UUID | None = None,
) -> dict[str, Any]:
    tenant = _effective_tenant(tenant_id, user)
    upstream = await _proxy_get(
        "/entity-risk/stats",
        params={"tenant_id": tenant},
    )
    if upstream is not None:
        return upstream
    return {
        "tenant_id": tenant,
        "threshold": _DEFAULT_THRESHOLD,
        "total": 0,
        "promoted": 0,
        "bands": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "alerts_total": 0,
    }


@router.get(
    "/entity-risk/{entity_type}/{entity_value}",
    summary="Entity risk record detail",
)
async def entity_risk_detail(
    entity_type: str,
    entity_value: str,
    user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    tenant_id: UUID | None = None,
) -> dict[str, Any]:
    tenant = _effective_tenant(tenant_id, user)
    if entity_type == "ip":
        entity_type = "src_ip"
    # URL-encode user-controlled path segments so they cannot inject `/`,
    # `?`, `#`, or other URL syntax into the proxied path.
    safe_type = quote(entity_type, safe="")
    safe_value = quote(entity_value, safe="")
    upstream = await _proxy_get(
        f"/entity-risk/{safe_type}/{safe_value}",
        params={"tenant_id": tenant},
    )
    if upstream is not None:
        return upstream
    # No fallback record exists when fusion is offline; surface 404 so the
    # drawer renders its empty state.
    raise HTTPException(status_code=404, detail="entity_not_found")
