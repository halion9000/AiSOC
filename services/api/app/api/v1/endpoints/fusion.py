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
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from urllib.parse import quote
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select

from app.api.v1.deps import AuthUser, require_permission
from app.core.internal_auth import fusion_service_headers
from app.core.logging import safe_log_value
from app.db.rls import TenantDBSession
from app.models.tenant import Tenant
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


async def _forward(
    method: str, path: str, *, params: dict[str, Any] | None = None, body: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    """Send a request to fusion if configured. Return None on a 5xx or a transport error."""
    if not _FUSION_URL:
        return None
    safe_path = _validate_proxy_path(path)
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=fusion_service_headers()) as client:
            if method == "POST":
                resp = await client.post(f"{_FUSION_URL}{safe_path}", json=body or {})
            else:
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


async def _proxy_get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Forward GET to fusion if configured. Return None on transport error."""
    return await _forward("GET", path, params=params)


async def _proxy_post(path: str, body: dict[str, Any]) -> dict[str, Any] | None:
    """Forward a POST with a JSON body to fusion if configured. Return None on transport error."""
    return await _forward("POST", path, body=body)


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

# Shown only when the fusion service cannot be reached. It must equal the fusion
# service's own default (rba_promotion_threshold in services/fusion/app/core/config.py,
# 80.0), which is what actually promotes an entity; the UI displays it as "promotion threshold".
_DEFAULT_THRESHOLD = 80.0


def _effective_tenant(tenant_id: UUID | None, user: AuthUser, clients: dict[str, str] | None = None) -> str:
    """The tenant this request is for. The fusion service trusts the tenant_id it is sent, so the check lives here.

    Omitted: the caller's own tenant (taken from their verified login, never from the request), so a client never has to know or guess it: the console used to send a BUILD-TIME constant here, which is 'default' (not even a UUID: a 422) on a standard build and some other tenant's id elsewhere (a 403).
    Naming one of the caller's own client tenants (an MSSP parent looking at a client it manages) is allowed; naming any other tenant needs platform:cross_tenant_query (app.services.tenant_selection)."""
    return resolve_requested_tenant(user, tenant_id, also_allowed=(clients or {}).keys())


_MAX_CLIENTS = 1000  # fusion's rollup routes take at most this many tenants in one call


async def _client_tenants(db: Any, own: Any) -> dict[str, str]:
    """The caller's client tenants (id -> name): the tenants whose parent is the caller's own. Empty for a tenant with no clients."""
    rows = (
        await db.execute(select(Tenant.id, Tenant.name).where(Tenant.parent_tenant_id == own).order_by(Tenant.name).limit(_MAX_CLIENTS))
    ).all()
    return {str(r[0]): r[1] for r in rows}


def _fix_z(value: Any) -> Any:
    """'...+00:00Z' -> '...Z'. Fusion once stacked an offset in front of the Z for a timezone-aware alert time; a browser reads that as an Invalid Date and the entity drawer crashed. Records already stored that way age out of Redis in a day."""
    if isinstance(value, str) and value.endswith("+00:00Z"):
        return value[: -len("+00:00Z")] + "Z"
    return value


RECENT_HOURS = 4  # the score's half-life: what was added since then is what is "heating up"


def _parse_at(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def trend_of(contributors: list[dict[str, Any]], now: datetime | None = None) -> dict[str, Any]:
    """How this entity's risk has moved lately, from its contributions (each has the points it added and when): the points and alerts added in the last four hours, and a label.

    ``new``: its first contribution is that recent; ``rising``: it picked up points that recently; ``fading``: nothing has been added for four hours, so its score is only decaying.
    With no dated contribution there is nothing to say, so the label is None rather than a guess."""
    moment = now or datetime.now(UTC)
    cutoff = moment - timedelta(hours=RECENT_HOURS)
    dated = [(at, float(c.get("points") or 0)) for c in contributors if isinstance(c, dict) and (at := _parse_at(c.get("at"))) is not None]
    if not dated:
        return {"recent_points": 0.0, "recent_alerts": 0, "trend": None}
    recent = [(at, pts) for at, pts in dated if at >= cutoff]
    label = "new" if min(at for at, _ in dated) >= cutoff else ("rising" if recent else "fading")
    return {"recent_points": round(sum(pts for _at, pts in recent), 2), "recent_alerts": len(recent), "trend": label}


def _shape_entity(rec: dict[str, Any], threshold: float, now: datetime | None = None) -> dict[str, Any]:
    """Give a fusion entity record the fields the console reads (display_score, threshold, promoted, first_seen, contributions, severity_histogram).

    The fusion service names them differently (score, promoted_at, contributors, severities), and the console read ``record.contributions.length`` and
    ``new Date(record.first_seen)``, so a real record would have broken the page. Only fields that are missing are added."""
    rec = {
        **rec,
        **{k: _fix_z(rec[k]) for k in ("last_seen", "promoted_at") if k in rec},
        "contributors": [{**c, "at": _fix_z(c.get("at"))} if isinstance(c, dict) else c for c in (rec.get("contributors") or [])],
    }
    contributors = [c for c in rec["contributors"] if isinstance(c, dict)]
    score = rec.get("score", 0) or 0
    shaped = {
        "display_score": round(score),
        "threshold": threshold,
        "promoted": bool(rec.get("promoted_at")),
        "promoted_incident_id": None,
        "first_seen": min((str(c["at"]) for c in contributors if c.get("at")), default=None) or rec.get("last_seen"),
        "contributions": [
            {
                "alert_id": c.get("alert_id"),
                "severity": c.get("severity"),
                "raw_points": c.get("points", 0),
                "observed_at": c.get("at"),
                "title": c.get("detection"),
                "source": None,
            }
            for c in reversed(contributors)
        ],
        "severity_histogram": rec.get("severities") or {},
        **trend_of(contributors, now),
    }
    return {**shaped, **rec}


def _shape_stats(st: dict[str, Any]) -> dict[str, Any]:
    """The console reads total / promoted / bands; fusion calls them tracked_entities / promoted_entities / score_bands."""
    return {
        "total": st.get("tracked_entities", 0),
        "promoted": st.get("promoted_entities", 0),
        "bands": st.get("score_bands", {"critical": 0, "high": 0, "medium": 0, "low": 0}),
        **st,
    }


def order_entities(entities: list[dict[str, Any]], sort: str) -> list[dict[str, Any]]:
    """``score``: as fusion ranked them. ``recent``: most points added lately first, ties by score."""
    if sort != "recent":
        return entities
    return sorted(entities, key=lambda e: (-(e.get("recent_points") or 0), -(e.get("score") or 0)))


@router.get("/entity-risk/queue", summary="Top entities by risk score")
async def entity_risk_queue(
    user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: TenantDBSession,
    tenant_id: UUID | None = None,
    limit: int = Query(default=25, ge=1, le=200),
    promoted_only: bool = False,
    sort: Literal["score", "recent"] = "score",
) -> dict[str, Any]:
    """``sort=recent`` orders the entities that are in the top ``limit`` by score by what they picked up in the last four hours (those heating up first), then by score."""
    clients = await _client_tenants(db, user.tenant_id)
    tenant = _effective_tenant(tenant_id, user, clients)
    # A parent that did not name a tenant sees its own entities and its clients' together (each row says which client): alerts for a mapped client are scored under that client's
    # tenant, so reading only the parent's would show nothing for them.
    scope = [tenant, *clients] if tenant_id is None and clients else [tenant]
    if len(scope) == 1:
        one = await _proxy_get(
            "/entity-risk/queue", params={"tenant_id": tenant, "limit": limit, "promoted_only": str(promoted_only).lower()}
        )
        if one is not None:
            threshold = one.get("threshold", _DEFAULT_THRESHOLD)
            return {**one, "entities": order_entities([_shape_entity(e, threshold) for e in one.get("entities", [])], sort)}
    else:
        # One call for the whole fleet: fusion merges the tenants and applies the limit once, instead of this gateway asking once per client.
        rolled = await _proxy_post("/entity-risk/rollup/queue", {"tenant_ids": scope, "limit": limit, "promoted_only": promoted_only})
        if rolled is not None:
            threshold = rolled.get("threshold", _DEFAULT_THRESHOLD)
            return {
                "tenant_id": tenant,
                "threshold": threshold,
                "entities": order_entities(
                    [
                        _shape_entity({**e, "client_name": clients.get(str(e.get("tenant_id")))}, threshold)
                        for e in rolled.get("entities", [])
                    ],
                    sort,
                ),
                "rolled_up": True,
            }
    return {
        "tenant_id": tenant,
        "threshold": _DEFAULT_THRESHOLD,
        "entities": [],
    }


@router.get("/entity-risk/stats", summary="Entity-risk queue stats")
async def entity_risk_stats(
    user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: TenantDBSession,
    tenant_id: UUID | None = None,
) -> dict[str, Any]:
    clients = await _client_tenants(db, user.tenant_id)
    tenant = _effective_tenant(tenant_id, user, clients)
    scope = [tenant, *clients] if tenant_id is None and clients else [tenant]
    if len(scope) == 1:
        one = await _proxy_get("/entity-risk/stats", params={"tenant_id": tenant})
        if one is not None:
            return _shape_stats(one)
    else:
        rolled = await _proxy_post("/entity-risk/rollup/stats", {"tenant_ids": scope, "limit": 1})
        if rolled is not None:
            return _shape_stats({**rolled, "tenant_id": tenant, "rolled_up": True})
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
    db: TenantDBSession,
    tenant_id: UUID | None = None,
) -> dict[str, Any]:
    tenant = _effective_tenant(tenant_id, user, await _client_tenants(db, user.tenant_id))
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
        return _shape_entity(upstream, _DEFAULT_THRESHOLD)
    # No fallback record exists when fusion is offline; surface 404 so the
    # drawer renders its empty state.
    raise HTTPException(status_code=404, detail="entity_not_found")
