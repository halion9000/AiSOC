"""Authenticated gateway to the osquery service's FIM (file integrity monitoring) data.

Why this exists. The console read FIM events straight from the osquery service through a Next.js
rewrite. That could never have worked (the rewrite pointed at localhost inside the web container, at the
wrong port, the service answered with `items/offset/limit` where the console expects `events/page/page_size`,
and the console's `node_key` / `since` filters and `active_nodes` field did not exist), and it was unsafe:
the service performed NO authentication and trusted a caller-supplied `tenant_id`, so anyone able to reach it
could read any tenant's file-change history.

Now the console calls the API, which requires a login and `alerts:read`, decides WHICH tenant may be read,
and calls the service with the internal bearer token (AISOC_OSQUERY_TLS_API_TOKEN). The browser never talks to
the osquery service. The caller's own credentials are not forwarded.

Tenants. The osquery service keeps tenants as free-form strings: agents that send no `X-AiSOC-Tenant` header
are recorded under "default". The API's tenants are UUIDs. A caller may read:
  - their own tenant's UUID, and
  - "default" ONLY if their tenant is the install's default tenant (the one the production setup creates), which
    is where a single-tenant install's agents land,
  - anything, if they are a platform admin.
Anything else is a 403. The `tenant_id` the console sends is a request, never trusted.
"""
import os
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, require_permission
from app.services.tenant_selection import resolve_requested_tenant
from app.api.v1.dev_auth import DEMO_TENANT_ID

router = APIRouter(prefix="/osquery/fim", tags=["osquery"])

OSQUERY_DEFAULT_TENANT = "default"


def allowed_tenants(user: Any) -> set[str]:
    allowed = {str(user.tenant_id)}
    if str(user.tenant_id) == str(DEMO_TENANT_ID):
        allowed.add(OSQUERY_DEFAULT_TENANT)
    return allowed


def resolve_tenant(user: Any, requested: str | None) -> str:
    """Which osquery tenant string this caller may read. Never trusts the request."""
    requested = (requested or "").strip()
    if not requested:
        return str(user.tenant_id)
    return resolve_requested_tenant(user, requested, also_allowed=allowed_tenants(user))


def _base_url() -> str:
    url = (os.getenv("OSQUERY_TLS_URL") or "").strip().rstrip("/")
    if not url:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="osquery service is not configured")
    return url


async def _get(path: str, params: dict[str, Any]) -> dict[str, Any]:
    headers: dict[str, str] = {}
    token = (os.getenv("AISOC_OSQUERY_TLS_API_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"  # the INTERNAL token, never the caller's credentials
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{_base_url()}/api/v1/osquery/fim{path}", params=params, headers=headers)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="osquery service unavailable") from exc
    if resp.status_code != 200:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="osquery service error")
    try:
        body = resp.json()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="osquery service returned an invalid response") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="osquery service returned an invalid response")
    return body


class FimEventsPage(BaseModel):
    """The console's FimEventsPage (apps/web/src/lib/osquery-api.ts)."""

    events: list[dict[str, Any]]
    total: int
    page: int
    page_size: int


class FimSummaryOut(BaseModel):
    """The console's FimSummary."""

    total_events: int
    by_action: list[dict[str, Any]] = Field(default_factory=list)
    top_paths: list[dict[str, Any]] = Field(default_factory=list)
    active_nodes: int


@router.get("/events", response_model=FimEventsPage, dependencies=[Depends(require_permission("alerts:read"))])
async def fim_events(
    current_user: AuthUser,
    tenant_id: str | None = Query(None, max_length=128),
    page: int = Query(1, ge=1, le=100000),
    page_size: int = Query(25, ge=1, le=200),
    action: str | None = Query(None, max_length=32),
    path_prefix: str | None = Query(None, max_length=1024),
    node_key: str | None = Query(None, max_length=128),
    since: str | None = Query(None, max_length=64, description="ISO-8601"),
) -> FimEventsPage:
    tenant = resolve_tenant(current_user, tenant_id)
    params: dict[str, Any] = {"tenant_id": tenant, "limit": page_size, "offset": (page - 1) * page_size}
    for name, value in (("action", action), ("path_prefix", path_prefix), ("node_key", node_key), ("since", since)):
        if value:
            params[name] = value
    body = await _get("/events", params)
    items = body.get("items")
    if not isinstance(items, list) or not isinstance(body.get("total"), int):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="osquery service returned an unexpected response")
    return FimEventsPage(events=items, total=body["total"], page=page, page_size=page_size)


@router.get("/summary", response_model=FimSummaryOut, dependencies=[Depends(require_permission("alerts:read"))])
async def fim_summary(
    current_user: AuthUser,
    tenant_id: str | None = Query(None, max_length=128),
    since: str | None = Query(None, max_length=64, description="ISO-8601"),
) -> FimSummaryOut:
    params: dict[str, Any] = {"tenant_id": resolve_tenant(current_user, tenant_id)}
    if since:
        params["since"] = since
    body = await _get("/summary", params)
    if not isinstance(body.get("total_events"), int) or not isinstance(body.get("active_nodes"), int):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="osquery service returned an unexpected response")
    return FimSummaryOut(
        total_events=body["total_events"],
        by_action=list(body.get("by_action") or []),
        top_paths=list(body.get("top_paths") or []),
        active_nodes=body["active_nodes"],
    )
