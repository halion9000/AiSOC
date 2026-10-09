"""
Pillar-2 Playbook proxy endpoints.

The api service acts as a gateway that forwards playbook CRUD and run
requests to the agents service.  This keeps the public API contract in
one place while the engine lives in services/agents.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, status, Depends
from app.core.internal_auth import internal_service_headers
from app.api.v1.deps import AuthUser, require_permission

_AGENTS_URL = os.getenv("AGENTS_SERVICE_URL") or os.getenv("AGENTS_API_URL", "http://agents:8084")

router = APIRouter(prefix="/playbooks", tags=["playbooks"])

# Allowlist for playbook/run IDs: UUIDs or short slug-style alphanumeric IDs.
# Prevents partial-SSRF via path traversal in proxied requests.
_SAFE_ID_RE = re.compile(r"^[0-9a-zA-Z_\-]{1,128}$")


def _validate_path_id(value: str, name: str = "id") -> str:
    """Validate that *value* is a safe ID and return it to break the taint flow.

    Raising HTTPException here prevents any tainted data from reaching _proxy.
    Returning the validated string (rather than void) lets callers use the
    return value in path construction, which CodeQL recognises as untainted.
    """
    if not _SAFE_ID_RE.match(value):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid {name} format",
        )
    # Return a new string built from the match to break the taint chain.
    return _SAFE_ID_RE.match(value).group(0)  # type: ignore[union-attr]


async def _proxy(method: str, path: str, **kwargs) -> Any:
    """Forward a request to the agents service and return the JSON body."""
    url = f"{_AGENTS_URL}/api/v1/playbooks{path}"
    try:
        headers = {**internal_service_headers(), **(kwargs.pop("headers", None) or {})}
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.request(method, url, headers=headers, **kwargs)
        if r.status_code >= 400:
            # A 4xx is the agents service explaining a refusal to the CALLER ("Shared library playbooks are read-only. Clone it...", "Playbook not found", a validation error): pass that through.
            # A 5xx stays generic: it is about our own plumbing.
            detail: Any = "Upstream service error"
            if r.status_code < 500:
                try:
                    upstream = r.json().get("detail")
                    detail = upstream if upstream else detail
                except (ValueError, AttributeError):
                    pass
            raise HTTPException(status_code=r.status_code, detail=detail)
        if r.status_code == 204:
            return None
        try:
            return r.json()
        except ValueError as exc:
            # A 2xx whose body is not JSON (a misbehaving upstream, or a proxy answering for it) used to escape as an unhandled JSONDecodeError, i.e. an HTTP 500 with a stack trace.
            raise HTTPException(status_code=502, detail="Agents service returned an invalid response") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail="Agents service unavailable") from exc


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


@router.get("", summary="List playbooks", dependencies=[Depends(require_permission("playbooks:read"))])
async def list_playbooks(user: AuthUser, enabled_only: bool = False):
    return await _proxy("GET", "", params={"enabled_only": enabled_only, "tenant_id": str(user.tenant_id)})


async def _json_body(request: Request) -> dict:
    """The request body as a JSON object. An EMPTY body is {} (the agents service then says what is missing); a malformed one is a 400 and a non-object a 422.

    Three handlers called `await request.json()` bare, so an empty or malformed body was an unhandled JSONDecodeError (HTTP 500 with a stack trace) found by sending a POST with no body. None of these reach the agents service."""
    raw = await request.body()
    if not raw.strip():
        return {}
    try:
        body = json.loads(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="Request body must be a JSON object")
    return body


@router.post("", summary="Create playbook", status_code=201, dependencies=[Depends(require_permission("playbooks:write"))])
async def create_playbook(request: Request, user: AuthUser):
    body = await _json_body(request)
    return await _proxy("POST", "", json=body, params={"tenant_id": str(user.tenant_id)})


@router.get("/runs", summary="List playbook runs", dependencies=[Depends(require_permission("playbooks:read"))])
async def list_runs(user: AuthUser, limit: int = 50):
    return await _proxy("GET", "/runs", params={"limit": limit, "tenant_id": str(user.tenant_id)})


@router.get("/runs/{run_id}", summary="Get a playbook run", dependencies=[Depends(require_permission("playbooks:read"))])
async def get_run(run_id: str, user: AuthUser):
    safe_run_id = _validate_path_id(run_id, "run_id")
    return await _proxy("GET", f"/runs/{safe_run_id}", params={"tenant_id": str(user.tenant_id)})


@router.get("/{playbook_id}", summary="Get a playbook", dependencies=[Depends(require_permission("playbooks:read"))])
async def get_playbook(playbook_id: str, user: AuthUser):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    return await _proxy("GET", f"/{safe_id}", params={"tenant_id": str(user.tenant_id)})


@router.put("/{playbook_id}", summary="Update a playbook", dependencies=[Depends(require_permission("playbooks:write"))])
async def update_playbook(playbook_id: str, request: Request, user: AuthUser):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    body = await _json_body(request)
    return await _proxy("PUT", f"/{safe_id}", json=body, params={"tenant_id": str(user.tenant_id)})


@router.delete("/{playbook_id}", summary="Delete a playbook", status_code=204, response_model=None, dependencies=[Depends(require_permission("playbooks:write"))])
async def delete_playbook(playbook_id: str, user: AuthUser):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    await _proxy("DELETE", f"/{safe_id}", params={"tenant_id": str(user.tenant_id)})


@router.post("/{playbook_id}/run", summary="Execute a playbook", status_code=202, dependencies=[Depends(require_permission("playbooks:execute"))])
async def run_playbook(playbook_id: str, request: Request, user: AuthUser):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    body = await _json_body(request)
    return await _proxy("POST", f"/{safe_id}/run", json=body, params={"tenant_id": str(user.tenant_id)})


@router.post("/{playbook_id}/clone", summary="Clone a shared library (or own) playbook into your tenant to customise it", status_code=201, dependencies=[Depends(require_permission("playbooks:write"))])
async def clone_playbook(playbook_id: str, request: Request, user: AuthUser):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    try:
        body = await _json_body(request)
    except HTTPException:
        body = {}  # a clone needs no body: an unreadable one is treated as none (unchanged behaviour)
    return await _proxy("POST", f"/{safe_id}/clone", json=body, params={"tenant_id": str(user.tenant_id)})
