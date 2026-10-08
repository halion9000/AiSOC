"""Who is calling, as established by AUTHENTICATION, never by what the request body claims.

The agents service used to take the tenant from a `tenant_id` field in the request body (default "default"): any caller could name any tenant, and the service would act for it: load that tenant's stored
LLM credential (so a caller could spend another tenant's API key), run work under it, and read its runs back. The web console reaches this service through rewrites that bypass the API, so the body was the only
tenant signal there was.

ServiceAuthMiddleware (app/core/service_auth.py) now records who an allowed request came from in `request.state.caller`:
  * kind "user": a login or API key. The tenant is what the API reported for that credential. It ALWAYS wins over the body.
  * kind "internal": the API's own proxy (it already authenticated and authorised the user and names the tenant); the body is trusted, as before.
  * no caller at all: the middleware is not enforcing (development); the body is used, as before.
A logged-in caller whose tenant could not be determined is REFUSED (403), never defaulted: guessing a tenant for an authenticated caller is exactly the bug.
"""

from __future__ import annotations

import structlog
from fastapi import HTTPException, Request, WebSocket, status

logger = structlog.get_logger()


def authenticated_tenant(source: Request | WebSocket) -> str | None:
    """The tenant of an authenticated end user / API key, or None when the caller is internal or nothing is enforcing (development)."""
    caller = getattr(getattr(source, "state", None), "caller", None)
    if not caller or caller.get("kind") != "user":
        return None
    tenant = caller.get("tenant_id")
    if not tenant:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Your tenant could not be determined, so this request was refused.")
    return str(tenant)


def resolve_tenant(claimed: str | None, authenticated: str | None) -> str:
    """The tenant to act for. An authenticated caller's own tenant wins; a different one named in the body is ignored and logged."""
    if authenticated is None:
        return claimed or "default"
    if claimed not in (None, "", "default", authenticated):
        logger.warning("agents.tenant_override", claimed=str(claimed), authenticated=authenticated)
    return authenticated


def visible_run(run: dict | None, source: Request | WebSocket, detail: str = "Run not found") -> dict:
    """The run, if it exists AND belongs to the authenticated caller's tenant; otherwise the SAME 404 as "no such run", so a probing caller learns nothing about other tenants' runs.
    (Runs used to be returned to whoever knew the id: they were stored without a tenant and no read route checked one.) Internal and development callers are not scoped, as before."""
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    authenticated = authenticated_tenant(source)
    if authenticated is not None and str(run.get("tenant_id")) != authenticated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    return run
