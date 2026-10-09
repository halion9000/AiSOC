"""Web Push proxy for the mobile responder PWA.

The realtime service owns Web Push state (VAPID keys, the Redis-backed
subscription store, and the `web-push` send loop). The PWA, however, only
ever talks to a single origin: the API gateway. Routing browser push calls
through the gateway means the PWA never has to know that a separate
realtime service exists, simplifies CORS, and gives us a single place to
enforce auth and tenant isolation.

This module exposes four endpoints under ``/api/v1/push/*`` that mirror the
realtime service's ``/v1/push/*`` surface and forward authorized requests
to ``REALTIME_BASE_URL``. The gateway:

* Authenticates the caller as a SIGNED-IN USER (a JWT session) using ``SessionUser``, so unauthenticated PWAs cannot subscribe. A push subscription belongs to a
  person's device, so an API key is refused with 403 (it used to be accepted, acting as the key's owner).
* Stamps the realtime call with ``X-AiSOC-User-Id``, ``X-AiSOC-Tenant-Id``
  and ``X-AiSOC-Internal-Token`` so the realtime side can attribute
  subscriptions to a real user without re-doing JWT verification.
* Forwards the JSON body so we don't have to keep two schemas in sync, but with the IDENTITY fields taken from the verified session, never from the client: the realtime
  service prefers `body.user_id` over the verified `X-User-Id` header, so a body that named another user used to subscribe the caller's device to THAT person's notifications.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Body, HTTPException, status

from app.api.v1.deps import SessionUser
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/push", tags=["push"])

_HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


async def _proxy(
    method: str,
    path: str,
    *,
    user: SessionUser | None,
    json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Forward a request to the realtime push API and return its JSON body.

    Raises ``HTTPException`` on transport errors or non-2xx responses so
    the caller sees a consistent gateway-level error.
    """
    url = f"{settings.REALTIME_BASE_URL.rstrip('/')}{path}"
    headers: dict[str, str] = {"Accept": "application/json"}
    if settings.REALTIME_INTERNAL_TOKEN:
        headers["X-AiSOC-Internal-Token"] = settings.REALTIME_INTERNAL_TOKEN
    if user is not None:
        # Mirror what the realtime push module expects (x-tenant-id /
        # x-user-id headers). We also send the AiSOC-prefixed variants so
        # any future audit logging in the realtime side can attribute
        # without parsing email separately.
        headers["X-Tenant-Id"] = str(user.tenant_id)
        headers["X-User-Id"] = str(user.user_id)
        headers["X-AiSOC-User-Email"] = user.email

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            response = await client.request(method, url, headers=headers, json=json)
    except httpx.HTTPError as exc:
        logger.warning("realtime push proxy failed", extra={"path": path, "error": str(exc)})
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Realtime service unavailable for web push",
        ) from exc

    if response.status_code >= 400:
        try:
            payload = response.json()
        except ValueError:
            payload = {"detail": response.text or "realtime error"}
        raise HTTPException(status_code=response.status_code, detail=payload)

    if response.status_code == status.HTTP_204_NO_CONTENT or not response.content:
        return {}
    try:
        return response.json()
    except ValueError:
        return {"detail": response.text}


# Fields a client must never get to choose: realtime reads `user_id` (and trusts it over the header), and a tenant or a list of users has no business in a request about the caller's own device.
_IDENTITY_FIELDS = frozenset({"user_id", "userId", "user_ids", "tenant_id", "tenantId", "tenant"})


def _own_body(user: SessionUser, body: dict[str, Any] | None) -> dict[str, Any]:
    """The body to forward: the client's, minus every identity-shaped field, plus the caller's own user id from the verified session. The client's dict is not modified."""
    forwarded = {k: v for k, v in (body or {}).items() if k not in _IDENTITY_FIELDS}
    forwarded["user_id"] = str(user.user_id)
    return forwarded


@router.get("/public-key")
async def get_public_key() -> dict[str, Any]:
    """Return the VAPID public key the PWA needs to subscribe.

    Public on purpose: the key is an application-server identifier, not a
    secret. Keeping it unauthenticated lets the service worker fetch it on
    install before the user has logged in.
    """
    return await _proxy("GET", "/v1/push/public-key", user=None)


@router.post("/subscribe")
async def subscribe(
    user: SessionUser,
    body: Annotated[dict[str, Any], Body(...)],
) -> dict[str, Any]:
    """Register a PushSubscription for the authenticated user."""
    return await _proxy("POST", "/v1/push/subscribe", user=user, json=_own_body(user, body))


@router.post("/unsubscribe")
async def unsubscribe(
    user: SessionUser,
    body: Annotated[dict[str, Any], Body(...)],
) -> dict[str, Any]:
    """Remove a PushSubscription for the authenticated user."""
    return await _proxy("POST", "/v1/push/unsubscribe", user=user, json=_own_body(user, body))


@router.post("/test")
async def test_notify(
    user: SessionUser,
    body: Annotated[dict[str, Any] | None, Body()] = None,
) -> dict[str, Any]:
    """Send a test notification to the authenticated user's devices.

    Useful for the PWA settings screen "send test" button.
    """
    return await _proxy("POST", "/v1/push/test", user=user, json=_own_body(user, body))
