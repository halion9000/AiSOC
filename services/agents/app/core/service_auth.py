"""Authentication for the agents service, enforced in production only.

Before this, the agents service authenticated nobody. In production the API
requires a login, yet the web console routes playbooks, hunts, investigations,
copilot and contextual actions straight to this service, so all of it stayed
usable without logging in.

In production every request (HTTP and WebSocket) must be one of:
  * an internal service call: header ``x-internal-token`` equal to this
    service's INTERNAL_TOKEN (the API's proxies send it; compose wires the
    same secret as the API's REALTIME_INTERNAL_TOKEN), or
  * a user/API-key call: ``Authorization: Bearer ...`` that the API accepts.
    Verified by asking the API itself (GET /api/v1/auth/me), so logins and API
    keys keep a single source of truth. Positive answers are cached briefly.
Health and metrics paths stay open for Docker's healthchecks. If the API cannot
be reached the request fails CLOSED (503). Development is unchanged: no checks.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time

import httpx
from starlette.responses import JSONResponse

from app.core.cors import _is_production_environment

OPEN_PATHS = frozenset({"/livez", "/readyz", "/healthz", "/health", "/metrics"})
CACHE_TTL_SECONDS = 30.0
_CACHE_MAX = 1024
_verified: dict[str, float] = {}  # sha256(Authorization header) -> expiry (monotonic)


def _internal_token() -> str:
    return os.getenv("INTERNAL_TOKEN", "").strip()


def _api_url() -> str:
    return os.getenv("API_URL", "http://api:8000").rstrip("/")


def clear_cache() -> None:
    _verified.clear()


async def bearer_is_valid(authorization: str) -> bool | None:
    """True if the API accepts this credential, False if it rejects it, None if unreachable."""
    key = hashlib.sha256(authorization.encode()).hexdigest()
    now = time.monotonic()
    if _verified.get(key, 0.0) > now:
        return True
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{_api_url()}/api/v1/auth/me", headers={"Authorization": authorization})
    except httpx.HTTPError:
        return None
    if resp.status_code == 200:
        if len(_verified) >= _CACHE_MAX:
            _verified.clear()
        _verified[key] = now + CACHE_TTL_SECONDS
        return True
    if resp.status_code in (401, 403):
        return False
    return None  # 5xx or anything unexpected: treat as unavailable, fail closed


async def authorize(headers: dict[str, str]) -> tuple[int, str]:
    """Return (0, "") to allow, or (status, reason) to deny. Headers lower-cased."""
    internal = _internal_token()
    sent = headers.get("x-internal-token", "")
    if internal and sent and hmac.compare_digest(sent, internal):
        return 0, ""
    authorization = headers.get("authorization", "")
    if not authorization.lower().startswith("bearer ") or len(authorization) < 8:
        return 401, "Not authenticated"
    valid = await bearer_is_valid(authorization)
    if valid is None:
        return 503, "Authentication service unavailable"
    if not valid:
        return 401, "Invalid or expired credentials"
    return 0, ""


class ServiceAuthMiddleware:
    """Plain ASGI middleware (streams and WebSockets pass through untouched)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket") or not _is_production_environment():
            return await self.app(scope, receive, send)
        if scope.get("path", "") in OPEN_PATHS or scope.get("method") == "OPTIONS":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        status, reason = await authorize(headers)
        if status == 0:
            return await self.app(scope, receive, send)
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4401 if status == 401 else 1013, "reason": reason})
            return None
        return await JSONResponse({"detail": reason}, status_code=status)(scope, receive, send)
