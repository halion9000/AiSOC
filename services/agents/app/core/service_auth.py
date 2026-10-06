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
from app.core.route_permissions import required_permission

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


async def check_with_api(authorization: str, permission: str | None) -> str:
    """Ask the API about this credential: "ok", "unauthenticated", "forbidden" or "unavailable".

    With a permission: POST /api/v1/auth/authorize (the API owns the role table, so
    there is one source of truth). Without one: GET /api/v1/auth/me (login only).
    Positive answers are cached briefly, per credential AND permission.
    """
    key = hashlib.sha256(f"{permission or ''}\n{authorization}".encode()).hexdigest()
    now = time.monotonic()
    if _verified.get(key, 0.0) > now:
        return "ok"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            if permission is None:
                resp = await client.get(f"{_api_url()}/api/v1/auth/me", headers={"Authorization": authorization})
            else:
                resp = await client.post(
                    f"{_api_url()}/api/v1/auth/authorize", json={"permission": permission}, headers={"Authorization": authorization}
                )
    except httpx.HTTPError:
        return "unavailable"
    if resp.status_code == 200:
        if len(_verified) >= _CACHE_MAX:
            _verified.clear()
        _verified[key] = now + CACHE_TTL_SECONDS
        return "ok"
    if resp.status_code == 401:
        return "unauthenticated"
    if resp.status_code == 403:
        return "forbidden"
    return "unavailable"  # 5xx, 422 (we asked about a permission the API does not know) or anything unexpected: fail closed


async def authorize(headers: dict[str, str], method: str = "GET", path: str = "") -> tuple[int, str]:
    """Return (0, "") to allow, or (status, reason) to deny. Headers lower-cased."""
    internal = _internal_token()
    sent = headers.get("x-internal-token", "")
    if internal and sent and hmac.compare_digest(sent, internal):
        return 0, ""  # the API already authenticated AND authorized this user before calling us
    authorization = headers.get("authorization", "")
    if not authorization.lower().startswith("bearer ") or len(authorization) < 8:
        return 401, "Not authenticated"
    outcome = await check_with_api(authorization, required_permission(method, path))
    if outcome == "ok":
        return 0, ""
    if outcome == "unauthenticated":
        return 401, "Invalid or expired credentials"
    if outcome == "forbidden":
        return 403, "You do not have permission to do this"
    return 503, "Authentication service unavailable"


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
        # WebSocket upgrades are GET requests as far as permissions go
        method = "GET" if scope["type"] == "websocket" else scope.get("method", "GET")
        status, reason = await authorize(headers, method, scope.get("path", ""))
        if status == 0:
            return await self.app(scope, receive, send)
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": {401: 4401, 403: 4403}.get(status, 1013), "reason": reason})
            return None
        return await JSONResponse({"detail": reason}, status_code=status)(scope, receive, send)
