"""The honeytoken tripwire: GET /api/v1/canary/{token_id}.

A honeytoken of type url (or a file that carries a beacon link) contains a link to this route with the token's own id in it. Anyone who opens the link, whoever they are, reaches here WITHOUT signing
in (a visitor who found a planted link has no AiSOC account); we record the visit with the honeytokens service, which marks the token triggered and raises the alert, and answer with a one pixel image.

Why this is safe to leave open:
  * The answer is identical for a real token, an unknown id and junk, so the route cannot be used to find out which tokens exist.
  * An id that is not a UUID is never forwarded.
  * A token's id is unguessable (a random UUID); a visit to a real token is the signal, and nothing else about the token is returned.
  * It is rate limited per token and overall, so it cannot be used to flood the honeytokens service or its database. Past a limit the visit is dropped quietly (the first visits already fired the alert).
  * Failing to reach the honeytokens service never changes the answer or raises an error to the visitor.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import os
import time
import uuid
from collections import deque

import httpx
from fastapi import APIRouter, Request, Response

logger = logging.getLogger("aisoc.canary")

router = APIRouter(prefix="/canary", tags=["canary"])

_GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")  # 1x1 transparent
_PER_TOKEN_PER_MINUTE = 30
_OVERALL_PER_MINUTE = 600
_FORWARDED_HEADERS = ("referer", "accept-language", "x-forwarded-for", "x-forwarded-host", "origin")

_token_hits: dict[str, deque[float]] = {}
_all_hits: deque[float] = deque()


def _allowed(token_id: str, now: float) -> bool:
    """True if this visit may be forwarded. Sliding one-minute windows, per token and overall."""
    window = now - 60.0
    while _all_hits and _all_hits[0] < window:
        _all_hits.popleft()
    hits = _token_hits.setdefault(token_id, deque())
    while hits and hits[0] < window:
        hits.popleft()
    if len(_all_hits) >= _OVERALL_PER_MINUTE or len(hits) >= _PER_TOKEN_PER_MINUTE:
        return False
    _all_hits.append(now)
    hits.append(now)
    if len(_token_hits) > 5000:  # forget tokens that have been quiet, so the table cannot grow without bound
        for key in [k for k, v in _token_hits.items() if not v or v[-1] < window]:
            _token_hits.pop(key, None)
    return True


def reset_limits() -> None:
    _token_hits.clear()
    _all_hits.clear()


def _is_our_proxy(host: str | None) -> bool:
    try:
        ip = ipaddress.ip_address(host or "")
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def client_ip(peer: str | None, forwarded_for: str | None) -> str | None:
    """The visitor's address. When the request came through one of our own proxies (the console in front of the API: a private or loopback peer), the address that proxy appended is the LAST entry of
    X-Forwarded-For; entries before it were sent by the visitor and can be anything. A request from a public peer is taken at its word for nothing but its own address."""
    if _is_our_proxy(peer) and forwarded_for:
        last = forwarded_for.split(",")[-1].strip()
        try:
            return str(ipaddress.ip_address(last))
        except ValueError:
            pass
    return peer


async def _forward(payload: dict) -> None:
    base = os.environ.get("HONEYTOKENS_SERVICE_URL", "http://honeytokens:8005").rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(f"{base}/api/v1/honeytokens/webhook/trigger", json=payload)
    except Exception as exc:  # noqa: BLE001 - the visitor must never see a difference
        logger.warning("canary.forward_failed", extra={"err": type(exc).__name__})


def _answer() -> Response:
    return Response(content=_GIF, media_type="image/gif", headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.get("/{token_id}", include_in_schema=True, summary="Honeytoken tripwire (public by design)")
async def canary_visit(token_id: str, request: Request) -> Response:
    try:
        parsed = uuid.UUID(token_id)
    except ValueError:
        return _answer()
    if not _allowed(str(parsed), time.monotonic()):
        return _answer()
    headers = {k: request.headers[k][:500] for k in _FORWARDED_HEADERS if k in request.headers}
    await _forward(
        {
            "token_id": str(parsed),
            "source_ip": client_ip(request.client.host if request.client else None, request.headers.get("x-forwarded-for")),
            "user_agent": (request.headers.get("user-agent") or "")[:500] or None,
            "headers": headers,
            "body": {"via": "canary-link"},
        }
    )
    return _answer()
