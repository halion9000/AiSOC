"""The honeytoken tripwire: GET /api/v1/canary/{token_id}.

A honeytoken of type url (or a file that carries a beacon link) contains a link to this route with the token's own id in it. Anyone who opens the link, whoever they are, reaches here WITHOUT signing
in (a visitor who found a planted link has no AiSOC account); we record the visit with the honeytokens service, which marks the token triggered and raises the alert, and answer with a one pixel image.

Why this is safe to leave open:
  * The answer is identical for a real token, an unknown id and junk, so the route cannot be used to find out which tokens exist.
  * An id that is not a UUID is never forwarded.
  * A token's id is unguessable (a random UUID); a visit to a real token is the signal, and nothing else about the token is returned.
  * It is rate limited per token and overall, so it cannot be used to flood the honeytokens service or its database. Past a limit the visit is dropped quietly (the first visits already fired the alert).
  * Failing to reach the honeytokens service, or to write the alert, never changes the answer or raises an error to the visitor.

Two things happen on a visit to a real token: the honeytokens service records the trigger (so the token shows as triggered, with the visitor's address and browser), and AiSOC raises an ALERT in the
token's own tenant (high severity, tagged honeytoken) so it reaches the queue analysts work. One alert per token per hour: later visits in that hour are in the trigger history, not new alerts.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import os
import time
import uuid
from collections import deque
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, Request, Response
from sqlalchemy import select, text

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


def alert_for_visit(token: dict, ip: str | None, user_agent: str | None, now: datetime) -> dict:
    """What the alert for a visit to ``token`` (``{id, tenant_id, name, token_type}``) looks like: the arguments for building the alert row. Pure."""
    where = f" from {ip}" if ip else ""
    client: dict = {"ipAddress": ip} if ip else {}
    return {
        "tenant_id": token["tenant_id"],
        "events": [{"eventType": "honeytoken_opened", "severity": "high", "client": client, "published": now.isoformat(), "honeytoken": {"id": str(token["id"]), "type": token.get("token_type")}}],
        "connector_type": "honeytoken",
        "override_title": f"Honeytoken opened: {token['name']}"[:500],
        "override_description": (
            f"Someone opened the decoy {token.get('token_type') or 'link'} \"{token['name']}\"{where}. Nothing legitimate should ever touch it, so treat this as an intruder or a compromised account looking around."
            + (f" Browser: {user_agent[:200]}." if user_agent else "")
        ),
        "override_severity": "high",
        "override_tags": ["honeytoken", "deception"],
        # One alert per token per hour: the first visit raises it, later ones are in the token's trigger history.
        "idempotency_key": f"honeytoken-{token['id']}-{now.strftime('%Y%m%d%H')}",
    }


async def _lookup_token(token_id: uuid.UUID) -> dict | None:
    from app.db.database import AsyncSessionLocal
    from app.db.rls_sessions import mark_platform

    async with AsyncSessionLocal() as db:
        mark_platform(db)  # the visitor has no tenant: find the token's
        row = (await db.execute(text("SELECT id, tenant_id, name, token_type FROM honeytokens WHERE id = :id AND status IN ('active', 'triggered')").bindparams(id=token_id))).first()
    return dict(row._mapping) if row else None


async def _store_alert(spec: dict) -> bool:
    """Write the alert in the token's own tenant. False when this token already raised one this hour."""
    from sqlalchemy.exc import IntegrityError

    from app.api.v1.endpoints.alerts import _synthesise_alert_from_events
    from app.db.database import AsyncSessionLocal
    from app.db.rls_sessions import mark_tenant
    from app.models.alert import Alert

    async with AsyncSessionLocal() as db:
        mark_tenant(db, spec["tenant_id"])
        existing = (await db.execute(select(Alert.id).where(Alert.tenant_id == spec["tenant_id"], Alert.idempotency_key == spec["idempotency_key"]))).first()
        if existing:
            return False
        alert = _synthesise_alert_from_events(**spec)
        db.add(alert)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            return False
    return True


async def _raise_alert(token_id: uuid.UUID, ip: str | None, user_agent: str | None) -> None:
    try:
        token = await _lookup_token(token_id)
        if token is None:
            return  # an unknown id: nothing to alert on
        await _store_alert(alert_for_visit(token, ip, user_agent, datetime.now(UTC)))
    except Exception as exc:  # noqa: BLE001 - the visitor must never see a difference
        logger.warning("canary.alert_failed", extra={"err": type(exc).__name__})


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
    ip = client_ip(request.client.host if request.client else None, request.headers.get("x-forwarded-for"))
    user_agent = (request.headers.get("user-agent") or "")[:500] or None
    await _forward({"token_id": str(parsed), "source_ip": ip, "user_agent": user_agent, "headers": headers, "body": {"via": "canary-link"}})
    await _raise_alert(parsed, ip, user_agent)
    return _answer()
