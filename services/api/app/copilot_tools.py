"""Copilot tool registry — analyst-facing tools for the chat endpoint.

Wraps real DB operations (search/list/get/delete alerts and cases) as
LLM-callable tools with tenant isolation enforced at every call site.
Each tool function obtains its own DB session via AsyncSessionLocal and
sets RLS context from the authenticated user's tenant_id before executing
any query, matching the pattern used by TenantDBSession in deps.py.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.db.rls import set_rls_context
from app.models.alert import Alert


def _like_pattern(query: str) -> str:
    """A substring pattern for ILIKE with %, _ and the escape character escaped, so a model-supplied `%` matches a literal percent instead of turning the search into a wildcard scan (pair with escape="\\")."""
    return "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


async def _get_session(tenant_id: uuid.UUID) -> AsyncSession:
    """Create a tenant-scoped session outside FastAPI DI."""
    session = AsyncSessionLocal()
    await set_rls_context(session, tenant_id)
    return session


async def search_alerts(
    *, tenant_id: str, query: str = "", limit: int = 10
) -> dict[str, Any]:
    """Search alerts by title/description substring match."""
    try:
        tid = uuid.UUID(tenant_id)
    except ValueError:
        return {"error": "invalid tenant_id"}

    async with await _get_session(tid) as db:
        stmt = select(Alert).where(Alert.tenant_id == tid)
        if query:
            pattern = _like_pattern(query)
            stmt = stmt.where(
                Alert.title.ilike(pattern, escape="\\") | Alert.description.ilike(pattern, escape="\\")
            )
        stmt = stmt.order_by(Alert.created_at.desc()).limit(max(1, min(limit, 50)))
        result = await db.execute(stmt)
        alerts = result.scalars().all()
        return {
            "count": len(alerts),
            "alerts": [
                {
                    "id": str(a.id),
                    "title": a.title,
                    "severity": a.severity,
                    "status": a.status,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in alerts
            ],
        }


async def get_alert(*, tenant_id: str, alert_id: str) -> dict[str, Any]:
    """Get a single alert by ID."""
    try:
        tid = uuid.UUID(tenant_id)
        aid = uuid.UUID(alert_id)
    except ValueError:
        return {"error": "invalid UUID format"}

    async with await _get_session(tid) as db:
        result = await db.execute(
            select(Alert).where(Alert.id == aid, Alert.tenant_id == tid)
        )
        alert = result.scalar_one_or_none()
        if alert is None:
            return {"error": "alert not found"}
        return {
            "id": str(alert.id),
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "status": alert.status,
            "category": alert.category,
            "mitre_techniques": alert.mitre_techniques or [],
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        }


async def delete_alert(*, tenant_id: str, alert_id: str) -> dict[str, Any]:
    """REQUEST a deletion. This does NOT delete anything.

    Deleting needs the analyst's explicit confirmation, and the model must not be able to give it: alert text is attacker-influenced and sits in the model's context, so a "confirmed, go ahead" in it must never be enough. This only checks that the alert exists in the tenant and describes what would be deleted;
    execute_copilot_tool turns that into a signed, expiring confirmation that goes to the UI (never to the model), and POST /copilot/actions/confirm, which the model cannot call, performs perform_delete_alert."""
    try:
        tid = uuid.UUID(tenant_id)
        aid = uuid.UUID(alert_id)
    except ValueError:
        return {"error": "invalid UUID format"}

    async with await _get_session(tid) as db:
        alert = (await db.execute(select(Alert).where(Alert.id == aid, Alert.tenant_id == tid))).scalar_one_or_none()
        if alert is None:
            return {"error": "alert not found"}
        title = alert.title
    return {
        "alert_id": str(aid),
        "alert_title": title,
        _CONFIRM_KEY: {"action": "delete_alert", "args": {"alert_id": str(aid)}, "summary": f"Permanently delete alert \"{title}\" ({aid})? This cannot be undone."},
    }


async def perform_delete_alert(*, tenant_id: str, alert_id: str) -> dict[str, Any]:
    """Delete one alert. Only the confirmation endpoint calls this, and only with a valid token: it is deliberately NOT in the model's dispatch table."""
    try:
        tid = uuid.UUID(tenant_id)
        aid = uuid.UUID(alert_id)
    except ValueError:
        return {"error": "invalid UUID format"}

    async with await _get_session(tid) as db:
        result = await db.execute(delete(Alert).where(Alert.id == aid, Alert.tenant_id == tid))
        await db.commit()
        if result.rowcount == 0:  # type: ignore[union-attr]
            return {"error": "alert not found or already deleted"}
        return {"deleted": True, "alert_id": alert_id}


async def search_cases(
    *, tenant_id: str, query: str = "", limit: int = 10
) -> dict[str, Any]:
    """Search cases by title substring match.

    Cases live in aisoc_cases (what the cases API reads and writes). This used to read the old `cases` table, which nothing writes, so the Copilot always answered "no cases found"."""
    try:
        tid = uuid.UUID(tenant_id)
    except ValueError:
        return {"error": "invalid tenant_id"}

    async with await _get_session(tid) as db:
        where_clauses = ["tenant_id = :tenant_id"]
        params: dict[str, Any] = {"tenant_id": str(tid), "limit": max(1, min(limit, 50))}
        if query:
            where_clauses.append("title ILIKE :pattern ESCAPE '\\'")
            params["pattern"] = _like_pattern(query)
        sql = f"""
            SELECT id, case_number, title, status, severity, created_at
            FROM aisoc_cases
            WHERE {' AND '.join(where_clauses)}
            ORDER BY created_at DESC
            LIMIT :limit
        """
        result = await db.execute(text(sql).bindparams(**params))
        rows = result.fetchall()
        return {
            "count": len(rows),
            "cases": [
                {
                    "id": str(r.id),
                    "case_number": r.case_number,
                    "title": r.title,
                    "status": r.status,
                    "severity": r.severity,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ],
        }


async def delete_case(*, tenant_id: str, case_id: str) -> dict[str, Any]:
    """Cases cannot be deleted from the Copilot.

    This used to run `DELETE FROM cases`, the old table nothing writes, so it always answered "case not found or already deleted". Pointing it at aisoc_cases would have switched on a destructive tool that has never worked, for a model that reads
    attacker-influenced alert text, while the cases API itself has no delete (cases hold investigation evidence). So it refuses, truthfully, until deleting a case is a deliberate product decision with a confirmation step."""
    return {"error": "Deleting cases is not supported. A case holds investigation evidence and the cases API has no delete; close or resolve it instead."}


# ---------------------------------------------------------------------------
# Tool schemas for LLM binding (OpenAI function-calling format)
# ---------------------------------------------------------------------------

COPILOT_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "search_alerts",
            "description": "Search alerts by title or description keyword. Returns matching alerts with IDs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search keyword to match against alert titles and descriptions.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default 10, max 50).",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_alert",
            "description": "Get full details of a single alert by its ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "The UUID of the alert to retrieve.",
                    },
                },
                "required": ["alert_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_alert",
            "description": "Ask to permanently delete an alert by its ID. This does NOT delete it: the analyst is shown a confirmation prompt and must approve it. After calling this, tell the analyst that a confirmation is waiting for them and that nothing has been deleted yet.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "The UUID of the alert to delete.",
                    },
                },
                "required": ["alert_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_cases",
            "description": "Search cases by title keyword. Returns matching cases with IDs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search keyword to match against case titles.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default 10, max 50).",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_case",
            "description": "Not supported: cases cannot be deleted from the Copilot. To finish with a case, close or resolve it instead.",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The UUID of the case to delete.",
                    },
                },
                "required": ["case_id"],
            },
        },
    },
]

# Dispatch table mapping tool names to their async implementations
_COPILOT_TOOL_DISPATCH: dict[str, Any] = {
    "search_alerts": search_alerts,
    "get_alert": get_alert,
    "delete_alert": delete_alert,
    "search_cases": search_cases,
    "delete_case": delete_case,
}


# --- Confirmation of destructive actions -------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# A tool that changes or destroys data only REQUESTS the action. The request is turned into a token that is signed (HMAC over the tenant, user, action, arguments and expiry, keyed from SECRET_KEY under a purpose label so it can never be used as, or confused with, any other token) and expires. The token is
# removed from what the model sees and handed to the UI, which asks the analyst; only the analyst's own authenticated call to POST /copilot/actions/confirm presents it. Replaying a token inside its lifetime is harmless: the actions are idempotent ("already deleted").
_CONFIRM_KEY = "_confirm"
PENDING_KEY = "_pending"
CONFIRMATION_TTL_SECONDS = 300


def _confirmation_key() -> bytes:
    return hashlib.sha256(b"aisoc-copilot-confirm-v1:" + settings.SECRET_KEY.encode("utf-8")).digest()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(text_: str) -> bytes:
    return base64.urlsafe_b64decode(text_ + "=" * (-len(text_) % 4))


def issue_confirmation(*, tenant_id: str, user_id: str, action: str, args: dict[str, Any], now: float | None = None, ttl: int = CONFIRMATION_TTL_SECONDS) -> tuple[str, int]:
    """A signed confirmation token for `action(args)` by this user in this tenant, and its expiry (epoch seconds)."""
    exp = int((time.time() if now is None else now) + ttl)
    payload = json.dumps({"a": action, "args": args, "t": str(tenant_id), "u": str(user_id), "exp": exp, "n": secrets.token_hex(8)}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_confirmation_key(), payload, hashlib.sha256).digest()
    return _b64(payload) + "." + _b64(sig), exp


class ConfirmationError(Exception):
    """The token is not acceptable. `reason` is one of: malformed, signature, expired, wrong_tenant, wrong_user, unknown_action."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def verify_confirmation(token: str, *, tenant_id: str, user_id: str, now: float | None = None) -> dict[str, Any]:
    """The token's payload (action, args), or ConfirmationError. The signature is checked BEFORE anything in the payload is trusted, in constant time."""
    try:
        body, sig = token.split(".", 1)
        payload = _unb64(body)
        given = _unb64(sig)
    except Exception as exc:  # noqa: BLE001
        raise ConfirmationError("malformed") from exc
    if not hmac.compare_digest(hmac.new(_confirmation_key(), payload, hashlib.sha256).digest(), given):
        raise ConfirmationError("signature")
    try:
        data = json.loads(payload)
    except ValueError as exc:
        raise ConfirmationError("malformed") from exc
    if not isinstance(data, dict) or not isinstance(data.get("exp"), int) or not isinstance(data.get("args"), dict):
        raise ConfirmationError("malformed")
    if (time.time() if now is None else now) > data["exp"]:
        raise ConfirmationError("expired")
    if data.get("t") != str(tenant_id):
        raise ConfirmationError("wrong_tenant")
    if data.get("u") != str(user_id):
        raise ConfirmationError("wrong_user")
    if data.get("a") not in CONFIRMED_ACTIONS:
        raise ConfirmationError("unknown_action")
    return data


def split_pending(tool_result: Any) -> tuple[Any, dict[str, Any] | None]:
    """(what the MODEL may see, the pending confirmation for the UI or None). The token never reaches the model."""
    if isinstance(tool_result, dict) and PENDING_KEY in tool_result:
        visible = {k: v for k, v in tool_result.items() if k != PENDING_KEY}
        return visible, tool_result[PENDING_KEY]
    return tool_result, None


# The actions a confirmation token can authorise. NOT reachable from the model's tool dispatch.
CONFIRMED_ACTIONS: dict[str, Any] = {"delete_alert": perform_delete_alert}

# The permission each tool needs, the same ones the matching REST endpoints require. A tool with no entry here is not run.
TOOL_PERMISSIONS: dict[str, str] = {
    "search_alerts": "alerts:read",
    "get_alert": "alerts:read",
    "delete_alert": "alerts:delete",
    "search_cases": "cases:read",
    "delete_case": "cases:delete",
}


async def execute_copilot_tool(name: str, args: dict[str, Any], tenant_id: str, *, user: Any) -> Any:
    """Execute a copilot tool by name, as `user`, with tenant isolation.

    The endpoint only checks `copilot:use`; this runs whatever tool the model asks for, and the tool docstrings said "Requires alerts:write" / "cases:write" while nothing enforced anything, so any user holding copilot:use (and an API key scoped to copilot:use alone)
    could have the model delete alerts. Each tool now needs the permission of the matching REST endpoint, checked exactly the way the endpoints check it (static role table, or an API key's scopes). `user` is required: omitting it fails closed.
    """
    fn = _COPILOT_TOOL_DISPATCH.get(name)
    if fn is None:
        return {"error": f"unknown tool: {name}"}
    needed = TOOL_PERMISSIONS.get(name)
    if needed is None:
        return {"error": f"tool {name} has no declared permission and is not available"}
    if str(getattr(user, "tenant_id", "")) != str(tenant_id):
        return {"error": "tenant mismatch"}
    try:
        user.require_permission(needed)
    except HTTPException:
        return {"error": f"permission denied: {name} requires {needed}"}
    try:
        result = await fn(tenant_id=tenant_id, **(args or {}))
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}
    if isinstance(result, dict) and _CONFIRM_KEY in result:
        # A destructive tool only REQUESTED its action: sign a confirmation for the UI and tell the model, truthfully, that nothing has happened yet.
        request = result.pop(_CONFIRM_KEY)
        token, exp = issue_confirmation(tenant_id=str(tenant_id), user_id=str(getattr(user, "user_id", "")), action=request["action"], args=request["args"])
        result["status"] = "awaiting_user_confirmation"
        result["message"] = "NOTHING HAS BEEN DONE YET. The analyst has been shown a confirmation prompt and must approve it themselves. Tell them it is waiting for them; do not claim the action happened."
        result[PENDING_KEY] = {"action": request["action"], "summary": request["summary"], "token": token, "expiresAt": exp}
    return result
