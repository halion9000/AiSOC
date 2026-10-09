"""Copilot tool registry — analyst-facing tools for the chat endpoint.

Wraps real DB operations (search/list/get/delete alerts and cases) as
LLM-callable tools with tenant isolation enforced at every call site.
Each tool function obtains its own DB session via AsyncSessionLocal and
sets RLS context from the authenticated user's tenant_id before executing
any query, matching the pattern used by TenantDBSession in deps.py.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

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
    """Delete a single alert by ID. Requires alerts:write permission."""
    try:
        tid = uuid.UUID(tenant_id)
        aid = uuid.UUID(alert_id)
    except ValueError:
        return {"error": "invalid UUID format"}

    async with await _get_session(tid) as db:
        result = await db.execute(
            delete(Alert).where(Alert.id == aid, Alert.tenant_id == tid)
        )
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
            "description": "Permanently delete an alert by its ID. This cannot be undone.",
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
        return await fn(tenant_id=tenant_id, **(args or {}))
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}
