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

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import AsyncSessionLocal
from app.db.rls import set_rls_context
from app.models.alert import Alert
from app.models.case import Case


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
            pattern = f"%{query}%"
            stmt = stmt.where(
                Alert.title.ilike(pattern) | Alert.description.ilike(pattern)
            )
        stmt = stmt.order_by(Alert.created_at.desc()).limit(min(limit, 50))
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
    """Search cases by title substring match."""
    try:
        tid = uuid.UUID(tenant_id)
    except ValueError:
        return {"error": "invalid tenant_id"}

    async with await _get_session(tid) as db:
        where_clauses = ["tenant_id = :tenant_id"]
        params: dict[str, Any] = {"tenant_id": str(tid), "limit": min(limit, 50)}
        if query:
            where_clauses.append("title ILIKE :pattern")
            params["pattern"] = f"%{query}%"
        sql = f"""
            SELECT id, case_number, title, status, severity, created_at
            FROM cases
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
    """Delete a single case by ID. Requires cases:write permission."""
    try:
        tid = uuid.UUID(tenant_id)
    except ValueError:
        return {"error": "invalid tenant_id"}

    async with await _get_session(tid) as db:
        result = await db.execute(
            text("DELETE FROM cases WHERE id = :id AND tenant_id = :tid").bindparams(
                id=case_id, tid=str(tid)
            )
        )
        await db.commit()
        if result.rowcount == 0:  # type: ignore[union-attr]
            return {"error": "case not found or already deleted"}
        return {"deleted": True, "case_id": case_id}


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
            "description": "Permanently delete a case by its ID. This cannot be undone.",
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


async def execute_copilot_tool(
    name: str, args: dict[str, Any], tenant_id: str
) -> Any:
    """Execute a copilot tool by name with tenant isolation."""
    fn = _COPILOT_TOOL_DISPATCH.get(name)
    if fn is None:
        return {"error": f"unknown tool: {name}"}
    try:
        return await fn(tenant_id=tenant_id, **(args or {}))
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}