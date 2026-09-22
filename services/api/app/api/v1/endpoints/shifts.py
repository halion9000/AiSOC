"""SOC Shift Management endpoints.

Backed by the ``aisoc_shifts`` table (migration 050). Tenant-scoped via
RLS — every query is automatically filtered to the current tenant by
Postgres row-level security, so analysts can only see their own tenant's
shift history.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession

router = APIRouter(prefix="/shifts", tags=["shifts"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ShiftAnalyst(BaseModel):
    id: str
    name: str
    role: str

    model_config = {"from_attributes": True}


class ShiftSummary(BaseModel):
    id: str
    name: str
    started_at: str
    ended_at: str | None = None
    status: str
    lead: ShiftAnalyst
    analyst_count: int
    alerts_handled: int
    escalations: int
    handoff_notes: str | None = None

    model_config = {"from_attributes": True}


class ShiftCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    analysts: list[str] = Field(default_factory=list, description="Analyst user IDs")
    lead_id: str | None = None


class HandoffNotes(BaseModel):
    notes: str = Field(..., min_length=1)
    pending_items: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_summary(row: dict) -> ShiftSummary:
    """Convert a raw DB row into the public response shape."""
    return ShiftSummary(
        id=str(row["id"]),
        name=row["name"],
        started_at=(
            row["started_at"].isoformat()
            if isinstance(row["started_at"], datetime)
            else str(row["started_at"])
        ),
        ended_at=(
            row["ended_at"].isoformat()
            if isinstance(row["ended_at"], datetime) and row["ended_at"]
            else None
        ),
        status=row["status"],
        lead=ShiftAnalyst(
            id=row.get("lead_id") or "unknown",
            name=row.get("lead_name") or "Unassigned",
            role=row.get("lead_role") or "soc_analyst",
        ),
        analyst_count=int(row.get("analyst_count") or 1),
        alerts_handled=int(row.get("alerts_handled") or 0),
        escalations=int(row.get("escalations") or 0),
        handoff_notes=row.get("handoff_notes"),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=list[ShiftSummary])
async def list_shifts(
    current_user: Annotated[AuthUser, Depends(require_permission("shifts:read"))],
    db: TenantDBSession,
    status_filter: str | None = Query(None, alias="status", description="active | completed | cancelled"),
    limit: int = Query(20, ge=1, le=100),
):
    """Return shift summaries, newest first."""
    params: dict = {"limit": limit}
    where_clause = ""
    if status_filter:
        where_clause = "AND status = :status"
        params["status"] = status_filter

    result = await db.execute(
        text(f"""
            SELECT id, name, status, lead_id, lead_name, lead_role,
                   analyst_count, alerts_handled, escalations,
                   handoff_notes, started_at, ended_at
            FROM aisoc_shifts
            WHERE 1=1 {where_clause}
            ORDER BY started_at DESC
            LIMIT :limit
        """),
        params,
    )
    rows = [dict(r._mapping) for r in result.fetchall()]
    return [_row_to_summary(r) for r in rows]


@router.get("/current", response_model=ShiftSummary)
async def get_current_shift(
    current_user: Annotated[AuthUser, Depends(require_permission("shifts:read"))],
    db: TenantDBSession,
):
    """Return the currently active shift."""
    result = await db.execute(
        text("""
            SELECT id, name, status, lead_id, lead_name, lead_role,
                   analyst_count, alerts_handled, escalations,
                   handoff_notes, started_at, ended_at
            FROM aisoc_shifts
            WHERE status = 'active'
            ORDER BY started_at DESC
            LIMIT 1
        """),
    )
    row = result.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No active shift")
    return _row_to_summary(dict(row._mapping))


@router.post("", response_model=ShiftSummary, status_code=201)
async def create_shift(
    body: ShiftCreate,
    current_user: Annotated[AuthUser, Depends(require_permission("shifts:write"))],
    db: TenantDBSession,
):
    """Start a new shift.

    Closes any currently active shift for this tenant before opening the
    new one — only one active shift per tenant at a time.
    """
    # Close any existing active shift first.
    await db.execute(
        text("""
            UPDATE aisoc_shifts
            SET status = 'completed', ended_at = now(), updated_at = now()
            WHERE status = 'active'
        """),
    )

    new_id = str(uuid.uuid4())
    analyst_count = max(len(body.analysts), 1)

    result = await db.execute(
        text("""
            INSERT INTO aisoc_shifts
                (id, tenant_id, name, status, lead_id, analyst_ids, analyst_count)
            VALUES
                (:id, :tenant_id, :name, 'active', :lead_id, :analyst_ids, :analyst_count)
            RETURNING id, name, status, lead_id, lead_name, lead_role,
                      analyst_count, alerts_handled, escalations,
                      handoff_notes, started_at, ended_at
        """),
        {
            "id": new_id,
            "tenant_id": str(current_user.tenant_id),
            "name": body.name,
            "lead_id": body.lead_id,
            "analyst_ids": body.analysts,
            "analyst_count": analyst_count,
        },
    )
    row = dict(result.fetchone()._mapping)
    await db.commit()
    return _row_to_summary(row)


class HandoffItemOut(BaseModel):
    """
    Hal, 2026-09-22, review: this endpoint (and this model) existed before
    the aisoc_shifts rewrite (migration 050) replaced the old in-memory
    _MOCK_SHIFTS system - that rewrite fixed a real, separate gap (shift
    tracking itself had no real table at all) but replaced this whole file
    wholesale in the process, silently dropping this endpoint along with
    the mock it was never part of. ShiftsView.tsx's frontend still calls
    GET /shifts/handoff-items directly (shiftsApi.handoffItems() in
    api.ts) - without this, that call 404s.

    Deliberately independent of the aisoc_shifts table above: "what's
    still open and worth flagging to the next shift" doesn't need a real
    shift record to answer, it's just currently-open alerts and cases,
    which the database already has for real.
    """
    id: str
    priority: str
    title: str
    type: str
    status: str
    assigned_to: str
    notes: str | None = None

    model_config = {"from_attributes": True}


@router.get("/handoff-items", response_model=list[HandoffItemOut])
async def list_handoff_items(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: TenantDBSession,
    priority: str | None = Query(default=None, description="Filter to one priority: critical/high/medium/low"),
    limit: int = Query(default=50, ge=1, le=200),
):
    """
    Real alerts and cases still open at query time - not resolved, not a
    false positive, not closed - the actual candidates for handoff to the
    next shift.
    """
    priority_clause = "AND severity = :priority" if priority else ""
    alert_rows = (await db.execute(
        text(f"""
            SELECT id, title, severity AS priority, status, assigned_to_id, ai_summary AS notes
            FROM alerts
            WHERE status NOT IN ('resolved', 'fp', 'closed') {priority_clause}
            ORDER BY created_at DESC
            LIMIT :limit
        """),
        {"priority": priority, "limit": limit} if priority else {"limit": limit},
    )).fetchall()

    case_priority_clause = "AND priority = :priority" if priority else ""
    case_rows = (await db.execute(
        text(f"""
            SELECT id, title, priority, status, assigned_to_id, description AS notes
            FROM cases
            WHERE status NOT IN ('resolved', 'closed') {case_priority_clause}
            ORDER BY created_at DESC
            LIMIT :limit
        """),
        {"priority": priority, "limit": limit} if priority else {"limit": limit},
    )).fetchall()

    items = [
        HandoffItemOut(
            id=str(r.id),
            priority=r.priority,
            title=r.title,
            type="alert",
            status=r.status,
            assigned_to=str(r.assigned_to_id) if r.assigned_to_id else "unassigned",
            notes=r.notes,
        )
        for r in alert_rows
    ] + [
        HandoffItemOut(
            id=str(r.id),
            priority=r.priority,
            title=r.title,
            type="case",
            status=r.status,
            assigned_to=str(r.assigned_to_id) if r.assigned_to_id else "unassigned",
            notes=r.notes,
        )
        for r in case_rows
    ]

    priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items.sort(key=lambda i: priority_rank.get(i.priority, 4))
    return items[:limit]


@router.put("/{shift_id}/handoff", response_model=ShiftSummary)
async def add_handoff_notes(
    shift_id: str,
    body: HandoffNotes,
    current_user: Annotated[AuthUser, Depends(require_permission("shifts:write"))],
    db: TenantDBSession,
):
    """Attach handoff notes to a shift and mark it completed."""
    result = await db.execute(
        text("""
            UPDATE aisoc_shifts
            SET handoff_notes = :notes,
                pending_items = :pending,
                status = 'completed',
                ended_at = now(),
                updated_at = now()
            WHERE id::text = :shift_id
            RETURNING id, name, status, lead_id, lead_name, lead_role,
                      analyst_count, alerts_handled, escalations,
                      handoff_notes, started_at, ended_at
        """),
        {
            "notes": body.notes,
            "pending": body.pending_items,
            "shift_id": shift_id,
        },
    )
    row = result.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Shift not found")
    await db.commit()
    return _row_to_summary(dict(row._mapping))