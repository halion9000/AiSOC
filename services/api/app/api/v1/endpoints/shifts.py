"""SOC Shift Management endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, select

from app.api.v1.deps import AuthUser, TenantDBSession, require_permission
from app.models.alert import Alert
from app.models.case import Case

router = APIRouter(prefix="/shifts", tags=["shifts"])


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


class HandoffItemOut(BaseModel):
    """
    Hal, 2026-09-21: "might as well build it out now" — the frontend's
    ShiftsView.tsx had a HandoffItem list with no matching backend query at
    all (flagged separately from this file's own pre-existing mock shift
    data, below — that's a bigger, separate gap: an in-memory _MOCK_SHIFTS
    list with no real shifts table at all). This endpoint is deliberately
    independent of that mock shift system, since "what's still open and
    worth flagging to the next shift" doesn't actually need a real shift
    record to answer — it's just currently-open alerts and cases, which the
    database already has for real.
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
    Real alerts and cases still open at query time - the actual candidates
    for handoff to the next shift, not a canned demo list. An alert/case
    counts as "still open" the same way the rest of the app already treats
    it: not resolved, not a false positive, not closed.
    """
    alert_filters = [
        Alert.tenant_id == current_user.tenant_id,
        Alert.status.notin_(["resolved", "fp", "closed"]),
    ]
    case_filters = [
        Case.tenant_id == current_user.tenant_id,
        Case.status.notin_(["resolved", "closed"]),
    ]
    if priority:
        alert_filters.append(Alert.severity == priority)
        case_filters.append(Case.priority == priority)

    alert_result = await db.execute(
        select(Alert).where(and_(*alert_filters)).order_by(Alert.created_at.desc()).limit(limit)
    )
    case_result = await db.execute(
        select(Case).where(and_(*case_filters)).order_by(Case.created_at.desc()).limit(limit)
    )

    items = [
        HandoffItemOut(
            id=str(a.id),
            priority=a.severity,
            title=a.title,
            type="alert",
            status=a.status,
            assigned_to=str(a.assigned_to_id) if a.assigned_to_id else "unassigned",
            notes=a.ai_summary,
        )
        for a in alert_result.scalars().all()
    ] + [
        HandoffItemOut(
            id=str(c.id),
            priority=c.priority,
            title=c.title,
            type="case",
            status=c.status,
            assigned_to=str(c.assigned_to_id) if c.assigned_to_id else "unassigned",
            notes=c.description,
        )
        for c in case_result.scalars().all()
    ]

    priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items.sort(key=lambda i: priority_rank.get(i.priority, 4))
    return items[:limit]


_MOCK_ANALYSTS = {
    "a1": ShiftAnalyst(id="a1", name="Jordan Lee", role="shift_lead"),
    "a2": ShiftAnalyst(id="a2", name="Morgan Chen", role="soc_analyst"),
    "a3": ShiftAnalyst(id="a3", name="Taylor Kim", role="soc_analyst"),
    "a4": ShiftAnalyst(id="a4", name="Alex Rivera", role="senior_analyst"),
}

_now = datetime.now(UTC)
_MOCK_SHIFTS: list[dict] = [
    {
        "id": "shift-001",
        "name": "Day Shift – 2026-05-07",
        "started_at": (_now - timedelta(hours=6)).isoformat(),
        "ended_at": None,
        "status": "active",
        "lead": _MOCK_ANALYSTS["a1"],
        "analyst_count": 3,
        "alerts_handled": 47,
        "escalations": 2,
        "handoff_notes": None,
    },
    {
        "id": "shift-002",
        "name": "Night Shift – 2026-05-06",
        "started_at": (_now - timedelta(hours=18)).isoformat(),
        "ended_at": (_now - timedelta(hours=6)).isoformat(),
        "status": "completed",
        "lead": _MOCK_ANALYSTS["a4"],
        "analyst_count": 2,
        "alerts_handled": 31,
        "escalations": 1,
        "handoff_notes": "3 open P2 investigations carried over. SentinelOne connector flapping – ops ticket INFRA-412 filed.",
    },
    {
        "id": "shift-003",
        "name": "Day Shift – 2026-05-06",
        "started_at": (_now - timedelta(hours=30)).isoformat(),
        "ended_at": (_now - timedelta(hours=18)).isoformat(),
        "status": "completed",
        "lead": _MOCK_ANALYSTS["a1"],
        "analyst_count": 3,
        "alerts_handled": 62,
        "escalations": 4,
        "handoff_notes": "Major phishing campaign resolved (INC-1042). New Sigma rule deployed for O365 impossible-travel.",
    },
]


@router.get("", response_model=list[ShiftSummary])
async def list_shifts(
    current_user: AuthUser,
    status_filter: str | None = Query(None, alias="status", description="active | completed"),
    limit: int = Query(20, ge=1, le=100),
):
    """Return shift summaries, newest first."""
    shifts = _MOCK_SHIFTS
    if status_filter:
        shifts = [s for s in shifts if s["status"] == status_filter]
    return [ShiftSummary(**s) for s in shifts[:limit]]


@router.get("/current", response_model=ShiftSummary)
async def get_current_shift(current_user: AuthUser):
    """Return the currently active shift."""
    for s in _MOCK_SHIFTS:
        if s["status"] == "active":
            return ShiftSummary(**s)
    raise HTTPException(status_code=404, detail="No active shift")


@router.post("", response_model=ShiftSummary, status_code=201)
async def create_shift(
    body: ShiftCreate,
    current_user: AuthUser,
):
    """Start a new shift."""
    new_shift = {
        "id": f"shift-{uuid.uuid4().hex[:8]}",
        "name": body.name,
        "started_at": datetime.now(UTC).isoformat(),
        "ended_at": None,
        "status": "active",
        "lead": _MOCK_ANALYSTS.get(body.lead_id or "a1", _MOCK_ANALYSTS["a1"]),
        "analyst_count": max(len(body.analysts), 1),
        "alerts_handled": 0,
        "escalations": 0,
        "handoff_notes": None,
    }
    _MOCK_SHIFTS.insert(0, new_shift)
    return ShiftSummary(**new_shift)


@router.put("/{shift_id}/handoff", response_model=ShiftSummary)
async def add_handoff_notes(
    shift_id: str,
    body: HandoffNotes,
    current_user: AuthUser,
):
    """Attach handoff notes to a shift and mark it completed."""
    for s in _MOCK_SHIFTS:
        if s["id"] == shift_id:
            s["handoff_notes"] = body.notes
            s["status"] = "completed"
            s["ended_at"] = datetime.now(UTC).isoformat()
            return ShiftSummary(**s)
    raise HTTPException(status_code=404, detail="Shift not found")
