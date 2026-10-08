"""Durable store for response actions (table response_actions, created by services/api/migrations/055_response_actions.sql).

Replaces a process-local dict that lost pending approvals, ChatOps approval links and the record of what had run on every restart.

Every state change that must happen AT MOST ONCE is a single conditional UPDATE (`... WHERE id = :id AND status = :expected`), so it is atomic across processes and replicas, not just within one:
claim() (awaiting_approval/approved -> running), reject(), and mark_chatops_responded(). The caller learns from the row count whether it won.

The complete original request is stored immutably (`request`) and approval rebuilds the ActionRequest from it. It used to be rebuilt from a record that had dropped `parameters`, `requested_by`,
`principal` and `auto_rollback`, so every action that needed approval executed without its parameters.

A row left in 'running' means the service stopped between claim() and finish(): the action may or may not have executed, so it is never re-run automatically.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.action import ActionRequest, ActionStatus
from app.models.action_record import ActionRecord


def _text(value: Any) -> str:
    return str(getattr(value, "value", value))


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _uuid(action_id: str | UUID) -> UUID | None:
    try:
        return action_id if isinstance(action_id, UUID) else UUID(str(action_id))
    except ValueError:
        return None


def _is_duplicate(exc: IntegrityError) -> bool:
    """Only a UNIQUE / primary-key violation means "already stored"; any other integrity fault is a different problem."""
    orig = exc.orig
    code = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None) or getattr(getattr(orig, "__cause__", None), "sqlstate", None)
    if code:
        return code == "23505"
    return "unique constraint failed" in str(orig).lower()


def to_dict(row: ActionRecord) -> dict[str, Any]:
    """The record as the API has always served it, plus whatever outcome fields exist (output, rollback_data, error, ...). Identity fields always win over outcome fields."""
    base: dict[str, Any] = {
        "id": str(row.id),
        "action_type": row.action_type,
        "target": row.target,
        "status": row.status,
        "blast_radius": row.blast_radius,
        "gate_reason": row.gate_reason,
        "incident_id": str(row.incident_id),
        "tenant_id": str(row.tenant_id),
        "rationale": row.rationale,
        "requested_by_user_id": row.requested_by_user_id,
    }
    if row.approved_by_user_id:
        base["approved_by_user_id"] = row.approved_by_user_id
    return {**(row.result or {}), **base}


async def _row(db: AsyncSession, action_id: str | UUID, *, fresh: bool = False) -> ActionRecord | None:
    uid = _uuid(action_id)
    if uid is None:
        return None
    stmt = select(ActionRecord).where(ActionRecord.id == uid)
    if fresh:
        stmt = stmt.execution_options(populate_existing=True)  # never trust a copy this session loaded earlier
    return (await db.execute(stmt)).scalar_one_or_none()


async def get(db: AsyncSession, action_id: str | UUID) -> dict[str, Any] | None:
    row = await _row(db, action_id)
    return None if row is None else to_dict(row)


async def load_request(db: AsyncSession, action_id: str | UUID) -> ActionRequest | None:
    """The ORIGINAL request, exactly as submitted (parameters, principal, auto_rollback and all)."""
    row = await _row(db, action_id)
    return None if row is None else ActionRequest.model_validate(row.request)


async def create(db: AsyncSession, request: ActionRequest, *, status: Any, blast_radius: Any, gate_reason: str) -> tuple[dict[str, Any], bool]:
    """Store a newly submitted action. Returns (record, created). Submitting the same id again returns the EXISTING record with created=False: callers must not execute it a second time."""
    principal = request.principal
    db.add(
        ActionRecord(
            id=request.id,
            tenant_id=request.tenant_id,
            incident_id=request.incident_id,
            action_type=_text(request.action_type),
            target=request.target,
            status=_text(status),
            blast_radius=_text(blast_radius),
            gate_reason=gate_reason or "",
            rationale=request.rationale or "",
            requested_by_user_id=str(principal.user_id) if principal and principal.user_id else None,
            request=request.model_dump(mode="json"),
            result={},
        )
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        if not _is_duplicate(exc):
            raise
        existing = await get(db, request.id)
        if existing is None:  # vanished between the conflict and the read: treat as a real fault
            raise
        return existing, False
    row = await _row(db, request.id, fresh=True)
    assert row is not None
    return to_dict(row), True


async def claim(db: AsyncSession, action_id: str | UUID, *, expected: ActionStatus, approved_by_user_id: str | None = None) -> bool:
    """Atomically move the action from `expected` to RUNNING. True only for the ONE caller that wins; committed immediately so every other process sees it."""
    uid = _uuid(action_id)
    if uid is None:
        return False
    values: dict[str, Any] = {"status": _text(ActionStatus.RUNNING), "updated_at": datetime.now(UTC)}
    if approved_by_user_id:
        values["approved_by_user_id"] = approved_by_user_id
    result = await db.execute(update(ActionRecord).where(ActionRecord.id == uid, ActionRecord.status == _text(expected)).values(**values))
    await db.commit()
    return result.rowcount == 1


async def finish(
    db: AsyncSession,
    action_id: str | UUID,
    status: Any,
    *,
    output: dict[str, Any] | None = None,
    rollback_data: dict[str, Any] | None = None,
    error: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record the outcome of an action this caller has claimed."""
    row = await _row(db, action_id, fresh=True)
    if row is None:
        raise KeyError(str(action_id))
    result = dict(row.result or {})
    if output is not None:
        result["output"] = _jsonable(output)
    if rollback_data is not None:
        result["rollback_data"] = _jsonable(rollback_data)
    if error:
        result["error"] = error
    if extra:
        result.update(_jsonable(extra))
    row.result = result
    row.status = _text(status)
    row.updated_at = datetime.now(UTC)
    await db.commit()
    return to_dict(row)


async def reject(db: AsyncSession, action_id: str | UUID) -> tuple[str, dict[str, Any] | None]:
    """Atomically reject an action that is still awaiting approval. Returns ("rejected" | "not_found" | "conflict", record)."""
    uid = _uuid(action_id)
    if uid is not None:
        result = await db.execute(
            update(ActionRecord)
            .where(ActionRecord.id == uid, ActionRecord.status == _text(ActionStatus.AWAITING_APPROVAL))
            .values(status=_text(ActionStatus.REJECTED), updated_at=datetime.now(UTC))
        )
        await db.commit()
        if result.rowcount == 1:
            return "rejected", await get(db, uid)
    current = await get(db, action_id)
    return ("not_found", None) if current is None else ("conflict", current)


async def mark_chatops_responded(db: AsyncSession, action_id: str | UUID) -> bool | None:
    """Atomically record the FIRST ChatOps response. True for the first caller, False if already recorded, None if there is no such action."""
    uid = _uuid(action_id)
    if uid is None:
        return None
    result = await db.execute(
        update(ActionRecord).where(ActionRecord.id == uid, ActionRecord.chatops_responded_at.is_(None)).values(chatops_responded_at=datetime.now(UTC))
    )
    await db.commit()
    if result.rowcount == 1:
        return True
    return False if await _row(db, uid) is not None else None


async def list_actions(
    db: AsyncSession, *, status: str | None = None, tenant_id: str | UUID | None = None, older_than_seconds: int | None = None, limit: int = 100
) -> list[dict[str, Any]]:
    """Actions, newest first. `status="running"` with `older_than_seconds` finds actions that look STUCK: claimed, but no outcome recorded (the service stopped mid-action)."""
    stmt = select(ActionRecord).order_by(ActionRecord.updated_at.desc()).limit(max(1, min(limit, 500)))
    if status:
        stmt = stmt.where(ActionRecord.status == status)
    tid = _uuid(tenant_id) if tenant_id else None
    if tenant_id and tid is None:
        return []
    if tid is not None:
        stmt = stmt.where(ActionRecord.tenant_id == tid)
    if older_than_seconds:
        stmt = stmt.where(ActionRecord.updated_at < datetime.now(UTC) - timedelta(seconds=older_than_seconds))
    return [to_dict(r) for r in (await db.execute(stmt)).scalars().all()]


async def resolve(db: AsyncSession, action_id: str | UUID, *, outcome: ActionStatus, note: str, resolved_by: str | None) -> tuple[str, dict[str, Any] | None]:
    """An operator records what ACTUALLY happened to an action stuck in 'running' (after checking the real system). Atomic (only from 'running'); never executes anything.
    Returns ("resolved" | "not_found" | "conflict", record)."""
    uid = _uuid(action_id)
    if uid is not None:
        row = await _row(db, uid, fresh=True)
        if row is not None and row.status == _text(ActionStatus.RUNNING):
            result = {**(row.result or {}), "resolution": _jsonable({"outcome": _text(outcome), "note": note, "resolved_by": resolved_by, "resolved_at": datetime.now(UTC).isoformat()})}
            claimed = await db.execute(
                update(ActionRecord)
                .where(ActionRecord.id == uid, ActionRecord.status == _text(ActionStatus.RUNNING))
                .values(status=_text(outcome), result=result, updated_at=datetime.now(UTC))
            )
            await db.commit()
            if claimed.rowcount == 1:
                return "resolved", await get(db, uid)
    current = await get(db, action_id)
    return ("not_found", None) if current is None else ("conflict", current)
