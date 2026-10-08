"""
Action Execution Service REST API.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db import SessionProvider, get_db, get_session_provider
from app.models.action import ActionPrincipal, ActionRequest, ActionStatus
from app.security.authz import (
    ActionAuthzError,
    authorize_action,
    authorize_approver,
    require_service_auth,
)
from app.security.chatops_token import ChatOpsTokenError, verify_token
from app.services import action_store
from app.services.blast_radius import BlastRadiusGate
from app.services.executor_registry import EXECUTOR_REGISTRY
from app.services.timeline_client import TimelineClientError, post_timeline_event

logger = structlog.get_logger()
router = APIRouter()
gate = BlastRadiusGate()

# Actions are stored in Postgres (table response_actions; see app/services/action_store.py). They used to live in a process-local dict, so a restart lost pending approvals, ChatOps links and the
# record of what had run.

# ChatOps replay protection for responses to actions that have NO row (e.g. a verification prompt whose action was never stored). For an action that has a row, the first response is recorded
# atomically in the database (chatops_responded_at), so it survives a restart and a double click.
_chatops_replied: set[str] = set()


def _status_text(record: dict[str, Any]) -> str:
    """The action's status as a plain word ("running"), not the enum's repr ("ActionStatus.RUNNING"), for error messages."""
    status = record["status"]
    return str(getattr(status, "value", status))


@router.post("/actions", response_model=dict)
async def submit_action(request: ActionRequest, _auth: None = Depends(require_service_auth), db: AsyncSession = Depends(get_db)):
    """Submit an action for execution (may require approval)."""
    # W4.2 - least-privilege: the invoking principal must hold the permission
    # this action's blast radius demands before it is gated or executed.
    try:
        authorize_action(request)
    except ActionAuthzError as exc:
        logger.warning("Action authorization denied", action_type=request.action_type, reason=str(exc))
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    status, blast_radius, reason = gate.evaluate(request)

    record, created = await action_store.create(db, request, status=status, blast_radius=blast_radius, gate_reason=reason)
    if not created:
        # The same action id again (a client retry, say). It used to overwrite the stored record AND execute the action a second time.
        logger.info("Action already submitted; returning the existing record without executing it again", action_id=str(request.id), status=record["status"])
        return record

    # Auto-execute if approved
    if status == ActionStatus.APPROVED:
        executor = EXECUTOR_REGISTRY.get(request.action_type)
        if executor:
            # Claim before executing, so this action cannot be run twice even across processes.
            if await action_store.claim(db, request.id, expected=ActionStatus.APPROVED):
                try:
                    result = await executor.execute(request)
                    record = await action_store.finish(db, request.id, result.status, output=result.output, rollback_data=result.rollback_data, error=result.error)
                except Exception as exc:
                    logger.error("Action execution failed", error=str(exc), exc_info=True)
                    record = await action_store.finish(db, request.id, ActionStatus.FAILED, error=f"execution failed ({type(exc).__name__})")
        else:
            record = await action_store.finish(db, request.id, ActionStatus.FAILED, error=f"No executor found for action type: {request.action_type}")

    logger.info(
        "Action submitted",
        action_id=str(request.id),
        action_type=request.action_type,
        status=record["status"],
        blast_radius=blast_radius,
    )
    return record


@router.post("/actions/{action_id}/approve")
async def approve_action(
    action_id: str,
    approver: ActionPrincipal | None = None,
    _auth: None = Depends(require_service_auth),
    db: AsyncSession = Depends(get_db),
):
    """Approve and execute an action that is awaiting approval.

    W4.4 - when an approver identity is supplied it is bound: the approver must
    hold the action's required permission and must not be the requester. When
    principals are required (``AISOC_ACTIONS_REQUIRE_PRINCIPAL``) an approver is
    mandatory."""
    record = await action_store.get(db, action_id)
    if not record:
        raise HTTPException(status_code=404, detail="Action not found")
    if record["status"] != ActionStatus.AWAITING_APPROVAL:
        raise HTTPException(status_code=400, detail=f"Action is not awaiting approval (current: {_status_text(record)})")

    approver_user_id: str | None = None
    if approver is None:
        if get_settings().AISOC_ACTIONS_REQUIRE_PRINCIPAL:
            raise HTTPException(status_code=403, detail="an approver identity is required")
    else:
        try:
            authorize_approver(record, approver)
        except ActionAuthzError as exc:
            logger.warning("Approval denied", action_id=action_id, reason=str(exc))
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        approver_user_id = str(approver.user_id)

    # CLAIM the action before executing it: one atomic conditional UPDATE (awaiting_approval -> running), so exactly one approval can win even across processes and replicas. The status used to stay
    # "awaiting_approval" for the whole execution, so a second approval arriving meanwhile also executed the action. Authorisation happened above, so a refused approver cannot strand an action.
    if not await action_store.claim(db, action_id, expected=ActionStatus.AWAITING_APPROVAL, approved_by_user_id=approver_user_id):
        current = await action_store.get(db, action_id)
        raise HTTPException(status_code=400, detail=f"Action is not awaiting approval (current: {_status_text(current or record)})")

    # The ORIGINAL request, exactly as submitted. This used to be rebuilt from a record that had dropped parameters, requested_by, principal and auto_rollback,
    # so every action that needed approval (the high-blast-radius ones) executed without its parameters.
    request = await action_store.load_request(db, action_id)
    if request is None:  # cannot happen after a successful claim; fail visibly rather than guess
        raise HTTPException(status_code=500, detail="Action request could not be loaded")

    executor = EXECUTOR_REGISTRY.get(request.action_type)
    if executor:
        try:
            result = await executor.execute(request)
            record = await action_store.finish(db, action_id, result.status, output=result.output, rollback_data=result.rollback_data, error=result.error)
        except Exception as exc:
            logger.error("Approved action execution failed", action_id=action_id, error=str(exc), exc_info=True)
            record = await action_store.finish(db, action_id, ActionStatus.FAILED, error=f"execution failed ({type(exc).__name__})")
    else:
        record = await action_store.finish(db, action_id, ActionStatus.FAILED, error="No executor available")

    logger.info("Action approved and executed", action_id=action_id, status=record["status"])
    return record


@router.post("/actions/{action_id}/reject")
async def reject_action(action_id: str, _auth: None = Depends(require_service_auth), db: AsyncSession = Depends(get_db)):
    """Reject an action that is awaiting approval. Atomic: an action that is running or has already run is left exactly as it was."""
    outcome, record = await action_store.reject(db, action_id)
    if outcome == "not_found":
        raise HTTPException(status_code=404, detail="Action not found")
    if outcome == "conflict":
        raise HTTPException(status_code=400, detail=f"Action is not awaiting approval (current: {_status_text(record or {})})")
    logger.info("Action rejected", action_id=action_id)
    return record


@router.get("/actions/{action_id}")
async def get_action(action_id: str, _auth: None = Depends(require_service_auth), db: AsyncSession = Depends(get_db)):
    """Get an action's record."""
    record = await action_store.get(db, action_id)
    if not record:
        raise HTTPException(status_code=404, detail="Action not found")
    return record


_CHOICE_COPY: dict[str, dict[str, str]] = {
    "acknowledge": {
        "headline": "Thanks — recorded as acknowledged.",
        "body": "We've logged that you confirmed this activity. You can close this tab.",
    },
    "deny": {
        "headline": "Thanks — recorded as denied.",
        "body": (
            "We've flagged this as suspicious. A security analyst will follow up shortly. "
            "If you didn't expect this prompt, please contact your security team."
        ),
    },
    "escalate": {
        "headline": "Thanks — escalated to security.",
        "body": "We've routed this to your security team for review.",
    },
}


def _chatops_response_html(headline: str, body: str, *, ok: bool = True) -> str:
    """Tiny self-contained response page rendered to the user's browser.

    Slack/Teams open the callback URL in a normal browser tab, so we can't
    redirect into the AiSOC console (the user may not have one). A static
    HTML acknowledgement is the smallest UX that confirms the click landed
    without leaking incident details into a URL the user might forward.
    """
    color = "#0a7" if ok else "#a33"
    return (
        '<!doctype html><html lang="en"><head>'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>AiSOC verification</title>"
        "<style>"
        "body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;"
        "background:#0b1220;color:#e6edf3;margin:0;padding:0;display:flex;min-height:100vh;"
        "align-items:center;justify-content:center}"
        ".card{max-width:480px;background:#111827;border:1px solid #1f2937;border-radius:12px;"
        "padding:32px;box-shadow:0 8px 24px rgba(0,0,0,.4)}"
        f".dot{{width:12px;height:12px;border-radius:50%;background:{color};display:inline-block;margin-right:8px}}"
        "h1{margin:0 0 12px 0;font-size:18px;display:flex;align-items:center}"
        "p{margin:0;color:#9ca3af;line-height:1.5}"
        "</style></head><body>"
        f'<div class="card"><h1><span class="dot"></span>{headline}</h1><p>{body}</p></div>'
        "</body></html>"
    )


@router.get("/chatops/callback", response_class=HTMLResponse)
async def chatops_callback(token: str = Query(..., min_length=8), session_provider: SessionProvider = Depends(get_session_provider)):
    """Receive a user's response to a ChatOps verification prompt.

    The token is the HMAC-signed payload minted by
    :class:`app.executors.chatops.ChatOpsVerifyExecutor`. We re-verify
    the signature + expiry, dedupe against ``_chatops_replied``, write a
    ``chatops.verify.responded`` event onto the case timeline, and update
    the in-memory action record so ``GET /actions/{id}`` reflects the
    final status.

    Returns an HTML acknowledgement page so the click lands cleanly in
    Slack/Teams' default browser tab.
    """
    settings = get_settings()
    secret = settings.AISOC_CHATOPS_RESPONSE_SECRET

    try:
        claims = verify_token(token, secret)
    except ChatOpsTokenError as exc:
        reason = str(exc)
        logger.info("ChatOps callback rejected", reason=reason)
        message = {
            "expired": ("This verification link has expired. If you still need to respond, contact your security team."),
            "invalid_signature": "This verification link is invalid.",
        }.get(reason, "This verification link is invalid.")
        return HTMLResponse(
            content=_chatops_response_html("Couldn't record your response", message, ok=False),
            status_code=400,
        )

    # The signature is verified; only now is the database touched (a forged or malformed link never reaches it).
    async with session_provider() as db:
        action_id_str = str(claims.action_id)
        # The FIRST response is recorded atomically in the database (so it survives a restart and a double click). None means there is no stored action; those fall back to the in-process set.
        first_response = await action_store.mark_chatops_responded(db, action_id_str)
        if first_response is False or (first_response is None and action_id_str in _chatops_replied):
            return HTMLResponse(
                content=_chatops_response_html(
                    "Response already recorded",
                    "We've already logged a response for this prompt. No further action is needed.",
                ),
                status_code=200,
            )

        record = await action_store.get(db, action_id_str) if first_response is not None else None
        # We still record on the timeline even if the in-memory record is gone
        # (e.g. service restart). The case timeline is the durable store —
        # losing the local record shouldn't lose the user's reply.

        timeline_warning: str | None = None
        try:
            await post_timeline_event(
                case_id=claims.case_id,
                event_type="chatops.verify.responded",
                content=(f"User {claims.user_ref or 'unknown'} responded '{claims.choice}' to the ChatOps verification prompt."),
                metadata={
                    "action_id": action_id_str,
                    "tenant_id": str(claims.tenant_id),
                    "choice": claims.choice,
                    "user_ref": claims.user_ref,
                    "issued_at": claims.issued_at,
                    "responded_at": int(datetime.now(UTC).timestamp()),
                },
            )
        except TimelineClientError as exc:
            timeline_warning = str(exc)
            logger.warning(
                "ChatOps response timeline write failed",
                action_id=action_id_str,
                case_id=str(claims.case_id),
                error=timeline_warning,
            )

        if first_response is None:
            _chatops_replied.add(action_id_str)

        if record is not None:
            output = dict(record.get("output") or {})
            output.update(
                {
                    "user_choice": claims.choice,
                    "user_ref": claims.user_ref,
                    "responded_at": datetime.now(UTC).isoformat(),
                }
            )
            if timeline_warning:
                output["timeline_warning"] = timeline_warning
            await action_store.finish(db, action_id_str, ActionStatus.COMPLETED, output=output)

        logger.info(
            "ChatOps response recorded",
            action_id=action_id_str,
            case_id=str(claims.case_id),
            choice=claims.choice,
        )

        copy = _CHOICE_COPY.get(claims.choice, _CHOICE_COPY["acknowledge"])
        return HTMLResponse(
            content=_chatops_response_html(copy["headline"], copy["body"]),
            status_code=200,
        )


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-actions"}
