"""POST /api/v1/copilot/chat — real LLM-backed analyst copilot.

Wires the CopilotDock (and eventually CopilotView) to the existing LiteLLM
gateway via the same ``make_chat_model`` / ``safe_ainvoke`` path that the
investigation pipeline already uses.  The ``aisoc-copilot`` alias is pinned
in ``model_pins.py`` and routed through whatever provider CORE's active
config points at (GhostCLI today, OpenRouter or local tomorrow).

Conversation history is persisted in Postgres (``copilot_conversations``), keyed by (tenant, owner, conversation) so follow-up questions work across restarts and a conversation id from another
tenant or user is simply an unknown id. It used to be a module-level dict keyed by the client-supplied conversationId alone: a restart silently dropped the model's memory while the UI still showed
the chat, any holder of another tenant's id could read and write that conversation, and its LRU was global so one tenant evicted everyone else's. See ``app/services/copilot_history.py``.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, require_permission
from app.copilot_tools import COPILOT_TOOL_SCHEMAS, execute_copilot_tool
from app.db.rls import TenantDBSession
from app.llm.contract import safe_ainvoke
from app.llm.factory import make_chat_model
from app.services import copilot_history

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/copilot", tags=["copilot"])

# ---------------------------------------------------------------------------
# Request / response shapes — must match apps/web/src/lib/api.ts
# ---------------------------------------------------------------------------


class CopilotContext(BaseModel):
    alertId: str | None = None
    caseId: str | None = None
    entity: str | None = None
    page: str | None = None


class CopilotChatRequest(BaseModel):
    conversationId: str | None = None
    message: str = Field(..., min_length=1)
    context: CopilotContext | None = None


class CopilotMessageOut(BaseModel):
    id: str
    role: str  # "user" | "assistant"
    content: str
    createdAt: str
    suggestions: list[str] | None = None


class CopilotChatResponse(BaseModel):
    conversationId: str
    reply: CopilotMessageOut
    degraded: bool = False


# ---------------------------------------------------------------------------
# System prompt — scoped to SOC analyst work
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are AiSOC Copilot, an AI assistant embedded in a Security Operations \
Center console. You help analysts triage alerts, investigate incidents, \
understand detection rules, and navigate the platform.

Guidelines:
- Be concise and actionable. Lead with the answer, not the reasoning.
- When referencing alerts, cases, hosts, or users, include their IDs so \
the analyst can jump to them.
- If you don't have enough context to answer, say what information would \
help rather than guessing.
- Never fabricate alert data, case details, or IOC values.
- Keep responses under 300 words unless the analyst asks for detail.
- If the analyst's message is not about the SOC environment (a greeting, \
a question about who or what you are, small talk), answer that plainly \
and briefly. Only produce security analysis when there is real alert, \
case, or entity data to analyze — either provided in context or from a \
tool call you actually made. Never invent a hypothetical incident, alert, \
or entity to illustrate a point.
"""


def _context_snippet(ctx: CopilotContext | None) -> str:
    """Build a short context line from the current page state."""
    if ctx is None:
        return ""
    parts: list[str] = []
    if ctx.page:
        parts.append(f"Current page: {ctx.page}")
    if ctx.alertId:
        parts.append(f"Viewing alert: {ctx.alertId}")
    if ctx.caseId:
        parts.append(f"Viewing case: {ctx.caseId}")
    if ctx.entity:
        parts.append(f"Focused entity: {ctx.entity}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/chat",
    response_model=CopilotChatResponse,
    status_code=status.HTTP_200_OK,
    summary="Send a message to the AI copilot and get a real LLM response.",
)
async def copilot_chat(
    body: CopilotChatRequest,
    user: Annotated[AuthUser, Depends(require_permission("copilot:use"))],
    db: TenantDBSession,
) -> CopilotChatResponse:
    """Route a copilot message through the LiteLLM gateway.

    Falls back to a deterministic error message if the LLM call fails —
    the dock treats any non-2xx as demo-mode, so we always return 200
    with *something* useful even when the gateway is unreachable.
    The ``degraded`` flag in the response tells the frontend whether the
    reply came from the real model or from the fallback path.
    """
    conversation_id = body.conversationId or str(uuid.uuid4())
    if not copilot_history.valid_conversation_id(conversation_id):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="conversationId must be 1-100 characters from A-Z a-z 0-9 . _ : -")
    owner = copilot_history.owner_key(user)
    # History is looked up by (tenant, owner, conversation), never by the client-supplied id alone.
    history = await copilot_history.load_history(db, user.tenant_id, owner, conversation_id)
    await db.rollback()  # release the connection: the model call below can take many seconds

    # Build the full message list: system prompt + context + stored history
    # + new user message. System/context messages are NOT stored — they're
    # rebuilt per request so context changes (page navigation) take effect.
    messages: list[Any] = [SystemMessage(content=_SYSTEM_PROMPT)]
    ctx_line = _context_snippet(body.context)
    if ctx_line:
        messages.append(SystemMessage(content=f"[Analyst context]\n{ctx_line}"))
    messages.extend(history)
    messages.append(HumanMessage(content=body.message))

    degraded = False
    content = ""
    try:
        llm = make_chat_model("copilot", temperature=0.3, max_tokens=1024)
        bound = llm.bind_tools(COPILOT_TOOL_SCHEMAS)
        tenant_id = str(user.tenant_id)
        max_tool_iters = 6
        for _iteration in range(max_tool_iters):
            result = await safe_ainvoke(bound, messages)
            messages.append(result)
            tool_calls = getattr(result, "tool_calls", None) or []
            if not tool_calls:
                content = getattr(result, "content", "") or ""
                break
            for call in tool_calls:
                name = call.get("name", "")
                args = call.get("args", {}) or {}
                call_id = call.get("id", "") or ""
                tool_result = await execute_copilot_tool(name, args, tenant_id, user=user)
                messages.append(
                    ToolMessage(
                        content=json.dumps(tool_result, default=str)[:4000],
                        tool_call_id=call_id,
                    )
                )
        else:
            content = getattr(result, "content", "") or ""
            # (This used structlog-style keyword arguments on a STDLIB logger, which raises TypeError: the warning itself crashed, the outer except caught it, and a model that was working was reported
            # to the analyst as "couldn't reach the LLM backend".)
            logger.warning("copilot.tool_loop.truncated iterations=%s", max_tool_iters)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Copilot LLM call failed: %s", exc, exc_info=True)
        degraded = True
        content = (
            "I couldn't reach the LLM backend right now. "
            "Check that the LiteLLM gateway is running and that CORE's "
            "provider config is synced (rebuild AISOC or run "
            "`syncAisocProviderConfig()` from the HUD)."
        )

    # Store this turn in conversation history — but only if the LLM call
    # actually succeeded. Storing fallback apologies as real assistant turns
    # would poison future context when the gateway recovers.
    if not degraded:
        try:
            await copilot_history.append_turn(db, user.tenant_id, owner, conversation_id, body.message, content)
        except Exception:  # noqa: BLE001
            # The analyst still gets the answer they waited for; only the stored context for their NEXT message is lost.
            logger.warning("copilot.history.save_failed conversation=%s", conversation_id, exc_info=True)
            try:
                await db.rollback()
            except Exception:  # noqa: BLE001
                pass

    reply = CopilotMessageOut(
        id=str(uuid.uuid4()),
        role="assistant",
        content=content,
        createdAt=__import__("datetime").datetime.now(
            tz=__import__("datetime").timezone.utc
        ).isoformat(),
        suggestions=None,
    )

    return CopilotChatResponse(conversationId=conversation_id, reply=reply, degraded=degraded)