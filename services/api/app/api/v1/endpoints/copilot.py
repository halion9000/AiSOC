"""POST /api/v1/copilot/chat — real LLM-backed analyst copilot.

Wires the CopilotDock (and eventually CopilotView) to the existing LiteLLM
gateway via the same ``make_chat_model`` / ``safe_ainvoke`` path that the
investigation pipeline already uses.  The ``aisoc-copilot`` alias is pinned
in ``model_pins.py`` and routed through whatever provider CORE's active
config points at (GhostCLI today, OpenRouter or local tomorrow).

Conversation history is kept in-memory (module-level dict keyed by
conversationId) so follow-up questions actually work.  A persistent store
(Postgres-backed ``copilot_conversations`` table) is a deliberate follow-up
once this endpoint is proven working end-to-end.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import OrderedDict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, require_permission
from app.llm.contract import safe_ainvoke
from app.llm.factory import make_chat_model

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/copilot", tags=["copilot"])

# ---------------------------------------------------------------------------
# In-memory conversation store
# ---------------------------------------------------------------------------

_MAX_HISTORY_PER_CONVERSATION = 40  # keep last N turns to bound token usage
_MAX_CONVERSATIONS = 500  # evict oldest when exceeded

# OrderedDict gives us O(1) move_to_end + popitem(last=False) for LRU eviction.
# Values are lists of LangChain message objects (SystemMessage excluded — those
# are rebuilt per request from _SYSTEM_PROMPT + context).
_conversation_store: OrderedDict[str, list[BaseMessage]] = OrderedDict()


def _get_or_create_history(conversation_id: str) -> list[BaseMessage]:
    """Return the stored message list for a conversation, creating if needed."""
    if conversation_id in _conversation_store:
        _conversation_store.move_to_end(conversation_id)
        return _conversation_store[conversation_id]
    # Evict oldest if at capacity
    while len(_conversation_store) >= _MAX_CONVERSATIONS:
        _conversation_store.popitem(last=False)
    history: list[BaseMessage] = []
    _conversation_store[conversation_id] = history
    return history

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
    user: AuthUser = Depends(require_permission("copilot:use")),
) -> CopilotChatResponse:
    """Route a copilot message through the LiteLLM gateway.

    Falls back to a deterministic error message if the LLM call fails —
    the dock treats any non-2xx as demo-mode, so we always return 200
    with *something* useful even when the gateway is unreachable.
    The ``degraded`` flag in the response tells the frontend whether the
    reply came from the real model or from the fallback path.
    """
    conversation_id = body.conversationId or str(uuid.uuid4())
    history = _get_or_create_history(conversation_id)

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
    try:
        llm = make_chat_model("copilot", temperature=0.3, max_tokens=1024)
        result = await safe_ainvoke(llm, messages)
        content = getattr(result, "content", "") or ""
    except Exception as exc:  # noqa: BLE001
        logger.warning("Copilot LLM call failed: %s", exc, exc_info=True)
        degraded = True
        content = (
            "I couldn't reach the LLM backend right now. "
            "Check that the LiteLLM gateway is running and that CORE's "
            "provider config is synced (rebuild AISOC or run "
            "`syncAisocProviderConfig()` from the HUD)."
        )

    # Store this turn in conversation history (both user and assistant).
    # Trim to _MAX_HISTORY_PER_CONVERSATION to bound token usage.
    history.append(HumanMessage(content=body.message))
    history.append(AIMessage(content=content))
    while len(history) > _MAX_HISTORY_PER_CONVERSATION:
        history.pop(0)

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