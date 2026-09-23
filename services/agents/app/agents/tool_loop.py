"""LLM tool-calling loop (Wave 4a).

A minimal, provider-agnostic ReAct loop: bind the registry's tools to the model,
let the model choose which to call, execute the calls, feed results back, and
repeat until the model answers without a tool call (or a cap is hit). This is
the primitive that lets specialist agents *use tools* instead of reasoning over
a single pre-serialised blob.

Bounded + fail-soft: at most ``max_iters`` round-trips; tool errors come back to
the model as structured results (via ToolRegistry.execute) rather than aborting.
"""

from __future__ import annotations

import json
from typing import Any

import structlog
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from app.llm.contract import safe_ainvoke
from app.tools.registry import ToolRegistry

logger = structlog.get_logger()


async def run_with_tools(
    llm: Any,
    *,
    system: str,
    user: str,
    registry: ToolRegistry,
    max_iters: int = 4,
) -> dict[str, Any]:
    """Run a tool-calling conversation and return the final content + tool trace.

    Returns ``{"content": str, "tool_trace": [...], "iterations": int,
    "truncated": bool}``.
    """
    bound = llm.bind_tools(registry.openai_schemas())
    messages: list[Any] = [SystemMessage(content=system), HumanMessage(content=user)]
    trace: list[dict[str, Any]] = []

    for iteration in range(1, max_iters + 1):
        # Hal, live review, 2026-09-22: was bound.ainvoke(messages) directly
        # - flagged by this service's own test_llm_contract_no_bypass.py,
        # which exists specifically to catch this. safe_ainvoke's contract
        # validation, cost/token tracking (the dashboard's own comment:
        # "the high-volume auto-triage path is finally visible in the cost
        # dashboard"), and response caching all apply just as much to a
        # tools-bound model as a plain one - confirmed directly that a
        # real ChatOpenAI().bind_tools([]) still exposes .model via
        # attribute delegation, which is what safe_ainvoke's own cost-
        # tracking helper reads, so nothing about routing through it here
        # needed a different code path. Every agent that calls into tools
        # via this loop was invisible to cost tracking until this fix.
        response = await safe_ainvoke(bound, messages)
        messages.append(response)
        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            return {
                "content": _content(response),
                "tool_trace": trace,
                "iterations": iteration,
                "truncated": False,
            }
        for call in tool_calls:
            name = call.get("name", "")
            args = call.get("args", {}) or {}
            call_id = call.get("id", "") or ""
            result = await registry.execute(name, args)
            trace.append({"tool": name, "args": args, "result_preview": str(result)[:200]})
            messages.append(ToolMessage(content=json.dumps(result, default=str)[:4000], tool_call_id=call_id))

    logger.info("tool_loop.truncated", iterations=max_iters, tools_called=len(trace))
    return {"content": _content(messages[-1]), "tool_trace": trace, "iterations": max_iters, "truncated": True}


def _content(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, AIMessage):  # pragma: no cover - defensive
        return str(content.content)
    return str(content)
