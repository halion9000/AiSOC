"""
Pillar-1 Investigation API
==========================
Endpoints:
  POST /api/v1/cases/{case_id}/investigate     → launch async investigation
  GET  /api/v1/investigations/{run_id}         → poll status + results
  GET  /api/v1/investigations/{run_id}/report.md
  GET  /api/v1/investigations/{run_id}/report.html
  GET  /api/v1/investigations/{run_id}/report.pdf  → weasyprint PDF
  WS   /api/v1/investigations/{run_id}/stream  → SSE-style step stream
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from app.investigator import InvestigatorOrchestrator
from app.orchestrator.router import RouterOrchestrator

logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1", tags=["investigations"])

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_REALTIME_URL = os.environ.get("REALTIME_URL", "http://realtime:8086")
_INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")

# ---------------------------------------------------------------------------
# Orchestrator selection
# ---------------------------------------------------------------------------
# T2.2: route /investigate through the four-agent ``RouterOrchestrator`` when
# the flag is on; otherwise keep the legacy ``InvestigatorOrchestrator`` path.
# Read at call time so operators can flip without restarting the service.
USE_ROUTER_FLAG = "AISOC_INVESTIGATE_USE_ROUTER"


def is_router_investigate_enabled() -> bool:
    """Return True if /investigate should use ``RouterOrchestrator`` (default off).

    Explicit truthy values (``1`` / ``true`` / ``yes`` / ``on`` / ``enabled``,
    case-insensitive) opt into the router path; everything else, including the
    unset case, keeps the investigator path. Mirrors the convention used by
    :func:`app.orchestrator.router.is_parallel_topology_enabled`.
    """
    raw = os.environ.get(USE_ROUTER_FLAG)
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}


# ---------------------------------------------------------------------------
# Simple in-memory run store (swap for Redis in production)
# ---------------------------------------------------------------------------
_runs: dict[str, dict[str, Any]] = {}
_orch = InvestigatorOrchestrator()
_router_orch = RouterOrchestrator()


def _investigate_stream(
    *,
    case_id: str,
    alert_summary: str,
    raw_alert: dict[str, Any],
    tenant_id: str,
    run_id: UUID | None = None,
):
    """Pick the orchestrator at call time based on ``AISOC_INVESTIGATE_USE_ROUTER``.

    Both orchestrators expose an investigator-compatible ``stream`` /
    ``stream_kwargs`` surface that yields the same ``step`` / ``done`` /
    ``error`` event taxonomy, so the consumer below can stay shape-agnostic.
    """
    if is_router_investigate_enabled():
        return _router_orch.stream_kwargs(
            case_id=case_id,
            alert_summary=alert_summary,
            raw_alert=raw_alert,
            tenant_id=tenant_id,
            run_id=run_id,
        )
    return _orch.stream(
        case_id=case_id,
        alert_summary=alert_summary,
        raw_alert=raw_alert,
        tenant_id=tenant_id,
        run_id=run_id,
    )


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class InvestigateRequest(BaseModel):
    alert_summary: str
    raw_alert: dict[str, Any] = {}
    tenant_id: str = "default"


class InvestigateResponse(BaseModel):
    run_id: str
    case_id: str
    status: str
    message: str


# ---------------------------------------------------------------------------
# Realtime broadcast helper
# ---------------------------------------------------------------------------


async def _emit_event(run_id: str, tenant_id: str, event: dict[str, Any]) -> None:
    """Forward an agent step event to the realtime service (best-effort)."""
    url = f"{_REALTIME_URL}/internal/agent-event"
    headers = {}
    if _INTERNAL_TOKEN:
        headers["x-internal-token"] = _INTERNAL_TOKEN
    payload = {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "kind": event.get("kind", "step"),
        "agent": event.get("agent", "unknown"),
        "summary": event.get("summary", ""),
        "data": event.get("data"),
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(url, json=payload, headers=headers)
    except Exception as exc:  # noqa: BLE001
        logger.debug("realtime_emit_skipped", reason=str(exc))


# ---------------------------------------------------------------------------
# Background task: runs investigation and streams steps to realtime service
# ---------------------------------------------------------------------------


async def _run_and_store(run_id: str, case_id: str, req: InvestigateRequest) -> None:
    audit_log: list[dict[str, Any]] = []
    # Reuse the API-issued run id as the ledger row id so consumers can
    # cross-reference the realtime stream and the persisted timeline.
    try:
        run_uuid = UUID(run_id)
    except (ValueError, TypeError):
        run_uuid = uuid4()
    try:
        # Use the streaming orchestrator so we can emit events progressively.
        # ``_investigate_stream`` picks investigator vs. router at call time
        # based on ``AISOC_INVESTIGATE_USE_ROUTER``.
        async for event in _investigate_stream(
            case_id=case_id,
            alert_summary=req.alert_summary,
            raw_alert=req.raw_alert,
            tenant_id=req.tenant_id,
            run_id=run_uuid,
        ):
            if event.get("type") == "step":
                audit_log.append(event)
                # Update the in-memory run so pollers see progress
                _runs[run_id]["audit_log"] = audit_log
                # Broadcast to realtime → WebSocket clients
                await _emit_event(run_id, req.tenant_id, event)

            elif event.get("type") == "done":
                state_data = event.get("state", {})
                _runs[run_id].update(
                    {
                        "status": "completed",
                        "report_md": state_data.get("report_md", ""),
                        "report_html": state_data.get("report_html", ""),
                        "audit_log": audit_log,
                        "recon": state_data.get("recon", {}),
                        "forensic": state_data.get("forensic", {}),
                        "responder": state_data.get("responder", {}),
                        "completed_at": datetime.utcnow().isoformat(),
                        "error": None,
                    }
                )
                await _emit_event(
                    run_id,
                    req.tenant_id,
                    {
                        "kind": "completed",
                        "agent": "orchestrator",
                        "summary": "Investigation completed",
                        "data": {"status": "completed"},
                    },
                )

            elif event.get("type") == "error":
                err_msg = event.get("error", "Unknown error")
                _runs[run_id].update({"status": "failed", "error": err_msg})
                await _emit_event(
                    run_id,
                    req.tenant_id,
                    {
                        "kind": "error",
                        "agent": "orchestrator",
                        "summary": err_msg,
                        "data": {"status": "failed"},
                    },
                )

    except Exception as exc:  # noqa: BLE001
        logger.error("investigation_bg_task failed", run_id=run_id, error=str(exc))
        _runs[run_id].update({"status": "failed", "error": str(exc)})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/cases/{case_id}/investigate", response_model=InvestigateResponse)
async def launch_investigation(
    case_id: str,
    body: InvestigateRequest,
    background_tasks: BackgroundTasks,
):
    """Launch a Pillar-1 autonomous investigation for a case."""
    run_id = str(uuid4())
    _runs[run_id] = {
        "run_id": run_id,
        "case_id": case_id,
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
    }
    background_tasks.add_task(_run_and_store, run_id, case_id, body)
    logger.info("investigation.launched", run_id=run_id, case_id=case_id)
    return InvestigateResponse(
        run_id=run_id,
        case_id=case_id,
        status="running",
        message=f"Investigation started. Poll GET /api/v1/investigations/{run_id}",
    )


@router.get("/investigations/{run_id}")
async def get_investigation(run_id: str):
    """Poll investigation status and results."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")
    # Strip large fields from polling response — use dedicated endpoints instead
    slim = {k: v for k, v in run.items() if k not in ("report_md", "report_html")}
    return slim


@router.get("/investigations/{run_id}/report.md", response_class=PlainTextResponse)
async def get_report_md(run_id: str):
    """Download the Markdown incident report."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"Investigation is {run['status']}")
    return run.get("report_md", "")


# B5 fix: case-scoped alias so the frontend's fetch of
# /api/v1/cases/{case_id}/investigations/{run_id}/report.md resolves here.
# The canonical route above doesn't include case_id because runs are globally
# unique by UUID; this alias accepts and ignores it for URL compatibility.
@router.get(
    "/cases/{case_id}/investigations/{run_id}/report.md",
    response_class=PlainTextResponse,
)
async def get_report_md_case_scoped(case_id: str, run_id: str):
    """Case-scoped alias for get_report_md (B5 frontend compat)."""
    return await get_report_md(run_id)


@router.get("/investigations/{run_id}/report.html", response_class=HTMLResponse)
async def get_report_html(run_id: str):
    """Download the HTML incident report."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"Investigation is {run['status']}")
    return run.get("report_html", "<html><body>No report yet.</body></html>")


@router.get("/investigations/{run_id}/report.pdf")
async def get_report_pdf(run_id: str):
    """Download the PDF incident report (rendered from HTML via weasyprint)."""
    from fastapi.responses import Response as FastAPIResponse

    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"Investigation is {run['status']}")

    html_content: str = run.get("report_html", "")
    if not html_content:
        raise HTTPException(status_code=404, detail="Report not yet generated")

    try:
        import weasyprint  # type: ignore

        pdf_bytes: bytes = weasyprint.HTML(string=html_content).write_pdf()
        return FastAPIResponse(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="aisoc-report-{run_id}.pdf"'},
        )
    except ImportError as exc:
        # weasyprint not installed — return the HTML with a PDF content-type note
        raise HTTPException(
            status_code=501,
            detail="PDF generation requires weasyprint. Install with: pip install weasyprint",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc


@router.websocket("/investigations/{run_id}/stream")
async def stream_investigation(ws: WebSocket, run_id: str):
    """
    WebSocket stream: emits per-step JSON events as the pipeline progresses.

    Two modes:
    1. If the run is already in _runs (background task is running), replay
       its current audit_log and then long-poll for completion.
    2. If query params case_id + alert_summary are supplied, run a fresh
       investigation directly on this connection (dev/test use-case).
    """
    case_id = ws.query_params.get("case_id", run_id)
    alert_summary = ws.query_params.get("alert_summary", "")
    tenant_id = ws.query_params.get("tenant_id", "default")

    await ws.accept()
    try:
        # If a background run exists, tail it via polling
        if run_id in _runs:
            seen = 0
            while True:
                run = _runs.get(run_id, {})
                audit = run.get("audit_log", [])
                # Send any new audit entries
                for entry in audit[seen:]:
                    await ws.send_text(json.dumps({"type": "step", **entry}))
                seen = len(audit)

                status = run.get("status", "running")
                if status in ("completed", "failed"):
                    await ws.send_text(
                        json.dumps(
                            {
                                "type": "done" if status == "completed" else "error",
                                "case_id": case_id,
                                "status": status,
                                "error": run.get("error"),
                            }
                        )
                    )
                    break
                await asyncio.sleep(0.5)
        else:
            # Direct streaming for ad-hoc calls; orchestrator selected by flag.
            async for event in _investigate_stream(
                case_id=case_id,
                alert_summary=alert_summary,
                raw_alert={},
                tenant_id=tenant_id,
            ):
                await ws.send_text(json.dumps(event))
    except WebSocketDisconnect:
        logger.info("ws.disconnected", run_id=run_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("ws.error", run_id=run_id, error=str(exc))
        await ws.close(code=1011)


# ---------------------------------------------------------------------------
# B3 adapter: legacy /api/v1/agents/investigate → case-scoped investigate
# ---------------------------------------------------------------------------
# The frontend's agentsApi.investigate(alertId) posts {alertId} to this path.
# No backend served it before; the real entry point is POST /cases/{case_id}/
# investigate which expects {alert_summary, raw_alert, tenant_id}. This thin
# adapter fetches the alert from the core API, derives a case_id (using the
# alert's own caseId when present, otherwise falling back to the alert id),
# and delegates to the existing launch_investigation handler so the frontend
# contract keeps working without changes beyond the next.config.js rewrite.


class _LegacyInvestigateRequest(BaseModel):
    alertId: str


class _AgentInvestigationResponse(BaseModel):
    """Shape expected by the frontend's AgentInvestigation interface."""
    id: str
    alertId: str
    status: str
    startedAt: str
    findings: str | None = None
    recommendations: list[str] | None = None
    completedAt: str | None = None


@router.post("/agents/investigate", response_model=_AgentInvestigationResponse)
async def legacy_investigate(
    body: _LegacyInvestigateRequest,
    background_tasks: BackgroundTasks,
):
    """Adapter for the frontend's agentsApi.investigate({alertId}).

    Returns the AgentInvestigation shape the UI expects. If the alert
    cannot be fetched from the core API, returns 502 instead of
    fabricating a stub alert.
    """
    import httpx
    from fastapi import HTTPException as FastAPIHTTPException

    api_url = os.environ.get("API_URL", "http://api:8000")
    alert_id = body.alertId
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{api_url}/api/v1/alerts/{alert_id}")
            resp.raise_for_status()
            alert = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.error("legacy_investigate.alert_fetch_failed", alert_id=alert_id, error=str(exc))
        raise FastAPIHTTPException(
            status_code=502,
            detail=f"Could not fetch alert {alert_id} from core API: {exc}",
        )

    case_id = str(alert.get("caseId") or alert.get("case_id") or alert_id)
    tenant_id = str(alert.get("tenantId") or alert.get("tenant_id") or "default")
    alert_summary = str(alert.get("title") or alert.get("description") or alert_id)

    req = InvestigateRequest(
        alert_summary=alert_summary,
        raw_alert=alert,
        tenant_id=tenant_id,
    )
    result = await launch_investigation(case_id=case_id, body=req, background_tasks=background_tasks)

    # Store the alertId on the run so the poll endpoint can return it
    _runs[result.run_id]["alert_id"] = alert_id

    return _AgentInvestigationResponse(
        id=result.run_id,
        alertId=alert_id,
        status=result.status,
        startedAt=_runs[result.run_id].get("started_at", datetime.utcnow().isoformat()),
    )


@router.get("/agents/investigations/{run_id}", response_model=_AgentInvestigationResponse)
async def get_agent_investigation(run_id: str):
    """Poll endpoint returning AgentInvestigation shape for the UI.

    Maps the internal _runs state to the frontend's expected shape,
    populating findings when the investigation completes.
    """
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")

    # Map internal status to frontend status values
    status_map = {
        "running": "running",
        "completed": "completed",
        "failed": "failed",
        "pending": "pending",
    }
    fe_status = status_map.get(run.get("status", "pending"), "running")

    # Extract findings from report_md if completed
    findings = None
    recommendations = None
    completed_at = run.get("completed_at")
    if fe_status == "completed":
        findings = run.get("report_md") or run.get("summary")
        # Try to extract recommendations from structured results
        results = run.get("results")
        if isinstance(results, dict):
            recommendations = results.get("recommendations")

    return _AgentInvestigationResponse(
        id=run_id,
        alertId=run.get("alert_id", ""),
        status=fe_status,
        startedAt=run.get("started_at", ""),
        findings=findings,
        recommendations=recommendations,
        completedAt=completed_at,
    )
