"""B3: verify the /agents/investigate adapter returns AgentInvestigation shape.

The frontend expects {id, alertId, status, startedAt, findings?, ...}.
The legacy adapter used to return {run_id, case_id, status, message} which
broke AlertDetailView. This test ensures the contract stays correct and
that the GET poll endpoint maps internal state properly.
"""
from __future__ import annotations

import pytest


def test_agent_investigation_response_model_fields():
    """_AgentInvestigationResponse must have the fields the UI reads."""
    from app.api.investigate import _AgentInvestigationResponse

    resp = _AgentInvestigationResponse(
        id="run-123",
        alertId="alert-456",
        status="running",
        startedAt="2026-10-05T00:00:00Z",
    )
    assert resp.id == "run-123"
    assert resp.alertId == "alert-456"
    assert resp.status == "running"
    assert resp.startedAt == "2026-10-05T00:00:00Z"
    assert resp.findings is None
    assert resp.recommendations is None
    assert resp.completedAt is None


def test_agent_investigation_response_with_findings():
    """Completed investigations should carry findings and recommendations."""
    from app.api.investigate import _AgentInvestigationResponse

    resp = _AgentInvestigationResponse(
        id="run-789",
        alertId="alert-abc",
        status="completed",
        startedAt="2026-10-05T00:00:00Z",
        findings="## Summary\nIndicator matched known C2.",
        recommendations=["Block IP at firewall", "Rotate credentials"],
        completedAt="2026-10-05T00:05:00Z",
    )
    assert resp.status == "completed"
    assert "C2" in resp.findings
    assert len(resp.recommendations) == 2
    assert resp.completedAt is not None


def test_get_agent_investigation_returns_404_for_unknown_run():
    """GET /agents/investigations/{id} must 404, never fabricate data."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    resp = client.get("/api/v1/agents/investigations/nonexistent-run-id")
    assert resp.status_code == 404