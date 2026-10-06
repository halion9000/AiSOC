"""GET /api/v1/health: the web UI's reachability probe (CopilotDock).

It must answer 200 without credentials, and it must appear in the OpenAPI
schema so the B10 frontend-route gate can see it.
"""
from fastapi.testclient import TestClient

from app.main import app


def test_api_v1_health_answers_without_auth() -> None:
    client = TestClient(app)
    resp = client.get("/api/v1/health")  # no Authorization header on purpose
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"status": "healthy", "service": "aisoc-api"}


def test_api_v1_health_is_in_the_openapi_schema() -> None:
    assert "/api/v1/health" in app.openapi()["paths"]
