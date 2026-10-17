"""The alert detail response must carry the stored raw event (the web Raw tab reads it)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

from app.api.v1.endpoints.alerts import AlertDetailResponse, AlertResponse


def _alert(raw_event):
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        title="t",
        description=None,
        severity="high",
        status="new",
        priority=1,
        category=None,
        mitre_tactics=[],
        mitre_techniques=[],
        connector_type=None,
        ai_score=None,
        ai_summary=None,
        ai_recommendations=[],
        affected_ips=[],
        affected_hosts=[],
        affected_users=[],
        case_id=None,
        tags=[],
        event_time=now,
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
        raw_event=raw_event,
    )


def test_detail_carries_raw_event():
    raw = {"source": "huntress", "device": {"name": "PC-1"}}
    assert AlertDetailResponse.model_validate(_alert(raw)).raw_event == raw


def test_detail_empty_raw_event_is_empty_object():
    assert AlertDetailResponse.model_validate(_alert({})).raw_event == {}


def test_list_shape_stays_light():
    assert "raw_event" not in AlertResponse.model_fields
