"""The engine hands the promotions it caused to the sink on the fused alert, so a case can be opened for them."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from app.models.alert import AlertSeverity, FusionDecision, RawAlert
from app.services.entity_risk import EntityRiskRecord
from app.services.fusion_engine import FusionEngine


class _Dedup:
    async def is_duplicate(self, alert):
        return False, None

    async def register(self, alert):
        return None


class _Correlator:
    async def correlate(self, alert):
        return False, SimpleNamespace(id=uuid.uuid4(), alert_count=1)


class _Risk:
    enabled = True

    def __init__(self, promotions):
        self._promotions = promotions

    async def observe(self, alert):
        return self._promotions


def _alert():
    return RawAlert(
        tenant_id=uuid.uuid4(),
        source="CrowdStrike Falcon",
        title="Credential dumping via LSASS access",
        severity=AlertSeverity.HIGH,
        hostname="WIN-DC01",
        connector_id=uuid.uuid4(),
        connector_type="crowdstrike_falcon",
        source_event_ids=["e1"],
        ocsf_class_uid=2004,
    )


def _record(**over):
    base = dict(
        tenant_id="t",
        entity_type="host",
        entity_value="WIN-DC01",
        score=91.5,
        alert_count=4,
        last_seen=datetime.now(UTC).replace(tzinfo=None),
        contributing_alerts=[str(uuid.uuid4())],
        severities={"high": 4},
        promoted_at=datetime.now(UTC).replace(tzinfo=None),
        contributors=[{"alert_id": "x", "points": 20, "big": "payload" * 100}],
    )
    base.update(over)
    return EntityRiskRecord(**base)


@pytest.mark.asyncio
async def test_a_promotion_is_carried_on_the_fused_alert_without_the_bulky_contributor_detail():
    engine = FusionEngine(_Dedup(), _Correlator(), entity_risk=_Risk([_record()]))
    fused = await engine.process(_alert())
    assert fused.fusion_decision is FusionDecision.NEW_INCIDENT
    (promotion,) = fused.enrichments["rba_promotions"]
    assert promotion["entity_type"] == "host" and promotion["entity_value"] == "WIN-DC01" and promotion["score"] == 91.5
    assert "contributors" not in promotion


@pytest.mark.asyncio
async def test_no_promotion_leaves_the_key_out_entirely():
    engine = FusionEngine(_Dedup(), _Correlator(), entity_risk=_Risk([]))
    fused = await engine.process(_alert())
    assert "rba_promotions" not in fused.enrichments
