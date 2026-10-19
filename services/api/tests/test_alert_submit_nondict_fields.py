"""A submitted event whose ``actor`` / ``client`` / ``geographicalContext`` is not an object no longer fails the whole batch with a 500.

``events: list[dict]`` only checks the top level; ``event.get("actor") or {}`` followed by ``.get`` raised AttributeError for a string, so a connector that sent ``"client": "1.2.3.4"`` lost its batch.
"""

from __future__ import annotations

import uuid

import pytest
from app.api.v1.endpoints.alerts import _synthesise_alert_from_events


def _synth(events):
    return _synthesise_alert_from_events(
        tenant_id=uuid.uuid4(),
        events=events,
        connector_type=None,
        override_title=None,
        override_description=None,
        override_severity=None,
        override_tags=None,
    )


@pytest.mark.parametrize(
    "event",
    [
        {"actor": "bob", "severity": "high"},
        {"client": "1.2.3.4", "severity": "high"},
        {"client": {"geographicalContext": "somewhere"}, "severity": "high"},
        {"actor": ["a", "b"], "client": 7},
    ],
)
def test_non_object_nested_fields_do_not_raise(event):
    alert = _synth([event])
    assert alert.title and alert.affected_users == [] or alert.affected_users is not None


def test_well_formed_nested_fields_are_still_read():
    alert = _synth(
        [{"actor": {"alternateId": "bob@example.test"}, "client": {"ipAddress": "1.2.3.4", "device": "PC-1"}, "severity": "high"}]
    )
    assert alert.affected_users == ["bob@example.test"]
    assert alert.affected_ips == ["1.2.3.4"]
    assert alert.affected_hosts == ["PC-1"]
