"""A result that ran nothing says so.

With no vendor credentials an executor returned COMPLETED with an id like ``SIM-ISO-host``: the record, the case timeline and the UI then showed the host isolated while it was still on the network. The status stays
(simulation is a supported demo mode) but the result now carries ``simulated=True``, so a reader can tell a real action from a rehearsal.
"""

from __future__ import annotations

import uuid

import pytest
from app.executors.endpoint import IsolateHostExecutor
from app.models.action import ActionRequest, ActionResult, ActionStatus, ActionType, BlastRadius


def _result(output):
    return ActionResult(action_id=uuid.uuid4(), status=ActionStatus.COMPLETED, blast_radius=BlastRadius.HIGH, output=output)


def test_a_real_result_is_not_marked_simulated():
    assert _result({"action": "isolate_host", "isolation_id": "iso-123"}).simulated is False


def test_a_result_with_the_simulation_note_or_id_is_marked():
    assert _result({"note": "Simulation mode — provide cs_client_id ..."}).simulated is True
    assert _result({"isolation_id": "SIM-ISO-host-1"}).simulated is True


def test_an_explicit_flag_is_kept():
    assert (
        ActionResult(action_id=uuid.uuid4(), status=ActionStatus.COMPLETED, blast_radius=BlastRadius.LOW, simulated=True).simulated is True
    )


@pytest.mark.asyncio
async def test_isolate_host_without_credentials_reports_simulated():
    request = ActionRequest(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        action_type=ActionType.ISOLATE_HOST,
        target="host-1",
        rationale="test",
        requested_by="agent",
        parameters={},
    )
    result = await IsolateHostExecutor().execute(request)
    assert result.status is ActionStatus.COMPLETED and result.simulated is True
