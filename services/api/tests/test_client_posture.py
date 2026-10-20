"""The device part of one client's posture (pure)."""

import uuid

from app.api.v1.endpoints import client_posture as ep


def test_devices_part_picks_the_clients_row_and_is_zero_for_a_client_without_devices():
    a, b = uuid.uuid4(), uuid.uuid4()
    rows = [ep.ClientRollup(client_id=a, client_name="A", devices=4, needs_attention=2, stale_agents=1, not_in_huntress=3, offline=1)]
    assert ep.devices_part(rows, a).model_dump() == {
        "devices": 4,
        "needs_attention": 2,
        "stale_agents": 1,
        "not_in_huntress": 3,
        "offline": 1,
    }
    assert ep.devices_part(rows, b).devices == 0
