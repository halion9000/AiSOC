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


def test_posture_carries_the_tools_the_client_is_mapped_to():
    import uuid
    from datetime import UTC, datetime

    from app.api.v1.endpoints.client_posture import ClientPosture, PostureAlerts, PostureDevices, PostureTool

    base = {"client_id": uuid.uuid4(), "client_name": "Acme", "generated_at": datetime.now(UTC), "devices": PostureDevices(), "identity": None, "alerts": PostureAlerts(open=0, critical=0, high=0, without_ticket=0), "open_cases": 0}
    assert ClientPosture(**base).tools == []
    p = ClientPosture(**base, tools=[PostureTool(vendor="ninjaone", vendor_client_id="83", vendor_client_name="Acme")])
    assert (p.tools[0].vendor, p.tools[0].vendor_client_id) == ("ninjaone", "83")
