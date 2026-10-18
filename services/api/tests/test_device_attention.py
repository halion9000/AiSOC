"""What a tool reports as wrong with a device (Huntress agent health) reaches the Devices page, and "not in Huntress" works like the other coverage gaps."""

import uuid
from datetime import UTC, datetime

from app.api.v1.endpoints.devices import DeviceOut, DeviceSourceOut, attention_of, is_missing_from


def device(os_name, sources):
    now = datetime.now(UTC)
    return DeviceOut(
        id=uuid.uuid4(), tenant_id=uuid.uuid4(), hostname="h", os=os_name, last_seen=now, first_seen=now,
        sources=[DeviceSourceOut(vendor=v, name="h", last_seen=now, details=d) for v, d in sources],
    )


def test_attention_collects_every_sources_problems_and_ignores_malformed_ones():
    d = device("Windows 11", [
        ("huntress", {"needs_attention": ["Defender: Unhealthy", "Firewall: Disabled"]}),
        ("ninjaone", {"needs_attention": "not a list"}),
        ("threatmate", {"needs_attention": ["", 5, "Exposed RDP"]}),
    ])
    assert attention_of(d) == ["Defender: Unhealthy", "Firewall: Disabled", "Exposed RDP"]


def test_no_reported_problem_means_no_attention():
    assert attention_of(device("Windows 11", [("huntress", {"needs_attention": []}), ("ninjaone", {})])) == []


def test_a_machine_without_a_huntress_agent_is_missing_from_it_but_phones_and_tablets_are_not():
    assert is_missing_from(device("Windows 11", [("ninjaone", {})]), "huntress")
    assert is_missing_from(device("macOS", [("ninjaone", {})]), "huntress")
    assert not is_missing_from(device("Windows 11", [("ninjaone", {}), ("huntress", {})]), "huntress")
    assert not is_missing_from(device("iOS 18", [("addigy", {})]), "huntress")
