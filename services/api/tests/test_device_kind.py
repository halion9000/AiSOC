"""Computers, network devices and cameras can be told apart and filtered on the Devices page."""

import uuid
from datetime import UTC, datetime

import pytest
from app.api.v1.endpoints.devices import DEVICE_KINDS, DeviceOut, DeviceSourceOut, device_kind, filter_devices, is_missing_from


def device(sources, hostname="h", os_name=None):
    now = datetime.now(UTC)
    return DeviceOut(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        hostname=hostname,
        os=os_name,
        last_seen=now,
        first_seen=now,
        sources=[DeviceSourceOut(vendor=v, name="h", last_seen=now, details=d) for v, d in sources],
    )


@pytest.mark.parametrize("device_type", ["switch", "l3Switch", "router", "accessPoint", "firewall", "utm", "securityAppliance", "bridge", "controller", "loadBalancer"])
def test_auvik_network_gear_is_network(device_type):
    assert device_kind(device([("auvik", {"device_type": device_type})]).sources) == "network"


def test_an_auvik_camera_is_a_camera():
    assert device([("auvik", {"device_type": "camera"})]).kind == "camera"


@pytest.mark.parametrize("device_type", ["workstation", "server", "hypervisor", "virtualMachine", "thinClient", "tablet"])
def test_auvik_computers_are_computers(device_type):
    assert device([("auvik", {"device_type": device_type})]).kind == "computer"


@pytest.mark.parametrize("device_type", ["printer", "ups", "ipPhone", "internetOfThings", "unknown", "", None])
def test_auvik_printers_phones_ups_and_unknowns_are_other_not_computers(device_type):
    assert device([("auvik", {"device_type": device_type})]).kind == "other"


def test_unifi_protect_products_are_cameras_and_every_other_unifi_device_is_network():
    assert device([("unifi", {"product_line": "protect", "is_console": False})]).kind == "camera"
    assert device([("unifi", {"product_line": "network"})]).kind == "network"
    assert device([("unifi", {})]).kind == "network"
    # A Protect console (an NVR) is not a camera.
    assert device([("unifi", {"product_line": "protect", "is_console": True})]).kind == "network"


def test_ninjaone_network_and_camera_node_classes():
    assert device([("ninjaone", {"node_class": "NMS_SWITCH"})]).kind == "network"
    assert device([("ninjaone", {"node_class": "NMS_FIREWALL"})]).kind == "network"
    assert device([("ninjaone", {"node_class": "NMS_CAMERA"})]).kind == "camera"
    assert device([("ninjaone", {"node_class": "WINDOWS_WORKSTATION"})]).kind == "computer"
    assert device([("ninjaone", {"node_class": "NMS_PRINTER"})]).kind == "other"
    assert device([("ninjaone", {})]).kind == "computer"


def test_anything_an_agent_tool_reports_is_a_computer():
    for vendor in ("huntress", "addigy", "threatmate", "screenconnect", "fieldeffect", "dnsfilter", "slide"):
        assert device([(vendor, {})]).kind == "computer", vendor


def test_a_device_no_tool_describes_is_other():
    assert device([]).kind == "other"
    assert device([("somenewtool", {})]).kind == "other"


def test_a_camera_or_network_signal_beats_a_computer_one():
    assert device([("auvik", {"device_type": "switch"}), ("ninjaone", {"node_class": "WINDOWS_WORKSTATION"})]).kind == "network"
    assert device([("auvik", {"device_type": "camera"}), ("unifi", {"product_line": "network"})]).kind == "camera"


def test_details_that_are_missing_or_not_text_do_not_crash_it():
    assert device([("auvik", {"device_type": 5}), ("unifi", {"product_line": None})]).kind == "network"


def test_the_kind_is_in_what_the_api_returns():
    assert device([("auvik", {"device_type": "router"})]).model_dump()["kind"] == "network"
    assert set(DEVICE_KINDS) == {"computer", "network", "camera", "other"}


def test_network_devices_and_cameras_are_never_a_coverage_gap_but_computers_still_are():
    for sources in ([("auvik", {"device_type": "switch"})], [("unifi", {"product_line": "protect"})]):
        d = device(sources)
        for tool in ("huntress", "threatmate", "screenconnect", "fieldeffect", "addigy"):
            assert not is_missing_from(d, tool), (d.kind, tool)
    assert is_missing_from(device([("ninjaone", {})], os_name="Windows 11"), "huntress")


def test_the_filter_returns_only_that_kind_and_none_means_all():
    pc = device([("ninjaone", {})], hostname="pc")
    sw = device([("auvik", {"device_type": "switch"})], hostname="sw")
    cam = device([("unifi", {"product_line": "protect"})], hostname="cam")
    odd = device([("auvik", {"device_type": "printer"})], hostname="printer")
    everything = [pc, sw, cam, odd]
    assert [d.hostname for d in filter_devices(everything, kind="computer")] == ["pc"]
    assert [d.hostname for d in filter_devices(everything, kind="network")] == ["sw"]
    assert [d.hostname for d in filter_devices(everything, kind="camera")] == ["cam"]
    assert [d.hostname for d in filter_devices(everything, kind="other")] == ["printer"]
    assert sorted(d.hostname for d in filter_devices(everything)) == ["cam", "pc", "printer", "sw"]


def test_the_kind_filter_combines_with_the_other_filters():
    a = device([("auvik", {"device_type": "switch"})], hostname="core-switch")
    b = device([("auvik", {"device_type": "switch"})], hostname="edge-router")
    assert [d.hostname for d in filter_devices([a, b], kind="network", search="edge")] == ["edge-router"]
    assert filter_devices([a, b], kind="camera", search="edge") == []
