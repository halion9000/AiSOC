"""Meraki and UniFi list physical hardware, each unit once: a name match with another unit or with an agent machine is a coincidence, never a duplicate."""

import pytest
from app.services.device_identity import HARDWARE_TOOLS, could_be_same_machine


def test_two_units_from_one_hardware_tool_are_never_the_same():
    assert not could_be_same_machine({"unifi"}, {"unifi"})
    assert not could_be_same_machine({"meraki"}, {"meraki"})


def test_a_meraki_unit_is_never_a_unifi_unit():
    assert not could_be_same_machine({"meraki"}, {"unifi"})
    assert not could_be_same_machine({"meraki", "auvik"}, {"unifi"})


@pytest.mark.parametrize("agent", ["ninjaone", "huntress", "addigy", "threatmate", "screenconnect", "dnsfilter", "slide", "cipp"])
def test_hardware_is_never_a_computer_an_agent_runs_on(agent):
    assert not could_be_same_machine({"unifi"}, {agent})
    assert not could_be_same_machine({agent}, {"meraki"})


def test_hardware_can_still_be_the_same_thing_a_network_monitor_sees():
    assert could_be_same_machine({"meraki"}, {"auvik"})
    assert could_be_same_machine({"auvik"}, {"unifi"})
    assert could_be_same_machine({"meraki"}, {"ninjaone-nms-placeholder"})


def test_other_tools_are_unaffected():
    assert could_be_same_machine({"ninjaone"}, {"huntress"})
    assert could_be_same_machine({"ninjaone"}, {"ninjaone"})
    assert could_be_same_machine(set(), set())


def test_the_hardware_tools_are_exactly_the_two():
    assert HARDWARE_TOOLS == {"meraki", "unifi"}
