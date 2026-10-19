"""Linking a tool client to a client without asking, when ALL its (non-generic) machine names are already machines under that one client."""

import pytest
from app.services.client_matching import DeviceOverlap, device_auto_match, device_suggestions, is_generic_hostname, usable_hostnames


@pytest.mark.parametrize(
    "name",
    [
        "mac",
        "Mac",
        "MacBook",
        "MacBook-Pro",
        "macbook-air",
        "iMac",
        "Mac-mini",
        "user",
        "Users",
        "server",
        "SERVER2",
        "server-01",
        "desktop",
        "laptop",
        "pc",
        "PC-7",
        "workstation",
        "localhost",
        "admin",
        "test",
        "win10",
        "dc",
        "vm1",
        "Johns-MacBook-Pro",
        "Hals-MacBook-Air",
        "Sarahs-iMac",
        "janes-iphone",
        "abc",
        "x1",
        "",
        "  ",
        "mac.local",
        "SERVER.corp.example.com",
    ],
)
def test_names_too_common_to_say_which_client_are_generic(name):
    assert is_generic_hostname(name), name


@pytest.mark.parametrize(
    "name",
    [
        "FRONT-DESK-1",
        "PC-MP2TJ2KH",
        "DESKTOP-4F8K2QH",
        "LAPTOP-5Q2OA87G",
        "SRV-FILE-ATX",
        "GLF10-002D",
        "pirkey-dc01",
        "XMD-L3086",
        "Acme-Reception",
    ],
)
def test_specific_names_including_windows_random_ones_are_not_generic(name):
    assert not is_generic_hostname(name), name


def test_usable_hostnames_drops_the_generic_ones():
    assert usable_hostnames({"mac", "server", "front-desk-1", "desktop-4f8k2qh", "pc-1"}) == {"front-desk-1", "desktop-4f8k2qh"}


def test_every_usable_name_under_one_client_links_it():
    assert device_auto_match([DeviceOverlap("t1", 5, 5)]) == "t1"
    assert device_auto_match([DeviceOverlap("t1", 3, 3)]) == "t1", "three is the least that counts"


def test_not_every_name_a_second_client_sharing_one_or_too_few_names_never_link():
    assert device_auto_match([DeviceOverlap("t1", 4, 5)]) is None, "four of five is a suggestion, not a certainty"
    assert device_auto_match([DeviceOverlap("t1", 5, 5), DeviceOverlap("t2", 1, 5)]) is None, "another client has one of the same names"
    assert device_auto_match([DeviceOverlap("t1", 2, 2)]) is None, "two machines agreeing is too little to act on"
    assert device_auto_match([]) is None
    assert device_auto_match([DeviceOverlap("t1", 0, 5)]) is None
    assert device_auto_match([DeviceOverlap("t1", 2, 2)], min_names=2) == "t1", "the bar can be lowered by whoever calls it"


def test_a_client_that_is_all_but_generic_names_has_nothing_to_go_on():
    usable = usable_hostnames({"mac", "macbook-pro", "server", "user", "pc-1"})
    assert usable == set()
    assert device_auto_match([DeviceOverlap("t1", 0, len(usable))]) is None


def test_the_stricter_auto_match_is_still_a_suggestion_when_it_falls_short():
    overlaps = [DeviceOverlap("t1", 4, 5)]
    assert device_auto_match(overlaps) is None
    assert device_suggestions(overlaps, {"t1": "Pirkey Barber PLLC"}), "four of five is still offered for a person to confirm"
