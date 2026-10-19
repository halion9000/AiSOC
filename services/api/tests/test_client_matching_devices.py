"""Suggesting a client from the machines it has in common with a tool's client."""

from app.models.client_alias import ClientAlias
from app.services.client_mapping import suggestions_with_devices
from app.services.client_matching import Candidate, DeviceOverlap, Suggestion, device_suggestions, merge_suggestions

NAMES = {"t1": "Pirkey Barber PLLC", "t2": "Acme Dental", "t3": "Other Co"}


def test_enough_shared_machines_make_a_suggestion_that_says_why():
    [s] = device_suggestions([DeviceOverlap("t1", 5, 6)], NAMES)
    assert (s.tenant_id, s.name) == ("t1", "Pirkey Barber PLLC")
    assert s.reason == "5 of its 6 devices are already under this client"
    assert 0.85 < s.score < 1.0, "strong, but below an exact name match"


def test_one_or_two_stray_machines_do_not_decide_it_but_a_small_client_can_be_matched():
    assert device_suggestions([DeviceOverlap("t1", 1, 100)], NAMES) == []
    assert device_suggestions([DeviceOverlap("t1", 2, 100)], NAMES) == [], "two of a hundred is a coincidence"
    assert device_suggestions([DeviceOverlap("t1", 3, 100)], NAMES) == [], "three but only 3%"
    assert device_suggestions([DeviceOverlap("t1", 3, 7)], NAMES), "three of seven is 43%"
    assert device_suggestions([DeviceOverlap("t1", 2, 3)], NAMES) == [], "two of three is 67%, under the 70% a small client needs"
    assert device_suggestions([DeviceOverlap("t1", 2, 2)], NAMES), "both machines of a two-machine client"
    assert (
        device_suggestions([DeviceOverlap("t1", 0, 5), DeviceOverlap("zz", 5, 5)], NAMES) == []
    ), "no match, or a tenant that is not a candidate"
    assert device_suggestions([DeviceOverlap("t1", 3, 0)], NAMES) == []


def test_the_stronger_of_name_and_machines_wins_and_a_name_match_the_machines_back_up_says_so():
    by_name = [Suggestion("t1", "Pirkey Barber PLLC", 1.0), Suggestion("t3", "Other Co", 0.7)]
    by_devices = device_suggestions([DeviceOverlap("t1", 6, 6), DeviceOverlap("t2", 4, 6)], NAMES)
    merged = merge_suggestions(by_name, by_devices)
    assert [s.tenant_id for s in merged] == ["t1", "t2", "t3"]
    assert merged[0].score == 1.0 and merged[0].reason == "6 of its 6 devices are already under this client"
    assert len({s.tenant_id for s in merged}) == len(merged), "one entry per client"


def test_machines_alone_can_find_a_client_whose_name_looks_nothing_alike():
    by_name = [Suggestion("t3", "Other Co", 0.62)]
    merged = merge_suggestions(by_name, device_suggestions([DeviceOverlap("t2", 5, 5)], NAMES))
    assert merged[0].tenant_id == "t2" and merged[0].reason


def test_only_an_unmapped_not_ignored_client_gets_suggestions():
    cands = [Candidate("t1", "Pirkey Barber PLLC")]
    overlaps = {("autoelevate", "c1"): [DeviceOverlap("t1", 5, 5)]}

    def alias(**kw):
        base = {
            "vendor": "autoelevate",
            "vendor_client_id": "c1",
            "vendor_client_name": "Totally Different",
            "child_tenant_id": None,
            "ignored": False,
        }
        base.update(kw)
        return ClientAlias(**base)

    assert [s.tenant_id for s in suggestions_with_devices(alias(), cands, overlaps)] == ["t1"]
    assert suggestions_with_devices(alias(ignored=True), cands, overlaps) == []
    import uuid

    assert suggestions_with_devices(alias(child_tenant_id=uuid.uuid4()), cands, overlaps) == []
    assert suggestions_with_devices(alias(vendor_client_id="other"), cands, overlaps) == [], "another client's machines are not used"
