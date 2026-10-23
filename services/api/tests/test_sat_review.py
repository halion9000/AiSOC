"""Huntress Security Awareness Training checks answer the review's training, phishing-simulation and awareness questions, and are never mixed into the Microsoft 365 answers."""

from types import SimpleNamespace

from app.services.client_review import device_facts, readiness
from app.services.sat_review import SAT_SOURCE, sat_awareness, sat_phishing, sat_training
from app.services.tech_stack import tech_stack


def chk(key, status, evidence="e"):
    return {"key": key, "status": status, "evidence": evidence}


GOOD = [
    chk("sat_training_assigned", "met", "2 assignments running"),
    chk("sat_training_completion", "met", "48 of 50 learners finished (96%)"),
    chk("sat_phishing_simulation", "met", 'Latest campaign "Q3" (2026-09-10): 50 sent, 6% clicked'),
]


def test_the_source_name_is_the_one_core_sends():
    assert SAT_SOURCE == "huntress-sat"


def test_training_is_met_when_assigned_and_finished():
    status, evidence = sat_training(GOOD)
    assert status == "met"
    assert "96%" in evidence


def test_training_is_the_worse_of_assigned_and_finished():
    assert sat_training([chk("sat_training_assigned", "met"), chk("sat_training_completion", "partly", "30 of 40 finished")])[0] == "partly"
    assert (
        sat_training([chk("sat_training_assigned", "met"), chk("sat_training_completion", "not_met", "5 of 40 finished")])[0] == "not_met"
    )
    assert sat_training([chk("sat_training_assigned", "not_met", "No training assignment has run")])[0] == "not_met"
    assert sat_training([chk("sat_training_assigned", "partly"), chk("sat_training_completion", "met")])[0] == "partly"


def test_training_with_no_completion_figure_rests_on_the_assignment_alone():
    status, evidence = sat_training([chk("sat_training_assigned", "met", "1 assignment running")])
    assert status == "met"
    assert "1 assignment running" in evidence


def test_no_checks_means_unknown_not_not_met():
    assert sat_training(None) is None
    assert sat_training([]) is None
    assert sat_phishing(None) is None
    assert sat_awareness([chk("something_else", "met")]) is None


def test_phishing_simulation_follows_its_check():
    assert sat_phishing(GOOD)[0] == "met"
    assert sat_phishing([chk("sat_phishing_simulation", "partly", "old")])[0] == "partly"
    assert sat_phishing([chk("sat_phishing_simulation", "not_met", "none")])[0] == "not_met"


def test_the_readiness_checklist_uses_the_training_answer_instead_of_unknown():
    facts = device_facts([], 0, 0)
    without = {i.key: i for i in readiness(facts, None, None).items}["training"]
    assert without.status == "unknown"
    with_sat = {i.key: i for i in readiness(facts, None, None, sat=GOOD).items}["training"]
    assert with_sat.status == "met"
    assert "96%" in with_sat.evidence
    bad = {i.key: i for i in readiness(facts, None, None, sat=[chk("sat_training_assigned", "not_met", "none ran")]).items}["training"]
    assert bad.status == "not_met"


def answers(sat=None):
    return {a.key: a for a in tech_stack([], device_facts([], 0, 0), False, sat=sat)}


def test_the_technology_questions_name_huntress_sat_when_it_is_in_use():
    a = answers(GOOD)
    assert (a["awareness"].status, a["awareness"].suggested) == ("seen", "Huntress SAT")
    assert (a["phishing_sim"].status, a["phishing_sim"].suggested) == ("seen", "Huntress SAT")


def test_they_say_none_seen_when_the_account_exists_but_nothing_has_run():
    a = answers(
        [
            chk("sat_training_assigned", "not_met", "No training assignment has run"),
            chk("sat_phishing_simulation", "not_met", "No campaign"),
        ]
    )
    assert (a["awareness"].status, a["awareness"].suggested) == ("not_seen", "None seen")
    assert a["phishing_sim"].status == "not_seen"


def test_they_stay_unknown_when_huntress_sat_has_sent_nothing():
    a = answers(None)
    assert a["awareness"].status == "unknown"
    assert a["phishing_sim"].status == "unknown"


def test_only_the_phishing_check_present_answers_only_phishing():
    a = answers([chk("sat_phishing_simulation", "met", "recent")])
    assert a["phishing_sim"].status == "seen"
    assert a["awareness"].status == "unknown"


def test_a_stale_training_assignment_is_still_seen_as_the_package_in_use():
    a = answers([chk("sat_training_assigned", "partly", "Training was assigned before but nothing in the last year")])
    assert (a["awareness"].status, a["awareness"].suggested) == ("seen", "Huntress SAT")


def test_the_nothing_here_touches_other_tools():
    # SimpleNamespace stand-in for a device is not needed: no devices, same answers as before for the rest.
    assert answers(GOOD)["dns_filter"].status == answers(None)["dns_filter"].status
    assert SimpleNamespace  # keep the import honest
