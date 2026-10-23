"""The client review's coverage numbers and cyber-insurance readiness checklist: every rule, without a database."""

from types import SimpleNamespace as NS

from app.services.client_review import device_facts, readiness


def dev(os, *tools, **details):
    return NS(os=os, sources=[NS(vendor=t, details=details.get(t, {})) for t in tools])


def items(r):
    return {i.key: i for i in r.items}


FULL_MFA = {"people": 20, "with_mfa": 20, "not_required": 0, "without_mfa": 0, "admins_without_mfa": 0}


def test_coverage_counts_each_tool_over_the_machines_it_should_be_on_and_ignores_phones():
    devices = [
        dev("Windows 11 Pro", "huntress", "ninjaone", "screenconnect", "autoelevate"),
        dev("Windows 10 Pro", "ninjaone"),
        dev("macOS 14", "huntress", "addigy"),
        dev("iOS 17", "addigy"),
    ]
    facts = device_facts(devices, stale_agents=1, offline=0)
    cov = {c.tool: (c.have, c.of, c.percent) for c in facts.coverage}
    assert facts.endpoints == 3, "the iPhone is not a computer"
    assert cov["huntress"] == (2, 3, 66.7)
    assert cov["ninjaone"] == (2, 3, 66.7)
    assert cov["autoelevate"] == (1, 2, 50.0), "Windows only"
    assert cov["screenconnect"] == (1, 3, 33.3), "every computer, Macs included; the iPhone is not counted"
    assert cov["addigy"] == (1, 1, 100.0), "Macs only: the iPhone and the Windows machines are not counted against it"
    assert facts.stale_agents == 1


def test_a_client_the_tool_does_not_have_is_not_enrolled_and_one_it_has_is():
    devices = [dev("Windows 11 Pro", "ninjaone"), dev("Windows 10 Pro", "ninjaone")]
    facts = device_facts(devices, 0, 0, enrolled_in={"huntress"}, mapped_tools={"huntress", "dnsfilter", "ninjaone"})
    enrolled = {c.tool: c.enrolled for c in facts.coverage}
    assert enrolled["ninjaone"] is True, "it reports machines"
    assert enrolled["huntress"] is True, "mapped to a Huntress organization, though none of its machines report yet"
    assert enrolled["dnsfilter"] is False, "DNSFilter maps clients and this one is not among them"
    assert enrolled["fieldeffect"] is None, "Field Effect maps no clients, so AiSOC cannot tell"
    assert {c.tool: c.enrolled for c in device_facts(devices, 0, 0).coverage}["dnsfilter"] is None, "nothing known about mapping: no claim"


def test_a_check_for_a_tool_the_client_is_not_enrolled_in_says_so_in_those_words():
    devices = [dev("Windows 11 Pro", "ninjaone")]
    facts = device_facts(devices, 0, 0, enrolled_in=set(), mapped_tools={"dnsfilter", "ninjaone"})
    item = {i.key: i for i in readiness(facts, None, None).items}["dns"]
    assert item.status == "not_met"
    assert item.evidence.startswith("Not currently enrolled in DNSFilter")


def test_a_tool_with_no_eligible_machine_has_no_percentage():
    facts = device_facts([dev("macOS 14", "huntress")], 0, 0)
    cov = {c.tool: c for c in facts.coverage}
    assert cov["autoelevate"].of == 0 and cov["autoelevate"].percent is None


def test_known_exploited_counts_come_from_the_scanned_machines_only():
    devices = [
        dev("Windows 11", "threatmate", threatmate={"kev_count": 3, "kev_ransomware": True}),
        dev("Windows 11", "threatmate", threatmate={"kev_count": 0}),
        dev("Windows 11", "ninjaone"),
    ]
    facts = device_facts(devices, 0, 0)
    assert (facts.with_known_exploited, facts.with_ransomware_exploit) == (1, 1)
    assert device_facts([dev("Windows 11", "ninjaone")], 0, 0).with_known_exploited is None, "nothing scanned: unknown, not zero"


def test_a_well_covered_client_meets_everything_AiSOC_can_see_and_leaves_the_rest_unknown():
    devices = [
        dev("Windows 11", "huntress", "ninjaone", "dnsfilter", "autoelevate", "threatmate", threatmate={"kev_count": 0}) for _ in range(20)
    ]
    r = readiness(device_facts(devices, 0, 0), FULL_MFA, 72.0)
    got = {i.key: i.status for i in r.items}
    for key in ("mfa_everyone", "mfa_admins", "edr", "management", "dns", "privilege", "agents_reporting", "patching", "secure_score"):
        assert got[key] == "met", key
    for key in ("backups", "email_filtering", "training", "ir_plan"):
        assert got[key] == "unknown", key
    assert (r.met, r.partly, r.not_met, r.unknown) == (9, 0, 0, 4)


def test_gaps_are_graded_and_the_evidence_says_the_numbers():
    devices = [dev("Windows 11", "huntress", "ninjaone")] * 17 + [dev("Windows 11", "ninjaone")] * 3
    facts = device_facts(devices, stale_agents=5, offline=0)
    r = readiness(facts, {"people": 20, "with_mfa": 12, "not_required": 2, "without_mfa": 6, "admins_without_mfa": 2}, 30.0)
    it = items(r)
    assert it["edr"].status == "partly" and "17 of 20" in it["edr"].evidence
    assert it["mfa_everyone"].status == "not_met" and "6 have none" in it["mfa_everyone"].evidence
    assert it["mfa_admins"].status == "not_met" and "2 administrator" in it["mfa_admins"].evidence
    assert it["agents_reporting"].status == "not_met", "5 of 20 is more than the 5% allowance"
    assert it["dns"].status == "not_met" and "0 of 20" in it["dns"].evidence
    assert it["secure_score"].status == "not_met"
    assert it["patching"].status == "unknown"


def test_missing_identity_and_score_data_is_unknown_and_an_empty_client_says_so():
    r = readiness(device_facts([], 0, 0), None, None)
    it = items(r)
    for key in ("mfa_everyone", "mfa_admins", "edr", "management", "dns", "privilege", "agents_reporting", "patching", "secure_score"):
        assert it[key].status == "unknown", key
    assert r.unknown == len(r.items)


def test_known_exploited_machines_are_partly_met_when_few_and_not_met_when_many():
    few = [dev("Windows 11", "threatmate", threatmate={"kev_count": 1 if i == 0 else 0}) for i in range(40)]
    many = [dev("Windows 11", "threatmate", threatmate={"kev_count": 1 if i < 10 else 0}) for i in range(40)]
    assert items(readiness(device_facts(few, 0, 0), None, None))["patching"].status == "partly"
    assert items(readiness(device_facts(many, 0, 0), None, None))["patching"].status == "not_met"
    ransom = [dev("Windows 11", "threatmate", threatmate={"kev_count": 1, "kev_ransomware": True})]
    assert "used in ransomware" in items(readiness(device_facts(ransom, 0, 0), None, None))["patching"].evidence


# ---- technology-stack suggestions ---------------------------------------------------------------------------------------------------------------------------


def _dev(os_name, *vendors):
    return NS(os=os_name, sources=[NS(vendor=v, details={}) for v in vendors], hidden_since=None)


def _stack(devices, enrolled=None, mapped=None, m365=False):
    from app.services.client_review import device_facts
    from app.services.tech_stack import tech_stack

    facts = device_facts(devices, stale_agents=0, offline=0, enrolled_in=enrolled or set(), mapped_tools=mapped or set())
    return {a.key: a for a in tech_stack(devices, facts, has_microsoft_365=m365)}


def test_tech_stack_has_every_template_question_in_order_and_guesses_nothing():
    from app.services.tech_stack import QUESTIONS

    answers = _stack([])
    assert list(answers) == [q[0] for q in QUESTIONS] and len(QUESTIONS) == 24
    assert all(a.status == "unknown" and a.suggested is None for a in answers.values())


def test_tech_stack_names_the_tool_when_machines_report_it_and_says_none_seen_when_they_do_not():
    devs = [
        _dev("Windows 11 Pro", "ninjaone", "huntress", "dnsfilter"),
        _dev("Windows 10 Pro", "ninjaone"),
        _dev("macOS 14", "ninjaone", "addigy"),
    ]
    a = _stack(devs, m365=True)
    assert (a["edr_pc"].status, a["edr_pc"].suggested) == ("seen", "Huntress") and "1 of 2 Windows" in a["edr_pc"].evidence
    assert a["edr_mac"].status == "not_seen" and a["edr_mac"].suggested == "None seen"
    assert a["apple_mdm"].suggested == "Addigy"
    assert a["dns_filter"].suggested == "DNSFilter" and "1 of 3 computers" in a["dns_filter"].evidence
    assert a["pam"].status == "not_seen"
    assert a["email_service"].suggested == "Microsoft 365"


def test_tech_stack_without_mac_or_windows_machines_is_unknown_not_none_seen():
    a = _stack([_dev("Windows 11", "ninjaone")])
    assert a["edr_mac"].status == "unknown" and "No Macs" in a["edr_mac"].evidence
    assert a["email_service"].status == "unknown"


def test_tech_stack_handles_machines_with_no_sources_unknown_systems_and_many_sources():
    devs = [
        _dev(None),
        _dev("Plan 9"),
        _dev("Windows 11", "ninjaone", "huntress", "dnsfilter", "autoelevate", "threatmate", "screenconnect"),
    ]
    devs[0].sources = []
    a = _stack(devs)
    assert a["edr_pc"].suggested == "Huntress" and "1 of 1 Windows" in a["edr_pc"].evidence
    assert a["pam"].suggested == "AutoElevate"
    assert a["dns_filter"].suggested == "DNSFilter" and "1 of 1 computers" in a["dns_filter"].evidence
    assert a["edr_mac"].status == "unknown"


def test_tech_stack_says_not_enrolled_when_the_tool_maps_other_clients_but_not_this_one():
    a = _stack([_dev("Windows 11", "ninjaone")], mapped={"huntress", "ninjaone"}, enrolled={"ninjaone"})
    assert a["edr_pc"].status == "not_seen" and "not enrolled in Huntress" in a["edr_pc"].evidence
