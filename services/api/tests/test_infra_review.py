"""Network equipment, servers, virtualization and backups answer the client review's questions from what the connected tools list."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.services.client_review import device_facts, readiness
from app.services.infra_review import backup_summary, edr_summary, hypervisor_of, network_online, network_role, saas_backup
from app.services.tech_stack import tech_stack
from app.services.vcio_proposals import drafts_from_readiness


def src(vendor, **details):
    return SimpleNamespace(vendor=vendor, details=details)


def dev(sources, os=None, manufacturer=None, model=None, hostname="h"):
    return SimpleNamespace(os=os, manufacturer=manufacturer, model=model, hostname=hostname, sources=sources)


def answers(devices):
    return {a.key: a for a in tech_stack(devices, device_facts(devices, 0, 0), False)}


# ---- network equipment ----------------------------------------------------------------------------------------------------------------------------------


def test_meraki_product_types_are_firewall_switch_and_wireless():
    assert network_role(dev([src("meraki", product_type="appliance")], model="MX68")) == ("firewall", "Meraki")
    assert network_role(dev([src("meraki", product_type="switch")])) == ("switch", "Meraki")
    assert network_role(dev([src("meraki", product_type="wireless")])) == ("wireless", "Meraki")
    assert network_role(dev([src("meraki", product_type="camera")])) is None
    assert network_role(dev([src("meraki", product_type="sensor")])) is None


def test_unifi_models_are_told_apart():
    for model, role in (("UDM-Pro", "firewall"), ("UCG-Ultra", "firewall"), ("USG-3P", "firewall"), ("USW-24-PoE", "switch"), ("US-8-60W", "switch"), ("USW-Flex-Mini", "switch"), ("U6-Pro", "wireless"), ("UAP-AC-Lite", "wireless"), ("U7-Pro", "wireless")):
        assert network_role(dev([src("unifi")], model=model)) == (role, "UniFi"), model
    assert network_role(dev([src("unifi")], model="UVC-G4-Bullet")) is None
    assert network_role(dev([src("unifi")], model=None)) is None


def test_auvik_types_use_the_maker_the_device_reports():
    assert network_role(dev([src("auvik", device_type="firewall")], manufacturer="Fortinet, Inc.")) == ("firewall", "Fortinet")
    assert network_role(dev([src("auvik", device_type="l3Switch")], manufacturer="Cisco Systems, Inc.")) == ("switch", "Cisco Systems")
    assert network_role(dev([src("auvik", device_type="accessPoint")])) == ("wireless", "Brand not reported")
    assert network_role(dev([src("auvik", device_type="printer")])) is None


def test_the_questions_name_the_brands_found():
    a = answers([dev([src("meraki", product_type="appliance")], model="MX68"), dev([src("unifi")], model="USW-24"), dev([src("unifi")], model="USW-48"), dev([src("meraki", product_type="wireless")], model="MR46")])
    assert (a["firewall"].status, a["firewall"].suggested) == ("seen", "Meraki")
    assert (a["switch"].status, a["switch"].suggested) == ("seen", "UniFi (2)")
    assert (a["wireless"].status, a["wireless"].suggested) == ("seen", "Meraki")
    assert "MX68" in a["firewall"].evidence


def test_network_gear_listed_but_none_of_a_kind_says_none_seen_and_nothing_listed_says_unknown():
    a = answers([dev([src("unifi")], model="U6-Pro")])
    assert a["wireless"].status == "seen"
    assert (a["firewall"].status, a["firewall"].suggested) == ("not_seen", "None seen")
    b = answers([dev([src("ninjaone")], os="Windows 11")])
    assert b["firewall"].status == "unknown"
    assert b["backup_isp"].status == "unknown"


# ---- servers and virtualization -------------------------------------------------------------------------------------------------------------------------


def test_physical_servers_report_their_maker_and_virtual_ones_are_counted_apart():
    a = answers(
        [
            dev([src("ninjaone")], os="Windows Server 2022", manufacturer="Dell Inc.", model="PowerEdge R650"),
            dev([src("ninjaone")], os="Windows Server 2019", manufacturer="Dell Inc.", model="PowerEdge R640"),
            dev([src("ninjaone")], os="Windows Server 2019", manufacturer="Microsoft Corporation", model="Virtual Machine"),
            dev([src("ninjaone")], os="Windows 11", manufacturer="HP", model="EliteBook"),
        ]
    )
    assert (a["server_brand"].status, a["server_brand"].suggested) == ("seen", "Dell (2)")
    assert "1 more run as virtual machines" in a["server_brand"].evidence
    assert (a["virtualization"].status, a["virtualization"].suggested) == ("seen", "Hyper-V")


def test_all_virtual_servers_have_no_maker_of_their_own():
    a = answers([dev([src("ninjaone")], os="Windows Server 2022", manufacturer="VMware, Inc.", model="VMware7,1")])
    assert a["server_brand"].suggested == "Virtual machines"
    assert a["virtualization"].suggested == "VMware"


def test_no_servers_or_no_virtual_machines_is_unknown_never_none():
    a = answers([dev([src("ninjaone")], os="Windows 11", manufacturer="HP", model="EliteBook")])
    assert a["server_brand"].status == "unknown"
    assert a["virtualization"].status == "unknown"
    assert hypervisor_of(dev([], manufacturer="QEMU", model="Standard PC")) == "KVM"
    assert hypervisor_of(dev([], manufacturer="Dell Inc.", model="PowerEdge R650")) is None


# ---- backups -------------------------------------------------------------------------------------------------------------------------------------------

NOW = None
RECENT = (datetime.now(UTC) - timedelta(hours=12)).isoformat()
OLD = (datetime.now(UTC) - timedelta(days=30)).isoformat()


def datto(when=RECENT):
    return src("datto-bcdr", last_snapshot_at=when)


def machines():
    return [
        dev([src("ninjaone"), datto()], os="Windows Server 2022"),
        dev([src("ninjaone"), src("slide")], os="Windows Server 2019"),
        dev([src("ninjaone")], os="Windows Server 2016"),
        dev([src("ninjaone"), src("slide")], os="Windows 11"),
        dev([src("ninjaone")], os="macOS 14"),
        dev([src("meraki", product_type="switch")]),
    ]


def test_each_backup_tool_is_counted_over_the_servers_and_computers_it_protects():
    s = backup_summary(machines())
    assert (s.servers, s.computers) == (3, 2)
    assert (s.tools["datto-bcdr"].servers, s.tools["datto-bcdr"].computers) == (1, 0)
    assert (s.tools["slide"].servers, s.tools["slide"].computers) == (1, 1)
    assert (s.protected, s.fresh) == (3, 3)


def test_the_backup_question_names_every_tool_in_use_with_its_counts():
    a = answers(machines())
    assert (a["backup_bcdr"].status, a["backup_bcdr"].suggested) == ("seen", "Slide (2), Datto BCDR (1)")
    assert "Datto BCDR protects 1 of 3 servers" in a["backup_bcdr"].evidence
    assert "Slide protects 1 of 3 servers and 1 of 2 computers" in a["backup_bcdr"].evidence


def test_one_tool_alone_is_named_plainly_and_none_is_unknown_not_none_seen():
    a = answers([dev([datto()], os="Windows Server 2022")])
    assert a["backup_bcdr"].suggested == "Datto BCDR"
    none = answers([dev([src("ninjaone")], os="Windows 11")])
    assert none["backup_bcdr"].status == "unknown"
    assert "ask the client" in none["backup_bcdr"].evidence


def test_a_datto_agent_listed_without_an_operating_system_still_counts_as_a_protected_machine():
    s = backup_summary([dev([datto()]), dev([], os="Windows 11")])
    assert s.tools["datto-bcdr"].computers == 1
    assert s.computers == 2


def test_a_datto_agent_with_no_recent_snapshot_is_flagged_and_not_counted_as_current():
    old = [dev([datto(OLD)], os="Windows Server 2022"), dev([datto(None)], os="Windows Server 2019"), dev([datto()], os="Windows Server 2016")]
    s = backup_summary(old)
    assert (s.tools["datto-bcdr"].quiet, s.protected, s.fresh) == (2, 3, 1)
    assert "2 with no snapshot in 3 days" in answers(old)["backup_bcdr"].evidence


def test_the_backups_checklist_item_is_never_met_because_restores_cannot_be_seen():
    facts = device_facts([], 0, 0)
    full = [dev([src("slide")], os="Windows Server 2022"), dev([datto()], os="Windows 11")]
    item = {i.key: i for i in readiness(facts, None, None, devices=full).items}["backups"]
    assert item.status == "partly"
    assert "cannot see whether restores are tested" in item.evidence
    thin = [dev([src("slide")], os="Windows 11")] + [dev([], os="Windows 11") for _ in range(4)]
    assert {i.key: i for i in readiness(facts, None, None, devices=thin).items}["backups"].status == "not_met"
    quiet = [dev([datto(OLD)], os="Windows Server 2022"), dev([datto(OLD)], os="Windows Server 2019")]
    assert {i.key: i for i in readiness(facts, None, None, devices=quiet).items}["backups"].status == "not_met"
    assert {i.key: i for i in readiness(facts, None, None, devices=[]).items}["backups"].status == "unknown"


def test_a_backup_gap_becomes_a_suggested_action():
    facts = device_facts([], 0, 0)
    thin = [dev([src("slide")], os="Windows 11")] + [dev([], os="Windows 11") for _ in range(4)]
    keys = {d.key for d in drafts_from_readiness(readiness(facts, None, None, devices=thin))}
    assert "backups" in keys


# ---- cloud backups (Datto SaaS Protection) ---------------------------------------------------------------------------------------------------------------


def chk(key, status, evidence="e"):
    return {"key": key, "status": status, "evidence": evidence}


def test_saas_backup_is_the_worst_product_and_none_reported_is_unknown():
    assert saas_backup(None) is None
    assert saas_backup([chk("something_else", "met")]) is None
    both = [chk("saas_backup_microsoft", "met", "Microsoft 365 ok"), chk("saas_backup_google", "not_met", "Google stale")]
    status, evidence = saas_backup(both)
    assert status == "not_met"
    assert "Microsoft 365 ok" in evidence and "Google stale" in evidence
    assert saas_backup([chk("saas_backup_microsoft", "partly")])[0] == "partly"


def test_the_cloud_backup_question_names_datto_saas_when_it_reports_and_is_unknown_otherwise():
    devices = []
    a = {x.key: x for x in tech_stack(devices, device_facts(devices, 0, 0), False, saas=[chk("saas_backup_microsoft", "met", "Microsoft 365 backed up")])}
    assert (a["backup_saas"].status, a["backup_saas"].suggested) == ("seen", "Datto SaaS Protection")
    assert "Microsoft 365 backed up" in a["backup_saas"].evidence
    none = {x.key: x for x in tech_stack(devices, device_facts(devices, 0, 0), False)}
    assert none["backup_saas"].status == "unknown"


def test_the_checklist_asks_whether_microsoft_and_google_are_backed_up_only_when_datto_saas_reports():
    facts = device_facts([], 0, 0)
    assert "saas_backup" not in {i.key for i in readiness(facts, None, None).items}
    item = {i.key: i for i in readiness(facts, None, None, saas=[chk("saas_backup_microsoft", "partly", "80% backed up")]).items}["saas_backup"]
    assert item.status == "partly"
    keys = {d.key for d in drafts_from_readiness(readiness(facts, None, None, saas=[chk("saas_backup_google", "not_met", "none")]))}
    assert "saas_backup" in keys


def test_datto_agents_are_computers_and_have_a_label():
    from app.api.v1.endpoints.devices import _COMPUTER_TOOLS
    from app.services.case_devices import VENDOR_LABELS

    assert "datto-bcdr" in _COMPUTER_TOOLS
    assert VENDOR_LABELS["datto-bcdr"] == "Datto BCDR"


# ---- network health ------------------------------------------------------------------------------------------------------------------------------------


def test_network_online_counts_known_states_for_network_hardware_only():
    d = [
        dev([src("meraki", product_type="switch", status="online")]),
        dev([src("meraki", product_type="wireless", status="offline")]),
        dev([src("meraki", product_type="camera", status="offline")]),
        dev([src("unifi", product_line="network", status="ONLINE")]),
        dev([src("unifi", product_line="protect", status="offline")]),
        dev([src("meraki", product_type="switch")]),
    ]
    assert network_online(d) == (2, 3)
    assert network_online([dev([src("ninjaone")])]) is None


def test_the_checklist_shows_network_health_only_when_a_tool_reports_it():
    facts = device_facts([], 0, 0)
    assert "network_online" not in {i.key for i in readiness(facts, None, None, devices=[]).items}
    up = [dev([src("meraki", product_type="switch", status="online")]) for _ in range(9)] + [dev([src("meraki", product_type="wireless", status="offline")])]
    item = {i.key: i for i in readiness(facts, None, None, devices=up).items}["network_online"]
    assert (item.status, "9 of 10" in item.evidence) == ("partly", True)
    allup = [dev([src("unifi", product_line="network", status="online")])]
    assert {i.key: i for i in readiness(facts, None, None, devices=allup).items}["network_online"].status == "met"


# ---- EDR: Huntress and Field Effect --------------------------------------------------------------------------------------------------------------------


def edr_devices():
    return [
        dev([src("huntress"), src("ninjaone")], os="Windows 11"),
        dev([src("fieldeffect")], os="Windows 10"),
        dev([src("huntress"), src("fieldeffect")], os="Windows Server 2022"),
        dev([src("ninjaone")], os="Windows 11"),
        dev([src("huntress")], os="macOS 14"),
        dev([src("ninjaone")], os="macOS 13"),
    ]


def test_a_machine_is_covered_when_either_edr_reports_it_and_counted_once():
    s = edr_summary(edr_devices(), {"windows", "mac", "linux"})
    assert (s.total, s.covered, s.both) == (6, 4, 1)
    assert s.by_tool == {"huntress": 3, "fieldeffect": 2}
    assert "Huntress 3, Field Effect 2, 1 report both" == s.line()


def test_the_checklist_counts_both_edrs_instead_of_huntress_alone():
    facts = device_facts(edr_devices(), 0, 0)
    item = {i.key: i for i in readiness(facts, None, None, devices=edr_devices()).items}["edr"]
    assert item.status == "not_met"
    assert "4 of 6" in item.evidence and "Field Effect" in item.evidence and "Huntress" in item.evidence
    covered = [dev([src("fieldeffect")], os="Windows 11") for _ in range(10)]
    ok = {i.key: i for i in readiness(device_facts(covered, 0, 0), None, None, devices=covered).items}["edr"]
    assert ok.status == "met"


def test_the_checklist_says_unknown_with_no_machines_and_not_met_when_neither_edr_is_enrolled():
    none = {i.key: i for i in readiness(device_facts([], 0, 0), None, None, devices=[]).items}["edr"]
    assert none.status == "unknown"
    plain = [dev([src("ninjaone")], os="Windows 11")]
    facts = device_facts(plain, 0, 0, mapped_tools={"huntress", "fieldeffect"})
    gone = {i.key: i for i in readiness(facts, None, None, devices=plain).items}["edr"]
    assert gone.status == "not_met"
    assert "Huntress or Field Effect" in gone.evidence


def test_the_endpoint_security_questions_name_both_edrs_for_pcs_and_macs():
    a = answers(edr_devices())
    assert a["edr_pc"].status == "seen"
    assert a["edr_pc"].suggested in ("Huntress (2), Field Effect (2)", "Field Effect (2), Huntress (2)")
    assert (a["edr_mac"].status, a["edr_mac"].suggested) == ("seen", "Huntress")
    nothing = answers([dev([src("ninjaone")], os="Windows 11")])
    assert (nothing["edr_pc"].status, nothing["edr_pc"].suggested) == ("not_seen", "None seen")
    assert "Field Effect" in nothing["edr_pc"].evidence
    assert answers([])["edr_pc"].status == "unknown"


# ---- the SOC, and Huntress SAT by being set up in it ---------------------------------------------------------------------------------------------------


def stack(enrolled=None, mapped=None, sat=None):
    return {a.key: a for a in tech_stack([], device_facts([], 0, 0), False, sat=sat, enrolled_in=enrolled, mapped_tools=mapped)}


def test_the_soc_question_names_each_managed_service_the_client_is_set_up_in():
    a = stack({"huntress", "petra", "ninjaone"}, {"huntress", "petra", "fieldeffect", "ninjaone"})["soc"]
    assert a.status == "seen"
    assert a.suggested == "Huntress MDR/ITDR + Petra MDR"
    assert "Field Effect" not in a.suggested
    assert stack({"fieldeffect"}, {"fieldeffect"})["soc"].suggested == "Field Effect MDR"
    assert stack({"huntress", "fieldeffect", "petra"}, set())["soc"].suggested == "Huntress MDR/ITDR + Field Effect MDR + Petra MDR"


def test_none_seen_when_other_clients_are_in_those_tools_but_this_one_is_not_and_unknown_when_none_is_in_use():
    a = stack(set(), {"huntress", "ninjaone"})["soc"]
    assert (a.status, a.suggested) == ("not_seen", "None seen")
    assert stack(set(), {"ninjaone"})["soc"].status == "unknown"
    assert stack()["soc"].status == "unknown"


def test_being_set_up_in_huntress_sat_answers_awareness_and_phishing_before_results_are_read():
    a = stack({"huntress-sat"}, {"huntress-sat"})
    assert (a["awareness"].status, a["awareness"].suggested) == ("seen", "Huntress SAT")
    assert (a["phishing_sim"].status, a["phishing_sim"].suggested) == ("seen", "Huntress SAT")
    assert "not been read yet" in a["awareness"].evidence


def test_not_being_in_huntress_sat_when_others_are_says_none_seen_and_results_still_win_over_enrolment():
    a = stack(set(), {"huntress-sat"})
    assert (a["awareness"].status, a["phishing_sim"].status) == ("not_seen", "not_seen")
    assert stack(set(), set())["awareness"].status == "unknown"
    with_results = stack({"huntress-sat"}, {"huntress-sat"}, sat=[chk("sat_training_assigned", "met", "2 assignments running")])
    assert "2 assignments running" in with_results["awareness"].evidence
