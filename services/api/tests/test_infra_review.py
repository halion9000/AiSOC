"""Network equipment, servers, virtualization and backups answer the client review's questions from what the connected tools list."""

from types import SimpleNamespace

from app.services.client_review import device_facts, readiness
from app.services.infra_review import backup_coverage, hypervisor_of, network_online, network_role
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


def machines():
    return [
        dev([src("ninjaone"), src("slide")], os="Windows Server 2022"),
        dev([src("ninjaone")], os="Windows Server 2019"),
        dev([src("ninjaone"), src("slide")], os="Windows 11"),
        dev([src("ninjaone")], os="macOS 14"),
        dev([src("meraki", product_type="switch")]),
    ]


def test_slide_coverage_counts_servers_and_computers_separately_and_ignores_network_gear():
    assert backup_coverage(machines()) == (1, 2, 1, 2)


def test_the_backup_question_names_slide_when_it_protects_machines_and_is_unknown_otherwise():
    a = answers(machines())
    assert (a["backup_bcdr"].status, a["backup_bcdr"].suggested) == ("seen", "Slide")
    assert "1 of 2 servers" in a["backup_bcdr"].evidence
    none = answers([dev([src("ninjaone")], os="Windows 11")])
    assert none["backup_bcdr"].status == "unknown"
    assert "ask the client" in none["backup_bcdr"].evidence
    assert answers(machines())["backup_saas"].status == "unknown"


def test_the_backups_checklist_item_is_never_met_because_restores_cannot_be_seen():
    facts = device_facts([], 0, 0)
    full = [dev([src("slide")], os="Windows Server 2022"), dev([src("slide")], os="Windows 11")]
    item = {i.key: i for i in readiness(facts, None, None, devices=full).items}["backups"]
    assert item.status == "partly"
    assert "cannot see whether restores are tested" in item.evidence
    thin = [dev([src("slide")], os="Windows 11")] + [dev([], os="Windows 11") for _ in range(4)]
    assert {i.key: i for i in readiness(facts, None, None, devices=thin).items}["backups"].status == "not_met"
    assert {i.key: i for i in readiness(facts, None, None, devices=[]).items}["backups"].status == "unknown"


def test_a_backup_gap_becomes_a_suggested_action():
    facts = device_facts([], 0, 0)
    thin = [dev([src("slide")], os="Windows 11")] + [dev([], os="Windows 11") for _ in range(4)]
    keys = {d.key for d in drafts_from_readiness(readiness(facts, None, None, devices=thin))}
    assert "backups" in keys


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
