"""Suggested answers to the technology-stack questions of the vCIO Toolbox review template (network equipment, servers, security tools, cloud services, backup).

The questions are the template's own, word for word. A suggestion is only ever drawn from what A.C.O.R.N already holds about the client (which tools report its machines, whether
Microsoft 365 data has arrived), and says what it looked at. Anything A.C.O.R.N has no way to see is ``unknown`` ("ask the client"); it is never guessed. Nothing is sent to vCIO Toolbox.
Pure functions over simple values, so every rule is testable without a database.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.services.client_review import DeviceFacts, tool_label
from app.services.device_merge import os_kind
from app.services.infra_review import (
    EDR_TOOLS,
    backup_answer,
    edr_answer,
    network_answer,
    saas_backup,
    saas_tools,
    server_brand_answer,
    soc_answer,
    virtualization_answer,
)
from app.services.sat_review import TOOL_NAME as SAT_NAME
from app.services.sat_review import sat_awareness, sat_phishing

# (id, group, the template's question)
QUESTIONS: tuple[tuple[str, str, str], ...] = (
    ("firewall", "Network equipment", "What is the client Firewall (Meraki/Unifi are preferred vendors)"),
    ("switch", "Network equipment", "What Switch technology is in place today? (Meraki/Unifi is Preferred)"),
    ("wireless", "Network equipment", "What wireless system is in place today (Ubiquiti/Meraki is our standard)"),
    ("backup_isp", "Network equipment", "Does each location have a secondary/backup ISP connection"),
    ("server_brand", "Physical servers", "What is the brand of the client server(s)? (Dell is our standard)"),
    ("virtualization", "Physical servers", "Who is the virtualization vendor (HyperV is our standard)"),
    ("edr_pc", "Security tools", "What endpoint security is in use for PCs (Huntress is preferred)"),
    ("encryption", "Security tools", "Are you currently utilizing encryption for laptops?"),
    ("spam_filter", "Security tools", "Do you have a spam filter in place beyond the stock MS/Google provided. (We prefer Inky)"),
    ("anti_phishing", "Security tools", "Do you have an Anti-Phishing Filter in place. (We prefer Inky)"),
    ("password_manager", "Security tools", "Are you Utilizing a password manager( we prefer lastpass)"),
    ("external_email_banner", "Security tools", "Do currently have notifications turned on for external emails? (We prefer Inky)"),
    (
        "pam",
        "Security tools",
        "Do you have a PAM system in place. This allows for users without admin rights to do some admin activities without contacting IT. (We prefer AutoElevate)",
    ),
    ("soc", "Security tools", "Is there any tool or SOC protecting the Microsoft Environment (We prefer huntress MDR)"),
    (
        "phishing_sim",
        "Security tools",
        'Do you have a system for phishing simulation, that sends fake "phishing` emails and reports back on who clicked on the fake bad links. ( We prefer Huntress SAT)',
    ),
    ("edr_mac", "Security tools", "What endpoint security is in use for Mac`s (Huntress is preferred)"),
    ("awareness", "Security tools", "What security awareness package is in use (Huntress is our standard)"),
    ("dns_filter", "Security tools", "What DNS Filter do you have in place. (We prefer DNSfilter)"),
    ("email_service", "Cloud services", "What email service is the client leveraging (Office 365/Google Preferred)"),
    ("cloud_servers", "Cloud services", "What service provider is the client leveraging for their cloud servers (Azure is our standard)"),
    ("apple_mdm", "Cloud services", "Are your Apple devices in any sort of Mobile Device management System? (We prefer Addigy)"),
    ("abm", "Cloud services", "Is the client already using ABM or at least have an ABM account."),
    ("backup_bcdr", "BCDR", "What vendor is the client using for backup services. (Datto is our Standard)"),
    ("backup_saas", "BCDR", "What vendor is the client using for backup services. (Datto SAAS is our Standard)"),
)


class TechAnswer(BaseModel):
    key: str
    group: str
    question: str
    # seen: A.C.O.R.N found something that answers it. not_seen: the tool that would show it covers other clients but not this one. unknown: A.C.O.R.N cannot see this.
    status: str
    suggested: str | None = None
    evidence: str


_UNKNOWN = "A.C.O.R.N does not collect this; ask the client."


def _count(devices: list[Any], kind: str, tool: str) -> tuple[int, int]:
    """(machines of this kind that report ``tool``, machines of this kind)."""
    of = [d for d in devices if os_kind(d.os) == kind]
    return sum(1 for d in of if any(s.vendor == tool for s in d.sources)), len(of)


def tech_stack(
    devices: list[Any],
    facts: DeviceFacts,
    has_microsoft_365: bool,
    sat: list[dict[str, Any]] | None = None,
    saas: list[dict[str, Any]] | None = None,
    enrolled_in: set[str] | None = None,
    mapped_tools: set[str] | None = None,
) -> list[TechAnswer]:
    """One entry per template question, in the template's order."""
    cov = {c.tool: c for c in facts.coverage}
    out: list[TechAnswer] = []

    def put(key: str, status: str, suggested: str | None, evidence: str) -> None:
        group, question = next((g, q) for k, g, q in QUESTIONS if k == key)
        out.append(TechAnswer(key=key, group=group, question=question, status=status, suggested=suggested, evidence=evidence))

    def by_tool(key: str, tool: str, kind: str, what: str) -> None:
        have, of = _count(devices, kind, tool)
        c = cov.get(tool)
        if have > 0:
            put(key, "seen", tool_label(tool), f"{have} of {of} {what} report {tool_label(tool)}.")
        elif of == 0:
            put(key, "unknown", None, f"No {what} are listed for this client.")
        elif c is not None and c.enrolled is False:
            put(key, "not_seen", "None seen", f"The client is not enrolled in {tool_label(tool)}: none of its {of} {what} report it.")
        else:
            put(key, "not_seen", "None seen", f"None of the client's {of} {what} report {tool_label(tool)}.")

    for key, role, noun in (("firewall", "firewall", "firewall"), ("switch", "switch", "switch"), ("wireless", "wireless", "wireless access point")):
        put(key, *network_answer(devices, role, noun))
    put("backup_isp", "unknown", None, _UNKNOWN)
    put("server_brand", *server_brand_answer(devices))
    put("virtualization", *virtualization_answer(devices))
    put("edr_pc", *edr_answer(devices, "windows", "Windows computers", {t: cov[t].enrolled for t in EDR_TOOLS if t in cov}))
    put("encryption", "unknown", None, _UNKNOWN)
    for key in ("spam_filter", "anti_phishing", "password_manager", "external_email_banner"):
        put(key, "unknown", None, _UNKNOWN)
    by_tool("pam", "autoelevate", "windows", "Windows computers")
    put("soc", *soc_answer(enrolled_in, mapped_tools))
    in_sat = "huntress-sat" in (enrolled_in or set())
    sat_listed = "huntress-sat" in (mapped_tools or set())
    phishing = sat_phishing(sat)
    if phishing is None and in_sat:
        put("phishing_sim", "seen", SAT_NAME, f"The client is set up in {SAT_NAME}; its campaign results have not been read yet.")
    elif phishing is None and sat_listed:
        put("phishing_sim", "not_seen", "None seen", f"The client is not set up in {SAT_NAME}, although other clients are.")
    elif phishing is None:
        put("phishing_sim", "unknown", None, _UNKNOWN)
    elif phishing[0] == "not_met":
        put("phishing_sim", "not_seen", "None seen", f"{SAT_NAME}: {phishing[1]}")
    else:
        put("phishing_sim", "seen", SAT_NAME, f"{SAT_NAME}: {phishing[1]}")
    put("edr_mac", *edr_answer(devices, "mac", "Macs", {t: cov[t].enrolled for t in EDR_TOOLS if t in cov}))
    awareness = sat_awareness(sat)
    if awareness is None and in_sat:
        put("awareness", "seen", SAT_NAME, f"The client is set up in {SAT_NAME}; its training results have not been read yet.")
    elif awareness is None and sat_listed:
        put("awareness", "not_seen", "None seen", f"The client is not set up in {SAT_NAME}, although other clients are.")
    elif awareness is None:
        put("awareness", "unknown", None, _UNKNOWN)
    elif awareness[0] == "seen":
        put("awareness", "seen", SAT_NAME, f"{SAT_NAME}: {awareness[1]}")
    else:
        put("awareness", "not_seen", "None seen", f"{SAT_NAME}: {awareness[1]}")
    all_endpoints = [d for d in devices if os_kind(d.os) in {"windows", "mac", "linux"}]
    dns = sum(1 for d in all_endpoints if any(s.vendor == "dnsfilter" for s in d.sources))
    if dns > 0:
        put("dns_filter", "seen", "DNSFilter", f"{dns} of {len(all_endpoints)} computers report DNSFilter.")
    elif not all_endpoints:
        put("dns_filter", "unknown", None, "No computers are listed for this client.")
    else:
        put("dns_filter", "not_seen", "None seen", f"None of the client's {len(all_endpoints)} computers report DNSFilter.")
    if has_microsoft_365:
        put("email_service", "seen", "Microsoft 365", "Microsoft 365 sign-in data is being read for this client through CIPP.")
    else:
        put("email_service", "unknown", None, "No Microsoft 365 data has arrived for this client; it may use Google or something else.")
    put("cloud_servers", "unknown", None, _UNKNOWN)
    by_tool("apple_mdm", "addigy", "mac", "Macs")
    put("abm", "unknown", None, _UNKNOWN)
    put("backup_bcdr", *backup_answer(devices))
    cloud = saas_backup(saas)
    if cloud is None:
        put("backup_saas", "unknown", None, "No Datto SaaS Protection or Dropsuite data has arrived for this client; it may use another cloud backup, or not be mapped to one of them yet, so ask the client.")
    else:
        put("backup_saas", "seen", saas_tools(saas) or "Cloud backup", cloud[1])
    return out
