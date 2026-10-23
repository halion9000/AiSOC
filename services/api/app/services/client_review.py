"""The numbers behind a client review and cyber-insurance readiness: tool coverage across a client's machines, and a plain checklist of the questions insurers and QBRs ask, each answered
from data AiSOC already holds (met, partly met, not met, or unknown when AiSOC has nothing to say). Pure functions over simple values, so every rule is testable without a database.

Nothing here is a certification: it reports what the connected tools show, and says "unknown" for what AiSOC does not collect (backups, e-mail filtering, training, a written incident plan).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.services.device_merge import os_kind
from app.services.sat_review import sat_training

# Which machines each tool should be on. Phones and tablets are never counted against a tool that has no agent for them.
_ENDPOINT = {"windows", "mac", "linux"}
COVERAGE_RULES: dict[str, set[str]] = {
    "huntress": _ENDPOINT,
    "ninjaone": _ENDPOINT,
    "dnsfilter": _ENDPOINT,
    "threatmate": _ENDPOINT,
    "fieldeffect": _ENDPOINT,
    "autoelevate": {"windows"},
    # ScreenConnect runs on Macs too; only phones, tablets and TVs are left out.
    "screenconnect": _ENDPOINT,
    "addigy": {"mac"},
}


class ToolCoverage(BaseModel):
    tool: str
    have: int
    of: int
    percent: float | None
    # Whether this client exists in the tool at all: True when the tool reports some of its machines or the client is mapped to one of its organizations, False when the tool maps clients and this one is not
    # among them ("not currently enrolled"), None when AiSOC cannot tell (the tool has no client mapping).
    enrolled: bool | None = None


class DeviceFacts(BaseModel):
    endpoints: int
    coverage: list[ToolCoverage]
    stale_agents: int
    offline: int
    # Machines ThreatMate says have a known-exploited vulnerability, and how many of those are used in ransomware. None when no machine here is covered by ThreatMate.
    with_known_exploited: int | None = None
    with_ransomware_exploit: int | None = None


def _vendors(device: Any) -> set[str]:
    return {s.vendor for s in device.sources}


def device_facts(
    devices: list[Any], stale_agents: int, offline: int, enrolled_in: set[str] | None = None, mapped_tools: set[str] | None = None
) -> DeviceFacts:
    """Coverage of each tool over the machines it should be on, and the known-exploited counts, from a client's shown devices (anything with ``os`` and ``sources``)."""
    kinds = [(d, os_kind(d.os)) for d in devices]
    endpoints = [d for d, k in kinds if k in _ENDPOINT]
    coverage: list[ToolCoverage] = []
    for tool, wanted in COVERAGE_RULES.items():
        eligible = [d for d, k in kinds if k in wanted]
        have = sum(1 for d in eligible if tool in _vendors(d))
        enrolled = (
            True
            if have > 0 or (enrolled_in is not None and tool in enrolled_in)
            else (False if mapped_tools is not None and tool in mapped_tools else None)
        )
        coverage.append(
            ToolCoverage(
                tool=tool,
                have=have,
                of=len(eligible),
                percent=round(100 * have / len(eligible), 1) if eligible else None,
                enrolled=enrolled,
            )
        )
    scanned = [d for d in endpoints if "threatmate" in _vendors(d)]
    kev = ransomware = 0
    for d in scanned:
        details = [s.details for s in d.sources if s.vendor == "threatmate"]
        if any(isinstance(x, dict) and (x.get("kev_count") or 0) > 0 for x in details):
            kev += 1
        if any(isinstance(x, dict) and x.get("kev_ransomware") is True for x in details):
            ransomware += 1
    return DeviceFacts(
        endpoints=len(endpoints),
        coverage=coverage,
        stale_agents=stale_agents,
        offline=offline,
        with_known_exploited=kev if scanned else None,
        with_ransomware_exploit=ransomware if scanned else None,
    )


class ReadinessItem(BaseModel):
    key: str
    question: str
    # met, partly, not_met, or unknown (AiSOC has no data to say either way).
    status: str
    evidence: str


class Readiness(BaseModel):
    met: int
    partly: int
    not_met: int
    unknown: int
    items: list[ReadinessItem]


def _share(part: int, whole: int) -> float:
    return 100 * part / whole if whole else 0.0


def _banded(percent: float, met: float, partly: float) -> str:
    return "met" if percent >= met else "partly" if percent >= partly else "not_met"


def readiness(
    facts: DeviceFacts, mfa: dict[str, int] | None, secure_percent: float | None, sat: list[dict[str, Any]] | None = None
) -> Readiness:
    """The checklist. ``mfa`` is ``counts_for_mfa``'s output (None when no multi-factor data has arrived); ``secure_percent`` is the Microsoft Secure Score as a percentage (None when not read)."""
    cov = {c.tool: c for c in facts.coverage}
    items: list[ReadinessItem] = []

    def add(key: str, question: str, status: str, evidence: str) -> None:
        items.append(ReadinessItem(key=key, question=question, status=status, evidence=evidence))

    if mfa is None or mfa["people"] == 0:
        add(
            "mfa_everyone",
            "Is Multi-Factor required for everyone?",
            "unknown",
            "No multi-factor data for this client yet (CIPP not connected or not mapped).",
        )
        add("mfa_admins", "Is Multi-Factor required for administrators?", "unknown", "No multi-factor data for this client yet.")
    else:
        pct = _share(mfa["with_mfa"], mfa["people"])
        if mfa.get("registration_unknown"):
            evidence = (
                f"{mfa['with_mfa']} of {mfa['people']} people ({pct:.0f}%) are required to use a second factor (security defaults, conditional access or a per-user setting); {mfa['without_mfa']} are not. "
                "Microsoft doesn't report who has registered one for this client (that needs Entra ID P1), so this shows what is required, not who has signed up."
            )
        else:
            evidence = f"{mfa['with_mfa']} of {mfa['people']} people ({pct:.0f}%) have a second factor that is required; {mfa['without_mfa']} have none."
        add("mfa_everyone", "Is Multi-Factor required for everyone?", _banded(pct, 95, 80), evidence)
        add(
            "mfa_admins",
            "Is Multi-Factor required for administrators?",
            "met" if mfa["admins_without_mfa"] == 0 else "not_met",
            "Every administrator has Multi-Factor."
            if mfa["admins_without_mfa"] == 0
            else f"{mfa['admins_without_mfa']} administrator(s) have no Multi-Factor.",
        )

    def tool_item(key: str, question: str, tool: str, met: float, partly: float, what: str) -> None:
        c = cov[tool]
        if c.of == 0:
            add(key, question, "unknown", f"No {what} machines are listed for this client.")
        elif c.enrolled is False:
            add(key, question, "not_met", f"Not currently enrolled in {tool_label(tool)}: none of the {c.of} {what} machines report it.")
        else:
            add(
                key,
                question,
                _banded(c.percent or 0.0, met, partly),
                f"{c.have} of {c.of} {what} machines ({c.percent:.0f}%) report {tool_label(tool)}.",
            )

    tool_item("edr", "Is endpoint detection and response on every computer?", "huntress", 95, 80, "Windows, Mac and Linux")
    tool_item("management", "Are computers managed and patched through a management tool?", "ninjaone", 95, 80, "Windows, Mac and Linux")
    tool_item("dns", "Is DNS or web filtering on every computer?", "dnsfilter", 90, 70, "Windows, Mac and Linux")
    tool_item("privilege", "Is administrator access controlled and approved (privilege elevation)?", "autoelevate", 90, 60, "Windows")

    if facts.endpoints == 0:
        add("agents_reporting", "Are protection agents checking in?", "unknown", "No computers are listed for this client.")
    elif facts.stale_agents == 0:
        add("agents_reporting", "Are protection agents checking in?", "met", "No agent has gone two weeks without checking in.")
    else:
        pct = _share(facts.stale_agents, facts.endpoints)
        add(
            "agents_reporting",
            "Are protection agents checking in?",
            "partly" if pct <= 5 else "not_met",
            f"{facts.stale_agents} agent(s) have not checked in for two weeks or more.",
        )

    if facts.with_known_exploited is None:
        add("patching", "Are known-exploited vulnerabilities fixed?", "unknown", "ThreatMate does not scan this client's machines.")
    elif facts.with_known_exploited == 0:
        add("patching", "Are known-exploited vulnerabilities fixed?", "met", "No scanned machine has a known-exploited vulnerability.")
    else:
        scanned = max(1, cov["threatmate"].have)
        ransom = f", {facts.with_ransomware_exploit} used in ransomware" if facts.with_ransomware_exploit else ""
        add(
            "patching",
            "Are known-exploited vulnerabilities fixed?",
            "partly" if _share(facts.with_known_exploited, scanned) <= 5 else "not_met",
            f"{facts.with_known_exploited} of {scanned} scanned machines have one{ransom}.",
        )

    if secure_percent is None:
        add(
            "secure_score",
            "Is Microsoft 365 configured to Microsoft's recommendations?",
            "unknown",
            "No Microsoft Secure Score read for this client yet.",
        )
    else:
        add(
            "secure_score",
            "Is Microsoft 365 configured to Microsoft's recommendations?",
            _banded(secure_percent, 60, 40),
            f"Microsoft Secure Score is {secure_percent:.0f}%.",
        )

    for key, question in (
        ("backups", "Are backups tested and kept offline?"),
        ("email_filtering", "Is e-mail filtered for phishing and malware?"),
        ("ir_plan", "Is there a written incident response plan?"),
    ):
        add(key, question, "unknown", "AiSOC does not collect this yet; answer it from the client's own records.")

    trained = sat_training(sat)
    if trained is None:
        add(
            "training",
            "Do staff take security awareness training?",
            "unknown",
            "AiSOC does not collect this yet; answer it from the client's own records.",
        )
    else:
        add("training", "Do staff take security awareness training?", trained[0], f"Huntress SAT: {trained[1]}")

    return Readiness(
        met=sum(1 for i in items if i.status == "met"),
        partly=sum(1 for i in items if i.status == "partly"),
        not_met=sum(1 for i in items if i.status == "not_met"),
        unknown=sum(1 for i in items if i.status == "unknown"),
        items=items,
    )


_LABELS = {
    "huntress": "Huntress",
    "ninjaone": "NinjaOne",
    "dnsfilter": "DNSFilter",
    "threatmate": "ThreatMate",
    "fieldeffect": "Field Effect",
    "autoelevate": "AutoElevate",
    "screenconnect": "ScreenConnect",
    "addigy": "Addigy",
}


def tool_label(tool: str) -> str:
    return _LABELS.get(tool, tool)
