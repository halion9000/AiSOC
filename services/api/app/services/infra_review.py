"""What the client's network equipment, servers and backup tools say, for the review's technology questions and readiness checklist.

Network equipment comes from the tools that list it (Meraki, UniFi, Auvik): each device is a firewall, a switch or a wireless access point by what that tool says it is. Servers and their brand, and the
virtualization in use, come from what each machine reports about itself. Backups come from Slide, the one backup tool A.C.O.R.N reads for machines. Pure functions over devices (anything with ``os``,
``manufacturer``, ``model`` and ``sources``), so every rule is testable without a database. Nothing here guesses: what cannot be seen is left to the caller as unknown.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from app.services.device_merge import os_kind

NETWORK_TOOLS = frozenset({"meraki", "unifi", "auvik"})
_BRAND_OF_TOOL = {"meraki": "Meraki", "unifi": "UniFi"}

_AUVIK_ROLE = {
    "firewall": "firewall",
    "utm": "firewall",
    "securityappliance": "firewall",
    "switch": "switch",
    "l3switch": "switch",
    "voipswitch": "switch",
    "accesspoint": "wireless",
    "thinaccesspoint": "wireless",
}
_MERAKI_NETWORK = {"appliance", "switch", "wireless", "cellulargateway", "wirelesscontroller"}
_MERAKI_ROLE = {"appliance": "firewall", "switch": "switch", "wireless": "wireless"}
# UniFi model codes: gateways (Dream Machines, Cloud Gateways, Security Gateways), switches, access points.
_UNIFI_FIREWALL = re.compile(r"^(UDM|UDR|UDW|UXG|UCG|USG|EFG)", re.IGNORECASE)
_UNIFI_SWITCH = re.compile(r"^(USW|US-|US\d|USL|USMINI|UFLEX)", re.IGNORECASE)
_UNIFI_WIRELESS = re.compile(r"^(UAP|U6|U7|UWB|UBB|UAL|E7)", re.IGNORECASE)


def _kind_text(value: Any) -> str:
    return str(value or "").strip().lower()


def network_role(device: Any) -> tuple[str, str] | None:
    """(role, brand) when a tool says this device is a firewall, switch or wireless access point; None when none does. The brand is the tool for Meraki and UniFi, else the maker the device reports."""
    for s in device.sources:
        det = s.details or {}
        role: str | None = None
        if s.vendor == "meraki":
            role = _MERAKI_ROLE.get(_kind_text(det.get("product_type")))
        elif s.vendor == "unifi":
            model = str(getattr(device, "model", None) or "").strip()
            role = "firewall" if _UNIFI_FIREWALL.match(model) else "switch" if _UNIFI_SWITCH.match(model) else "wireless" if _UNIFI_WIRELESS.match(model) else None
        elif s.vendor == "auvik":
            role = _AUVIK_ROLE.get(_kind_text(det.get("device_type")))
        if role:
            brand = _BRAND_OF_TOOL.get(s.vendor) or _brand(getattr(device, "manufacturer", None)) or "Brand not reported"
            return role, brand
    return None


def _brand(maker: Any) -> str | None:
    text = re.sub(r"[,.]?\s*\b(inc|corp|corporation|ltd|llc|co|company|technologies|international)\b\.?", "", str(maker or ""), flags=re.IGNORECASE).strip(" ,.")
    return text[:60] or None


def _has_network_tool(device: Any) -> bool:
    return any(s.vendor in NETWORK_TOOLS for s in device.sources)


def _summary(counter: Counter[str]) -> str:
    return ", ".join(f"{brand} ({n})" if n > 1 else brand for brand, n in counter.most_common())


def network_answer(devices: list[Any], role: str, noun: str) -> tuple[str, str | None, str]:
    """(status, suggested, evidence) for one network question: ``seen`` with the brands, ``not_seen`` when the client's network gear is listed but none is of this kind, ``unknown`` when none is listed."""
    found = [(d, r) for d in devices if (r := network_role(d)) is not None and r[0] == role]
    if found:
        brands = Counter(r[1] for _, r in found)
        models = sorted({str(d.model).strip() for d, _ in found if getattr(d, "model", None)})[:6]
        shown = f" Models: {', '.join(models)}." if models else ""
        return "seen", _summary(brands), f"{len(found)} {noun}{'' if len(found) == 1 else 's'} listed by the network tools.{shown}"
    if any(_has_network_tool(d) for d in devices):
        return "not_seen", "None seen", f"The client's network equipment is listed, but none of it is a {noun}."
    return "unknown", None, "No network equipment is listed for this client (Meraki, UniFi and Auvik are the tools A.C.O.R.N reads); ask the client."


def _is_server(device: Any) -> bool:
    return "server" in _kind_text(getattr(device, "os", None))


_VIRTUAL = (
    (re.compile(r"vmware", re.IGNORECASE), "VMware"),
    (re.compile(r"virtualbox|innotek", re.IGNORECASE), "VirtualBox"),
    (re.compile(r"kvm|qemu", re.IGNORECASE), "KVM"),
    (re.compile(r"xen\b", re.IGNORECASE), "Xen"),
)


def hypervisor_of(device: Any) -> str | None:
    """The virtualization a machine runs on, from the make and model it reports about itself. A Windows machine that reports Microsoft's "Virtual Machine" is Hyper-V (or Azure, which is Hyper-V)."""
    text = f"{getattr(device, 'manufacturer', '') or ''} {getattr(device, 'model', '') or ''}"
    if re.search(r"microsoft", text, re.IGNORECASE) and re.search(r"virtual machine", text, re.IGNORECASE):
        return "Hyper-V"
    for pattern, name in _VIRTUAL:
        if pattern.search(text):
            return name
    return None


def server_brand_answer(devices: list[Any]) -> tuple[str, str | None, str]:
    """The make of the client's physical servers. Virtual servers have no make of their own and are counted apart."""
    servers = [d for d in devices if _is_server(d)]
    if not servers:
        return "unknown", None, "No servers are listed for this client."
    virtual = [d for d in servers if hypervisor_of(d)]
    physical = [d for d in servers if d not in virtual]
    brands = Counter(b for d in physical if (b := _brand(getattr(d, "manufacturer", None))))
    note = f" {len(virtual)} more run as virtual machines." if virtual else ""
    if brands:
        return "seen", _summary(brands), f"{sum(brands.values())} of {len(servers)} servers report a maker.{note}"
    if virtual:
        return "seen", "Virtual machines", f"All {len(servers)} servers run as virtual machines, so they have no maker of their own."
    return "unknown", None, f"None of the {len(servers)} servers report a maker; ask the client."


def virtualization_answer(devices: list[Any]) -> tuple[str, str | None, str]:
    """The virtualization in use, from machines that report running on one. A physical host cannot be told from the machines it runs, so none seen is unknown, never "no virtualization"."""
    found = Counter(h for d in devices if (h := hypervisor_of(d)))
    if found:
        return "seen", _summary(found), f"{sum(found.values())} machines report running on it."
    return "unknown", None, "No machine reports running as a virtual machine; a physical host cannot be seen from here, so ask the client."


# ---- endpoint detection and response (Huntress and Field Effect) ------------------------------------------------------------------------------------

# Two tools act as the endpoint EDR: a machine is covered when either reports it.
EDR_TOOLS = {"huntress": "Huntress", "fieldeffect": "Field Effect"}


class EdrSummary:
    def __init__(self, total: int) -> None:
        self.total = total
        self.covered = 0
        self.by_tool: dict[str, int] = {}
        self.both = 0

    @property
    def percent(self) -> float:
        return 100 * self.covered / self.total if self.total else 0.0

    def line(self) -> str:
        parts = ", ".join(f"{EDR_TOOLS[t]} {n}" for t, n in self.by_tool.items())
        both = f", {self.both} report both" if self.both else ""
        return f"{parts}{both}" if parts else "none report an EDR"


def edr_summary(devices: list[Any], kinds: set[str]) -> EdrSummary:
    """How many of the client's machines of these operating systems are covered by an EDR: Huntress or Field Effect, counted once each."""
    eligible = [d for d in devices if os_kind(getattr(d, "os", None)) in kinds]
    out = EdrSummary(len(eligible))
    for d in eligible:
        have = {s.vendor for s in d.sources} & set(EDR_TOOLS)
        for tool in have:
            out.by_tool[tool] = out.by_tool.get(tool, 0) + 1
        out.covered += 1 if have else 0
        out.both += 1 if len(have) == len(EDR_TOOLS) else 0
    out.by_tool = {t: out.by_tool[t] for t in EDR_TOOLS if t in out.by_tool}
    return out


def edr_answer(devices: list[Any], kind: str, what: str, enrolled: dict[str, bool | None] | None = None) -> tuple[str, str | None, str]:
    """Suggested answer for "what endpoint security is in use": every EDR that covers machines of this kind, with its count."""
    s = edr_summary(devices, {kind})
    if s.covered > 0:
        names = ", ".join(f"{EDR_TOOLS[t]} ({n})" if len(s.by_tool) > 1 else EDR_TOOLS[t] for t, n in sorted(s.by_tool.items(), key=lambda kv: -kv[1]))
        return "seen", names, f"{s.covered} of {s.total} {what} report an EDR ({s.line()})."
    if s.total == 0:
        return "unknown", None, f"No {what} are listed for this client."
    out = [EDR_TOOLS[t] for t in EDR_TOOLS if (enrolled or {}).get(t) is False]
    if out:
        return "not_seen", "None seen", f"The client is not enrolled in {' or '.join(out)}: none of its {s.total} {what} report an EDR."
    return "not_seen", "None seen", f"None of the client's {s.total} {what} report Huntress or Field Effect."


# ---- backups -------------------------------------------------------------------------------------------------------------------------------------------

# The tools that back up machines: Datto BCDR and Slide both protect servers (and the computers a client chooses to add). Datto SaaS Protection backs up Microsoft 365 and Google Workspace instead and is
# read through its own checks (see ``saas_backup``).
BACKUP_TOOLS = {"datto-bcdr": "Datto BCDR", "slide": "Slide"}
SAAS_SOURCE = "datto-saas"
SAAS_NAME = "Datto SaaS Protection"
_BACKUP_OS = {"windows", "mac", "linux"}
STALE_SNAPSHOT_DAYS = 3


class ToolBackup:
    """What one backup tool protects: servers and other machines, and (Datto) how many of them have gone quiet."""

    def __init__(self) -> None:
        self.servers = 0
        self.computers = 0
        self.quiet = 0


class BackupSummary:
    def __init__(self, servers: int, computers: int) -> None:
        self.servers = servers
        self.computers = computers
        self.tools: dict[str, ToolBackup] = {}
        self.protected = 0
        # Machines with a backup that is current: Slide, or a Datto agent that snapshotted within the last few days.
        self.fresh = 0


def _snapshot_is_old(source: Any, now: datetime) -> bool:
    raw = (getattr(source, "details", None) or {}).get("last_snapshot_at")
    if not raw:
        return True
    try:
        taken = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return True
    if taken.tzinfo is None:
        taken = taken.replace(tzinfo=UTC)
    return now - taken > timedelta(days=STALE_SNAPSHOT_DAYS)


def backup_summary(devices: list[Any], now: datetime | None = None) -> BackupSummary | None:
    """What each backup tool protects out of the client's servers and computers, counting each machine once per tool. None when no machine reports a backup tool, since another may be in use.
    A machine only a backup tool lists (no operating system known) counts as a computer."""
    now = now or datetime.now(UTC)
    machines = [d for d in devices if os_kind(getattr(d, "os", None)) in _BACKUP_OS or any(s.vendor in BACKUP_TOOLS for s in d.sources)]
    out = BackupSummary(sum(1 for d in machines if _is_server(d)), sum(1 for d in machines if not _is_server(d)))
    for d in machines:
        covered = fresh = False
        for tool in BACKUP_TOOLS:
            mine = [s for s in d.sources if s.vendor == tool]
            if not mine:
                continue
            covered = True
            t = out.tools.setdefault(tool, ToolBackup())
            if _is_server(d):
                t.servers += 1
            else:
                t.computers += 1
            if tool == "datto-bcdr" and all(_snapshot_is_old(s, now) for s in mine):
                t.quiet += 1
            else:
                fresh = True
        out.protected += 1 if covered else 0
        out.fresh += 1 if fresh else 0
    return out if out.tools else None


def _tool_line(tool: str, t: ToolBackup, s: BackupSummary) -> str:
    quiet = f" ({t.quiet} with no snapshot in {STALE_SNAPSHOT_DAYS} days)" if t.quiet else ""
    return f"{BACKUP_TOOLS[tool]} protects {t.servers} of {s.servers} servers and {t.computers} of {s.computers} computers{quiet}."


def backup_answer(devices: list[Any], now: datetime | None = None) -> tuple[str, str | None, str]:
    """Suggested answer for "what vendor is the client using for backup services (Datto is our standard)": every machine backup tool that protects some of the client's machines."""
    s = backup_summary(devices, now)
    if s is None:
        return "unknown", None, "No machine reports Datto BCDR or Slide, the backup tools A.C.O.R.N reads for machines; another tool may be in use, so ask the client."
    ranked = sorted(s.tools.items(), key=lambda kv: -(kv[1].servers + kv[1].computers))
    names = ", ".join(f"{BACKUP_TOOLS[k]} ({t.servers + t.computers})" if len(s.tools) > 1 else BACKUP_TOOLS[k] for k, t in ranked)
    return "seen", names, " ".join(_tool_line(k, t, s) for k, t in ranked)


def backup_readiness(devices: list[Any], now: datetime | None = None) -> tuple[str, str] | None:
    """(status, evidence) for the readiness item "are backups tested and kept offline". Coverage by any machine backup tool is all A.C.O.R.N can see: it cannot see a restore test or an offline copy, so this is
    never ``met``. A Datto agent with no recent snapshot is not counted as protected. None when no machine reports a backup tool."""
    s = backup_summary(devices, now)
    if s is None:
        return None
    total = s.servers + s.computers
    share = 100 * s.fresh / total if total else 0.0
    status = "partly" if share >= 50 else "not_met"
    lines = " ".join(_tool_line(k, t, s) for k, t in s.tools.items())
    gap = "" if s.protected >= total else f" {total - s.protected} of {total} machines have no backup tool."
    return status, f"{lines}{gap} A.C.O.R.N cannot see whether restores are tested or copies kept offline; confirm that with the client."


# ---- cloud backups (Datto SaaS Protection) ---------------------------------------------------------------------------------------------------------------

_RANK = {"met": 0, "partly": 1, "not_met": 2}
_SAAS_KEYS = {"saas_backup_microsoft": "Microsoft 365", "saas_backup_google": "Google Workspace"}


def saas_backup(checks: list[dict[str, Any]] | None) -> tuple[str, str] | None:
    """(status, evidence) for "are Microsoft 365 and Google Workspace data backed up": the worst of the products Datto SaaS Protection reports. None when it reported nothing."""
    found = [c for c in checks or [] if isinstance(c, dict) and c.get("key") in _SAAS_KEYS and c.get("status") in _RANK]
    if not found:
        return None
    worst = max(found, key=lambda c: _RANK[c["status"]])
    return worst["status"], " ".join(str(c.get("evidence", "")).strip().rstrip(".") + "." for c in found)[:400]


# ---- network health ------------------------------------------------------------------------------------------------------------------------------------

_ONLINE = {"online", "connected"}
_OFFLINE = {"offline", "dormant", "alerting", "disconnected"}


def network_online(devices: list[Any]) -> tuple[int, int] | None:
    """(online, with a known state) over network devices whose tool reports online/offline (Meraki, UniFi). None when none does."""
    online = known = 0
    for d in devices:
        for s in d.sources:
            det = s.details or {}
            if s.vendor not in ("meraki", "unifi") or (s.vendor == "meraki" and _kind_text(det.get("product_type")) not in _MERAKI_NETWORK) or (s.vendor == "unifi" and _kind_text(det.get("product_line")) == "protect"):
                continue
            state = _kind_text(det.get("status"))
            if state in _ONLINE:
                online += 1
                known += 1
                break
            if state in _OFFLINE:
                known += 1
                break
    return (online, known) if known else None
