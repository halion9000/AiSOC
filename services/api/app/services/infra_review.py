"""What the client's network equipment, servers and backup tools say, for the review's technology questions and readiness checklist.

Network equipment comes from the tools that list it (Meraki, UniFi, Auvik): each device is a firewall, a switch or a wireless access point by what that tool says it is. Servers and their brand, and the
virtualization in use, come from what each machine reports about itself. Backups come from Slide, the one backup tool A.C.O.R.N reads for machines. Pure functions over devices (anything with ``os``,
``manufacturer``, ``model`` and ``sources``), so every rule is testable without a database. Nothing here guesses: what cannot be seen is left to the caller as unknown.
"""

from __future__ import annotations

import re
from collections import Counter
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


# ---- backups -------------------------------------------------------------------------------------------------------------------------------------------

BACKUP_TOOL = "slide"
_BACKUP_OS = {"windows", "mac", "linux"}


def backup_coverage(devices: list[Any]) -> tuple[int, int, int, int] | None:
    """(servers protected, servers, computers protected, computers) by Slide, counting each machine once. None when no machine reports Slide, since another backup tool may be in use."""
    eligible = [d for d in devices if os_kind(getattr(d, "os", None)) in _BACKUP_OS]
    protected = {id(d) for d in eligible if any(s.vendor == BACKUP_TOOL for s in d.sources)}
    if not protected:
        return None
    servers = [d for d in eligible if _is_server(d)]
    computers = [d for d in eligible if not _is_server(d)]
    return (
        sum(1 for d in servers if id(d) in protected),
        len(servers),
        sum(1 for d in computers if id(d) in protected),
        len(computers),
    )


def backup_answer(devices: list[Any]) -> tuple[str, str | None, str]:
    """Suggested answer for "what vendor is the client using for backup services"."""
    cov = backup_coverage(devices)
    if cov is None:
        return "unknown", None, "No machine reports Slide, the only backup tool A.C.O.R.N reads for machines; another tool may be in use, so ask the client."
    ps, s, pc, c = cov
    return "seen", "Slide", f"Slide protects {ps} of {s} servers and {pc} of {c} computers."


def backup_readiness(devices: list[Any]) -> tuple[str, str] | None:
    """(status, evidence) for the readiness item "are backups tested and kept offline". Coverage is all A.C.O.R.N can see: it cannot see a restore test or an offline copy, so this is never ``met``. None when no machine reports Slide."""
    cov = backup_coverage(devices)
    if cov is None:
        return None
    ps, s, pc, c = cov
    total, protected = s + c, ps + pc
    share = 100 * protected / total if total else 0.0
    status = "partly" if share >= 50 else "not_met"
    gap = "" if protected == total else f" {total - protected} are not protected."
    return status, f"Slide protects {ps} of {s} servers and {pc} of {c} computers.{gap} A.C.O.R.N cannot see whether restores are tested or copies kept offline; confirm that with the client."


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
