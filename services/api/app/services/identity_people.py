"""People (e-mail identities) across the connected tools, put together per client.

A person is one e-mail address (lower case) in one client. Microsoft 365 people come from CIPP's list (``identity_mfa_users``); every other tool reports its own people into ``identity_sources``.
This puts a person's rows from all tools together, says which tools know them, works out their multi-factor state from the Microsoft 365 row, and ties alerts to them by the e-mail address the alert
names. Pure functions over simple values, so every rule is testable without a database.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from app.services.mfa_registration import has_second_factor, registration_known, required_of

MICROSOFT = "cipp"
# A tool's row not refreshed for this long is no longer shown: the person has gone from that tool.
STALE_DAYS = 3
_EMAIL = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,190}\.[^@\s]{2,63}$")
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def normalize_email(raw: Any) -> str | None:
    """The e-mail address in lower case, or None when it is not one (a bare user name or a device account)."""
    text = str(raw or "").strip().lower()
    return text if _EMAIL.match(text) else None


@dataclass
class SourceRef:
    vendor: str
    external_id: str
    enabled: bool | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Person:
    tenant_id: uuid.UUID
    email: str
    client_name: str | None = None
    display_name: str | None = None
    kind: str = "user"  # user / guest / shared / other
    enabled: bool | None = None
    admin: bool = False
    licensed: bool | None = None
    mfa: str = "unknown"  # covered / registered_not_required / none / unknown
    mfa_methods: str | None = None
    sources: list[SourceRef] = field(default_factory=list)
    open_alerts: int = 0
    top_severity: str | None = None
    # Open alerts by the tool that raised them ("huntress": 2, "petra": 1); "other" when an alert names no tool.
    alerts_by_source: dict[str, int] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.tenant_id}:{self.email}"

    @property
    def vendors(self) -> list[str]:
        return sorted({s.vendor for s in self.sources})


def mfa_state(user: Any, registration_is_known: bool) -> str:
    """covered: a second factor is required of them and they have one. registered_not_required: they signed up for one but nothing requires it. none: neither. (Same rules as the Multi-Factor page.)"""
    if has_second_factor(user, registration_is_known) and required_of(user):
        return "covered"
    if registration_is_known and user.registered and not required_of(user):
        return "registered_not_required"
    return "none"


def build_people(
    names: dict[uuid.UUID, str],
    microsoft_users: list[Any],
    sources: list[Any],
    now: datetime,
    stale_days: int = STALE_DAYS,
) -> list[Person]:
    """Every person, one row each, with the tools that know them. ``microsoft_users`` are IdentityMfaUser rows and ``sources`` IdentitySource rows (anything with the same fields)."""
    people: dict[str, Person] = {}

    def person(tenant_id: uuid.UUID, email: str) -> Person:
        key = f"{tenant_id}:{email}"
        if key not in people:
            people[key] = Person(tenant_id=tenant_id, email=email, client_name=names.get(tenant_id))
        return people[key]

    by_tenant: dict[uuid.UUID, list[Any]] = {}
    for u in microsoft_users:
        by_tenant.setdefault(u.tenant_id, []).append(u)
    known = {tid: registration_known(rows) for tid, rows in by_tenant.items()}
    for u in microsoft_users:
        email = normalize_email(u.upn)
        if email is None:
            continue
        p = person(u.tenant_id, email)
        p.display_name = p.display_name or (u.display_name or None)
        p.kind = "guest" if str(u.user_type or "").lower() == "guest" else "user"
        p.enabled = bool(u.enabled)
        p.admin = bool(u.admin)
        p.licensed = bool(u.licensed)
        p.mfa = mfa_state(u, known[u.tenant_id])
        p.mfa_methods = u.methods or None
        p.sources.append(SourceRef(vendor=MICROSOFT, external_id=str(u.user_id), enabled=bool(u.enabled), details={"licensed": bool(u.licensed), "admin": bool(u.admin)}))

    cutoff = now - timedelta(days=stale_days)
    for s in sources:
        email = normalize_email(s.email)
        refreshed = s.refreshed_at if s.refreshed_at.tzinfo else s.refreshed_at.replace(tzinfo=now.tzinfo)
        if email is None or refreshed < cutoff:
            continue
        p = person(s.tenant_id, email)
        p.display_name = p.display_name or (s.display_name or None)
        if p.kind == "user" and s.kind in ("shared", "guest", "other"):
            p.kind = s.kind
        if s.enabled is False and p.enabled is None:
            p.enabled = False
        p.sources.append(SourceRef(vendor=s.vendor, external_id=s.external_id, enabled=s.enabled, details=dict(s.details or {})))
    out = list(people.values())
    for p in out:
        p.sources.sort(key=lambda r: (r.vendor != MICROSOFT, r.vendor, r.external_id))
    return out


# The managed detection and response tools: none lists its people to us, but each says who a threat is about. A person one of them raised an alert about is a person that tool is watching.
ALERT_TOOLS = frozenset({"huntress", "petra", "fieldeffect", "blumira"})


def add_alert_sources(people: list[Person], alerts: list[Any], names: dict[uuid.UUID, str], source_of: Any, tools: frozenset[str] = ALERT_TOOLS) -> list[Person]:
    """Add each MDR tool that raised an alert naming a person to that person's tools (creating the person when no other tool knows them). Returns the people, with any new ones added."""
    index = {p.key: p for p in people}
    out = list(people)
    for a in alerts:
        tool = source_of(a.raw_event, getattr(a, "connector_type", None))
        if tool not in tools:
            continue
        for raw in a.affected_users if isinstance(a.affected_users, list) else []:
            addr = normalize_email(raw)
            if addr is None:
                continue
            key = f"{a.tenant_id}:{addr}"
            p = index.get(key)
            if p is None:
                p = Person(tenant_id=a.tenant_id, email=addr, client_name=names.get(a.tenant_id))
                index[key] = p
                out.append(p)
            if not any(s.vendor == tool for s in p.sources):
                p.sources.append(SourceRef(vendor=tool, external_id="alert", details={"via": "an alert it raised"}))
    for p in out:
        p.sources.sort(key=lambda r: (r.vendor != MICROSOFT, r.vendor, r.external_id))
    return out


def attach_alerts(people: list[Person], alerts: list[Any], source_of: Any = None) -> dict[str, list[Any]]:
    """Tie open alerts to the people they name (by e-mail address, same client). Sets each person's count and highest severity; returns the alerts by person key, newest first."""
    index = {p.key: p for p in people}
    by_key: dict[str, list[Any]] = {}
    for a in alerts:
        seen: set[str] = set()
        for raw in a.affected_users if isinstance(a.affected_users, list) else []:
            email = normalize_email(raw)
            key = f"{a.tenant_id}:{email}" if email else ""
            if key and key in index and key not in seen:
                seen.add(key)
                by_key.setdefault(key, []).append(a)
    for key, rows in by_key.items():
        rows.sort(key=lambda a: a.created_at, reverse=True)
        p = index[key]
        p.open_alerts = len(rows)
        counts: dict[str, int] = {}
        for a in rows:
            tool = (source_of(a.raw_event, getattr(a, "connector_type", None)) if source_of else None) or "other"
            counts[tool] = counts.get(tool, 0) + 1
        p.alerts_by_source = dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
        p.top_severity = max((str(a.severity).lower() for a in rows), key=lambda s: _SEVERITY_RANK.get(s, -1))
    return by_key


def filter_people(
    people: list[Person],
    *,
    search: str | None = None,
    source: str | None = None,
    has_alerts: bool = False,
    mfa: str | None = None,
    admin: bool = False,
    disabled: bool = False,
    kind: str | None = None,
    only_in: str | None = None,
    alert_source: str | None = None,
) -> list[Person]:
    """The people a page asked for: every filter given must hold. ``only_in`` keeps people known to just that one tool."""
    rows = people
    if search:
        needle = search.strip().lower()
        rows = [p for p in rows if needle in p.email or needle in (p.display_name or "").lower() or needle in (p.client_name or "").lower()]
    if source:
        rows = [p for p in rows if source in p.vendors]
    if only_in:
        rows = [p for p in rows if p.vendors == [only_in]]
    if has_alerts:
        rows = [p for p in rows if p.open_alerts > 0]
    if alert_source:
        rows = [p for p in rows if p.alerts_by_source.get(alert_source, 0) > 0]
    if mfa:
        rows = [p for p in rows if p.mfa == mfa]
    if admin:
        rows = [p for p in rows if p.admin]
    if disabled:
        rows = [p for p in rows if p.enabled is False]
    if kind:
        rows = [p for p in rows if p.kind == kind]
    return rows


SORTS = ("alerts", "email", "name", "client", "tools")


def sort_people(people: list[Person], by: str = "alerts") -> list[Person]:
    """Most alerts first by default (then the most serious), or by e-mail, name, client or number of tools."""
    if by == "email":
        return sorted(people, key=lambda p: p.email)
    if by == "name":
        return sorted(people, key=lambda p: ((p.display_name or "~").lower(), p.email))
    if by == "client":
        return sorted(people, key=lambda p: ((p.client_name or "").lower(), p.email))
    if by == "tools":
        return sorted(people, key=lambda p: (-len(p.vendors), p.email))
    return sorted(people, key=lambda p: (-p.open_alerts, -_SEVERITY_RANK.get(p.top_severity or "", -1), p.email))
