"""The alert email: one plain-text message listing alerts, built so that nothing in an alert can change what the message IS.

Alert text comes from monitored systems and therefore from attackers (a hostname, a username, a rule name can say anything). So every field that came from an alert is: stripped of control, line-break, bidirectional-override and zero-width characters
(no header injection, no "line" an attacker can forge, no reversed text), collapsed to one line, limited in length, and has its links DEFANGED (`http://` becomes `hxxp://`) so a mail client does not turn it into a clickable lure. Raw events and the alert description are
never included. The only link in the message is the console's own address plus the alert's id, which is a UUID.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
_LINK = re.compile(r"(?i)\b(https?)://")

TITLE_LIMIT, NAME_LIMIT, RULE_LIMIT, SUBJECT_LIMIT = 200, 80, 80, 150


def clean(value: object, limit: int) -> str:
    """One safe line of at most `limit` characters from untrusted text."""
    text = _UNSAFE.sub(" ", str(value or ""))
    text = " ".join(text.split())
    text = _LINK.sub(lambda m: m.group(1).lower().replace("tt", "xx") + "://", text)
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


@dataclass(frozen=True)
class AlertLine:
    id: uuid.UUID
    tenant_name: str
    title: str
    severity: str
    rule_name: str | None
    connector_type: str | None
    created_at: datetime | None


def _severity(value: str) -> str:
    return value.lower() if value and value.lower() in SEVERITY_ORDER else "info"


def build_message(alerts: list[AlertLine], *, pending_more: int, min_severity: str, console_base_url: str = "") -> tuple[str, str]:
    """(subject, body) for these alerts, most severe first."""
    ordered = sorted(alerts, key=lambda a: (-SEVERITY_ORDER[_severity(a.severity)], a.created_at or datetime.min))
    top = _severity(ordered[0].severity) if ordered else "info"
    count = len(ordered)
    subject = clean(f"[AiSOC] {count} alert{'' if count == 1 else 's'}, highest {top.upper()}: {clean(ordered[0].title, 70) if ordered else ''}", SUBJECT_LIMIT)
    base = console_base_url.strip().rstrip("/") if console_base_url.lower().startswith(("http://", "https://")) else ""
    lines = [f"AiSOC: {count} alert{'' if count == 1 else 's'} at or above {min_severity.upper()} severity.", ""]
    for a in ordered:
        when = a.created_at.strftime("%Y-%m-%d %H:%M UTC") if a.created_at else "time unknown"
        detail = " | ".join(p for p in (f"rule: {clean(a.rule_name, RULE_LIMIT)}" if a.rule_name else "", f"source: {clean(a.connector_type, RULE_LIMIT)}" if a.connector_type else "", when) if p)
        lines.append(f"[{_severity(a.severity).upper()}] {clean(a.tenant_name, NAME_LIMIT)}: {clean(a.title, TITLE_LIMIT)}")
        lines.append(f"  {detail}")
        if base:
            lines.append(f"  {base}/alerts/{a.id}")
        lines.append("")
    if pending_more > 0:
        lines += [f"{pending_more} more alert{'' if pending_more == 1 else 's'} {'is' if pending_more == 1 else 'are'} waiting and will follow in the next email.", ""]
    lines += [
        "You receive this because you are listed in AiSOC's platform alert email setting (platform administrators only).",
        "Names and titles above come from monitored systems: treat them as untrusted, and open alerts in the console.",
    ]
    return subject, "\n".join(lines)
