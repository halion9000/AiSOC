"""Rules for the actions an analyst can ask CORE to carry out at a vendor (today: Huntress incident remediation).

Pure functions, no database, so the rules are testable on their own. The API routes call these before queueing anything.

What Huntress allows (its API reference, ``/v1/incident_reports``): the remediation plan on an incident can be approved or rejected as a whole, and an incident can be
resolved only when its report status is ``sent`` and every remediation has been approved. Rejecting sends the incident back to the Huntress SOC.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

SUPPORTED_VENDOR = "huntress"
ACTIONS = ("approve", "reject", "resolve")
# Vendors whose incident can only be RESOLVED from AiSOC (no remediation plan to approve first). Blumira: POST .../findings/{id}/resolve with a ``resolution`` code;
# Field Effect: POST /v1/aros/{id}/transition to status Closed / resolution Resolved. Both bodies are from the vendors' own API docs.
RESOLVE_ONLY_VENDORS = ("blumira", "fieldeffect")
BLUMIRA_RESOLUTIONS = {10: "Valid", 20: "False Positive", 30: "No Action Needed", 40: "Risk Accepted"}

# A queued action nobody collected within this long is treated as expired: an approval clicked while CORE was off must not fire hours later.
PENDING_TTL = timedelta(minutes=30)
# A claimed action CORE never reported on within this long is failed, so it cannot sit "running" forever.
CLAIMED_TTL = timedelta(minutes=10)

REJECT_REASONS = (
    "unspecified",
    "approved_application",
    "manually_remediated",
    "host_reimaged",
    "testing_security_controls",
    "other",
    "approved_user_login_location_m365",
    "approved_user_email_forwarding_rule_m365",
    "approved_application_m365",
    "manually_remediated_m365",
    "testing_security_controls_m365",
    "approved_vpn_or_proxy_usage_m365",
    "other_m365",
)

_UID = re.compile(r"^huntress:([0-9]{1,12})$")
_RESOLVE_ONLY_UID = re.compile(r"^(blumira|fieldeffect):[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")
# Remediation statuses from Huntress's list endpoint; only ``unapproved`` can still be approved or rejected.
_OPEN_REMEDIATION = "unapproved"


def huntress_incident_id(uid: Any) -> int | None:
    """The numeric Huntress incident id in a ``huntress:<id>`` finding uid, or None if this is not one."""
    if not isinstance(uid, str):
        return None
    m = _UID.match(uid)
    return int(m.group(1)) if m else None


def alert_incident_uid(raw_event: Any) -> str | None:
    """The finding uid of a Huntress alert (``huntress:<id>``), or None when the alert did not come from Huntress or carries no id."""
    if not isinstance(raw_event, dict) or raw_event.get("source") != SUPPORTED_VENDOR:
        return None
    finding = raw_event.get("finding")
    uid = finding.get("uid") if isinstance(finding, dict) else None
    return uid if huntress_incident_id(uid) is not None else None


def alert_vendor_and_uid(raw_event: Any) -> tuple[str, str] | None:
    """(vendor, finding uid) of an alert AiSOC can act on: a Huntress incident, or a Blumira finding / Field Effect ARO (resolve only). None for anything else."""
    huntress = alert_incident_uid(raw_event)
    if huntress is not None:
        return SUPPORTED_VENDOR, huntress
    if not isinstance(raw_event, dict):
        return None
    source = raw_event.get("source")
    finding = raw_event.get("finding")
    uid = finding.get("uid") if isinstance(finding, dict) else None
    if source in RESOLVE_ONLY_VENDORS and isinstance(uid, str) and uid.startswith(f"{source}:") and _RESOLVE_ONLY_UID.match(uid):
        return source, uid
    return None


def vendor_account_id(raw_event: Any) -> str | None:
    """The Blumira account (client) id an alert came from, kept in the record's context; needed to resolve through an MSP key. None when absent."""
    ctx = (
        raw_event.get("unmapped", {}).get("context")
        if isinstance(raw_event, dict) and isinstance(raw_event.get("unmapped"), dict)
        else None
    )
    value = ctx.get("blumira_account_id") if isinstance(ctx, dict) else None
    return value.strip() if isinstance(value, str) and value.strip() else None


def problem_with_resolve_only(vendor: str, action: str, resolution: int | None, alert_status: str) -> str | None:
    """Why a Blumira / Field Effect alert cannot be resolved from AiSOC right now, or None."""
    if action != "resolve":
        return f"Only resolving is supported for {vendor}; there is no remediation plan to approve or reject."
    if alert_status == "resolved":
        return "This alert is already resolved."
    if vendor == "blumira" and resolution not in BLUMIRA_RESOLUTIONS:
        return "Pick how Blumira should record it: " + ", ".join(f"{k} {v}" for k, v in BLUMIRA_RESOLUTIONS.items()) + "."
    return None


def _remediations(vendor_state: Any) -> list[dict[str, Any]]:
    items = vendor_state.get("remediations") if isinstance(vendor_state, dict) else None
    return [r for r in items if isinstance(r, dict)] if isinstance(items, list) else []


def problem_with_request(action: str, vendor_state: Any) -> str | None:
    """Why this action cannot be requested right now, or None if it can.

    ``vendor_state`` is what CORE last reported for the incident (``status`` and ``remediations``). With nothing reported yet we refuse: AiSOC would be acting blind.
    """
    if action not in ACTIONS:
        return f"Unknown action {action!r}."
    if not isinstance(vendor_state, dict) or not vendor_state.get("status"):
        return "CORE has not reported this incident's current state yet; wait for its next sync."
    if str(vendor_state.get("status")).lower() != "sent":
        return f"The incident is {vendor_state.get('status')!r} in Huntress; only an open ('sent') incident can be acted on."
    open_ones = [r for r in _remediations(vendor_state) if str(r.get("status", "")).lower() == _OPEN_REMEDIATION]
    if action in ("approve", "reject") and not open_ones:
        return "There are no unapproved remediations to approve or reject."
    if action == "resolve" and open_ones:
        return f"{len(open_ones)} remediation(s) are still unapproved; Huntress requires every remediation to be approved before an incident is resolved."
    return None


def effective_status(status: str, created_at: datetime, claimed_at: datetime | None, now: datetime | None = None) -> str:
    """The status to show: a pending action past its time-to-live reads ``expired``, a claimed one CORE never answered reads ``failed``."""
    now = now or datetime.now(UTC)
    if status == "pending" and now - created_at > PENDING_TTL:
        return "expired"
    if status == "claimed" and claimed_at is not None and now - claimed_at > CLAIMED_TTL:
        return "failed"
    return status
