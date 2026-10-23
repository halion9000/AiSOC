"""What Huntress Security Awareness Training tells the client review.

CORE reads each mapped SAT account once a day and sends three plain checks (``sat_training_assigned``, ``sat_training_completion``, ``sat_phishing_simulation``) on the same route as the Microsoft 365
checks, under the vendor ``huntress-sat``. Each check is ``{key, status: met|partly|not_met, evidence}``. They answer three review questions. Pure functions over those lists.
"""

from __future__ import annotations

from typing import Any

SAT_SOURCE = "huntress-sat"
TOOL_NAME = "Huntress SAT"

_RANK = {"met": 0, "partly": 1, "not_met": 2}


def _find(checks: list[dict[str, Any]] | None, key: str) -> dict[str, Any] | None:
    return next((c for c in checks or [] if isinstance(c, dict) and c.get("key") == key and c.get("status") in _RANK), None)


def sat_training(checks: list[dict[str, Any]] | None) -> tuple[str, str] | None:
    """(status, evidence) for "do staff take security awareness training": the worse of "is training assigned" and "are staff finishing it". None when SAT sent nothing about training."""
    parts = [c for c in (_find(checks, "sat_training_assigned"), _find(checks, "sat_training_completion")) if c is not None]
    if not parts:
        return None
    worst = max(parts, key=lambda c: _RANK[c["status"]])
    return worst["status"], " ".join(str(c.get("evidence", "")).strip().rstrip(".") + "." for c in parts)[:400]


def sat_phishing(checks: list[dict[str, Any]] | None) -> tuple[str, str] | None:
    """(status, evidence) for "do you have a phishing simulation system", or None when SAT sent nothing about it."""
    c = _find(checks, "sat_phishing_simulation")
    return (c["status"], str(c.get("evidence", ""))) if c is not None else None


def sat_awareness(checks: list[dict[str, Any]] | None) -> tuple[str, str] | None:
    """(status, evidence) for "what awareness package is in use": ``seen`` when the account has run training at all (even a while ago), ``not_seen`` when it never has. None when SAT sent nothing."""
    c = _find(checks, "sat_training_assigned")
    if c is None:
        return None
    return ("seen" if c["status"] in ("met", "partly") else "not_seen"), str(c.get("evidence", ""))
