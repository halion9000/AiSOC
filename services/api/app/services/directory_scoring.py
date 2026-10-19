"""Turn directory audit entries (a role added, a password reset, a security method registered, ...) into numbers for the UEBA service, scored per actor.

What makes one of these unusual is who did it and what it was, so the features are:

- ``hour_of_day`` (UTC): an administrator who always works 14:00-22:00 UTC is unusual at 04:00.
- ``sensitivity`` (0-3): how much the action matters. 3 role changes, consent to an app, new app secrets, sign-in policy changes; 2 password resets, registering or removing a security
  method, revoking sessions, adding a user or inviting a guest, a change to another person's account; 1 anything else kept.
- ``failed``: 1 when the change was refused.
- ``on_others``: 1 when the actor did it to someone else (an administrator action) rather than to themselves.
- ``security_method``: 1 for adding or removing a way to sign in (the step an account takeover needs).
- ``role_change``: 1 for a role assignment change.

An app acting on its own is stored but not scored (UEBA scores people).
"""

from __future__ import annotations

import re
from datetime import datetime

_ROLE = re.compile(
    r"\b(add|remove|delete|update)\b.*\b(member|eligible member|active member)\b.*\brole\b|\brole\b.*\b(assignment|member)\b", re.I
)
_HIGH = re.compile(
    r"consent to application|add delegated permission grant|add oauth2permissiongrant|add app role assignment|add service principal credentials|update application . certificates|"
    r"add service principal$|conditional access|disable strong authentication|delete user|add (eligible )?member to role|remove (eligible )?member from role|"
    r"set (company|domain) (information|authentication)|change.*(federat)",
    re.I,
)
_MEDIUM = re.compile(
    r"reset (user )?password|reset password|add user|invite external user|change user license|stsrefreshtokenvalidfrom|update user|change user password|add (a )?passkey|windows hello|registered",
    re.I,
)
_SECURITY_METHOD = re.compile(r"security info|passkey|windows hello|authentication method|strong authentication|fido|authenticator", re.I)


def sensitivity_of(activity: str, *, on_others: bool) -> int:
    """0-3: how much this action matters (see the module comment). ``Update user`` is only medium when done to someone else."""
    if _HIGH.search(activity) or _ROLE.search(activity):
        return 3
    if re.search(r"update user", activity, re.I) and not on_others:
        return 1
    if _MEDIUM.search(activity):
        return 2
    return 1


def is_role_change(activity: str) -> bool:
    return bool(_ROLE.search(activity)) or bool(re.search(r"member (to|from) role", activity, re.I))


def directory_features(*, occurred_at: datetime, activity: str, success: bool, actor: str, target: str | None) -> dict[str, float]:
    """The features of one entry; see the module comment."""
    on_others = bool(target) and (target or "").lower() != actor.lower()
    return {
        "hour_of_day": float(occurred_at.hour),
        "sensitivity": float(sensitivity_of(activity, on_others=on_others)),
        "failed": 0.0 if success else 1.0,
        "on_others": 1.0 if on_others else 0.0,
        "security_method": 1.0 if _SECURITY_METHOD.search(activity) else 0.0,
        "role_change": 1.0 if is_role_change(activity) else 0.0,
    }
