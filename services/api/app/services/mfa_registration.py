"""Who has a second factor, when Microsoft may not say who registered one.

Microsoft's registration report (which methods each person has set up) needs Entra ID P1. Without it CIPP reports nobody as registered, even where security defaults or a conditional access policy
require everyone to. Reading that as "nobody has multi-factor" is wrong. So: when not one person in a client shows a registered method, registration is *unknown*, and a person counts as covered when
something requires a second factor of them (security defaults, conditional access, or the per-user setting). When even one person shows a method, registration is reported and decides, as before.
"""

from __future__ import annotations

from typing import Any


def required_of(u: Any) -> bool:
    """Something makes this person use a second factor: a conditional access policy, security defaults, or the per-user setting."""
    return bool(u.ca_enforced or u.security_defaults or (u.per_user or "").lower() in ("enforced", "enabled"))


def registration_known(users: list[Any]) -> bool:
    """True when the client's data shows at least one person with a registered or usable second factor, so the report exists for this client."""
    return any(u.registered or getattr(u, "capable", False) or getattr(u, "methods", None) for u in users)


def has_second_factor(u: Any, known: bool) -> bool:
    """Whether this person has a second factor: what they registered when that is reported, otherwise whether one is required of them."""
    return bool(u.registered or getattr(u, "capable", False)) if known else required_of(u)
