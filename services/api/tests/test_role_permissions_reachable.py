"""Every permission a route enforces can be held by someone other than a platform wildcard.

Thirteen permissions enforced with ``require_permission`` (audit_log:read, copilot:use, graph:read, roles:*, sla:*, shifts:*, plugins:read, playbooks:admin, rules:admin) appeared in no role's list, so a tenant's own
administrator got a 403 on their own audit log, SLA targets, shifts, copilot and role management; and /auth/authorize answered 422 "unknown permission" for them.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core.security import PLATFORM_PERMISSIONS, ROLE_PERMISSIONS, has_permission, known_permissions

APP = Path(__file__).resolve().parent.parent / "app"
# Enforced on purpose for a PLATFORM operator only, or deliberately granted to no role yet.
DELIBERATELY_UNGRANTED = {"plugins:execute"}


def _enforced() -> set[str]:
    found: set[str] = set()
    for path in APP.rglob("*.py"):
        found |= set(re.findall(r'require_permission\("([a-z_]{2,}:[a-z_]{2,})"\)', path.read_text(encoding="utf-8")))
    return found


def test_every_enforced_permission_is_grantable_to_a_non_wildcard_role():
    held = {p for role, perms in ROLE_PERMISSIONS.items() if "*" not in perms for p in perms}
    unreachable = sorted(p for p in _enforced() if p not in held and p not in PLATFORM_PERMISSIONS and p not in DELIBERATELY_UNGRANTED and p not in known_permissions())
    assert unreachable == []


def test_a_tenant_admin_can_use_the_features_of_their_own_tenant():
    for permission in ("audit_log:read", "copilot:use", "graph:read", "roles:read", "roles:write", "sla:read", "sla:write", "shifts:read", "shifts:write", "plugins:read", "playbooks:admin", "rules:admin"):
        assert has_permission("tenant_admin", permission), permission


def test_analysts_can_use_the_copilot_graph_sla_and_shifts_but_not_administer_roles():
    for permission in ("copilot:use", "graph:read", "sla:read", "shifts:read"):
        assert has_permission("soc_analyst", permission), permission
    for permission in ("roles:write", "sla:write", "audit_log:read"):
        assert not has_permission("soc_analyst", permission), permission


def test_nobody_below_platform_admin_gets_platform_powers_from_this():
    for role in ("tenant_admin", "soc_lead", "soc_analyst", "threat_hunter", "viewer"):
        for permission in PLATFORM_PERMISSIONS | DELIBERATELY_UNGRANTED:
            assert not has_permission(role, permission), (role, permission)
