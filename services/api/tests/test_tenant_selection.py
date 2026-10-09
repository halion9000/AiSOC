"""One rule for "may this caller read that tenant", shared by every endpoint that lets a caller name one.

Own tenant: always. Any other tenant: only with the platform permission platform:cross_tenant_query (platform_admin, or an API key carrying that exact scope). fusion and osquery_fim used to check the role NAME, /nl-query checked the permission: an API key was allowed in one place and refused in another."""
import ast
import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import fusion, osquery_fim
from app.services import tenant_selection as ts

HOME, OTHER = uuid.uuid4(), uuid.uuid4()
APP = Path(__file__).resolve().parent.parent / "app"


def principal(role="viewer", scopes=None):
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=HOME, role=role, email=f"{role}@example.test", scopes=scopes)


class TestTheRule:
    @pytest.mark.parametrize("requested", [None, "", "   ", HOME, str(HOME), f" {HOME} "])
    @pytest.mark.parametrize("role", ["viewer", "soc_analyst", "tenant_admin", "admin", "platform_admin"])
    def test_nothing_or_your_own_tenant_is_always_yours(self, role, requested):
        assert ts.resolve_requested_tenant(principal(role), requested) == str(HOME)

    @pytest.mark.parametrize("role", ["viewer", "soc_analyst", "soc_lead", "threat_hunter", "tenant_admin", "admin", "api_service"])
    def test_another_tenant_is_a_403_for_every_role_without_the_platform_permission(self, role):
        with pytest.raises(HTTPException) as exc:
            ts.resolve_requested_tenant(principal(role), OTHER)
        assert exc.value.status_code == 403 and exc.value.detail == ts.MISMATCH_DETAIL

    def test_a_platform_admin_may_name_another_tenant(self):
        assert ts.resolve_requested_tenant(principal("platform_admin"), OTHER) == str(OTHER)
        assert ts.resolve_requested_tenant(principal("platform_admin"), str(OTHER)) == str(OTHER)

    def test_an_api_key_with_the_exact_scope_may(self):
        assert ts.resolve_requested_tenant(principal("viewer", scopes=[ts.CROSS_TENANT_PERMISSION]), OTHER) == str(OTHER)

    @pytest.mark.parametrize("scopes", [["*"], ["platform:*"], ["alerts:read"], []])
    def test_a_key_without_the_exact_scope_may_not_even_if_it_has_the_wildcard(self, scopes):
        with pytest.raises(HTTPException):
            ts.resolve_requested_tenant(principal("platform_admin", scopes=scopes), OTHER)

    def test_a_key_is_judged_by_its_scopes_not_by_the_role_string_it_carries(self):
        """The old fusion/osquery checks looked at the role name, so a key carrying role=platform_admin was let through whatever its scopes were."""
        assert principal("platform_admin", scopes=["alerts:read"]).role == "platform_admin"
        with pytest.raises(HTTPException):
            ts.resolve_requested_tenant(principal("platform_admin", scopes=["alerts:read"]), OTHER)

    def test_an_endpoint_specific_alias_is_honoured_for_everyone_entitled_to_it(self):
        assert ts.resolve_requested_tenant(principal("viewer"), "default", also_allowed={"default"}) == "default"
        with pytest.raises(HTTPException):
            ts.resolve_requested_tenant(principal("viewer"), "other-alias", also_allowed={"default"})

    def test_the_result_is_always_a_string_and_whitespace_is_stripped(self):
        out = ts.resolve_requested_tenant(principal("platform_admin"), f"  {OTHER}  ")
        assert out == str(OTHER) and isinstance(out, str)

    def test_may_select_other_tenants_matches_the_permission(self):
        assert ts.may_select_other_tenants(principal("platform_admin")) and not ts.may_select_other_tenants(principal("admin"))
        assert not ts.may_select_other_tenants(principal("platform_admin", scopes=["*"]))

    def test_the_permission_name_is_the_one_the_security_module_marks_as_platform_level(self):
        from app.core.security import PLATFORM_PERMISSIONS

        assert ts.CROSS_TENANT_PERMISSION in PLATFORM_PERMISSIONS


class TestTheEndpointsUseIt:
    def test_fusion_refuses_another_tenant_for_a_non_holder_and_allows_a_holder(self):
        with pytest.raises(HTTPException) as exc:
            fusion._require_own_tenant(OTHER, principal("admin"))
        assert exc.value.status_code == 403
        fusion._require_own_tenant(HOME, principal("viewer"))
        fusion._require_own_tenant(OTHER, principal("platform_admin"))

    def test_fusion_no_longer_trusts_the_role_name(self):
        with pytest.raises(HTTPException):
            fusion._require_own_tenant(OTHER, principal("platform_admin", scopes=["alerts:read"]))

    def test_osquery_defaults_to_the_callers_tenant(self):
        assert osquery_fim.resolve_tenant(principal("viewer"), None) == str(HOME)

    def test_osquery_refuses_another_tenant_for_a_non_holder_and_allows_a_holder(self):
        with pytest.raises(HTTPException) as exc:
            osquery_fim.resolve_tenant(principal("admin"), str(OTHER))
        assert exc.value.status_code == 403
        assert osquery_fim.resolve_tenant(principal("platform_admin"), str(OTHER)) == str(OTHER)

    def test_osquery_keeps_its_demo_tenant_alias_for_the_demo_tenant_only(self):
        demo = CurrentUser(user_id=uuid.uuid4(), tenant_id=osquery_fim.DEMO_TENANT_ID, role="viewer", email="d@example.test")
        assert osquery_fim.resolve_tenant(demo, osquery_fim.OSQUERY_DEFAULT_TENANT) == osquery_fim.OSQUERY_DEFAULT_TENANT
        with pytest.raises(HTTPException):
            osquery_fim.resolve_tenant(principal("viewer"), osquery_fim.OSQUERY_DEFAULT_TENANT)

    def test_the_nl_query_endpoint_uses_the_same_permission_constant(self):
        from app.api.v1.endpoints import nl_query

        assert nl_query.CROSS_TENANT_PERMISSION is ts.CROSS_TENANT_PERMISSION


def test_no_endpoint_decides_cross_tenant_access_by_comparing_a_role_name():
    """The three separate checks became one because role-name checks disagree with the permission model (keys, database roles). Keep it that way."""
    problems = []
    for path in sorted((APP / "api").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8", errors="replace"))):
            if isinstance(node, ast.Compare):
                text = ast.unparse(node)
                if "platform_admin" in text and ("role" in text):
                    problems.append(f"{path.relative_to(APP.parent)}:{node.lineno}: {text}")
    assert not problems, "decide by permission (app.services.tenant_selection), not by role name:\n  " + "\n  ".join(problems)
