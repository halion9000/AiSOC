"""connectors:view: see which connectors exist and whether they are healthy, split out of connectors:read.

connectors:read guards 11 routes. Besides the five that list connectors it guards POST /federated/search, which runs a free-text or indicator query across the tenant's connected SIEMs (Splunk, Elastic...) with their stored credentials and returns the merged rows: telemetry from the customer's own systems. It also guards the federated backend list, the agent tool list, the inbox template and token lists and the OAuth app view.
CORE's key held connectors:read so Cipher could list connectors and read their health, so it could also search the customer's SIEM. (`GET /connectors/{id}` omits auth_config, so credentials do not come back on a read; `connector_config` is free-form and documented as non-secret, but nothing enforces that.)
Each claim is tested over the whole application rather than assumed:
  1. NOBODY LOSES ACCESS: whatever held connectors:read (a role, a custom database role, a `connectors:*` wildcard, a key) still reads connectors AND still reaches the six routes that stay.
  2. connectors:view ALONE GRANTS NOTHING ELSE: a key holding only it satisfies exactly the five reads among every route in the application.
  3. CORE's real key scopes reach none of the six routes that stay, and still reach the three connector routes its tools call.
NOT VERIFIED LIVE: a real federated search returning real rows needs a connected SIEM; what was shown is that authorization let the key in (and that it no longer does).
"""
import asyncio
import re
import uuid
from pathlib import Path

import pytest
from route_introspect import required_permissions as _required_permissions
from route_introspect import walk_routes

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import api_keys
from app.core.security import IMPLIED_BY, PLATFORM_PERMISSIONS, ROLE_PERMISSIONS, has_permission, known_permissions, permission_in
from app.main import app
from app.scripts import bootstrap_production as bp

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
VIEW_ROUTES = {("GET", "/connectors"), ("GET", "/connectors/catalog"), ("GET", "/connectors/health"), ("GET", "/connectors/{connector_id}"), ("GET", "/connectors/{connector_id}/last_event_at")}
STAY_ROUTES = {
    ("POST", "/federated/search"), ("GET", "/federated/backends"), ("GET", "/agents/tools"),
    ("GET", "/inbox/templates"), ("GET", "/inbox/tokens"), ("GET", "/oauth/app/{connector_type}"),
}


def required_permissions(route) -> set[str]:
    return set(_required_permissions(route))


ALL_ROUTES = [(path.replace("/api/v1", "", 1), route) for path, route in walk_routes(app.routes)]


def _satisfied_by(scopes) -> set[tuple[str, str]]:
    out = set()
    for path, route in ALL_ROUTES:
        needed = required_permissions(route)
        if needed and all(permission_in(scopes, p) for p in needed):
            out |= {(m, path) for m in route.methods if m not in {"HEAD", "OPTIONS"}}
    return out


class TestTheImplication:
    @pytest.mark.parametrize("granted,expected", [(["connectors:view"], True), (["connectors:read"], True), (["connectors:*"], True), (["*"], True), (["connectors:write"], False), (["connectors:delete"], False), (["alerts:read"], False), ([], False)])
    def test_who_holds_connectors_view(self, granted, expected):
        assert permission_in(granted, "connectors:view") is expected

    def test_connectors_view_alone_grants_no_other_permission(self):
        assert {p for p in known_permissions() if permission_in(["connectors:view"], p)} == {"connectors:view"}

    def test_connectors_read_grants_exactly_what_it_did_plus_view_and_the_implication_is_one_way(self):
        assert {p for p in known_permissions() if permission_in(["connectors:read"], p)} == {"connectors:read", "connectors:view"}
        assert not permission_in(["connectors:view"], "connectors:read")

    def test_the_pair_is_in_the_rule_and_no_platform_permission_is_involved(self):
        assert IMPLIED_BY["connectors:view"] == ("connectors:read",)
        assert "connectors:view" not in PLATFORM_PERMISSIONS and "connectors:read" not in PLATFORM_PERMISSIONS

    def test_connectors_view_is_a_known_permission_and_a_valid_key_scope(self):
        assert "connectors:view" in known_permissions()
        assert "connectors:view" in api_keys.VALID_SCOPES


class TestRolesAreUnchanged:
    def test_every_role_reads_connectors_exactly_when_it_could_before_nobody_gains_or_loses_it(self):
        for role in ROLE_PERMISSIONS:
            assert has_permission(role, "connectors:view") == has_permission(role, "connectors:read"), role

    def test_the_comparison_is_not_vacuous_some_roles_hold_it_and_some_do_not(self):
        outcomes = {role: has_permission(role, "connectors:view") for role in ROLE_PERMISSIONS}
        assert outcomes["admin"] is True and outcomes["soc_analyst"] is True and outcomes["viewer"] is False and outcomes["threat_hunter"] is False, outcomes


class TestTheRoutes:
    def test_exactly_these_five_routes_need_connectors_view_and_each_is_a_get(self):
        found = {(m, p) for p, r in ALL_ROUTES if required_permissions(r) == {"connectors:view"} for m in r.methods if m not in {"HEAD", "OPTIONS"}}
        assert found == VIEW_ROUTES and all(m == "GET" for m, _ in found)

    def test_a_key_holding_only_connectors_view_can_use_exactly_those_five_routes_in_the_whole_application(self):
        assert _satisfied_by(["connectors:view"]) == VIEW_ROUTES

    def test_exactly_these_six_routes_still_need_connectors_read_and_connectors_view_does_not_reach_them(self):
        found = {(m, p) for p, r in ALL_ROUTES if required_permissions(r) == {"connectors:read"} for m in r.methods if m not in {"HEAD", "OPTIONS"}}
        assert found == STAY_ROUTES
        assert not (_satisfied_by(["connectors:view"]) & STAY_ROUTES)

    def test_whoever_held_connectors_read_still_reaches_all_eleven_routes(self):
        assert _satisfied_by(["connectors:read"]) == VIEW_ROUTES | STAY_ROUTES

    def test_the_federated_search_is_the_one_that_queries_connected_systems_and_stays_behind_connectors_read(self):
        """The reason for the split, pinned: if this route ever needs a different permission, or stops querying connected systems, re-read the split."""
        route = next(r for p, r in ALL_ROUTES if p == "/federated/search" and "POST" in r.methods)
        assert required_permissions(route) == {"connectors:read"}
        assert "_fetch_target_connectors" in __import__("inspect").getsource(route.endpoint)

    def test_nothing_that_writes_or_deletes_a_connector_was_touched(self):
        writers = {(m, p) for p, r in ALL_ROUTES if required_permissions(r) & {"connectors:write", "connectors:delete"} for m in r.methods}
        assert writers and not (_satisfied_by(["connectors:view"]) & writers) and not (_satisfied_by(["connectors:read"]) & writers)


class TestCoresKeyNoLongerReachesTheFederatedSearch:
    def test_cores_real_key_scopes_satisfy_none_of_the_six_routes_that_stay(self):
        reached = _satisfied_by(bp.CORE_KEY_SCOPES)
        assert not (reached & STAY_ROUTES), sorted(reached & STAY_ROUTES)

    def test_the_key_holds_connectors_view_and_not_connectors_read(self):
        assert "connectors:view" in bp.CORE_KEY_SCOPES and "connectors:read" not in bp.CORE_KEY_SCOPES

    def test_cores_key_still_reaches_the_connector_routes_its_tools_call(self):
        import importlib.util
        import sys

        spec = importlib.util.spec_from_file_location("tctc_for_connectors_view", Path(__file__).with_name("test_cipher_tool_contract.py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules["tctc_for_connectors_view"] = module
        spec.loader.exec_module(module)
        norm = lambda p: re.sub(r"\{[^}]*\}", "{}", p)  # noqa: E731
        reached = {(m, norm(p)) for m, p in _satisfied_by(bp.CORE_KEY_SCOPES)}
        wanted = [(name, method, path) for name, method, path, *_ in module.CIPHER_CALLS if method == "GET" and path.startswith("/connectors")]
        assert {n for n, _, _ in wanted} == {"aisoc_list_connectors", "aisoc_connector_catalog", "aisoc_connector_health"}, wanted
        for name, method, path in wanted:
            assert (method, norm(path)) in reached, f"{name}: CORE's key no longer reaches {method} {path}"


class TestACurrentUserOnTheRealPaths:
    @staticmethod
    def user(role="analyst", scopes=None):
        return CurrentUser(uuid.uuid4(), uuid.uuid4(), role, "u@example.com", scopes=scopes)

    @staticmethod
    def db_with(names):
        class Result:
            def all(self):
                return [(n,) for n in names]

        class DB:
            async def execute(self, _statement):
                return Result()

        return DB()

    def test_a_key_with_only_connectors_view_passes_for_view_and_is_refused_the_federated_search_naming_the_scope(self):
        key = self.user(scopes=["connectors:view"])
        key.require_permission("connectors:view")
        with pytest.raises(Exception) as refused:
            key.require_permission("connectors:read")
        assert getattr(refused.value, "status_code", None) == 403 and "API key missing scope: connectors:read" in str(refused.value.detail)

    def test_a_key_with_connectors_read_still_passes_the_connectors_view_check(self):
        self.user(scopes=["connectors:read"]).require_permission("connectors:view")

    def test_a_database_role_with_only_connectors_view_lists_connectors_and_cannot_search(self):
        user = self.user()
        assert asyncio.run(user.has_permission_db("connectors:view", self.db_with(["connectors:view"]))) is True
        assert asyncio.run(user.has_permission_db("connectors:read", self.db_with(["connectors:view"]))) is False

    def test_a_database_role_with_connectors_read_lists_connectors(self):
        assert asyncio.run(self.user().has_permission_db("connectors:view", self.db_with(["connectors:read"]))) is True

    def test_a_database_role_with_neither_does_not(self):
        assert asyncio.run(self.user(role="nobody").has_permission_db("connectors:view", self.db_with(["alerts:read"]))) is False


class TestTheMigration:
    sql = (MIGRATIONS / "079_connectors_view_permission.sql").read_text(encoding="utf-8")
    code = re.sub(r"--[^\n]*", "", sql)

    def test_it_adds_only_the_name_to_the_catalog_and_is_idempotent(self):
        assert re.search(r"INSERT INTO permissions \(name, description, category\) VALUES\s*\('connectors:view'", self.sql)
        assert "ON CONFLICT (name) DO NOTHING" in self.sql
        assert "role_permissions" not in self.code, "nothing is backfilled onto roles: connectors:read implies connectors:view in code"
        assert not re.search(r"\b(DELETE|DROP|UPDATE|ALTER)\b", self.code, re.I)

    def test_it_says_what_is_not_included_and_why(self):
        assert "POST /federated/search" in self.sql and "SIEMs" in self.sql and "telemetry" in self.sql

    def test_it_follows_migration_078(self):
        numbers = sorted(int(p.name[:3]) for p in MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql"))
        assert numbers.count(79) == 1 and 78 in numbers
