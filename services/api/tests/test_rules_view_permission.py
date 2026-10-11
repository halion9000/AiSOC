"""rules:view: read the detection rules, split out of rules:read.

rules:read guards 18 routes: 13 plain reads and 5 that compute. One of the five, POST /rules/{id}/backtest, runs a rule over up to 365 days of the tenant's REAL events in the ClickHouse data lake and returns `sample_matches`, the matching event rows: telemetry, which is what lake:query exists to gate and what CORE's key was deliberately not given. So a key that only needed to READ rules could read lake telemetry.
(/rules/hunt, /rules/{id}/execute and /detection/test only evaluate events the CALLER sends; /translation/translate translates a rule.) Each claim is tested over the whole application rather than assumed:
  1. NOBODY LOSES ACCESS: whatever held rules:read (a role, a custom database role, a `rules:*` wildcard, a key) still reads rules AND still reaches all five computing routes.
  2. rules:view ALONE GRANTS NOTHING ELSE: a key holding only it satisfies exactly the 13 reads among every route in the application.
  3. CORE's real key scopes reach none of the five computing routes, and still reach every rules route its detection tools call.
NOT VERIFIED LIVE: the lake is not configured in the test environment, so a real backtest returning real rows was not demonstrated; what was shown is that authorization let the key in (and that it no longer does).
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
from app.api.v1.endpoints.detection_rules import BacktestResponse
from app.core.security import IMPLIED_BY, PLATFORM_PERMISSIONS, ROLE_PERMISSIONS, has_permission, known_permissions, permission_in
from app.main import app
from app.scripts import bootstrap_production as bp

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
VIEW_ROUTES = {
    ("GET", "/rules"), ("GET", "/rules/{rule_id}"), ("GET", "/detection/rules"), ("GET", "/detection/rules/{rule_id}"),
    ("GET", "/detection/coverage"), ("GET", "/detection/drift"), ("GET", "/detection/confidence"), ("GET", "/detection/tuning"), ("GET", "/detection/tuning/summary"),
    ("GET", "/detection-proposals"), ("GET", "/detection-proposals/baselines"), ("GET", "/detection-proposals/{proposal_id}"), ("GET", "/translation/formats"),
}
COMPUTE_ROUTES = {("POST", "/rules/hunt"), ("POST", "/rules/{rule_id}/execute"), ("POST", "/detection/test"), ("POST", "/translation/translate"), ("POST", "/rules/{rule_id}/backtest")}


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
    @pytest.mark.parametrize("granted,expected", [(["rules:view"], True), (["rules:read"], True), (["rules:*"], True), (["*"], True), (["rules:write"], False), (["hunts:read"], False), (["alerts:read"], False), ([], False)])
    def test_who_holds_rules_view(self, granted, expected):
        assert permission_in(granted, "rules:view") is expected

    def test_rules_view_alone_grants_no_other_permission(self):
        assert {p for p in known_permissions() if permission_in(["rules:view"], p)} == {"rules:view"}

    def test_rules_read_grants_exactly_what_it_did_plus_rules_view_and_the_implication_is_one_way(self):
        assert {p for p in known_permissions() if permission_in(["rules:read"], p)} == {"rules:read", "rules:view"}
        assert not permission_in(["rules:view"], "rules:read")

    def test_the_pair_is_in_the_rule_and_no_platform_permission_is_involved(self):
        assert IMPLIED_BY["rules:view"] == ("rules:read",)
        assert "rules:view" not in PLATFORM_PERMISSIONS and "rules:read" not in PLATFORM_PERMISSIONS

    def test_rules_view_is_a_known_permission_and_a_valid_key_scope(self):
        assert "rules:view" in known_permissions()
        assert "rules:view" in api_keys.VALID_SCOPES


class TestRolesAreUnchanged:
    def test_every_role_reads_rules_exactly_when_it_could_before_nobody_gains_or_loses_it(self):
        for role in ROLE_PERMISSIONS:
            assert has_permission(role, "rules:view") == has_permission(role, "rules:read"), role

    def test_the_comparison_is_not_vacuous_some_roles_hold_it_and_some_do_not(self):
        outcomes = {role: has_permission(role, "rules:view") for role in ROLE_PERMISSIONS}
        assert outcomes["admin"] is True and outcomes["threat_hunter"] is True and outcomes["viewer"] is False and outcomes["soc_analyst"] is False, outcomes


class TestTheRoutes:
    def test_exactly_these_thirteen_routes_need_rules_view_and_each_is_a_get(self):
        found = {(m, p) for p, r in ALL_ROUTES if required_permissions(r) == {"rules:view"} for m in r.methods if m not in {"HEAD", "OPTIONS"}}
        assert found == VIEW_ROUTES and len(found) == 13 and all(m == "GET" for m, _ in found)

    def test_a_key_holding_only_rules_view_can_use_exactly_those_thirteen_routes_in_the_whole_application(self):
        assert _satisfied_by(["rules:view"]) == VIEW_ROUTES

    def test_exactly_these_five_routes_still_need_rules_read_and_rules_view_does_not_reach_them(self):
        found = {(m, p) for p, r in ALL_ROUTES if "rules:read" in required_permissions(r) for m in r.methods if m not in {"HEAD", "OPTIONS"}}
        assert found == COMPUTE_ROUTES
        assert not (_satisfied_by(["rules:view"]) & COMPUTE_ROUTES)

    def test_whoever_held_rules_read_still_reaches_all_eighteen_routes(self):
        assert _satisfied_by(["rules:read"]) == VIEW_ROUTES | COMPUTE_ROUTES

    def test_the_backtest_route_returns_matching_event_rows_which_is_why_it_stays_behind_rules_read(self):
        """The reason for the split, pinned: if sample_matches ever stops carrying event rows, re-read whether the backtest still needs to be kept away from a read-only key."""
        assert "sample_matches" in BacktestResponse.model_fields

    def test_nothing_that_writes_rules_was_touched(self):
        writers = {(m, p) for p, r in ALL_ROUTES if "rules:write" in required_permissions(r) for m in r.methods}
        assert writers and not (_satisfied_by(["rules:view"]) & writers) and not (_satisfied_by(["rules:read"]) & writers)


class TestCoresKeyNoLongerReachesTheBacktest:
    def test_cores_real_key_scopes_satisfy_none_of_the_five_computing_routes(self):
        reached = _satisfied_by(bp.CORE_KEY_SCOPES)
        assert not (reached & COMPUTE_ROUTES), sorted(reached & COMPUTE_ROUTES)

    def test_the_key_holds_rules_view_and_not_rules_read(self):
        assert "rules:view" in bp.CORE_KEY_SCOPES and "rules:read" not in bp.CORE_KEY_SCOPES

    def test_cores_key_still_reaches_every_rules_route_its_detection_tools_call(self):
        import importlib.util
        import sys

        spec = importlib.util.spec_from_file_location("tctc_for_rules_view", Path(__file__).with_name("test_cipher_tool_contract.py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules["tctc_for_rules_view"] = module
        spec.loader.exec_module(module)
        norm = lambda p: re.sub(r"\{[^}]*\}", "{}", p)  # noqa: E731
        reached = {(m, norm(p)) for m, p in _satisfied_by(bp.CORE_KEY_SCOPES)}
        wanted = [(name, method, path) for name, method, path, *_ in module.CIPHER_CALLS if method == "GET" and path.split("/")[1] in {"rules", "detection", "detection-proposals", "detection-loop"}]
        assert len(wanted) >= 12, wanted
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

    def test_a_key_with_only_rules_view_passes_for_rules_view_and_is_refused_the_backtest_naming_the_scope(self):
        key = self.user(scopes=["rules:view"])
        key.require_permission("rules:view")
        with pytest.raises(Exception) as refused:
            key.require_permission("rules:read")
        assert getattr(refused.value, "status_code", None) == 403 and "API key missing scope: rules:read" in str(refused.value.detail)

    def test_a_key_with_rules_read_still_passes_the_rules_view_check(self):
        self.user(scopes=["rules:read"]).require_permission("rules:view")

    def test_a_database_role_with_only_rules_view_reads_rules_and_cannot_backtest(self):
        user = self.user()
        assert asyncio.run(user.has_permission_db("rules:view", self.db_with(["rules:view"]))) is True
        assert asyncio.run(user.has_permission_db("rules:read", self.db_with(["rules:view"]))) is False

    def test_a_database_role_with_rules_read_reads_rules(self):
        assert asyncio.run(self.user().has_permission_db("rules:view", self.db_with(["rules:read"]))) is True

    def test_a_database_role_with_neither_does_not(self):
        assert asyncio.run(self.user(role="nobody").has_permission_db("rules:view", self.db_with(["alerts:read"]))) is False


class TestTheMigration:
    sql = (MIGRATIONS / "078_rules_view_permission.sql").read_text(encoding="utf-8")
    code = re.sub(r"--[^\n]*", "", sql)

    def test_it_adds_only_the_name_to_the_catalog_and_is_idempotent(self):
        assert re.search(r"INSERT INTO permissions \(name, description, category\) VALUES\s*\('rules:view'", self.sql)
        assert "ON CONFLICT (name) DO NOTHING" in self.sql
        assert "role_permissions" not in self.code, "nothing is backfilled onto roles: rules:read implies rules:view in code"
        assert not re.search(r"\b(DELETE|DROP|UPDATE|ALTER)\b", self.code, re.I)

    def test_it_says_what_is_not_included_and_why(self):
        assert "POST /rules/{id}/backtest" in self.sql and "sample_matches" in self.sql and "telemetry" in self.sql and "lake:query" in self.sql

    def test_it_follows_migration_077(self):
        numbers = sorted(int(p.name[:3]) for p in MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql"))
        assert numbers.count(78) == 1 and 77 in numbers
