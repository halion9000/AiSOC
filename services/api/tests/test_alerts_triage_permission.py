"""alerts:triage: claim, escalate and snooze an alert, split out of alerts:write.

alerts:write guards 29 routes. Besides triaging an alert it covers submitting and patching alerts and creating assets, adding cloud posture
findings, creating identity graph nodes, adding insider-threat indicators and changing an employee profile's watchlist, graph entities,
honeytokens, feedback and phishing re-triage.
CORE's agent only claims, escalates and snoozes alerts, so it was given all of that. Confirmed on a real deployment: with CORE's scopes the
five writes above passed authorization (201 for an identity node; 422 only because the body was empty), and a read-only key got 403 on every
one. Each claim is tested over the whole application rather than assumed:
  1. NOBODY LOSES ACCESS: whatever held alerts:write (a role, a custom database role, an `alerts:*` wildcard, a key) still triages, and
  still reaches every other alerts:write route.
  2. alerts:triage ALONE GRANTS NOTHING ELSE: a key holding only it satisfies exactly three routes among every route in the application.
  3. CORE's real key scopes reach none of the 26 other alerts:write routes.
"""

import asyncio
import re
import uuid
from pathlib import Path

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import api_keys
from app.core.security import IMPLIED_BY, PLATFORM_PERMISSIONS, ROLE_PERMISSIONS, has_permission, known_permissions, permission_in
from app.main import app
from app.scripts import bootstrap_production as bp
from route_introspect import required_permissions as _required_permissions
from route_introspect import walk_routes

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
TRIAGE_ROUTES = {("POST", "/alerts/{alert_id}/claim"), ("POST", "/alerts/{alert_id}/escalate"), ("POST", "/alerts/{alert_id}/snooze")}
# The ones the confirmed live run showed CORE's key passing, plus the alert ones: all must stay alerts:write.
NAMED_WRITE_ONLY = {
    ("POST", "/alerts/submit"),
    ("PATCH", "/alerts/{alert_id}"),
    ("POST", "/assets"),
    ("POST", "/posture/findings"),
    ("POST", "/identity-graph/nodes"),
    ("POST", "/insider-threat/indicators"),
    ("PATCH", "/insider-threat/profiles/{profile_id}/watchlist"),
}


def required_permissions(route) -> set[str]:
    return set(_required_permissions(route))


ALL_ROUTES = [(path.replace("/api/v1", "", 1), route) for path, route in walk_routes(app.routes)]
WRITE_ONLY = {
    (m, p) for p, r in ALL_ROUTES if required_permissions(r) == {"alerts:write"} for m in r.methods if m not in {"HEAD", "OPTIONS"}
}


def _satisfied_by(scopes) -> set[tuple[str, str]]:
    out = set()
    for path, route in ALL_ROUTES:
        needed = required_permissions(route)
        if needed and all(permission_in(scopes, p) for p in needed):
            out |= {(m, path) for m in route.methods if m not in {"HEAD", "OPTIONS"}}
    return out


class TestTheImplication:
    @pytest.mark.parametrize(
        "granted,expected",
        [
            (["alerts:triage"], True),
            (["alerts:write"], True),
            (["alerts:*"], True),
            (["*"], True),
            (["alerts:read"], False),
            (["cases:write"], False),
            (["intel:read"], False),
            ([], False),
        ],
    )
    def test_who_holds_alerts_triage(self, granted, expected):
        assert permission_in(granted, "alerts:triage") is expected

    def test_alerts_triage_alone_grants_no_other_permission(self):
        assert {p for p in known_permissions() if permission_in(["alerts:triage"], p)} == {"alerts:triage"}

    def test_alerts_write_grants_exactly_what_it_did_plus_triage_and_the_implication_is_one_way(self):
        assert {p for p in known_permissions() if permission_in(["alerts:write"], p)} == {"alerts:write", "alerts:triage"}
        assert not permission_in(["alerts:triage"], "alerts:write")

    def test_the_pair_is_in_the_rule_and_no_platform_permission_is_involved(self):
        assert IMPLIED_BY["alerts:triage"] == ("alerts:write",)
        assert "alerts:triage" not in PLATFORM_PERMISSIONS and "alerts:write" not in PLATFORM_PERMISSIONS

    def test_alerts_triage_is_a_known_permission_and_a_valid_key_scope(self):
        assert "alerts:triage" in known_permissions()
        assert "alerts:triage" in api_keys.VALID_SCOPES


class TestRolesAreUnchanged:
    def test_every_role_triages_exactly_when_it_could_before_nobody_gains_or_loses_it(self):
        for role in ROLE_PERMISSIONS:
            assert has_permission(role, "alerts:triage") == has_permission(role, "alerts:write"), role

    def test_the_comparison_is_not_vacuous_some_roles_hold_it_and_some_do_not(self):
        outcomes = {role: has_permission(role, "alerts:triage") for role in ROLE_PERMISSIONS}
        assert outcomes["soc_analyst"] is True and outcomes["viewer"] is False and outcomes["threat_hunter"] is False, outcomes


class TestTheRoutes:
    def test_exactly_these_three_routes_need_alerts_triage_and_each_is_a_post(self):
        found = {
            (m, p) for p, r in ALL_ROUTES if required_permissions(r) == {"alerts:triage"} for m in r.methods if m not in {"HEAD", "OPTIONS"}
        }
        assert found == TRIAGE_ROUTES and all(m == "POST" for m, _ in found)

    def test_a_key_holding_only_alerts_triage_can_use_exactly_those_three_routes_in_the_whole_application(self):
        assert _satisfied_by(["alerts:triage"]) == TRIAGE_ROUTES

    def test_submitting_and_patching_alerts_and_the_confirmed_live_writes_still_need_alerts_write(self):
        for method, path in NAMED_WRITE_ONLY:
            route = next(r for p, r in ALL_ROUTES if p == path and method in r.methods)
            assert required_permissions(route) == {"alerts:write"}, f"{method} {path}"
        assert NAMED_WRITE_ONLY <= WRITE_ONLY and not (_satisfied_by(["alerts:triage"]) & WRITE_ONLY)

    def test_there_are_26_other_alerts_write_routes_and_whoever_held_alerts_write_still_reaches_all_29(self):
        assert len(WRITE_ONLY) == 26, "a route moved onto or off alerts:write: re-read why, and update this number deliberately"
        assert _satisfied_by(["alerts:write"]) >= TRIAGE_ROUTES | WRITE_ONLY


class TestCoresKeyNoLongerReachesTheOtherWrites:
    def test_cores_real_key_scopes_satisfy_none_of_the_26_other_alerts_write_routes(self):
        reached = _satisfied_by(bp.CORE_KEY_SCOPES)
        assert not (reached & WRITE_ONLY), sorted(reached & WRITE_ONLY)

    def test_cores_key_still_triages_and_still_reaches_what_its_other_tools_call(self):
        reached = _satisfied_by(bp.CORE_KEY_SCOPES)
        assert TRIAGE_ROUTES <= reached
        for call in (
            ("POST", "/cases/{case_id}/comments"),
            ("PATCH", "/cases/{case_id}"),
            ("POST", "/cases/{case_id}/investigate"),
            ("POST", "/investigations/{run_id}/close"),
        ):
            assert any(m == call[0] and re.sub(r"\{[^}]*\}", "{}", p) == re.sub(r"\{[^}]*\}", "{}", call[1]) for m, p in reached), call

    def test_the_key_holds_alerts_triage_and_not_alerts_write(self):
        assert "alerts:triage" in bp.CORE_KEY_SCOPES and "alerts:write" not in bp.CORE_KEY_SCOPES


class TestACurrentUserOnTheRealPaths:
    @staticmethod
    def user(role="soc_analyst", scopes=None):
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

    def test_a_key_with_only_alerts_triage_passes_for_triage_and_is_refused_alerts_write_naming_the_scope(self):
        key = self.user(scopes=["alerts:triage"])
        key.require_permission("alerts:triage")
        with pytest.raises(Exception) as refused:
            key.require_permission("alerts:write")
        assert getattr(refused.value, "status_code", None) == 403 and "API key missing scope: alerts:write" in str(refused.value.detail)

    def test_a_key_with_alerts_write_still_passes_the_triage_check(self):
        self.user(scopes=["alerts:write"]).require_permission("alerts:triage")

    def test_a_database_role_with_only_alerts_triage_triages_and_cannot_write_alerts(self):
        user = self.user()
        assert asyncio.run(user.has_permission_db("alerts:triage", self.db_with(["alerts:triage"]))) is True
        assert asyncio.run(user.has_permission_db("alerts:write", self.db_with(["alerts:triage"]))) is False

    def test_a_database_role_with_alerts_write_triages(self):
        assert asyncio.run(self.user().has_permission_db("alerts:triage", self.db_with(["alerts:write"]))) is True

    def test_a_database_role_with_neither_does_not(self):
        assert asyncio.run(self.user(role="nobody").has_permission_db("alerts:triage", self.db_with(["alerts:read"]))) is False


class TestTheMigration:
    sql = (MIGRATIONS / "077_alerts_triage_permission.sql").read_text(encoding="utf-8")
    code = re.sub(r"--[^\n]*", "", sql)

    def test_it_adds_only_the_name_to_the_catalog_and_is_idempotent(self):
        assert re.search(r"INSERT INTO permissions \(name, description, category\) VALUES\s*\('alerts:triage'", self.sql)
        assert "ON CONFLICT (name) DO NOTHING" in self.sql
        assert "role_permissions" not in self.code, "nothing is backfilled onto roles: alerts:write implies alerts:triage in code"
        assert not re.search(r"\b(DELETE|DROP|UPDATE|ALTER)\b", self.code, re.I)

    def test_it_names_the_three_routes_and_what_is_not_included(self):
        for route in (
            "POST /alerts/{id}/claim",
            "POST /alerts/{id}/escalate",
            "POST /alerts/{id}/snooze",
            "POST /alerts/submit",
            "PATCH /alerts/{id}",
        ):
            assert route in self.sql, route
        assert "29 routes" in self.sql

    def test_it_follows_migration_076(self):
        numbers = sorted(int(p.name[:3]) for p in MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql"))
        assert numbers.count(77) == 1 and 76 in numbers
