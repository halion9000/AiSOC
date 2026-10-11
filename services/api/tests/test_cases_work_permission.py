"""cases:work: work on an existing case, split out of cases:write.

cases:write guards 14 routes. Besides updating a case, commenting on it, launching an investigation from it and closing one, it covers
creating cases, attaching alerts, notes, observables and tasks, updating a task, RAISING and DECIDING agent approvals (the human sign-off
for destructive actions) and publishing or unpublishing investigation replays.
CORE's agent only does the first four, so its key held all of it: it could create cases and tasks, put approval requests in front of the
on-call analyst (and, until a signed-in session was required, decide them), and publish replays. Each claim is tested over the whole
application rather than assumed:
  1. NOBODY LOSES ACCESS: whatever held cases:write (a role, a custom database role, a `cases:*` wildcard, a key) still works on cases AND
  still reaches the ten other routes.
  2. cases:work ALONE GRANTS NOTHING ELSE: a key holding only it satisfies exactly four routes among every route in the application.
  3. CORE's real key scopes reach none of the ten, and still reach the four its case tools call.
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
WORK_ROUTES = {
    ("PATCH", "/cases/{case_id}"),
    ("POST", "/cases/{case_id}/comments"),
    ("POST", "/cases/{case_id}/investigate"),
    ("POST", "/investigations/{run_id}/close"),
}
STAY_ROUTES = {
    ("POST", "/cases"),
    ("POST", "/cases/{case_id}/alerts"),
    ("POST", "/cases/{case_id}/notes"),
    ("POST", "/cases/{case_id}/observables"),
    ("POST", "/cases/{case_id}/tasks"),
    ("PATCH", "/cases/{case_id}/tasks/{task_id}"),
    ("POST", "/approvals"),
    ("POST", "/approvals/{approval_id}/decide"),
    ("POST", "/ledger/{run_id}/publish"),
    ("DELETE", "/ledger/publish/{slug}"),
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
    @pytest.mark.parametrize(
        "granted,expected",
        [
            (["cases:work"], True),
            (["cases:write"], True),
            (["cases:*"], True),
            (["*"], True),
            (["cases:read"], False),
            (["cases:delete"], False),
            (["alerts:write"], False),
            ([], False),
        ],
    )
    def test_who_holds_cases_work(self, granted, expected):
        assert permission_in(granted, "cases:work") is expected

    def test_cases_work_alone_grants_no_other_permission(self):
        assert {p for p in known_permissions() if permission_in(["cases:work"], p)} == {"cases:work"}

    def test_cases_write_grants_exactly_what_it_did_plus_cases_work_and_the_implication_is_one_way(self):
        assert {p for p in known_permissions() if permission_in(["cases:write"], p)} == {"cases:write", "cases:work"}
        assert not permission_in(["cases:work"], "cases:write")

    def test_the_pair_is_in_the_rule_and_no_platform_permission_is_involved(self):
        assert IMPLIED_BY["cases:work"] == ("cases:write",)
        assert "cases:work" not in PLATFORM_PERMISSIONS and "cases:write" not in PLATFORM_PERMISSIONS

    def test_cases_work_is_a_known_permission_and_a_valid_key_scope(self):
        assert "cases:work" in known_permissions()
        assert "cases:work" in api_keys.VALID_SCOPES


class TestRolesAreUnchanged:
    def test_every_role_works_on_cases_exactly_when_it_could_before_nobody_gains_or_loses_it(self):
        for role in ROLE_PERMISSIONS:
            assert has_permission(role, "cases:work") == has_permission(role, "cases:write"), role

    def test_the_comparison_is_not_vacuous_the_viewer_holds_neither_and_the_working_roles_hold_both(self):
        outcomes = {role: has_permission(role, "cases:work") for role in ROLE_PERMISSIONS}
        assert outcomes["viewer"] is False and all(
            outcomes[r] for r in ("admin", "soc_analyst", "soc_lead", "threat_hunter", "api_service")
        ), outcomes


class TestTheRoutes:
    def test_exactly_these_four_routes_need_cases_work(self):
        found = {
            (m, p) for p, r in ALL_ROUTES if required_permissions(r) == {"cases:work"} for m in r.methods if m not in {"HEAD", "OPTIONS"}
        }
        assert found == WORK_ROUTES

    def test_a_key_holding_only_cases_work_can_use_exactly_those_four_routes_in_the_whole_application(self):
        assert _satisfied_by(["cases:work"]) == WORK_ROUTES

    def test_exactly_these_ten_routes_still_need_cases_write_and_cases_work_does_not_reach_them(self):
        found = {
            (m, p) for p, r in ALL_ROUTES if "cases:write" in required_permissions(r) for m in r.methods if m not in {"HEAD", "OPTIONS"}
        }
        assert found == STAY_ROUTES and len(found) == 10
        assert not (_satisfied_by(["cases:work"]) & STAY_ROUTES)

    def test_whoever_held_cases_write_still_reaches_all_fourteen_routes(self):
        assert _satisfied_by(["cases:write"]) >= WORK_ROUTES | STAY_ROUTES

    def test_neither_cases_work_nor_cases_write_grants_cases_delete(self):
        """No route needs cases:delete today (checked, not assumed: the set below is empty), so the guarantee is the permission relation
        itself, which would also cover one added later."""
        deleters = {(m, p) for p, r in ALL_ROUTES if "cases:delete" in required_permissions(r) for m in r.methods}
        assert not (_satisfied_by(["cases:work"]) & deleters) and not (_satisfied_by(["cases:write"]) & deleters)
        assert not permission_in(["cases:work"], "cases:delete") and not permission_in(["cases:write"], "cases:delete")


class TestCoresKeyNoLongerReachesTheOthers:
    def test_cores_real_key_scopes_satisfy_none_of_the_ten_routes_that_stay(self):
        reached = _satisfied_by(bp.CORE_KEY_SCOPES)
        assert not (reached & STAY_ROUTES), sorted(reached & STAY_ROUTES)

    def test_cores_real_key_scopes_still_reach_the_four_case_routes_its_tools_call(self):
        assert WORK_ROUTES <= _satisfied_by(bp.CORE_KEY_SCOPES)

    def test_the_key_holds_cases_work_and_not_cases_write(self):
        assert "cases:work" in bp.CORE_KEY_SCOPES and "cases:write" not in bp.CORE_KEY_SCOPES


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

    def test_a_key_with_only_cases_work_passes_for_work_and_is_refused_cases_write_naming_the_scope(self):
        key = self.user(scopes=["cases:work"])
        key.require_permission("cases:work")
        with pytest.raises(Exception) as refused:
            key.require_permission("cases:write")
        assert getattr(refused.value, "status_code", None) == 403 and "API key missing scope: cases:write" in str(refused.value.detail)

    def test_a_key_with_cases_write_still_passes_the_cases_work_check(self):
        self.user(scopes=["cases:write"]).require_permission("cases:work")

    def test_a_database_role_with_only_cases_work_works_on_cases_and_cannot_create_them(self):
        user = self.user()
        assert asyncio.run(user.has_permission_db("cases:work", self.db_with(["cases:work"]))) is True
        assert asyncio.run(user.has_permission_db("cases:write", self.db_with(["cases:work"]))) is False

    def test_a_database_role_with_cases_write_works_on_cases(self):
        assert asyncio.run(self.user().has_permission_db("cases:work", self.db_with(["cases:write"]))) is True

    def test_a_database_role_with_neither_does_not(self):
        assert asyncio.run(self.user(role="nobody").has_permission_db("cases:work", self.db_with(["cases:read"]))) is False


class TestTheMigration:
    sql = (MIGRATIONS / "080_cases_work_permission.sql").read_text(encoding="utf-8")
    code = re.sub(r"--[^\n]*", "", sql)
    statements = re.sub(
        r"'[^']*'", "''", code
    )  # string literals removed: the permission's DESCRIPTION says "Update a case", which is not an UPDATE statement

    def test_it_adds_only_the_name_to_the_catalog_and_is_idempotent(self):
        assert re.search(r"INSERT INTO permissions \(name, description, category\) VALUES\s*\('cases:work'", self.sql)
        assert "ON CONFLICT (name) DO NOTHING" in self.sql
        assert "role_permissions" not in self.code, "nothing is backfilled onto roles: cases:write implies cases:work in code"
        assert not re.search(r"\b(DELETE|DROP|UPDATE|ALTER)\b", self.statements, re.I)

    def test_it_names_the_four_routes_and_what_is_not_included(self):
        for route in ("PATCH /cases/{id}", "POST /cases/{id}/comments", "POST /cases/{id}/investigate", "POST /investigations/{id}/close"):
            assert route in self.sql, route
        assert "14 routes" in self.sql and "approvals" in self.sql

    def test_it_follows_migration_079(self):
        numbers = sorted(int(p.name[:3]) for p in MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql"))
        assert numbers.count(80) == 1 and 79 in numbers
