"""hunts:read: read the DEFINITIONS of hunts, split out of lake:query.

lake:query is one permission for creating, running and deleting hunts AND for running arbitrary queries against telemetry, so nothing could be allowed to read which hunts exist without also being allowed to run queries. hunts:read is the read half, for exactly five routes. Three properties matter,
and each is tested over the whole application rather than assumed:
  1. NOBODY LOSES ACCESS: whatever held lake:query (a role, a custom database role, a wildcard) still reads hunts.
  2. hunts:read ALONE GRANTS NOTHING ELSE: a key holding only it satisfies exactly those five routes among every route in the application.
  3. WHAT A HUNT FOUND STAYS BEHIND lake:query: GET /hunts/{id}/runs returns result_sample, event rows sampled from the lake, so it is telemetry, not a definition.
"""
import asyncio
import re
import uuid
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from route_introspect import required_permissions as _required_permissions

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import api_keys
from app.core.security import IMPLIED_BY, PLATFORM_PERMISSIONS, ROLE_PERMISSIONS, has_permission, known_permissions, permission_in
from app.main import app

def required_permissions(route) -> set[str]:
    """The introspection helper returns a list; every comparison here is about sets."""
    return set(_required_permissions(route))


MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"

# The five routes hunts:read covers, and nothing else.
HUNTS_READ_ROUTES = {
    ("GET", "/hunts"),
    ("GET", "/hunts/{hunt_id}"),
    ("GET", "/saved-hunts"),
    ("GET", "/saved-hunts/{hunt_id}"),
    ("GET", "/hunt/saved"),
}


def _walk(routes, prefix=""):
    for route in routes:
        if isinstance(route, APIRoute):
            yield prefix + route.path, route
        elif hasattr(route, "original_router"):
            context = getattr(route, "include_context", None)
            yield from _walk(route.original_router.routes, prefix + (getattr(context, "prefix", "") or ""))


ALL_ROUTES = [(re.sub(r"^/api/v1", "", p), r) for p, r in _walk(app.routes)]


def _satisfied_by(scopes) -> set[tuple[str, str]]:
    """Every (method, path) in the application whose required permissions are ALL covered by `scopes` (a route with no required permission is not counted)."""
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
            (["lake:query"], True),
            (["lake:*"], True),
            (["*"], True),
            (["hunts:read"], True),
            (["hunts:*"], True),
            (["alerts:read", "lake:query"], True),
            ([], False),
            (["lake:read_schema"], False),
            (["alerts:read"], False),
            (["rules:read"], False),
            (["hunts:write"], False),
            (["lake:schema"], False),
        ],
    )
    def test_who_holds_hunts_read(self, granted, expected):
        assert permission_in(granted, "hunts:read") is expected

    def test_hunts_read_alone_grants_no_other_permission(self):
        for permission in known_permissions() - {"hunts:read"}:
            assert not permission_in(["hunts:read"], permission), f"hunts:read must not grant {permission}"
        assert not permission_in(["hunts:read"], "lake:query")
        assert not permission_in(["hunts:read"], "lake:read_schema")

    def test_lake_query_still_grants_exactly_what_it_did_and_the_implication_is_one_way(self):
        assert permission_in(["lake:query"], "lake:query") and not permission_in(["lake:query"], "lake:read_schema")
        assert not permission_in(["hunts:read"], "lake:query")

    def test_the_rule_is_exactly_these_pairs(self):
        """Adding an implication must be a conscious act: this lists every one. The second pair, intel:read implied by threat_intel:read, is tested in test_intel_read_permission.py, and the third, alerts:triage implied by alerts:write, in test_alerts_triage_permission.py."""
        assert IMPLIED_BY == {"hunts:read": ("lake:query",), "intel:read": ("threat_intel:read",), "alerts:triage": ("alerts:write",), "rules:view": ("rules:read",)}

    def test_no_implied_permission_is_a_platform_permission_and_nothing_implies_a_platform_permission(self):
        for weaker, stronger in IMPLIED_BY.items():
            assert weaker not in PLATFORM_PERMISSIONS and not (set(stronger) & PLATFORM_PERMISSIONS)

    def test_a_wildcard_still_does_not_cover_a_platform_permission(self):
        assert not permission_in(["*"], "platform:cross_tenant_query") and not permission_in(["lake:query"], "platform:cross_tenant_query")

    def test_any_kind_of_iterable_works(self):
        for kind in (list, tuple, set, frozenset, lambda it: (x for x in it)):
            assert permission_in(kind(["lake:query"]), "hunts:read")

    def test_hunts_read_is_a_known_permission_and_a_valid_key_scope(self):
        assert "hunts:read" in known_permissions()
        assert "hunts:read" in api_keys.VALID_SCOPES


class TestRolesAreUnchanged:
    def test_every_role_reads_hunts_exactly_when_it_could_before_nobody_gains_or_loses_it(self):
        for role in ROLE_PERMISSIONS:
            assert has_permission(role, "hunts:read") == has_permission(role, "lake:query"), role

    def test_a_role_with_only_schema_access_does_not_read_hunts(self):
        schema_only = [r for r in ROLE_PERMISSIONS if has_permission(r, "lake:read_schema") and not has_permission(r, "lake:query")]
        for role in schema_only:
            assert not has_permission(role, "hunts:read"), role

    def test_there_is_a_role_that_holds_it_and_a_role_that_does_not(self):
        assert any(has_permission(r, "hunts:read") for r in ROLE_PERMISSIONS) and not all(has_permission(r, "hunts:read") for r in ROLE_PERMISSIONS)


class TestTheRoutes:
    def test_exactly_these_five_routes_need_hunts_read_and_each_is_a_get(self):
        needing = {(m, p) for p, r in ALL_ROUTES if "hunts:read" in required_permissions(r) for m in r.methods if m not in {"HEAD", "OPTIONS"}}
        assert needing == HUNTS_READ_ROUTES

    def test_a_key_holding_only_hunts_read_can_use_exactly_those_five_routes_in_the_whole_application(self):
        assert _satisfied_by(["hunts:read"]) == HUNTS_READ_ROUTES

    def test_lake_query_still_reaches_those_five_and_the_runs_and_every_write(self):
        reachable = _satisfied_by(["lake:query"])
        assert HUNTS_READ_ROUTES <= reachable
        for must in [("GET", "/hunts/{hunt_id}/runs"), ("POST", "/hunts"), ("POST", "/hunts/{hunt_id}/run"), ("PATCH", "/hunts/{hunt_id}"), ("POST", "/hunts/{hunt_id}/findings"), ("POST", "/saved-hunts"), ("DELETE", "/saved-hunts/{hunt_id}"), ("POST", "/saved-hunts/{hunt_id}/run"), ("POST", "/hunt/saved"), ("DELETE", "/hunt/saved/{search_id}"), ("POST", "/nl-query/execute"), ("POST", "/nl-query/translate")]:
            assert must in reachable, must

    def test_what_a_hunt_found_stays_behind_lake_query(self):
        runs = next(r for p, r in ALL_ROUTES if p == "/hunts/{hunt_id}/runs" and "GET" in r.methods)
        assert required_permissions(runs) == {"lake:query"}, "a run's result_sample is event rows sampled from the lake: that is telemetry"
        assert ("GET", "/hunts/{hunt_id}/runs") not in _satisfied_by(["hunts:read"])

    def test_everything_that_writes_or_queries_in_hunting_still_needs_lake_query(self):
        for path, route in ALL_ROUTES:
            if path.startswith(("/hunts", "/saved-hunts", "/hunt/saved", "/nl-query")) and (route.methods & {"POST", "PUT", "PATCH", "DELETE"}):
                assert required_permissions(route) == {"lake:query"}, f"{sorted(route.methods)} {path}"

    def test_a_hunts_read_key_cannot_use_a_route_that_needs_a_different_permission(self):
        reachable = _satisfied_by(["hunts:read"])
        for path, route in ALL_ROUTES:
            if not (required_permissions(route) - {"hunts:read"}):
                continue
            for method in route.methods - {"HEAD", "OPTIONS"}:
                assert (method, path) not in reachable or (method, path) in HUNTS_READ_ROUTES, f"{method} {path}"


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

    def test_a_key_with_only_hunts_read_passes_the_check_for_hunts_read_and_is_refused_for_lake_query_naming_the_scope(self):
        key = self.user(scopes=["hunts:read"])
        key.require_permission("hunts:read")
        with pytest.raises(Exception) as refused:
            key.require_permission("lake:query")
        assert getattr(refused.value, "status_code", None) == 403 and "API key missing scope: lake:query" in str(refused.value.detail)

    def test_a_key_with_lake_query_passes_the_hunts_read_check(self):
        self.user(scopes=["lake:query"]).require_permission("hunts:read")

    def test_a_database_role_with_only_hunts_read_reads_hunts_and_cannot_query(self):
        user = self.user()
        assert asyncio.run(user.has_permission_db("hunts:read", self.db_with(["hunts:read"]))) is True
        assert asyncio.run(user.has_permission_db("lake:query", self.db_with(["hunts:read"]))) is False

    def test_a_database_role_with_lake_query_reads_hunts(self):
        assert asyncio.run(self.user().has_permission_db("hunts:read", self.db_with(["lake:query"]))) is True

    def test_a_database_role_with_neither_does_not(self):
        assert asyncio.run(self.user().has_permission_db("hunts:read", self.db_with(["alerts:read", "lake:read_schema"]))) is False

    def test_a_user_with_no_database_roles_falls_back_to_the_static_map(self):
        for role in ROLE_PERMISSIONS:
            assert asyncio.run(self.user(role=role).has_permission_db("hunts:read", self.db_with([]))) is has_permission(role, "hunts:read"), role


class TestTheMigration:
    sql = (MIGRATIONS / "075_hunts_read_permission.sql").read_text(encoding="utf-8")

    def test_it_adds_only_the_name_to_the_catalog_and_is_idempotent(self):
        assert re.search(r"INSERT INTO permissions \(name, description, category\) VALUES\s*\('hunts:read'", self.sql)
        assert "ON CONFLICT (name) DO NOTHING" in self.sql
        assert not re.search(r"role_permissions", re.sub(r"--[^\n]*", "", self.sql)), "nothing is backfilled onto roles: lake:query implies hunts:read in code"
        assert not re.search(r"\b(DELETE|DROP|UPDATE|ALTER)\b", re.sub(r"--[^\n]*", "", self.sql), re.I)

    def test_it_says_why_runs_are_not_included(self):
        assert "GET /hunts/{id}/runs" in self.sql and "lake:query" in self.sql

    def test_it_follows_the_last_migration(self):
        numbers = sorted(int(p.name[:3]) for p in MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql"))
        assert numbers.count(75) == 1 and 74 in numbers, "075 follows 074 (later migrations may follow it)"
