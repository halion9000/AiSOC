"""intel:read: read the tenant's stored threat intelligence, split out of threat_intel:read.

threat_intel:read ALSO guards the feed list (a feed's free-form `config` can hold credentials) and the enrichment routes (they send an indicator to outside providers), so nothing that should only READ intelligence (an AI agent's API key) could be given it without those. Confirmed on a real deployment: a key holding
threat_intel:read got 200 on GET /threat-intel/feeds. Each claim is tested over the whole application rather than assumed:
  1. NOBODY LOSES ACCESS: whatever held threat_intel:read (a role, a custom database role, a `threat_intel:*` wildcard, a key) still reads intelligence AND still reaches the feed list and enrichment.
  2. intel:read ALONE GRANTS NOTHING ELSE: a key holding only it satisfies exactly the five routes among every route in the application, and it does not satisfy the feed list, enrichment, TAXII or MISP health.
  3. The implication is one way and is exactly this pair.
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

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"

INTEL_READ_ROUTES = {
    ("GET", "/threat-intel/iocs"),
    ("GET", "/threat-intel/iocs/{ioc_id}"),
    ("GET", "/threat-intel/actors"),
    ("GET", "/threatintel/stix/indicators"),
    ("GET", "/threatintel/stix/bundles"),
}
# What threat_intel:read still guards, and intel:read must NOT reach.
STILL_THREAT_INTEL_READ = {
    ("GET", "/threat-intel/feeds"),
    ("GET", "/enrichment/lookup"),
    ("POST", "/enrichment/bulk"),
    ("GET", "/threatintel/stix/taxii/collections"),
    ("GET", "/threatintel/stix/misp/health"),
}


def required_permissions(route) -> set[str]:
    return set(_required_permissions(route))


ALL_ROUTES = [(path.replace("/api/v1", "", 1), route) for path, route in walk_routes(app.routes)]


def _satisfied_by(scopes) -> set[tuple[str, str]]:
    """Every (method, path) whose required permissions are ALL covered by `scopes` (a route that needs no permission is not counted)."""
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
            (["intel:read"], True),
            (["threat_intel:read"], True),
            (["threat_intel:*"], True),
            (["intel:*"], True),
            (["*"], True),
            (["threat_intel:write"], False),
            (["hunts:read"], False),
            (["lake:query"], False),
            ([], False),
        ],
    )
    def test_who_holds_intel_read(self, granted, expected):
        assert permission_in(granted, "intel:read") is expected

    def test_intel_read_alone_grants_no_other_permission(self):
        assert {p for p in known_permissions() if permission_in(["intel:read"], p)} == {"intel:read"}

    def test_threat_intel_read_grants_exactly_what_it_did_plus_intel_read_and_the_implication_is_one_way(self):
        assert {p for p in known_permissions() if permission_in(["threat_intel:read"], p)} == {"threat_intel:read", "intel:read"}
        assert not permission_in(["intel:read"], "threat_intel:read")

    def test_the_rule_is_exactly_these_pairs(self):
        assert IMPLIED_BY == {"hunts:read": ("lake:query",), "intel:read": ("threat_intel:read",), "alerts:triage": ("alerts:write",)}

    def test_no_implied_permission_is_a_platform_permission_and_nothing_implies_one(self):
        for narrow, broad in IMPLIED_BY.items():
            assert narrow not in PLATFORM_PERMISSIONS and not (set(broad) & PLATFORM_PERMISSIONS)

    def test_intel_read_is_a_known_permission_and_a_valid_key_scope(self):
        assert "intel:read" in known_permissions()
        assert "intel:read" in api_keys.VALID_SCOPES


class TestRolesAreUnchanged:
    def test_every_role_reads_intelligence_exactly_when_it_could_before_nobody_gains_or_loses_it(self):
        for role in ROLE_PERMISSIONS:
            assert has_permission(role, "intel:read") == has_permission(role, "threat_intel:read"), role

    def test_every_standard_role_reads_intelligence_today_so_the_console_loses_nothing(self):
        """All eight standard roles hold threat_intel:read (the alerts UI renders indicator enrichment inline), so all of them hold intel:read. That the equality above is not vacuous is shown by the key and database-role tests below, which DO tell holders from non-holders."""
        assert all(has_permission(role, "intel:read") for role in ROLE_PERMISSIONS), {r: has_permission(r, "intel:read") for r in ROLE_PERMISSIONS}


class TestTheRoutes:
    def test_exactly_these_five_routes_need_intel_read_and_each_is_a_get(self):
        found = {(m, p) for p, r in ALL_ROUTES if required_permissions(r) == {"intel:read"} for m in r.methods if m not in {"HEAD", "OPTIONS"}}
        assert found == INTEL_READ_ROUTES and all(m == "GET" for m, _ in found)

    def test_a_key_holding_only_intel_read_can_use_exactly_those_five_routes_in_the_whole_application(self):
        assert _satisfied_by(["intel:read"]) == INTEL_READ_ROUTES

    def test_the_feed_list_enrichment_taxii_and_misp_health_still_need_threat_intel_read_and_intel_read_does_not_reach_them(self):
        for method, path in STILL_THREAT_INTEL_READ:
            route = next(r for p, r in ALL_ROUTES if p == path and method in r.methods)
            assert required_permissions(route) == {"threat_intel:read"}, f"{method} {path}"
        assert not (_satisfied_by(["intel:read"]) & STILL_THREAT_INTEL_READ)

    def test_whoever_held_threat_intel_read_still_reaches_all_ten_routes(self):
        assert _satisfied_by(["threat_intel:read"]) == INTEL_READ_ROUTES | STILL_THREAT_INTEL_READ

    def test_everything_that_writes_intelligence_still_needs_threat_intel_write(self):
        writers = {(m, p) for p, r in ALL_ROUTES if required_permissions(r) == {"threat_intel:write"} for m in r.methods}
        assert writers and not (_satisfied_by(["intel:read"]) & writers) and not (_satisfied_by(["threat_intel:read"]) & writers)


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

    def test_a_key_with_only_intel_read_passes_for_intel_read_and_is_refused_the_feed_list_naming_the_scope(self):
        key = self.user(scopes=["intel:read"])
        key.require_permission("intel:read")
        with pytest.raises(Exception) as refused:
            key.require_permission("threat_intel:read")
        assert getattr(refused.value, "status_code", None) == 403 and "API key missing scope: threat_intel:read" in str(refused.value.detail)

    def test_a_key_with_threat_intel_read_still_passes_the_intel_read_check(self):
        self.user(scopes=["threat_intel:read"]).require_permission("intel:read")

    def test_a_database_role_with_only_intel_read_reads_intelligence_and_cannot_use_enrichment(self):
        user = self.user()
        assert asyncio.run(user.has_permission_db("intel:read", self.db_with(["intel:read"]))) is True
        assert asyncio.run(user.has_permission_db("threat_intel:read", self.db_with(["intel:read"]))) is False

    def test_a_database_role_with_threat_intel_read_reads_intelligence(self):
        assert asyncio.run(self.user().has_permission_db("intel:read", self.db_with(["threat_intel:read"]))) is True

    def test_a_database_role_with_neither_does_not(self):
        assert asyncio.run(self.user(role="nobody").has_permission_db("intel:read", self.db_with(["alerts:read"]))) is False


class TestTheMigration:
    sql = (MIGRATIONS / "076_intel_read_permission.sql").read_text(encoding="utf-8")
    code = re.sub(r"--[^\n]*", "", sql)

    def test_it_adds_only_the_name_to_the_catalog_and_is_idempotent(self):
        assert re.search(r"INSERT INTO permissions \(name, description, category\) VALUES\s*\('intel:read'", self.sql)
        assert "ON CONFLICT (name) DO NOTHING" in self.sql
        assert "role_permissions" not in self.code, "nothing is backfilled onto roles: threat_intel:read implies intel:read in code"
        assert not re.search(r"\b(DELETE|DROP|UPDATE|ALTER)\b", self.code, re.I)

    def test_it_says_what_is_not_included_and_why(self):
        assert "GET /threat-intel/feeds" in self.sql and "config" in self.sql and "credentials" in self.sql
        assert "GET /enrichment/lookup" in self.sql and "outside providers" in self.sql

    def test_it_follows_migration_075(self):
        numbers = sorted(int(p.name[:3]) for p in MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql"))
        assert numbers.count(76) == 1 and 75 in numbers
