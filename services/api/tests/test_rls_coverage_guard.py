"""Every tenant-scoped table has row-level security, or an explicit, written reason why not. And migration 063's classification rules hold.

Only 38 of 79 tenant-scoped tables had RLS because nothing stopped a new tenant table being added without it. This guard reads the migration files (it was checked against a real migrated database: the same 79 tenant-scoped tables
and the identical 5 uncovered ones) and fails when a new one appears without RLS, naming what to do. It also fails when a documented gap has since been closed, so the list of exceptions cannot go stale.
"""
import re
from pathlib import Path

import pytest

from app.scripts import rls_audit as ra

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"

# The tenant-scoped tables that deliberately have NO RLS, and why. Adding a table here needs a reason a reviewer would accept.
KNOWN_GAPS = {
    "users": "authentication reads it before any tenant is known (migration 002 leaves it out for this reason)",
    "mssp_tenant_metrics": "a PARENT tenant reads its CHILD tenants' rows: needs a parent-aware policy, not an own-tenant one",
    "aisoc_autonomy_thresholds": "tenant_id is TEXT (may hold a slug): a uuid policy would error or hide rows until the code stores the canonical uuid",
    "aisoc_institutional_memory": "tenant_id is TEXT (may hold a slug): as above",
    "aisoc_run_costs": "tenant_id is TEXT (may hold a slug): as above",
}


def strip_comments(text: str) -> str:
    return "\n".join(re.sub(r"--.*$", "", line) for line in text.splitlines())


def parse_migrations():
    """-> (tables with a tenant_id column {name: {"type", "nullable"}}, tables with RLS enabled)."""
    scoped: dict[str, dict] = {}
    enabled: set[str] = set()
    for f in sorted(MIGRATIONS.glob("*.sql")):
        raw = f.read_text(encoding="utf-8", errors="replace")
        text = strip_comments(raw)
        for m in re.finditer(r"CREATE TABLE(?: IF NOT EXISTS)?\s+(?:public\.)?(\w+)\s*\((.*?)\n\)\s*;", text, re.S | re.I):
            col = re.search(r"^\s*tenant_id\s+(\w+)([^,\n]*)", m.group(2), re.M | re.I)
            if col:
                scoped[m.group(1)] = {"type": col.group(1).upper(), "nullable": "NOT NULL" not in col.group(2).upper() and "PRIMARY KEY" not in col.group(2).upper()}
        for m in re.finditer(r"ALTER TABLE(?: IF EXISTS)?\s+(?:public\.)?(\w+)\s+ADD COLUMN(?: IF NOT EXISTS)?\s+tenant_id\s+(\w+)([^,;\n]*)", text, re.I):
            scoped.setdefault(m.group(1), {"type": m.group(2).upper(), "nullable": "NOT NULL" not in m.group(3).upper()})
        for m in re.finditer(r"ALTER TABLE(?: IF EXISTS)?\s+(?:public\.)?(\w+)\s+(?:ENABLE|FORCE)\s+ROW LEVEL SECURITY", text, re.I):
            enabled.add(m.group(1))
        if f.name.startswith("063_"):
            for arr in re.findall(r"ARRAY\[(.*?)\]", raw, re.S):
                enabled |= set(re.findall(r"'([a-z_]+)'", arr))
    return scoped, enabled


SCOPED, ENABLED = parse_migrations()
MIG063 = (MIGRATIONS / "063_rls_for_uncovered_tenant_tables.sql").read_text(encoding="utf-8")
ARRAYS = [re.findall(r"'([a-z_]+)'", a) for a in re.findall(r"ARRAY\[(.*?)\]", MIG063, re.S)]
STANDARD_LIST, SHARED_LIST = ARRAYS


class TestTheCoverageGuard:
    def test_the_parse_finds_what_a_real_database_has(self):
        """Ground truth from a real migrated Postgres 16: 79 tenant-scoped tables, 5 without RLS."""
        assert len(SCOPED) >= 79
        assert {t for t in SCOPED if t not in ENABLED} == set(KNOWN_GAPS)

    def test_every_tenant_scoped_table_has_rls_or_a_written_reason(self):
        uncovered = sorted(t for t in SCOPED if t not in ENABLED and t not in KNOWN_GAPS)
        assert uncovered == [], (
            f"tenant-scoped tables with NO row-level security: {uncovered}. Enable RLS with the standard policy (see migrations 060/061/063: "
            "`tenant_id = current_tenant_id() OR current_tenant_id() IS NULL`, plus `OR tenant_id IS NULL` if tenant_id is nullable), or add the table to KNOWN_GAPS with a reason."
        )

    def test_a_documented_gap_that_has_been_closed_must_be_removed_from_the_list(self):
        stale = sorted(t for t in KNOWN_GAPS if t in ENABLED)
        assert stale == [], f"these now have RLS, so remove them from KNOWN_GAPS: {stale}"

    def test_every_documented_gap_is_a_real_tenant_scoped_table(self):
        assert sorted(t for t in KNOWN_GAPS if t not in SCOPED) == []

    def test_the_text_typed_gaps_really_are_text(self):
        for t in ("aisoc_autonomy_thresholds", "aisoc_institutional_memory", "aisoc_run_costs"):
            assert SCOPED[t]["type"] in ("TEXT", "VARCHAR"), t


class TestMigration063:
    def test_the_two_lists_cover_36_tables_and_do_not_overlap(self):
        assert (len(STANDARD_LIST), len(SHARED_LIST)) == (27, 9) and not set(STANDARD_LIST) & set(SHARED_LIST)
        assert len(set(STANDARD_LIST) | set(SHARED_LIST)) == len(STANDARD_LIST) + len(SHARED_LIST)

    def test_every_listed_table_is_a_real_tenant_scoped_table(self):
        assert sorted(t for t in STANDARD_LIST + SHARED_LIST if t not in SCOPED) == []

    def test_the_deliberate_exclusions_are_in_neither_list(self):
        assert not set(KNOWN_GAPS) & set(STANDARD_LIST + SHARED_LIST)

    def test_every_listed_table_has_a_uuid_tenant_id(self):
        """A uuid policy on a TEXT column would raise an error (or hide slug-keyed rows)."""
        assert sorted(t for t in STANDARD_LIST + SHARED_LIST if SCOPED[t]["type"] != "UUID") == []

    def test_a_not_null_tenant_id_gets_the_standard_policy(self):
        assert sorted(t for t in STANDARD_LIST if SCOPED[t]["nullable"]) == [], "a NULLABLE tenant_id in the standard list would make its NULL rows vanish for tenant-scoped sessions"

    def test_a_nullable_tenant_id_gets_the_shared_rows_variant(self):
        assert sorted(t for t in SHARED_LIST if not SCOPED[t]["nullable"]) == [], "a NOT NULL tenant_id does not need the shared variant (it would be pointless but harmless): keep the lists exact"

    def test_the_two_policies_are_classified_as_standard_by_the_audit_tool(self):
        block = MIG063
        using = [" ".join(u.split()) for u in re.findall(r"CREATE POLICY tenant_isolation ON %I USING \((.*?)\)', t\);", block, re.S)]
        assert len(using) == 2 and all(ra.classify_policy(u) == "standard" for u in using)
        assert "tenant_id IS NULL" in using[1] and "tenant_id IS NULL" not in using[0]

    def test_it_enables_rls_without_forcing_it_so_the_owner_is_not_constrained(self):
        code = strip_comments(MIG063)
        assert "ENABLE ROW LEVEL SECURITY" in code and "FORCE" not in code.upper()

    def test_it_is_idempotent_and_skips_tables_that_do_not_exist(self):
        code = strip_comments(MIG063)
        assert code.count("DROP POLICY IF EXISTS tenant_isolation") == 2 and code.count("to_regclass('public.' || t) IS NOT NULL") == 2

    def test_it_uses_the_standard_helper_not_current_setting(self):
        assert "current_setting" not in strip_comments(MIG063)

    def test_the_header_documents_every_exclusion_and_the_reason(self):
        header = MIG063.split("DO $$")[0]
        for t, needle in (("users", "authentication"), ("mssp_tenant_metrics", "PARENT"), ("aisoc_run_costs", "TEXT")):
            assert t in header and needle in header


@pytest.mark.parametrize("table", sorted(KNOWN_GAPS))
def test_the_guard_message_names_a_way_forward_for_each_gap(table):
    assert len(KNOWN_GAPS[table]) > 20  # a reason, not a placeholder
