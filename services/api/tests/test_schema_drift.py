"""The ORM and the database agree, and the tool that checks it works.

`IdentityNode.is_active` was mapped as a String for a boolean column, so every node insert failed, and the unit suite (SQLite) could not notice. Comparing the ORM to a real migrated Postgres found that; this keeps the models and the migrations in step without needing a database
(every ORM table and column must be created by some migration) and tests the read-only tool that does the full comparison against a live one (verified on real Postgres: it reports exactly identity_nodes.is_active when the old mapping is put back).
"""
import json
import re
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from app.scripts import schema_drift as sd

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"


class TestCompatibleTypes:
    @pytest.mark.parametrize("col_type,db_type", [
        (sa.Boolean(), "boolean"), (sa.String(10), "character varying"), (sa.String(10), "text"), (sa.Text(), "text"), (sa.Integer(), "integer"), (sa.Integer(), "bigint"), (sa.BigInteger(), "bigint"),
        (sa.Float(), "double precision"), (sa.DateTime(timezone=True), "timestamp with time zone"), (sa.DateTime(), "timestamp without time zone"), (pg.UUID(as_uuid=True), "uuid"), (sa.Uuid(), "uuid"),
        (pg.JSONB(), "jsonb"), (sa.JSON(), "json"), (pg.ARRAY(sa.Text()), "ARRAY"), (sa.Enum("a", "b", name="x"), "USER-DEFINED"), (sa.LargeBinary(), "bytea"), (pg.INET(), "inet"),
    ])
    def test_a_type_the_column_can_hold_is_accepted(self, col_type, db_type):
        assert db_type in sd.compatible_types(col_type)

    @pytest.mark.parametrize("col_type,db_type", [
        (sa.String(10), "boolean"), (sa.Boolean(), "character varying"), (sa.Integer(), "text"), (sa.DateTime(), "text"), (pg.UUID(), "text"), (pg.JSONB(), "text"), (sa.Boolean(), "integer"), (sa.Text(), "uuid"),
    ])
    def test_a_type_it_cannot_hold_is_rejected(self, col_type, db_type):
        assert db_type not in sd.compatible_types(col_type)

    def test_an_unknown_type_is_not_judged(self):
        class Exotic(sa.types.UserDefinedType):
            cache_ok = True

            def get_col_spec(self, **kw):
                return "EXOTIC"

        assert sd.compatible_types(Exotic()) is None


def meta(**tables):
    m = sa.MetaData()
    for name, cols in tables.items():
        sa.Table(name, m, *cols)
    return m


def db_of(**tables):
    return {t: {c: {"data_type": dt, "is_nullable": nl} for c, (dt, nl) in cols.items()} for t, cols in tables.items()}


class TestCompare:
    def test_a_matching_schema_has_no_defects(self):
        m = meta(t=[sa.Column("id", sa.Integer, primary_key=True), sa.Column("name", sa.String(20), nullable=True)])
        d = sd.compare(m, db_of(t={"id": ("integer", "NO"), "name": ("character varying", "YES")}))
        assert d.defects == 0 and d.orm_tables == 1

    def test_a_table_the_database_lacks_is_reported(self):
        d = sd.compare(meta(a=[sa.Column("id", sa.Integer, primary_key=True)], b=[sa.Column("id", sa.Integer, primary_key=True)]), db_of(a={"id": ("integer", "NO")}))
        assert d.missing_tables == ["b"] and d.defects == 1

    def test_a_column_the_database_lacks_is_reported(self):
        d = sd.compare(meta(t=[sa.Column("id", sa.Integer, primary_key=True), sa.Column("extra", sa.Text)]), db_of(t={"id": ("integer", "NO")}))
        assert d.missing_columns == [("t", "extra")] and d.defects == 1

    def test_the_identity_node_bug_is_a_type_mismatch(self):
        """ORM String, database boolean: what made every identity node insert fail."""
        d = sd.compare(meta(identity_nodes=[sa.Column("id", sa.Integer, primary_key=True), sa.Column("is_active", sa.String(10))]), db_of(identity_nodes={"id": ("integer", "NO"), "is_active": ("boolean", "YES")}))
        assert d.type_mismatches == [("identity_nodes", "is_active", "String", "boolean")]

    def test_an_unenforced_not_null_is_information_not_a_defect(self):
        m = meta(t=[sa.Column("id", sa.Integer, primary_key=True), sa.Column("event_time", sa.DateTime, nullable=False)])
        d = sd.compare(m, db_of(t={"id": ("integer", "NO"), "event_time": ("timestamp with time zone", "YES")}))
        assert d.not_null_not_enforced == [("t", "event_time")] and d.defects == 0

    def test_a_column_with_a_default_or_a_primary_key_is_not_reported_as_unenforced(self):
        m = meta(t=[sa.Column("id", sa.Integer, primary_key=True), sa.Column("a", sa.Integer, nullable=False, default=1), sa.Column("b", sa.Integer, nullable=False, server_default="1")])
        d = sd.compare(m, db_of(t={"id": ("integer", "YES"), "a": ("integer", "YES"), "b": ("integer", "YES")}))
        assert d.not_null_not_enforced == []

    def test_extra_database_columns_the_orm_does_not_know_are_fine(self):
        d = sd.compare(meta(t=[sa.Column("id", sa.Integer, primary_key=True)]), db_of(t={"id": ("integer", "NO"), "legacy": ("text", "YES")}))
        assert d.defects == 0


class TestRenderAndExit:
    def drift(self):
        return sd.Drift(orm_tables=3, missing_tables=["gone"], missing_columns=[("t", "c")], type_mismatches=[("t", "d", "String", "boolean")], not_null_not_enforced=[("t", "e")])

    def test_it_names_every_problem(self):
        text = sd.render(self.drift())
        assert "gone" in text and "t.c" in text and "t.d: ORM String, database boolean" in text and "t.e" in text and "3 defect(s)" in text

    def test_a_clean_report_says_so(self):
        assert "0 defect(s)" in sd.render(sd.Drift(orm_tables=2))

    @pytest.mark.parametrize("strict,defective,expected", [(False, True, 0), (True, True, 1), (True, False, 0), (False, False, 0)])
    def test_exit_codes(self, strict, defective, expected):
        d = self.drift() if defective else sd.Drift(orm_tables=1, not_null_not_enforced=[("t", "x")])
        assert sd.exit_code(d, strict=strict) == expected


class TestCommand:
    def run(self, monkeypatch, capsys, argv, drift):
        import app.scripts.run_migrations as rm

        asked = []

        class Conn:
            async def fetch(self, sql):
                assert sql.strip().upper().startswith("SELECT") and "information_schema" in sql
                return []

            async def close(self):
                pass

        async def connect(url=None):
            asked.append(url)
            return Conn()

        monkeypatch.setattr(rm, "_connect", connect)
        monkeypatch.setattr(sd, "compare", lambda metadata, db: drift)
        import asyncio

        code = asyncio.run(sd.main(argv))
        return code, capsys.readouterr().out, asked

    def test_it_uses_the_services_own_connection_never_the_migration_one(self, monkeypatch, capsys):
        from app.core.config import settings

        monkeypatch.setattr(settings, "MIGRATION_DATABASE_URL", "postgresql+asyncpg://owner:x@db/aisoc")
        _, _, asked = self.run(monkeypatch, capsys, [], sd.Drift())
        assert asked == [str(settings.DATABASE_URL)]

    def test_strict_fails_on_a_defect_and_a_plain_report_does_not(self, monkeypatch, capsys):
        bad = sd.Drift(orm_tables=1, missing_columns=[("t", "c")])
        assert self.run(monkeypatch, capsys, ["--strict"], bad)[0] == 1
        assert self.run(monkeypatch, capsys, [], bad)[0] == 0

    def test_json_output_carries_the_defect_count(self, monkeypatch, capsys):
        _, out, _ = self.run(monkeypatch, capsys, ["--json"], sd.Drift(orm_tables=1, missing_tables=["x"]))
        assert json.loads(out)["defects"] == 1 and json.loads(out)["missing_tables"] == ["x"]


# --- the static guard: no database needed -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

NOT_COLUMN = {"primary", "unique", "check", "foreign", "constraint", "exclude", "like"}


def migration_columns() -> dict[str, set[str]]:
    """{table: columns} after every migration: CREATE TABLE bodies, ALTER TABLE ... ADD COLUMN, then RENAME COLUMN and DROP COLUMN (comments removed). Within a file the order is create, add, rename, drop.
    RENAME matters: the connectors table's connector_config, auth_config, health_status and last_sync exist only because migration 025 renames older columns inside DO blocks."""
    cols: dict[str, set[str]] = {}
    for f in sorted(MIGRATIONS.glob("*.sql")):
        text = "\n".join(re.sub(r"--.*$", "", line) for line in f.read_text(encoding="utf-8", errors="replace").splitlines())
        for m in re.finditer(r"CREATE TABLE(?: IF NOT EXISTS)?\s+(?:public\.)?(\w+)\s*\((.*?)\n\)\s*;", text, re.S | re.I):
            for line in m.group(2).split("\n"):
                c = re.match(r"\s*\"?(\w+)\"?\s+\w", line)
                if c and c.group(1).lower() not in NOT_COLUMN:
                    cols.setdefault(m.group(1), set()).add(c.group(1))
        for m in re.finditer(r"ALTER TABLE(?: IF EXISTS)?(?: ONLY)?\s+(?:public\.)?(\w+)\s+(.*?);", text, re.S | re.I):
            for c in re.finditer(r"ADD COLUMN(?: IF NOT EXISTS)?\s+\"?(\w+)\"?", m.group(2), re.I):
                cols.setdefault(m.group(1), set()).add(c.group(1))
        for m in re.finditer(r"ALTER TABLE(?: IF EXISTS)?\s+(?:public\.)?(\w+)\s+RENAME COLUMN\s+\"?(\w+)\"?\s+TO\s+\"?(\w+)\"?", text, re.I):
            table_cols = cols.setdefault(m.group(1), set())
            table_cols.discard(m.group(2))
            table_cols.add(m.group(3))
        for m in re.finditer(r"ALTER TABLE(?: IF EXISTS)?\s+(?:public\.)?(\w+)\s+DROP COLUMN(?: IF EXISTS)?\s+\"?(\w+)\"?", text, re.I):
            cols.setdefault(m.group(1), set()).discard(m.group(2))
    return cols


class TestEveryOrmTableAndColumnIsCreatedByAMigration:
    def test_the_parser_understands_the_migrations(self):
        cols = migration_columns()
        assert len(cols) >= 90 and {"id", "tenant_id", "name"} <= cols["assets"] and "is_active" in cols["identity_nodes"]

    def test_the_parser_reads_a_synthetic_migration(self, tmp_path, monkeypatch):
        (tmp_path / "001.sql").write_text("CREATE TABLE IF NOT EXISTS widgets (\n  id UUID PRIMARY KEY,\n  name TEXT NOT NULL,\n  PRIMARY KEY (id),\n  UNIQUE (name),\n  CONSTRAINT c CHECK (name <> '')\n);\nALTER TABLE widgets ADD COLUMN IF NOT EXISTS colour TEXT, ADD COLUMN size INT;\n")
        monkeypatch.setattr(__import__("tests.test_schema_drift", fromlist=["x"]) if False else __import__("sys").modules[__name__], "MIGRATIONS", tmp_path)
        assert migration_columns() == {"widgets": {"id", "name", "colour", "size"}}

    def test_the_parser_applies_renames_and_drops(self, tmp_path, monkeypatch):
        (tmp_path / "001.sql").write_text("CREATE TABLE t (\n  id INT,\n  config JSONB,\n  old_col TEXT\n);\n")
        (tmp_path / "002.sql").write_text("DO $$ BEGIN\n  EXECUTE 'ALTER TABLE t RENAME COLUMN config TO connector_config';\nEND $$;\nALTER TABLE t DROP COLUMN IF EXISTS old_col;\n")
        monkeypatch.setattr(__import__("sys").modules[__name__], "MIGRATIONS", tmp_path)
        assert migration_columns() == {"t": {"id", "connector_config"}}

    def test_every_orm_table_and_column_exists_in_the_migrations(self):
        import app.models  # noqa: F401
        from app.db.database import Base

        cols = migration_columns()
        missing_tables = sorted(t for t in Base.metadata.tables if t not in cols)
        missing_cols = sorted(f"{t}.{c.name}" for t, tbl in Base.metadata.tables.items() if t in cols for c in tbl.columns if c.name not in cols[t])
        assert missing_tables == [] and missing_cols == [], f"the ORM expects what no migration creates: tables {missing_tables}, columns {missing_cols}"
