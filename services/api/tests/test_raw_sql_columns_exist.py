"""Raw INSERT statements name only columns that exist; a failing proposal cannot cost a scheduled hunt its case.

Three writers INSERTed a `source` into detection_rule_proposals and no migration ever created the column: the detection-loop suggestion swallowed the error behind a savepoint (the draft came back but no proposal was ever created), POST /rule-tuning/auto-suggest answered HTTP 500 whenever it
had suggestions, and the hunt scheduler's failure, with no savepoint, aborted the whole transaction. Shown on real Postgres: after the scheduler's default callback the transaction was POISONED and the commit left 0 cases and 0 proposals, so a scheduled hunt could never keep a case.
With migration 064 and a savepoint the same run leaves 1 case and 1 proposal (source=hunt-finding), and a deliberately invalid query inside the proposal step leaves the transaction healthy and the case committed.
"""
import ast
import re
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from test_schema_drift import migration_columns  # tests/ is on sys.path (pytest's default import mode); the parser is already tested there

APP = Path(__file__).resolve().parent.parent / "app"
MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"
INSERT = re.compile(r"INSERT\s+INTO\s+(?:public\.)?([a-z_][a-z0-9_]*)\s*\(([^)]*)\)", re.I | re.S)
# created by the migration runner itself, not by a migration file
RUNNER_TABLES = {"aisoc_schema_migrations"}


def raw_inserts(source: str) -> list[tuple[str, list[str], int]]:
    """(table, columns, line) for every INSERT INTO t (cols) in the file's string literals, docstrings excluded."""
    tree = ast.parse(source)
    docs = {id(n.body[0].value) for n in ast.walk(tree) if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant)}
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs:
            for m in INSERT.finditer(n.value):
                out.append((m.group(1).lower(), [c.strip().strip('"').split()[0].lower() for c in m.group(2).split(",") if c.strip()], n.lineno))
    return out


class TestTheDetector:
    def test_it_finds_the_table_and_columns(self):
        src = 'q = """\n    INSERT INTO widgets\n      (id, "window", name)\n    VALUES (:a, :b, :c)\n"""\n'
        assert raw_inserts(src) == [("widgets", ["id", "window", "name"], 1)]

    def test_it_ignores_docstrings(self):
        assert raw_inserts('def f():\n    """INSERT INTO ghosts (a, b) VALUES"""\n    return 1\n') == []

    def test_it_finds_several_in_one_file(self):
        assert [t for t, _, _ in raw_inserts('a = "INSERT INTO one (x) VALUES (1)"\nb = "INSERT INTO two (y, z) VALUES (1, 2)"\n')] == ["one", "two"]

    def test_it_reports_a_column_the_table_lacks(self):
        cols = {"proposals": {"id", "name"}}
        (table, names, _), = raw_inserts('x = "INSERT INTO proposals (id, name, source) VALUES (1, 2, 3)"')
        assert [c for c in names if c not in cols[table]] == ["source"]


class TestEveryRawInsertNamesRealColumns:
    def scan(self):
        columns = migration_columns()
        checked, bad, skipped = 0, [], set()
        for f in sorted(APP.rglob("*.py")):
            for table, names, line in raw_inserts(f.read_text(encoding="utf-8", errors="replace")):
                if table not in columns:
                    skipped.add(table)
                    continue
                checked += 1
                missing = [c for c in names if c not in columns[table]]
                if missing:
                    bad.append(f"{f.relative_to(APP)}:{line} INSERT INTO {table}: no such column {missing}")
        return checked, bad, skipped

    def test_no_insert_names_a_column_no_migration_creates(self):
        checked, bad, _ = self.scan()
        assert checked >= 20, f"the scan only reached {checked} INSERT statements: it has gone blind"
        assert bad == [], "an INSERT that names a missing column fails on every call (and, unguarded, aborts the whole transaction):\n" + "\n".join(bad)

    def test_the_only_tables_skipped_are_the_runners_own(self):
        _, _, skipped = self.scan()
        assert skipped <= RUNNER_TABLES, f"INSERTs into tables no migration creates: {skipped - RUNNER_TABLES}"


# ---- reads and updates --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Only forms that can be judged reliably: a single table (no JOIN / UNION / WITH), a plain column list (no function, cast, expression or `*`), and UPDATE ... SET col = ... . Anything else is not judged, never guessed at.
IDENT = r"[a-z_][a-z0-9_]*"
SELECT = re.compile(rf"\bSELECT\s+(?!DISTINCT\b)(?P<list>[^;()]*?)\s+FROM\s+(?:public\.)?(?P<t>{IDENT})(?:\s+(?:AS\s+)?(?P<alias>{IDENT}))?\s*(?=WHERE|ORDER|LIMIT|GROUP|$|\)|\n|;|FOR\s)", re.I | re.S)
UPDATE = re.compile(rf"\bUPDATE\s+(?:public\.)?(?P<t>{IDENT})\s+SET\s+(?P<set>.*?)(?:\s+WHERE\b|\s+RETURNING\b|$)", re.I | re.S)
NOT_COLUMNS = {"select", "from", "where", "null", "true", "false", "case", "when", "then", "else", "end", "and", "or", "not", "distinct", "as", "count", "now", "coalesce"}


def select_columns(select_list: str) -> list[str] | None:
    names = []
    for part in select_list.split(","):
        part = " ".join(part.split())
        m = re.fullmatch(rf"(?:{IDENT}\.)?({IDENT})(?:\s+AS\s+{IDENT})?", part, re.I)
        if part == "*" or not m:
            return None
        names.append(m.group(1).lower())
    return names


def raw_reads_and_updates(source: str) -> list[tuple[str, str, list[str], int]]:
    """(kind, table, columns, line) for every judgeable single-table SELECT list and UPDATE ... SET in the file's string literals."""
    tree = ast.parse(source)
    docs = {id(n.body[0].value) for n in ast.walk(tree) if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant)}
    out = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs and len(n.value) < 3000) or re.search(r"\bJOIN\b|\bUNION\b|\bWITH\b", n.value, re.I):
            continue
        for m in SELECT.finditer(n.value):
            names = select_columns(m.group("list"))
            if names is not None:
                out.append(("SELECT", m.group("t").lower(), [c for c in names if c not in NOT_COLUMNS], n.lineno))
        for m in UPDATE.finditer(n.value):
            assigns = re.findall(rf"(?:^|,)\s*({IDENT})\s*=", re.sub(r"\([^()]*\)", "()", m.group("set")), re.I)
            out.append(("UPDATE", m.group("t").lower(), [c.lower() for c in assigns], n.lineno))
    return out


class TestTheReadAndUpdateDetector:
    def judge(self, sql):
        (kind, table, names, _), = raw_reads_and_updates(f'x = "{sql}"')
        cols = {"alerts": {"id", "title", "severity", "created_at", "tenant_id", "rule_id", "status", "updated_at"}}
        return kind, [c for c in names if c not in cols[table]]

    def test_the_old_detection_loop_query_is_flagged(self):
        assert self.judge("SELECT rule_id, evidence, tenant_id FROM alerts WHERE id = :a") == ("SELECT", ["evidence"])

    def test_a_correct_query_and_aliased_columns_are_clean(self):
        assert self.judge("SELECT id, title, severity, created_at FROM alerts WHERE id = :i") == ("SELECT", [])
        assert self.judge("SELECT a.id, a.title AS t FROM alerts a WHERE a.id = :i") == ("SELECT", [])

    def test_an_update_naming_a_missing_column_is_flagged(self):
        assert self.judge("UPDATE alerts SET status = :s, bogus_col = :b, updated_at = NOW() WHERE id = :i") == ("UPDATE", ["bogus_col"])
        assert self.judge("UPDATE alerts SET status = :s, updated_at = NOW() WHERE id = :i") == ("UPDATE", [])

    @pytest.mark.parametrize("sql", ["SELECT count(*) FROM alerts", "SELECT * FROM alerts", "SELECT lower(title) FROM alerts", "SELECT a.id FROM alerts a JOIN x ON x.id = a.id", "WITH q AS (SELECT 1) SELECT id FROM alerts"])
    def test_shapes_it_cannot_judge_are_skipped_not_guessed(self, sql):
        assert [r for r in raw_reads_and_updates(f'x = "{sql}"') if r[0] == "SELECT"] == []


class TestEveryJudgeableReadAndUpdateNamesRealColumns:
    def scan(self):
        columns = migration_columns()
        judged = {"SELECT": 0, "UPDATE": 0}
        bad = []
        for f in sorted(APP.rglob("*.py")):
            if "scripts" in f.parts or "seed" in f.name:
                continue
            for kind, table, names, line in raw_reads_and_updates(f.read_text(encoding="utf-8", errors="replace")):
                if table not in columns:
                    continue
                judged[kind] += 1
                missing = [c for c in names if c not in columns[table]]
                if missing:
                    bad.append(f"{f.relative_to(APP)}:{line} {kind} {table}: no such column {missing}")
        return judged, bad

    def test_no_judgeable_select_or_update_names_a_missing_column(self):
        judged, bad = self.scan()
        assert judged["SELECT"] >= 25 and judged["UPDATE"] >= 10, f"the scan has gone blind: {judged}"
        assert bad == [], "a SELECT or UPDATE naming a missing column fails on every call:\n" + "\n".join(bad)


class TestMigration064:
    sql = (MIGRATIONS / "064_detection_proposal_source.sql").read_text(encoding="utf-8")

    def test_it_adds_a_nullable_source_column_idempotently_in_a_transaction(self):
        assert re.search(r"ALTER TABLE detection_rule_proposals ADD COLUMN IF NOT EXISTS source VARCHAR\(50\);", self.sql)
        assert "NOT NULL" not in self.sql.split("ADD COLUMN", 1)[1].split(";", 1)[0] and "DEFAULT" not in self.sql.split("ADD COLUMN", 1)[1].split(";", 1)[0]
        assert self.sql.count("BEGIN;") == 1 and self.sql.count("COMMIT;") == 1

    def test_the_parser_sees_it(self):
        assert "source" in migration_columns()["detection_rule_proposals"]

    def test_the_orm_model_has_the_column(self):
        from sqlalchemy import String

        from app.models.detection_proposal import DetectionRuleProposal

        col = DetectionRuleProposal.__table__.c.source
        assert col.nullable and isinstance(col.type, String) and col.type.length == 50

    def test_it_follows_the_latest_earlier_migration(self):
        names = sorted(p.name for p in MIGRATIONS.glob("*.sql"))
        assert names.index("064_detection_proposal_source.sql") == names.index("063_rls_for_uncovered_tenant_tables.sql") + 1

    @pytest.mark.parametrize("path,source", [("api/v1/endpoints/detection_loop.py", "detection-loop"), ("api/v1/endpoints/rule_tuning.py", "auto-tuner"), ("workers/hunt_scheduler.py", "hunt-finding")])
    def test_each_writer_records_its_own_source(self, path, source):
        assert f"'{source}'" in (APP / path).read_text(encoding="utf-8")


class Savepoint:
    """What AsyncSession.begin_nested() returns; records how it was left."""

    def __init__(self):
        self.entered, self.left_with = False, "not left"

    async def __aenter__(self):
        self.entered = True
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.left_with = exc_type.__name__ if exc_type else None
        return False  # never swallow: the caller decides


@pytest.mark.asyncio
class TestAFailedProposalCannotCostTheCase:
    def setup(self, monkeypatch, proposal):
        from app.workers import hunt_scheduler as hs

        sp = Savepoint()
        db = MagicMock()
        db.execute, db.commit = AsyncMock(), AsyncMock()
        db.begin_nested = MagicMock(return_value=sp)
        monkeypatch.setattr(hs, "_propose_detection_from_hunt", proposal)
        hunt = SimpleNamespace(id=uuid.uuid4(), tenant_id=uuid.uuid4(), name="h", nl_query="q")
        return hs, db, sp, hunt

    async def test_the_case_is_opened_and_the_failure_does_not_propagate(self, monkeypatch):
        async def failing(db, hunt, hits):
            raise RuntimeError("proposal insert failed")

        hs, db, sp, hunt = self.setup(monkeypatch, failing)
        await hs._on_hunt_hits(db, hunt, 3)  # must not raise
        assert any("INSERT INTO aisoc_cases" in " ".join(str(c.args[0]).split()) for c in db.execute.await_args_list)

    async def test_the_proposal_runs_inside_a_savepoint_that_is_rolled_back_by_the_failure(self, monkeypatch):
        async def failing(db, hunt, hits):
            raise RuntimeError("boom")

        hs, db, sp, hunt = self.setup(monkeypatch, failing)
        await hs._on_hunt_hits(db, hunt, 1)
        assert sp.entered and sp.left_with == "RuntimeError"

    async def test_a_successful_proposal_releases_the_savepoint_cleanly(self, monkeypatch):
        called = []

        async def fine(db, hunt, hits):
            called.append(hits)

        hs, db, sp, hunt = self.setup(monkeypatch, fine)
        await hs._on_hunt_hits(db, hunt, 4)
        assert called == [4] and sp.entered and sp.left_with is None

    async def test_the_failure_is_logged_not_silent(self, monkeypatch, caplog):
        async def failing(db, hunt, hits):
            raise RuntimeError("boom")

        hs, db, sp, hunt = self.setup(monkeypatch, failing)
        with caplog.at_level("WARNING", logger="app.workers.hunt_scheduler"):
            await hs._on_hunt_hits(db, hunt, 1)
        assert any("detection_proposal_failed" in r.getMessage() and str(hunt.id) in r.getMessage() for r in caplog.records)

    async def test_the_helper_does_not_commit_the_caller_does(self, monkeypatch):
        async def fine(db, hunt, hits):
            return None

        hs, db, sp, hunt = self.setup(monkeypatch, fine)
        await hs._on_hunt_hits(db, hunt, 1)
        db.commit.assert_not_awaited()

    def test_it_no_longer_relies_on_a_bare_suppress(self):
        """Judged on the function's code (its comment explains the old behaviour and names suppress)."""
        tree = ast.parse((APP / "workers" / "hunt_scheduler.py").read_text(encoding="utf-8"))
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "_on_hunt_hits")
        calls = {ast.unparse(n.func) for n in ast.walk(fn) if isinstance(n, ast.Call)}
        assert "contextlib.suppress" not in calls and "db.begin_nested" in calls
