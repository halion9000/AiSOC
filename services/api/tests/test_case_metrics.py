"""Dashboards, insights and the executive digest count cases from aisoc_cases, with its real statuses.

They counted the old `cases` table (the ORM `Case` model), which nothing writes, with the words 'open' and 'in_progress', which no case ever has. After cases were created through the cases API, /metrics/soc said cases_opened_7d 0 and cases_closed_7d 0 and the dashboard, insights tiles and
weekly digest showed no cases. Checked on real Postgres with nine cases of known status and deadline, every consumer then reported exactly the predicted numbers: dashboard open 3 / in progress 2 / resolved this week 4, SOC opened 9 / closed 4, insights 3.0 hours saved, digest opened 9 /
closed 4 / SLA breaches 2, tenant B all zeros. Running the real dashboard handler also caught a bug in the first version of this change (a module import named case_metrics collided with a local variable of the same name there, an UnboundLocalError neither pyflakes nor the old tests could see).
"""
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.api.v1.deps import CurrentUser
from app.services import case_metrics as cm

APP = Path(__file__).resolve().parent.parent / "app"
TID = uuid.uuid4()
NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def norm(stmt) -> str:
    return " ".join(str(stmt).split())


class RecordingDB:
    """Records every aisoc_cases statement as (sql, params); counts answer by recognising the SQL, everything else is zero or empty."""

    def __init__(self, answers=(), rows=()):
        self.answers, self.rows, self.case_sql = list(answers), list(rows), []

    def _note(self, stmt, params):
        sql = norm(stmt)
        if "aisoc_cases" in sql:
            self.case_sql.append((sql, params or {}))
        return sql

    async def scalar(self, stmt, params=None, *a, **k):
        sql = self._note(stmt, params)
        for needle, value in self.answers:
            if needle in sql:
                return value
        return 0

    async def execute(self, stmt, params=None, *a, **k):
        self._note(stmt, params)
        res = MagicMock()
        res.all.return_value = res.fetchall.return_value = list(self.rows)
        res.first.return_value = None
        res.scalar.return_value = res.scalar_one.return_value = 0
        res.scalars.return_value.all.return_value = []
        res.mappings.return_value.all.return_value = []
        res.mappings.return_value.first.return_value = None
        res.__iter__ = lambda self_: iter([])
        return res


@pytest.mark.asyncio
class TestTheHelpers:
    async def test_count_with_status_is_tenant_scoped_and_uses_the_given_statuses(self):
        db = RecordingDB([("status IN ('new')", 3)])
        assert await cm.count_with_status(db, TID, cm.OPEN) == 3
        sql, params = db.case_sql[0]
        assert "FROM aisoc_cases" in sql and "tenant_id = :tid" in sql and params == {"tid": TID} and not re.search(r"FROM cases\b", sql)

    async def test_in_progress_means_triaged_investigating_or_contained(self):
        db = RecordingDB()
        await cm.count_with_status(db, TID, cm.IN_PROGRESS)
        assert "status IN ('triaged', 'investigating', 'contained')" in db.case_sql[0][0]

    async def test_count_created_is_half_open_and_open_ended_without_an_end(self):
        db = RecordingDB()
        await cm.count_created(db, TID, NOW - timedelta(days=7), NOW)
        await cm.count_created(db, TID, NOW - timedelta(days=7))
        (sql1, p1), (sql2, p2) = db.case_sql
        assert "created_at >= :start" in sql1 and "created_at < :end" in sql1 and p1 == {"tid": TID, "start": NOW - timedelta(days=7), "end": NOW}
        assert "created_at < :end" not in sql2 and "end" not in p2

    async def test_count_created_can_be_limited_to_statuses(self):
        db = RecordingDB()
        await cm.count_created(db, TID, NOW, NOW, statuses=cm.FINISHED)
        assert "status IN ('resolved', 'closed')" in db.case_sql[0][0]
        db2 = RecordingDB()
        await cm.count_created(db2, TID, NOW, NOW)
        assert "status IN" not in db2.case_sql[0][0]

    async def test_finished_is_the_first_finish_time(self):
        db = RecordingDB()
        await cm.count_finished_since(db, TID, NOW)
        sql, params = db.case_sql[0]
        assert "COALESCE(resolved_at, closed_at) >= :since" in sql and params == {"tid": TID, "since": NOW}

    async def test_created_timestamps_returns_the_first_column(self):
        db = RecordingDB(rows=[(NOW,), (NOW - timedelta(hours=1),)])
        assert await cm.created_timestamps(db, TID, NOW - timedelta(days=1), NOW) == [NOW, NOW - timedelta(hours=1)]
        assert "SELECT created_at FROM aisoc_cases" in db.case_sql[0][0]

    async def test_open_before_excludes_finished_cases(self):
        db = RecordingDB()
        await cm.count_open_before(db, TID, NOW)
        sql, params = db.case_sql[0]
        assert "created_at < :at" in sql and "status NOT IN ('resolved', 'closed')" in sql and params == {"tid": TID, "at": NOW}

    async def test_digest_rows_carry_the_first_finish_time_and_a_derived_sla_flag(self):
        row = SimpleNamespace(status="new", created_at=NOW, closed_at=None, sla_breached=False)
        db = RecordingDB(rows=[row])
        assert await cm.digest_rows(db, TID, NOW) == [row]
        sql, params = db.case_sql[0]
        assert "COALESCE(resolved_at, closed_at) AS closed_at" in sql and "AS sla_breached" in sql and "created_at >= :since" in sql
        assert (params["tid"], params["since"]) == (TID, NOW) and isinstance(params["now"], datetime) and params["now"].tzinfo is not None and set(params) == {"tid", "since", "now"}

    async def test_a_null_count_is_zero(self):
        class NullDB(RecordingDB):
            async def scalar(self, *a, **k):
                return None

        assert await cm.count_with_status(NullDB(), TID, cm.OPEN) == 0 and await cm.count_created(NullDB(), TID, NOW) == 0 and await cm.count_finished_since(NullDB(), TID, NOW) == 0


class TestTheSlaRuleEvaluated:
    """The breach rule is SQL, so it is checked by running that exact expression (SQLite understands it) against a truth table rather than by inspecting strings."""

    DUE = "2026-10-08 12:00:00"
    EARLIER, LATER, NOW_ = "2026-10-07 12:00:00", "2026-10-09 06:00:00", "2026-10-09 12:00:00"

    def evaluate(self, due, resolved, closed, now=None):
        import sqlite3

        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE aisoc_cases (sla_due_at TEXT, resolved_at TEXT, closed_at TEXT)")
        con.execute("INSERT INTO aisoc_cases VALUES (?, ?, ?)", (due, resolved, closed))
        return bool(con.execute(f"SELECT {cm.SLA_BREACHED} FROM aisoc_cases", {"now": now or self.NOW_}).fetchone()[0])

    @pytest.mark.parametrize("due,resolved,closed,expected,why", [
        (None, None, None, False, "no deadline never breaches"),
        (None, "2026-10-09 06:00:00", None, False, "no deadline, even if finished"),
        ("2026-10-10 12:00:00", None, None, False, "open, deadline still ahead"),
        ("2026-10-08 12:00:00", None, None, True, "open and past its deadline"),
        ("2026-10-10 12:00:00", "2026-10-09 06:00:00", None, False, "resolved before the deadline"),
        ("2026-10-08 12:00:00", "2026-10-09 06:00:00", None, True, "resolved AFTER the deadline"),
        ("2026-10-08 12:00:00", "2026-10-07 12:00:00", None, False, "resolved before a deadline that has since passed"),
        ("2026-10-08 12:00:00", None, "2026-10-09 06:00:00", True, "closed (never resolved) after the deadline"),
        ("2026-10-08 12:00:00", None, "2026-10-07 12:00:00", False, "closed before the deadline"),
        ("2026-10-08 12:00:00", "2026-10-07 12:00:00", "2026-10-09 06:00:00", False, "judged at the FIRST finish (resolve), not the later close"),
        ("2026-10-08 12:00:00", "2026-10-09 06:00:00", "2026-10-07 12:00:00", True, "resolved late; an earlier closed_at would be odd data but resolve decides"),
        ("2026-10-08 12:00:00", "2026-10-08 12:00:00", None, False, "resolved exactly at the deadline is not a breach"),
    ])
    def test_truth_table(self, due, resolved, closed, expected, why):
        assert self.evaluate(due, resolved, closed) is expected, why

    def test_an_open_case_flips_to_breached_as_time_passes(self):
        assert self.evaluate("2026-10-09 18:00:00", None, None, now="2026-10-09 12:00:00") is False
        assert self.evaluate("2026-10-09 18:00:00", None, None, now="2026-10-09 18:00:01") is True
        assert self.evaluate("2026-10-09 18:00:00", None, None, now="2026-10-09 18:00:00") is False  # exactly at the deadline is not yet a breach

    def test_the_expression_names_no_function_the_database_could_disagree_about(self):
        assert "NOW()" not in cm.SLA_BREACHED and ":now" in cm.SLA_BREACHED


class TestTheVocabulary:
    def migrated_statuses(self) -> set[str]:
        sql = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in sorted((APP.parent / "migrations").glob("*.sql")))
        m = re.search(r"aisoc_cases[^;]*?status\s+TEXT[^;]*?CHECK\s*\(\s*status\s+IN\s*\(([^)]*)\)", sql, re.S | re.I)
        assert m, "could not find the status CHECK on aisoc_cases"
        return set(re.findall(r"'([a-z_]+)'", m.group(1)))

    def test_the_groups_do_not_overlap(self):
        assert not (set(cm.OPEN) & set(cm.IN_PROGRESS)) and not (set(cm.OPEN) & set(cm.FINISHED)) and not (set(cm.IN_PROGRESS) & set(cm.FINISHED))

    def test_together_they_are_exactly_the_statuses_the_table_allows(self):
        assert set(cm.OPEN) | set(cm.IN_PROGRESS) | set(cm.FINISHED) == self.migrated_statuses()

    def test_the_legacy_words_are_gone(self):
        src = (APP / "services" / "case_metrics.py").read_text(encoding="utf-8")
        assert "'open'" not in src.split('"""', 2)[2] and "in_progress" not in src.split('"""', 2)[2].replace("IN_PROGRESS", "")


def user():
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TID, role="admin", email="a@example.test")


@pytest.mark.asyncio
class TestTheRealHandlersAreWiredToIt:
    """Runs the actual endpoint functions (the old suite never called get_dashboard_metrics, which is how a name collision in it went unseen)."""

    ANSWERS = [("status IN ('new')", 3), ("status IN ('triaged', 'investigating', 'contained')", 2), ("COALESCE(resolved_at, closed_at) >= :since", 4), ("created_at >= :start", 9)]

    async def test_the_dashboard_reports_open_in_progress_and_resolved_this_week(self):
        from app.api.v1.endpoints import metrics

        out = await metrics.get_dashboard_metrics(user=user(), db=RecordingDB(self.ANSWERS))
        assert (out.cases.open, out.cases.inProgress, out.cases.resolvedThisWeek) == (3, 2, 4)

    async def test_the_dashboard_queries_are_for_the_callers_tenant(self):
        from app.api.v1.endpoints import metrics

        db = RecordingDB(self.ANSWERS)
        await metrics.get_dashboard_metrics(user=user(), db=db)
        assert db.case_sql and all(params.get("tid") == TID for _, params in db.case_sql)

    async def test_the_soc_metrics_report_cases_opened_and_closed(self):
        from app.api.v1.endpoints import metrics

        out = await metrics.get_soc_metrics(user=user(), db=RecordingDB(self.ANSWERS))
        assert (out.kpis.cases_opened_7d, out.kpis.cases_closed_7d) == (9, 4)

    async def test_insights_use_aisoc_cases_for_the_count_and_the_hours_saved(self):
        from app.api.v1.endpoints.insights import get_soc_insights

        db = RecordingDB([("status IN ('resolved', 'closed')", 4), ("created_at >= :start", 9)])
        out = await get_soc_insights(user=user(), db=db, window="24h")
        assert {t.key: t.value for t in out.tiles}["analyst_hours_saved"] == round(4 * 45 / 60.0, 2)
        assert any("status IN ('resolved', 'closed')" in sql for sql, _ in db.case_sql) and all(params.get("tid") == TID for _, params in db.case_sql)

    async def test_the_digest_builds_its_case_section_from_aisoc_cases(self):
        from app.services import executive_digest as ed

        past = NOW - timedelta(days=1)
        rows = [SimpleNamespace(status="new", created_at=past, closed_at=None, sla_breached=True), SimpleNamespace(status="resolved", created_at=past, closed_at=past, sla_breached=False)]
        got = await ed._fetch_cases(RecordingDB(rows=rows), TID, NOW - timedelta(days=7), NOW)
        assert [(r.status, r.closed_at is not None, r.sla_breached) for r in got] == [("new", False, True), ("resolved", True, False)]

    async def test_the_digest_open_count_uses_the_shared_definition(self):
        from app.services import executive_digest as ed

        db = RecordingDB([("created_at < :at", 6)])
        assert await ed._count_open_cases(db, TID, NOW) == 6 and "status NOT IN ('resolved', 'closed')" in db.case_sql[0][0]


@pytest.mark.parametrize("path", ["api/v1/endpoints/metrics.py", "api/v1/endpoints/insights.py", "services/executive_digest.py", "workers/hunt_scheduler.py", "api/v1/endpoints/attack_chain.py"])
def test_no_consumer_imports_the_legacy_case_model_any_more(path):
    src = (APP / path).read_text(encoding="utf-8")
    assert "app.models.case" not in src and not re.search(r"\bselect\(Case\b|Case\.tenant_id|Case\.status", src)
