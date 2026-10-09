"""GraphQL reads cases from aisoc_cases, the table the cases REST API writes.

The resolvers used to read the old `cases` table, which never receives a case: after a case was created through REST (201, and REST listed it), GraphQL answered `cases.total = 0`, `case(id) = null` and `socStats.openCases = 0`
(shown on real Postgres, and fixed there: total 1, the case found, openCases 1; the status and severity filters, a literal `%` search, tenant isolation and invalid ids were all checked against a real database too).
aisoc_cases has no priority, case_type, tactics, ticket refs, summary or resolution and its assignee is free text, so the GraphQL schema is unchanged and the mapping invents nothing.
"""
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.graphql import query as q

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)


def row(**over):
    base = dict(id=uuid.uuid4(), tenant_id=uuid.uuid4(), case_number=None, title="t", description=None, severity="high", status="new", assignee=None, mitre_techniques=[], alert_ids=[], tags={},
                sla_due_at=None, resolved_at=None, created_at=NOW, updated_at=NOW)
    base.update(over)
    return SimpleNamespace(**base)


class TestFieldMapping:
    def test_severity_doubles_as_priority(self):
        c = q._aisoc_case_to_type(row(severity="critical"), NOW)
        assert (c.priority, c.severity) == ("critical", "critical")

    def test_case_number_is_the_stored_one_or_else_the_real_id(self):
        r = row(case_number="CASE-42")
        assert q._aisoc_case_to_type(r, NOW).case_number == "CASE-42"
        r2 = row()
        assert q._aisoc_case_to_type(r2, NOW).case_number == str(r2.id)

    def test_the_assignee_is_a_uuid_only_if_it_parses_as_one(self):
        u = uuid.uuid4()
        assert q._aisoc_case_to_type(row(assignee=str(u)), NOW).assigned_to_id == u
        assert q._aisoc_case_to_type(row(assignee="dana@example.com"), NOW).assigned_to_id is None
        assert q._aisoc_case_to_type(row(assignee=None), NOW).assigned_to_id is None
        assert q._aisoc_case_to_type(row(assignee=""), NOW).assigned_to_id is None

    def test_fields_with_no_source_are_empty_not_invented(self):
        c = q._aisoc_case_to_type(row(), NOW)
        assert (c.case_type, c.mitre_tactics, c.ticket_refs, c.summary, c.resolution) == ("unspecified", [], [], None, None)

    def test_alert_ids_are_strings_and_mitre_techniques_are_ids(self):
        a = uuid.uuid4()
        c = q._aisoc_case_to_type(row(alert_ids=[a], mitre_techniques=["T1041", {"id": "T1566", "name": "Phishing"}, {"name": "no id"}, 7]), NOW)
        assert c.alert_ids == [str(a)] and c.mitre_techniques == ["T1041", "T1566"]

    def test_null_collections_become_empty(self):
        c = q._aisoc_case_to_type(row(alert_ids=None, mitre_techniques=None, tags=None), NOW)
        assert (c.alert_ids, c.mitre_techniques, c.tags) == ([], [], {})

    def test_tags_pass_through_only_as_an_object(self):
        assert q._aisoc_case_to_type(row(tags={"k": "v"}), NOW).tags == {"k": "v"}
        assert q._aisoc_case_to_type(row(tags=["x"]), NOW).tags == {}

    def test_the_deadline_comes_from_sla_due_at(self):
        due = NOW + HOUR
        assert q._aisoc_case_to_type(row(sla_due_at=due), NOW).sla_deadline == due


class TestSlaBreached:
    @pytest.mark.parametrize("due,resolved,status,expected", [
        (None, None, "new", False),  # no deadline is never a breach
        (NOW + HOUR, None, "new", False),  # not due yet
        (NOW - HOUR, None, "new", True),  # open and overdue
        (NOW - HOUR, None, "investigating", True),
        (NOW - HOUR, None, "resolved", False),  # finished (no resolved_at recorded): not counted as overdue
        (NOW - HOUR, None, "closed", False),
        (NOW - HOUR, NOW - 2 * HOUR, "resolved", False),  # resolved before the deadline
        (NOW - 2 * HOUR, NOW - HOUR, "resolved", True),  # resolved after the deadline
    ])
    def test_table(self, due, resolved, status, expected):
        assert q._sla_breached(due, resolved, status, NOW) is expected


def fake_db(*, rows=None, count=0, first=None):
    """Records (sql, params); answers count(*) with scalar_one, the by-id lookup with first(), anything else with fetchall()."""
    db = MagicMock()
    db.executed = []

    async def execute(clause, params=None):
        sql = " ".join(str(clause).split())
        db.executed.append((sql, params or {}))
        res = MagicMock()
        res.scalar_one.return_value = count
        res.first.return_value = first
        res.fetchall.return_value = rows or []
        return res

    db.execute = AsyncMock(side_effect=execute)
    return db


@pytest.mark.asyncio
class TestFetchCase:
    async def test_an_invalid_id_is_none_and_nothing_is_queried(self):
        db = fake_db()
        assert await q._fetch_case(db, uuid.uuid4(), "not-a-uuid") is None
        assert db.executed == []

    async def test_a_missing_case_is_none(self):
        assert await q._fetch_case(fake_db(first=None), uuid.uuid4(), str(uuid.uuid4())) is None

    async def test_a_found_case_is_mapped(self):
        r = row(title="found")
        c = await q._fetch_case(fake_db(first=r), r.tenant_id, str(r.id))
        assert c.title == "found" and c.id == r.id

    async def test_the_lookup_is_scoped_to_the_callers_tenant_by_bound_parameter(self):
        tid, cid = uuid.uuid4(), uuid.uuid4()
        db = fake_db()
        await q._fetch_case(db, tid, str(cid))
        sql, params = db.executed[0]
        assert "FROM aisoc_cases" in sql and "id = :id AND tenant_id = :tid" in sql and params == {"id": cid, "tid": tid}


@pytest.mark.asyncio
class TestListCases:
    async def listing(self, **kw):
        db = fake_db(rows=[row(title="a"), row(title="b")], count=2)
        args = dict(page=1, page_size=25, status=None, priority=None, search=None)
        args.update(kw)
        items, total, page, size = await q._list_cases(db, kw.pop("tid", uuid.uuid4()), **args)
        return db, items, total, page, size

    async def test_it_reads_aisoc_cases_scoped_to_the_tenant(self):
        tid = uuid.uuid4()
        db = fake_db(count=0)
        await q._list_cases(db, tid, page=1, page_size=25, status=None, priority=None, search=None)
        for sql, params in db.executed:
            assert "FROM aisoc_cases" in sql and "tenant_id = :tid" in sql and params["tid"] == tid and not re.search(r"FROM cases\b", sql)

    async def test_items_total_page_and_size(self):
        _, items, total, page, size = await self.listing()
        assert [i.title for i in items] == ["a", "b"] and (total, page, size) == (2, 1, 25)

    async def test_status_filters_status(self):
        db, *_ = await self.listing(status="closed")
        assert "AND status = :status" in db.executed[0][0] and db.executed[0][1]["status"] == "closed"

    async def test_priority_filters_severity(self):
        db, *_ = await self.listing(priority="critical")
        assert "AND severity = :priority" in db.executed[0][0] and db.executed[0][1]["priority"] == "critical" and "priority = :priority AND" not in db.executed[0][0]

    async def test_search_is_a_bound_escaped_pattern(self):
        db, *_ = await self.listing(search="50%_off\\")
        sql, params = db.executed[0]
        assert "title ILIKE :search ESCAPE" in sql and params["search"] == "%50\\%\\_off\\\\%"

    async def test_user_text_never_reaches_the_sql_string(self):
        evil = "x'; DROP TABLE aisoc_cases; --"
        db, *_ = await self.listing(search=evil, status=evil, priority=evil)
        assert all(evil not in sql and "DROP" not in sql for sql, _ in db.executed)

    @pytest.mark.parametrize("page,size,exp_page,exp_size,offset", [(1, 25, 1, 25, 0), (3, 10, 3, 10, 20), (-5, 10, 1, 10, 0), (0, 10, 1, 10, 0), (1, 99999, 1, 200, 0), (1, 0, 1, 1, 0), (1, -3, 1, 1, 0), (2, 200, 2, 200, 200)])
    async def test_paging_is_clamped(self, page, size, exp_page, exp_size, offset):
        db, _, _, got_page, got_size = await self.listing(page=page, page_size=size)
        assert (got_page, got_size) == (exp_page, exp_size)
        assert db.executed[1][1]["limit"] == exp_size and db.executed[1][1]["offset"] == offset

    async def test_newest_first(self):
        db, *_ = await self.listing()
        assert "ORDER BY created_at DESC" in db.executed[1][0]


@pytest.mark.asyncio
async def test_open_cases_means_not_resolved_or_closed_for_this_tenant():
    tid, db = uuid.uuid4(), fake_db(count=7)
    assert await q._count_open_cases(db, tid) == 7
    sql, params = db.executed[0]
    assert "FROM aisoc_cases" in sql and "status NOT IN ('resolved', 'closed')" in sql and "tenant_id = :tid" in sql and params == {"tid": tid}
    assert "'open'" not in sql and "in_progress" not in sql, "the legacy vocabulary no case ever has"


def schema():
    import os

    os.environ.setdefault("ENVIRONMENT", "development")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes!!")
    from app.graphql.schema import schema as s

    return s


@pytest.mark.asyncio
class TestThroughTheSchema:
    """Real GraphQL execution with a fake database: the resolvers wire to the helpers, and an anonymous caller gets nothing and touches no table."""

    async def run(self, query, db, user):
        return await schema().execute(query, context_value={"db": db, "user": user})

    async def test_cases_resolves_from_the_database_rows(self):
        tid = uuid.uuid4()
        db = fake_db(rows=[row(title="one", severity="critical", tenant_id=tid)], count=1)
        r = await self.run("{ cases { total pages page pageSize items { title priority severity caseNumber caseType } } }", db, SimpleNamespace(tenant_id=tid))
        assert r.errors is None
        cases = r.data["cases"]
        assert cases["total"] == 1 and cases["pages"] == 1 and cases["items"][0]["title"] == "one" and cases["items"][0]["priority"] == "critical" and cases["items"][0]["caseType"] == "unspecified"

    async def test_an_anonymous_caller_gets_an_empty_page_and_no_query_runs(self):
        db = fake_db(rows=[row()], count=9)
        r = await self.run("{ cases { total items { title } } }", db, None)
        assert r.errors is None and r.data["cases"] == {"total": 0, "items": []} and db.executed == []

    async def test_case_by_id_resolves_and_scopes(self):
        tid, rw = uuid.uuid4(), row(title="by-id")
        db = fake_db(first=rw)
        r = await self.run('{ case(id: "%s") { title } }' % rw.id, db, SimpleNamespace(tenant_id=tid))
        assert r.errors is None and r.data["case"] == {"title": "by-id"} and db.executed[0][1] == {"id": rw.id, "tid": tid}

    async def test_case_by_id_is_null_for_an_anonymous_caller_and_for_an_invalid_id(self):
        db = fake_db(first=row())
        assert (await self.run('{ case(id: "%s") { title } }' % uuid.uuid4(), db, None)).data["case"] is None
        assert (await self.run('{ case(id: "nope") { title } }', db, SimpleNamespace(tenant_id=uuid.uuid4()))).data["case"] is None
        assert db.executed == []

    async def test_stats_count_open_cases_from_aisoc_cases(self):
        tid = uuid.uuid4()
        db = fake_db(count=4)
        r = await self.run("{ socStats { openCases } }", db, SimpleNamespace(tenant_id=tid))
        assert r.errors is None and r.data["socStats"]["openCases"] == 4
        assert any("FROM aisoc_cases" in sql and "NOT IN ('resolved', 'closed')" in sql for sql, _ in db.executed)


def test_the_legacy_case_model_is_gone_from_the_graphql_query_module():
    src = (Path(__file__).resolve().parent.parent / "app" / "graphql" / "query.py").read_text(encoding="utf-8")
    assert "app.models.case" not in src and not re.search(r"\bselect\(Case\)", src) and "Case.tenant_id" not in src
    assert src.count("aisoc_cases") >= 4
