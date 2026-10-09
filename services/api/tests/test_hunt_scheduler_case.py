"""A scheduled hunt's case lands in aisoc_cases, where the cases API, GraphQL and the dashboards look.

`_open_case_for_hits` added a row to the old `cases` table, which nothing reads, so every case a scheduled hunt opened was invisible everywhere. Checked on real Postgres: after the fix a hunt's case is listed by REST and GraphQL for its own tenant and by no other, and a hunt with no hits opens nothing.
"""
import json
import re
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.workers import hunt_scheduler as hs

APP = Path(__file__).resolve().parent.parent / "app"


def hunt(**over):
    base = dict(id=uuid.uuid4(), tenant_id=uuid.uuid4(), name="lateral-movement sweep", nl_query="show me psexec from workstations")
    base.update(over)
    return SimpleNamespace(**base)


def fake_db():
    db = MagicMock()
    db.execute, db.add, db.commit = AsyncMock(), MagicMock(), AsyncMock()
    return db


async def opened(h=None, hits=3):
    db = fake_db()
    await hs._open_case_for_hits(db, h or hunt(), hits)
    return db


@pytest.mark.asyncio
class TestWhenACaseIsOpened:
    @pytest.mark.parametrize("hits", [0, -1])
    async def test_no_hits_opens_nothing(self, hits):
        db = await opened(hits=hits)
        db.execute.assert_not_awaited()
        db.add.assert_not_called()

    async def test_hits_open_exactly_one_case_with_one_insert(self):
        db = await opened()
        assert db.execute.await_count == 1

    async def test_it_does_not_commit_the_caller_does(self):
        db = await opened()
        db.commit.assert_not_awaited()


@pytest.mark.asyncio
class TestWhatIsWritten:
    async def row(self, h=None, hits=3):
        db = await opened(h, hits)
        stmt, params = db.execute.await_args.args
        return " ".join(str(stmt).split()), params

    async def test_it_inserts_into_aisoc_cases_not_the_legacy_table(self):
        sql, _ = await self.row()
        assert sql.startswith("INSERT INTO aisoc_cases") and not re.search(r"\bINTO cases\b", sql)

    async def test_the_case_belongs_to_the_hunts_tenant(self):
        h = hunt()
        _, params = await self.row(h)
        assert params["tenant_id"] == h.tenant_id

    async def test_it_is_a_new_medium_severity_case_created_by_the_system(self):
        sql, params = await self.row()
        assert "'medium', 'new'" in sql and "'system'" in sql

    async def test_title_description_and_number_identify_the_hunt(self):
        h = hunt(name="beacon hunt", nl_query="outbound to rare domains")
        _, p = await self.row(h, hits=7)
        assert p["title"] == "Scheduled hunt fired: beacon hunt"
        assert "'beacon hunt'" in p["description"] and "7 hit(s)" in p["description"] and "outbound to rare domains" in p["description"]
        assert re.fullmatch(rf"HUNT-{h.id.hex[:8].upper()}-\d{{10}}", p["case_number"])

    async def test_each_case_gets_its_own_id(self):
        ids = {(await self.row())[1]["id"] for _ in range(3)}
        assert len(ids) == 3 and all(isinstance(i, uuid.UUID) for i in ids)

    async def test_collections_are_empty_and_tags_are_an_object_carrying_the_hunt(self):
        h = hunt()
        _, p = await self.row(h)
        assert p["mitre"] == "[]" and p["alert_ids"] == [] and p["frameworks"] == []
        assert json.loads(p["tags"]) == {"source": "scheduled-hunt", "hunt_id": str(h.id), "case_type": "hunt_finding"}

    async def test_casts_are_written_as_CAST_not_the_glued_double_colon(self):
        sql, _ = await self.row()
        assert "CAST(:mitre AS JSONB)" in sql and "CAST(:alert_ids AS UUID[])" in sql and "CAST(:frameworks AS TEXT[])" in sql and "CAST(:tags AS JSONB)" in sql
        assert not re.search(r":\w+::", sql)

    async def test_every_named_parameter_is_supplied(self):
        sql, p = await self.row()
        assert set(re.findall(r"(?<![:\w]):(\w+)", sql)) == set(p)


class TestItStaysInStepWithTheRestInsert:
    def columns(self, sql: str) -> list[str]:
        m = re.search(r"INSERT INTO aisoc_cases \((.*?)\)\s*VALUES", sql, re.S)
        return [c.strip() for c in m.group(1).split(",")]

    def test_every_column_it_writes_is_one_the_rest_api_writes_or_is_the_case_number(self):
        rest = self.columns((APP / "api" / "v1" / "endpoints" / "cases.py").read_text(encoding="utf-8"))
        mine = self.columns((APP / "workers" / "hunt_scheduler.py").read_text(encoding="utf-8"))
        assert set(mine) - {"case_number"} <= set(rest), f"the scheduler writes columns REST does not: {set(mine) - set(rest)}"

    def test_case_number_is_a_real_column_of_aisoc_cases(self):
        sql = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in sorted((APP.parent / "migrations").glob("*.sql")))
        assert re.search(r"ALTER TABLE\s+aisoc_cases[^;]*case_number|CREATE TABLE[^;]*aisoc_cases[^;]*case_number", sql, re.S | re.I)


def test_the_legacy_case_model_is_no_longer_imported_or_used_by_the_scheduler():
    src = (APP / "workers" / "hunt_scheduler.py").read_text(encoding="utf-8")
    assert "app.models.case" not in src and not re.search(r"\bCase\(", src)
