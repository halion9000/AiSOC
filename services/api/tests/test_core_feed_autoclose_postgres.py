"""Cases AiSOC opened itself close once every alert in them is closed, against a REAL Postgres (opt in with AISOC_TEST_PG_URL, a DISPOSABLE, fully migrated database)."""

import os
import uuid
from datetime import UTC, datetime

import pytest
from app.db.rls import set_rls_context
from app.services import core_feed_cases as cfc
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database")

NOW = datetime(2026, 10, 21, 20, 0, tzinfo=UTC)


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:10]
    ids = {k: uuid.uuid4() for k in ("parent", "child")}
    cases: dict[str, uuid.UUID] = {}
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for key, tid in ids.items():
            await c.execute(
                text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                {"i": tid, "n": f"ac-{key}-{tag}", "s": f"ac-{key}-{tag}", "p": None if key == "parent" else ids["parent"], "r": "parent" if key == "parent" else "child"},
            )

        async def alert(tenant: str, status: str) -> uuid.UUID:
            aid = uuid.uuid4()
            await c.execute(
                text("insert into alerts (id, tenant_id, title, severity, status) values (:i, :t, 'x', 'high', :s)"),
                {"i": aid, "t": ids[tenant], "s": status},
            )
            return aid

        async def case(name: str, tenant: str, alerts: list[uuid.UUID], *, status: str = "new", created_by: str | None = "system", assignee: str | None = None) -> None:
            cid = uuid.uuid4()
            cases[name] = cid
            await c.execute(
                text(
                    "insert into aisoc_cases (id, tenant_id, title, severity, status, alert_ids, created_by, assignee, case_number) "
                    "values (:i, :t, :n, 'high', :s, CAST(:a AS UUID[]), :cb, :as, :num)"
                ),
                {"i": cid, "t": ids[tenant], "n": name, "s": status, "a": [str(x) for x in alerts], "cb": created_by, "as": assignee, "num": f"AC-{tag}-{name}"},
            )

        await case("all_done", "parent", [await alert("parent", "resolved")])
        await case("mixed", "parent", [await alert("parent", "resolved"), await alert("parent", "new")])
        await case("assigned", "parent", [await alert("parent", "resolved")], assignee="ann@x.com")
        await case("by_hand", "parent", [await alert("parent", "resolved")], created_by="ann@x.com")
        await case("no_alerts", "parent", [])
        await case("already_closed", "parent", [await alert("parent", "resolved")], status="closed")
        await case("child_done", "child", [await alert("child", "closed")])
        await case("fp_and_closed", "child", [await alert("child", "false_positive"), await alert("child", "closed")], status="investigating")
    yield {"ids": ids, "cases": cases}
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(text("delete from aisoc_cases where id = any(cast(:c as uuid[]))"), {"c": [str(x) for x in cases.values()]})
        await c.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
    await engine.dispose()


async def run(parent, work):
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            await set_rls_context(db, parent)
            out = await work(db)
            await db.commit()
            return out
    finally:
        await engine.dispose()


async def statuses(world):
    engine = create_async_engine(PG_URL)
    try:
        async with engine.connect() as c:
            await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            rows = (await c.execute(text("select title, status, closed_at is not null as has_closed_at from aisoc_cases where id = any(cast(:c as uuid[]))"), {"c": [str(x) for x in world["cases"].values()]})).all()
            comments = (
                await c.execute(text("select c.title, count(*) from aisoc_case_comments m join aisoc_cases c on c.id = m.case_id where c.id = any(cast(:c as uuid[])) and m.is_system group by 1"), {"c": [str(x) for x in world["cases"].values()]})
            ).all()
        return {r.title: (r.status, r.has_closed_at) for r in rows}, dict(comments)
    finally:
        await engine.dispose()


async def test_only_unassigned_system_cases_whose_alerts_are_all_closed_are_closed_and_each_says_why(world):
    closed = await run(world["ids"]["parent"], lambda db: cfc.close_finished_cases(db, world["ids"]["parent"], now=NOW))
    assert closed == 3
    got, comments = await statuses(world)
    assert got["all_done"] == ("closed", True)
    assert got["child_done"] == ("closed", True), "a client tenant's case is closed too"
    assert got["fp_and_closed"] == ("closed", True), "false positives count as closed; an investigating case with nobody assigned also closes"
    assert got["mixed"][0] == "new", "one alert is still open"
    assert got["assigned"][0] == "new", "somebody took it"
    assert got["by_hand"][0] == "new", "a person opened it"
    assert got["no_alerts"][0] == "new", "nothing to judge it by"
    assert comments == {"all_done": 1, "child_done": 1, "fp_and_closed": 1}, "a system note on each case it closed, none on the others, none on one that was already closed"


async def test_a_second_run_does_nothing_and_the_kill_switch_turns_it_off(world, monkeypatch):
    monkeypatch.setenv("AISOC_AUTO_CLOSE_CASES", "false")
    assert await run(world["ids"]["parent"], lambda db: cfc.close_finished_cases(db, world["ids"]["parent"], now=NOW)) == 0
    assert (await statuses(world))[0]["all_done"][0] == "new"
    monkeypatch.delenv("AISOC_AUTO_CLOSE_CASES")
    assert await run(world["ids"]["parent"], lambda db: cfc.close_finished_cases(db, world["ids"]["parent"], now=NOW)) == 3
    assert await run(world["ids"]["parent"], lambda db: cfc.close_finished_cases(db, world["ids"]["parent"], now=NOW)) == 0
    assert (await statuses(world))[1] == {"all_done": 1, "child_done": 1, "fp_and_closed": 1}, "no second note"


async def test_a_case_reopened_after_a_new_alert_joins_it_is_not_closed_while_that_alert_is_open(world):
    async def join_new_alert(db):
        aid = uuid.uuid4()
        tid = world["ids"]["parent"]
        await db.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await db.execute(text("insert into alerts (id, tenant_id, title, severity, status) values (:i, :t, 'late', 'high', 'new')"), {"i": aid, "t": tid})
        await db.execute(text("update aisoc_cases set alert_ids = alert_ids || CAST(:a AS UUID) where id = :c"), {"a": str(aid), "c": world["cases"]["all_done"]})

    await run(world["ids"]["parent"], join_new_alert)
    await run(world["ids"]["parent"], lambda db: cfc.close_finished_cases(db, world["ids"]["parent"], now=NOW))
    assert (await statuses(world))[0]["all_done"][0] == "new"


async def test_an_auto_closed_case_is_told_apart_from_one_a_person_closed_in_the_counts_and_the_list(world):
    from types import SimpleNamespace

    from app.api.v1.endpoints import cases as cases_ep

    parent = world["ids"]["parent"]
    await run(parent, lambda db: cfc.close_finished_cases(db, parent, now=NOW))
    user = SimpleNamespace(tenant_id=parent)
    counts = await run(parent, lambda db: cases_ep.case_counts(db, user, scope="own", client_id=None))
    assert (counts.closed, counts.auto_closed) == (1, 1), "the parent holds one case a person closed and one that closed itself"
    assert counts.by_status.get("auto_closed") == 1

    async def listed(status):
        rows = await run(parent, lambda db: cases_ep.list_cases(db, user, status_filter=status, severity=None, assignee=None, limit=50, offset=0, scope="own", client_id=None))
        return sorted(r.title for r in rows)

    assert await listed("auto_closed") == ["all_done"]
    assert await listed("closed") == ["already_closed"], "Closed is the cases a person closed"
    assert await listed("closed,auto_closed") == ["all_done", "already_closed"]
    assert sorted(set(await listed("new,closed")) - {"mixed", "assigned", "by_hand", "no_alerts"}) == ["already_closed"]
    tags = await run(parent, lambda db: db.execute(text("select tags from aisoc_cases where id = :c"), {"c": world["cases"]["all_done"]}))
    assert tags.scalar_one()["auto_closed"] is True
