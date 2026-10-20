"""The Cases "all clients" view against a REAL Postgres (opt in with AISOC_TEST_PG_URL, a DISPOSABLE, fully migrated database; the role must be allowed to write every table)."""

import os
import uuid
from types import SimpleNamespace as NS

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import cases as ep
from app.db.rls import set_rls_context
from app.services.case_scope import case_scoped, find_case_tenant
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database")


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:8]
    ids = {k: uuid.uuid4() for k in ("msp", "c1", "c2", "other_msp", "other_client")}
    cases = {}
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for key, tid in ids.items():
            parent = {"c1": "msp", "c2": "msp", "other_client": "other_msp"}.get(key)
            await c.execute(
                text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                {
                    "i": tid,
                    "n": f"cs-{key}-{tag}",
                    "s": f"cs-{key}-{tag}",
                    "p": ids[parent] if parent else None,
                    "r": "child" if parent else "parent",
                },
            )
        for key, tenant, status in (
            ("own", "msp", "new"),
            ("c1a", "c1", "new"),
            ("c1b", "c1", "resolved"),
            ("c2a", "c2", "triaged"),
            ("theirs", "other_client", "new"),
        ):
            cid = uuid.uuid4()
            cases[key] = cid
            await c.execute(
                text("insert into aisoc_cases (id, tenant_id, title, status, case_number) values (:i, :t, :n, :s, :num)"),
                {"i": cid, "t": ids[tenant], "n": f"case {key}", "s": status, "num": f"CS-{tag}-{key}".upper()},
            )
    yield {**ids, "cases": cases, "tag": tag}
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(text("delete from aisoc_cases where tenant_id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
        await c.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
    await engine.dispose()


def _user(tenant):
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant, role="platform_admin", email="a@x.com")


async def run(owner, work):
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            await set_rls_context(db, owner)
            return await work(db)
    finally:
        await engine.dispose()


def _list(world, **over):
    args = {"status_filter": None, "severity": None, "assignee": None, "limit": 100, "offset": 0, "scope": "all", "client_id": None}
    args.update(over)
    return lambda db: ep.list_cases(db, _user(world["msp"]), **args)


async def test_own_scope_is_still_only_this_organizations_cases(world):
    rows = await run(world["msp"], _list(world, scope="own"))
    assert [r.title for r in rows if r.title.startswith("case ")] == ["case own"]
    assert all(r.client_name is None for r in rows)


async def test_all_scope_lists_this_organization_and_its_clients_with_the_client_name_and_never_anyone_elses(world):
    rows = await run(world["msp"], _list(world))
    mine = {r.title: r for r in rows if r.title.startswith("case ")}
    assert set(mine) == {"case own", "case c1a", "case c1b", "case c2a"}, "another organization's client is never listed"
    assert mine["case own"].client_name is None and mine["case own"].tenant_id == world["msp"]
    assert mine["case c1a"].client_name == f"cs-c1-{world['tag']}" and mine["case c1a"].tenant_id == world["c1"]


async def test_all_scope_filters_by_status_and_by_one_client(world):
    open_only = await run(world["msp"], _list(world, status_filter="new,triaged"))
    assert {r.title for r in open_only if r.title.startswith("case ")} == {"case own", "case c1a", "case c2a"}
    one = await run(world["msp"], _list(world, client_id=world["c1"]))
    assert {r.title for r in one if r.title.startswith("case ")} == {"case c1a", "case c1b"}
    outsider = await run(world["msp"], _list(world, client_id=world["other_client"]))
    assert [r for r in outsider if r.title.startswith("case ")] == [], "asking for someone else's client returns nothing"


async def test_counts_cover_the_chosen_scope(world):
    own = await run(world["msp"], lambda db: ep.case_counts(db, _user(world["msp"]), scope="own", client_id=None))
    everything = await run(world["msp"], lambda db: ep.case_counts(db, _user(world["msp"]), scope="all", client_id=None))
    one_client = await run(world["msp"], lambda db: ep.case_counts(db, _user(world["msp"]), scope="all", client_id=world["c1"]))
    assert everything.all >= own.all + 3, "the three client cases are added"
    assert (one_client.all, one_client.open, one_client.resolved) == (2, 1, 1)
    outsider = await run(world["msp"], lambda db: ep.case_counts(db, _user(world["msp"]), scope="all", client_id=world["other_client"]))
    assert outsider.all == 0


async def test_a_client_case_is_found_for_its_parent_by_id_or_number_and_someone_elses_is_not(world):
    async def work(db):
        by_id = await find_case_tenant(db, world["msp"], str(world["cases"]["c1a"]))
        by_number = await find_case_tenant(db, world["msp"], f"cs-{world['tag']}-c2a")
        own = await find_case_tenant(db, world["msp"], str(world["cases"]["own"]))
        theirs = await find_case_tenant(db, world["msp"], str(world["cases"]["theirs"]))
        nothing = await find_case_tenant(db, world["msp"], "INC-DOES-NOT-EXIST")
        return by_id, by_number, own, theirs, nothing

    by_id, by_number, own, theirs, nothing = await run(world["msp"], work)
    assert (by_id, by_number, own) == (world["c1"], world["c2"], world["msp"])
    assert theirs is None and nothing is None


async def test_a_route_with_a_case_id_works_on_a_clients_case_through_the_scoped_dependency(world):
    async def work(db):
        dep = case_scoped("cases:read")
        # The permission check is the real one; the parent's role holds cases:read.
        gen = dep(request=NS(path_params={"case_id": str(world["cases"]["c1a"])}), user=_user(world["msp"]), db=db)
        scoped = await gen.__anext__()
        try:
            case = await ep.get_case(str(world["cases"]["c1a"]), db, scoped)
        finally:
            await gen.aclose()
        return scoped.tenant_id, case.title

    tenant, title = await run(world["msp"], work)
    assert tenant == world["c1"] and title == "case c1a"


async def test_the_same_route_still_answers_not_found_for_a_case_that_is_not_the_callers(world):
    async def work(db):
        gen = case_scoped("cases:read")(request=NS(path_params={"case_id": str(world["cases"]["theirs"])}), user=_user(world["msp"]), db=db)
        scoped = await gen.__anext__()
        try:
            await ep.get_case(str(world["cases"]["theirs"]), db, scoped)
        finally:
            await gen.aclose()

    with pytest.raises(Exception) as err:
        await run(world["msp"], work)
    assert getattr(err.value, "status_code", None) == 404
