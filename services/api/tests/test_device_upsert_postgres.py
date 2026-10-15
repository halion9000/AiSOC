"""Device matching across tools, against a REAL Postgres (opt in with AISOC_TEST_PG_URL / AISOC_TEST_PG_APP_URL, a disposable fully migrated database)."""

import os
import uuid

import pytest
from app.db.rls import set_rls_context
from app.services.device_upsert import DeviceReport, possible_duplicates, upsert_device
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL), reason="set AISOC_TEST_PG_URL and AISOC_TEST_PG_APP_URL to a DISPOSABLE, fully migrated API database"
)


@pytest.fixture
async def tenants():
    tag = uuid.uuid4().hex[:10]
    ids = {"acme": uuid.uuid4(), "birch": uuid.uuid4()}
    owner = create_async_engine(PG_URL)
    try:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            for key, tid in ids.items():
                await conn.execute(
                    text("insert into tenants (id, name, slug) values (:i, :n, :s)"), {"i": tid, "n": f"{key}-{tag}", "s": f"{key}-{tag}"}
                )
        yield ids
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
        await owner.dispose()


async def run(tenant_id, work):
    engine = create_async_engine(APP_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            await set_rls_context(db, tenant_id)
            result = await work(db)
            await db.commit()
            return result
    finally:
        await engine.dispose()


async def scalar(tenant_id, sql):
    async def work(db):
        return (await db.execute(text(sql), {"t": tenant_id})).scalar_one()

    return await run(tenant_id, work)


async def test_same_serial_from_two_tools_is_one_device_with_two_sources(tenants):
    t = tenants["acme"]
    d1 = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "13212", "YX0LP9NE-WL", serial="5cg1234abc")))
    d2 = await run(t, lambda db: upsert_device(db, t, DeviceReport("addigy", "ad-9", "yx0lp9ne", serial=" 5CG1234ABC ", model="ThinkPad")))
    assert d1 == d2
    assert await scalar(t, "select count(*) from devices where tenant_id = :t") == 1
    assert await scalar(t, "select count(*) from device_sources where tenant_id = :t") == 2
    assert await scalar(t, "select model from devices where tenant_id = :t") == "ThinkPad"  # filled by the second tool


async def test_same_tool_reporting_twice_does_not_duplicate(tenants):
    t = tenants["acme"]
    a = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "1", "PC", serial="SER12345")))
    b = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "1", "PC", serial="SER12345")))
    assert a == b
    assert await scalar(t, "select count(*) from device_sources where tenant_id = :t") == 1


async def test_placeholder_serial_never_merges_two_machines(tenants):
    t = tenants["acme"]
    a = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "1", "PC-A", serial="To Be Filled By O.E.M.")))
    b = await run(t, lambda db: upsert_device(db, t, DeviceReport("addigy", "2", "PC-B", serial="To Be Filled By O.E.M.")))
    assert a != b
    assert await scalar(t, "select count(*) from devices where tenant_id = :t") == 2


async def test_same_hostname_without_serial_is_offered_as_possible_duplicate_not_merged(tenants):
    t = tenants["acme"]
    a = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "1", "FRONT-DESK")))
    b = await run(t, lambda db: upsert_device(db, t, DeviceReport("addigy", "2", "front-desk.corp.local")))
    assert a != b
    pairs = await run(t, lambda db: possible_duplicates(db, t))
    assert pairs == [tuple(sorted((a, b), key=str))]


async def test_different_serials_with_same_hostname_are_not_suggested(tenants):
    t = tenants["acme"]
    await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "1", "LAPTOP", serial="AAAA1111")))
    await run(t, lambda db: upsert_device(db, t, DeviceReport("addigy", "2", "laptop", serial="BBBB2222")))
    assert await run(t, lambda db: possible_duplicates(db, t)) == []


async def test_a_known_source_that_gains_a_serial_joins_the_device_that_has_it(tenants):
    t = tenants["acme"]
    first = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "1", "PC", serial="SER99999")))
    loose = await run(t, lambda db: upsert_device(db, t, DeviceReport("addigy", "2", "PC")))
    assert loose != first
    joined = await run(t, lambda db: upsert_device(db, t, DeviceReport("addigy", "2", "PC", serial="SER99999")))
    assert joined == first
    assert await scalar(t, "select count(*) from devices where tenant_id = :t") == 1  # the emptied device is gone
    assert await scalar(t, "select count(*) from device_sources where tenant_id = :t") == 2


async def test_clients_never_share_a_device(tenants):
    a, b = tenants["acme"], tenants["birch"]
    da = await run(a, lambda db: upsert_device(db, a, DeviceReport("ninjaone", "1", "PC", serial="SAME12345")))
    db_ = await run(b, lambda db: upsert_device(db, b, DeviceReport("ninjaone", "1", "PC", serial="SAME12345")))
    assert da != db_
