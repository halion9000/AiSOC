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


# ---- a person's decisions about possible duplicates ------------------------------------------------------------------------------------------------------------


async def _two_same_name(t):
    a = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "n-1", "FRONT-DESK")))
    b = await run(t, lambda db: upsert_device(db, t, DeviceReport("addigy", "a-1", "front-desk", os="macOS", ip_addresses=["10.0.0.5"])))
    assert a != b
    return a, b


async def test_dismissing_a_pair_stops_it_being_suggested_and_is_safe_to_repeat(tenants):
    from app.services.device_merge import dismiss_pair

    t = tenants["acme"]
    a, b = await _two_same_name(t)
    assert len(await run(t, lambda db: possible_duplicates(db, t))) == 1
    await run(t, lambda db: dismiss_pair(db, t, b, a))  # either order
    await run(t, lambda db: dismiss_pair(db, t, a, b))  # twice
    assert await run(t, lambda db: possible_duplicates(db, t)) == []
    assert await scalar(t, "select count(*) from device_merge_dismissals where tenant_id = :t") == 1


async def test_merging_moves_every_tool_to_the_kept_device_and_fills_its_blanks(tenants):
    from app.services.device_merge import merge_devices

    t = tenants["acme"]
    a, b = await _two_same_name(t)
    kept = await run(t, lambda db: merge_devices(db, t, a, b))
    assert kept == a
    assert await scalar(t, "select count(*) from devices where tenant_id = :t") == 1
    assert (
        await scalar(
            t, "select count(*) from device_sources where tenant_id = :t and device_id = (select id from devices where tenant_id = :t)"
        )
        == 2
    )
    assert await scalar(t, "select os from devices where tenant_id = :t") == "macOS"
    assert await scalar(t, "select ip_addresses[1] from devices where tenant_id = :t") == "10.0.0.5"
    assert await run(t, lambda db: possible_duplicates(db, t)) == []


async def test_the_kept_device_takes_the_serial_of_the_one_removed(tenants):
    from app.services.device_merge import merge_devices

    t = tenants["acme"]
    a = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "n-1", "LAB-PC")))
    b = await run(t, lambda db: upsert_device(db, t, DeviceReport("addigy", "a-1", "lab-pc", serial="ABC12345")))
    await run(t, lambda db: merge_devices(db, t, a, b))
    assert await scalar(t, "select serial_number from devices where tenant_id = :t") == "ABC12345"


async def test_two_different_serials_are_never_merged(tenants):
    from app.services.device_merge import DeviceMergeError, merge_devices

    t = tenants["acme"]
    a = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "n-1", "LAB-PC", serial="AAA11111")))
    b = await run(t, lambda db: upsert_device(db, t, DeviceReport("addigy", "a-1", "LAB-PC", serial="BBB22222")))
    with pytest.raises(DeviceMergeError, match="different serial"):
        await run(t, lambda db: merge_devices(db, t, a, b))
    assert await scalar(t, "select count(*) from devices where tenant_id = :t") == 2


async def test_a_device_from_another_client_cannot_be_merged_or_dismissed(tenants):
    from app.services.device_merge import DeviceMergeError, dismiss_pair, merge_devices

    acme, birch = tenants["acme"], tenants["birch"]
    a = await run(acme, lambda db: upsert_device(db, acme, DeviceReport("ninjaone", "n-1", "PC-1")))
    b = await run(birch, lambda db: upsert_device(db, birch, DeviceReport("ninjaone", "n-2", "PC-1")))
    with pytest.raises(DeviceMergeError):
        await run(acme, lambda db: merge_devices(db, acme, a, b))
    with pytest.raises(DeviceMergeError):
        await run(acme, lambda db: dismiss_pair(db, acme, a, b))
    assert await scalar(birch, "select count(*) from devices where tenant_id = :t") == 1


async def test_a_device_cannot_be_merged_into_itself(tenants):
    from app.services.device_merge import DeviceMergeError, merge_devices

    t = tenants["acme"]
    a = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "n-1", "PC-1")))
    with pytest.raises(DeviceMergeError):
        await run(t, lambda db: merge_devices(db, t, a, a))


async def test_the_client_check_holds_even_without_row_level_security(tenants):
    """Row-level security already hides the other client's devices; this proves the query's own client filter would refuse too (defence in depth)."""
    from app.services.device_merge import DeviceMergeError, dismiss_pair, merge_devices

    acme, birch = tenants["acme"], tenants["birch"]
    a = await run(acme, lambda db: upsert_device(db, acme, DeviceReport("ninjaone", "n-1", "PC-1")))
    b = await run(birch, lambda db: upsert_device(db, birch, DeviceReport("ninjaone", "n-2", "PC-1")))
    engine = create_async_engine(PG_URL, poolclass=NullPool)  # the table owner: not subject to row-level security
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            with pytest.raises(DeviceMergeError):
                await merge_devices(db, acme, a, b)
            with pytest.raises(DeviceMergeError):
                await dismiss_pair(db, acme, a, b)
    finally:
        await engine.dispose()
