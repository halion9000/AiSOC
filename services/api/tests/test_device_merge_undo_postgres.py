"""Merging two devices and undoing it, against a REAL Postgres (opt in with AISOC_TEST_PG_URL / AISOC_TEST_PG_APP_URL, a disposable fully migrated database)."""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.db.rls import set_rls_context
from app.services.device_merge import DeviceMergeError, merge_devices, undo_merge
from app.services.device_upsert import DeviceReport, upsert_device
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


async def scalar(tenant_id, sql, **params):
    async def work(db):
        return (await db.execute(text(sql), {"t": tenant_id, **params})).scalar_one()

    return await run(tenant_id, work)


async def two_devices(t):
    """Two same-name devices with no serial: the kind a person is asked to merge. The first (ninja) has more filled in on the second (addigy)."""
    a = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "1", "FRONT-DESK", ip_addresses=[])))
    b = await run(
        t,
        lambda db: upsert_device(
            db, t, DeviceReport("addigy", "2", "front-desk", serial="SER12345", os="macOS", model="MacBook", ip_addresses=["10.0.0.5"])
        ),
    )
    assert a != b
    return a, b


async def test_a_merge_can_be_undone_and_everything_comes_back(tenants):
    t = tenants["acme"]
    keep, remove = await two_devices(t)
    await run(t, lambda db: merge_devices(db, t, keep, remove))
    assert await scalar(t, "select count(*) from devices where tenant_id = :t") == 1
    assert await scalar(t, "select count(*) from device_sources where device_id = :k", k=keep) == 2
    merged = await run(
        t, lambda db: db.execute(text("select serial_number, os, model, ip_addresses from devices where id = :k"), {"k": keep})
    )
    assert merged is not None
    log_id = await scalar(t, "select id from device_merge_log where tenant_id = :t and undone_at is null")

    restored = await run(t, lambda db: undo_merge(db, t, log_id))
    assert restored == remove, "the removed device comes back with its own id"
    assert await scalar(t, "select count(*) from devices where tenant_id = :t") == 2
    assert await scalar(t, "select serial_number from devices where id = :r", r=remove) == "SER12345", "its serial is back on it"
    assert (
        await scalar(t, "select count(*) from device_sources where device_id = :r and vendor = 'addigy'", r=remove) == 1
    ), "its feed moved back"
    assert await scalar(t, "select count(*) from device_sources where device_id = :k and vendor = 'ninjaone'", k=keep) == 1
    # What was filled in on the kept device from the removed one is blank again.
    assert await scalar(t, "select serial_number is null and os is null and model is null from devices where id = :k", k=keep) is True
    assert await scalar(t, "select undone_at is not null from device_merge_log where id = :i", i=log_id) is True


async def test_an_undone_merge_cannot_be_undone_twice_and_an_old_one_cannot_be_undone(tenants):
    t = tenants["acme"]
    keep, remove = await two_devices(t)
    await run(t, lambda db: merge_devices(db, t, keep, remove))
    log_id = await scalar(t, "select id from device_merge_log where tenant_id = :t")
    await run(t, lambda db: undo_merge(db, t, log_id))
    with pytest.raises(DeviceMergeError, match="already undone"):
        await run(t, lambda db: undo_merge(db, t, log_id))

    keep2, remove2 = await two_devices(tenants["birch"])
    b = tenants["birch"]
    await run(b, lambda db: merge_devices(db, b, keep2, remove2))
    old_id = await scalar(b, "select id from device_merge_log where tenant_id = :t")
    with pytest.raises(DeviceMergeError, match="too old"):
        await run(b, lambda db: undo_merge(db, b, old_id, now=datetime.now(UTC) + timedelta(days=30)))


async def test_if_the_kept_device_is_gone_the_undo_is_refused_and_nothing_changes(tenants):
    t = tenants["acme"]
    keep, remove = await two_devices(t)
    await run(t, lambda db: merge_devices(db, t, keep, remove))
    log_id = await scalar(t, "select id from device_merge_log where tenant_id = :t")
    await run(t, lambda db: db.execute(text("delete from devices where id = :k"), {"k": keep}))
    with pytest.raises(DeviceMergeError, match="no longer exists"):
        await run(t, lambda db: undo_merge(db, t, log_id))
    assert await scalar(t, "select count(*) from devices where tenant_id = :t") == 0


async def test_one_client_cannot_undo_anothers_merge(tenants):
    a, b = tenants["acme"], tenants["birch"]
    keep, remove = await two_devices(a)
    await run(a, lambda db: merge_devices(db, a, keep, remove))
    log_id = await scalar(a, "select id from device_merge_log where tenant_id = :t")
    with pytest.raises(DeviceMergeError, match="not found"):
        await run(b, lambda db: undo_merge(db, b, log_id))
