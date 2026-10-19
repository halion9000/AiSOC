"""Hiding a device until it checks back in, against a REAL Postgres (opt in with AISOC_TEST_PG_URL / AISOC_TEST_PG_APP_URL, a disposable fully migrated database)."""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.api.v1.endpoints import devices as ep
from app.db.rls import set_rls_context
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
async def tenant():
    tid = uuid.uuid4()
    tag = uuid.uuid4().hex[:10]
    owner = create_async_engine(PG_URL)
    try:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(
                text("insert into tenants (id, name, slug) values (:i, :n, :s)"), {"i": tid, "n": f"hide-{tag}", "s": f"hide-{tag}"}
            )
        yield tid
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(text("delete from tenants where id = :t"), {"t": tid})
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


async def shown(t):
    async def work(db):
        return {d.hostname: d for d in await ep._load(db, t, [t], {t: "Acme"}, None)}

    return await run(t, work)


async def test_a_hidden_device_is_hidden_until_a_tool_sees_it_online_afterwards(tenant):
    t = tenant
    old = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    device_id = await run(
        t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "1", "LAPTOP-1", details={"last_contact": old}, ip_addresses=[]))
    )
    assert (await shown(t))["LAPTOP-1"].hidden_since is None

    async def hide(db):
        db.add(ep.DeviceSnooze(device_id=device_id, tenant_id=t, snoozed_at=datetime.now(UTC)))

    await run(t, hide)
    assert (await shown(t))["LAPTOP-1"].hidden_since is not None, "last seen a month ago, hidden now: stays hidden"

    back = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    await run(
        t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "1", "LAPTOP-1", details={"last_contact": back}, ip_addresses=[]))
    )
    assert (await shown(t))["LAPTOP-1"].hidden_since is None, "checked in after being hidden: shown again without anyone doing anything"


async def test_deleting_a_device_removes_its_hide_row(tenant):
    t = tenant
    device_id = await run(t, lambda db: upsert_device(db, t, DeviceReport("ninjaone", "9", "GONE-1", ip_addresses=[])))

    async def hide(db):
        db.add(ep.DeviceSnooze(device_id=device_id, tenant_id=t, snoozed_at=datetime.now(UTC)))

    await run(t, hide)
    await run(t, lambda db: db.execute(text("delete from devices where id = :d"), {"d": device_id}))
    left = await run(t, lambda db: db.execute(text("select count(*) from device_snoozes where device_id = :d"), {"d": device_id}))
    assert left.scalar_one() == 0
