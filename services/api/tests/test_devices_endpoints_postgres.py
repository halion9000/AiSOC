"""Devices as CORE posts them and an MSSP parent reads them, against a REAL Postgres (AISOC_TEST_PG_URL / AISOC_TEST_PG_APP_URL, a disposable fully migrated database)."""

import os
import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints.devices import DeviceIn, DeviceSettings, DevicesReport, apply_devices, get_device, list_devices, put_settings
from app.db.rls import set_rls_context
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL), reason="set AISOC_TEST_PG_URL and AISOC_TEST_PG_APP_URL to a DISPOSABLE, fully migrated API database"
)


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:10]
    ids = {k: uuid.uuid4() for k in ("parent", "acme", "birch", "other_parent", "stranger")}
    owner = create_async_engine(PG_URL)
    try:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            for key, tid in ids.items():
                parent = ids["parent"] if key in ("acme", "birch") else (ids["other_parent"] if key == "stranger" else None)
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                    {"i": tid, "n": f"{key}-{tag}", "s": f"{key}-{tag}", "p": parent, "r": "child" if parent else "parent"},
                )
            for vendor, vid, child, ignored in [
                ("ninjaone", "5", "acme", False),
                ("addigy", "a1", "acme", False),
                ("ninjaone", "6", "birch", False),
                ("addigy", "ig", "birch", True),
            ]:
                await conn.execute(
                    text(
                        "insert into client_aliases (tenant_id, vendor, vendor_client_id, vendor_client_name, normalized_name, child_tenant_id, ignored, match_source) "
                        "values (:p, :v, :vid, :n, :n, :c, :ig, 'manual')"
                    ),
                    {"p": ids["parent"], "v": vendor, "vid": vid, "n": f"{child}", "c": ids[child], "ig": ignored},
                )
        yield ids
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
        await owner.dispose()


async def session(tenant_id, work):
    engine = create_async_engine(APP_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            await set_rls_context(db, tenant_id)
            result = await work(db)
            await db.commit()
            return result
    finally:
        await engine.dispose()


def user(tenant_id):
    return SimpleNamespace(tenant_id=tenant_id)


def dev(vendor, vid, ext, host, serial=None):
    return DeviceIn(vendor=vendor, vendor_client_id=vid, external_id=ext, hostname=host, serial=serial)


async def test_devices_land_under_their_mapped_client_and_unmapped_ones_are_counted(world):
    p = world["parent"]
    report = DevicesReport(
        items=[
            dev("ninjaone", "5", "1", "ACME-PC", "SER-ACME-1"),
            dev("ninjaone", "6", "2", "BIRCH-PC", "SER-BIRCH-1"),
            dev("ninjaone", "999", "3", "NOBODY"),
            dev("addigy", "ig", "4", "IGNORED"),
        ]
    )
    res = await session(p, lambda db: apply_devices(db, p, report))
    assert (res.accepted, res.unmapped) == (2, 2)
    listing = await session(
        p, lambda db: list_devices(user(p), db, client_id=None, search=None, vendor=None, not_in_master=False, page=1, page_size=50)
    )
    assert sorted(d.hostname for d in listing.items) == ["ACME-PC", "BIRCH-PC"]
    assert {d.tenant_id for d in listing.items} == {world["acme"], world["birch"]}


async def test_same_serial_from_ninja_and_addigy_is_one_device_in_the_client_view(world):
    p = world["parent"]
    report = DevicesReport(
        items=[dev("ninjaone", "5", "1", "ACME-PC", "SER-ONE-1"), dev("addigy", "a1", "9", "acme-pc.local", "ser-one-1")]
    )
    await session(p, lambda db: apply_devices(db, p, report))
    a = world["acme"]
    listing = await session(
        p, lambda db: list_devices(user(p), db, client_id=a, search=None, vendor=None, not_in_master=False, page=1, page_size=50)
    )
    assert len(listing.items) == 1
    assert sorted(s.vendor for s in listing.items[0].sources) == ["addigy", "ninjaone"]


async def test_master_flags_devices_the_master_does_not_report(world):
    p = world["parent"]
    report = DevicesReport(
        items=[dev("ninjaone", "5", "1", "IN-NINJA", "SER-A-0001"), dev("addigy", "a1", "9", "ONLY-ADDIGY", "SER-B-0002")]
    )
    await session(p, lambda db: apply_devices(db, p, report))
    assert (await session(p, lambda db: put_settings(DeviceSettings(master_vendor="ninjaone"), user(p), db))).master_vendor == "ninjaone"
    gaps = await session(
        p, lambda db: list_devices(user(p), db, client_id=None, search=None, vendor=None, not_in_master=True, page=1, page_size=50)
    )
    assert [d.hostname for d in gaps.items] == ["ONLY-ADDIGY"]
    assert gaps.summary.total == 2 and gaps.summary.not_in_master == 1 and gaps.master_vendor == "ninjaone"
    await session(p, lambda db: put_settings(DeviceSettings(master_vendor=None), user(p), db))
    nogaps = await session(
        p, lambda db: list_devices(user(p), db, client_id=None, search=None, vendor=None, not_in_master=True, page=1, page_size=50)
    )
    assert nogaps.items == []  # with no master nothing is a gap


async def test_a_parent_cannot_read_another_parents_client_or_device(world):
    p, stranger = world["parent"], world["stranger"]
    await session(p, lambda db: apply_devices(db, p, DevicesReport(items=[dev("ninjaone", "5", "1", "ACME-PC", "SER-ACME-9")])))
    with pytest.raises(HTTPException) as err:
        await session(
            world["other_parent"],
            lambda db: list_devices(
                user(world["other_parent"]),
                db,
                client_id=world["acme"],
                search=None,
                vendor=None,
                not_in_master=False,
                page=1,
                page_size=50,
            ),
        )
    assert err.value.status_code == 404
    mine = await session(
        p, lambda db: list_devices(user(p), db, client_id=None, search=None, vendor=None, not_in_master=False, page=1, page_size=50)
    )
    with pytest.raises(HTTPException) as err2:
        await session(world["other_parent"], lambda db: get_device(mine.items[0].id, user(world["other_parent"]), db))
    assert err2.value.status_code == 404
    assert (await session(p, lambda db: get_device(mine.items[0].id, user(p), db))).hostname == "ACME-PC"
    del stranger


async def test_search_and_tool_filter(world):
    p = world["parent"]
    await session(
        p,
        lambda db: apply_devices(
            db,
            p,
            DevicesReport(
                items=[dev("ninjaone", "5", "1", "FRONT-DESK", "SER-FD-0001"), dev("addigy", "a1", "2", "MAC-STUDIO", "SER-MS-0002")]
            ),
        ),
    )
    by_name = await session(
        p, lambda db: list_devices(user(p), db, client_id=None, search="front", vendor=None, not_in_master=False, page=1, page_size=50)
    )
    assert [d.hostname for d in by_name.items] == ["FRONT-DESK"]
    by_serial = await session(
        p, lambda db: list_devices(user(p), db, client_id=None, search="ser-ms", vendor=None, not_in_master=False, page=1, page_size=50)
    )
    assert [d.hostname for d in by_serial.items] == ["MAC-STUDIO"]
    by_tool = await session(
        p, lambda db: list_devices(user(p), db, client_id=None, search=None, vendor="addigy", not_in_master=False, page=1, page_size=50)
    )
    assert [d.hostname for d in by_tool.items] == ["MAC-STUDIO"]
