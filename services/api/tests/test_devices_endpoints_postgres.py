"""Devices as CORE posts them and an MSSP parent reads them, against a REAL Postgres (AISOC_TEST_PG_URL / AISOC_TEST_PG_APP_URL, a disposable fully migrated database)."""

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints.devices import (
    DeviceIn,
    DeviceOut,
    DeviceSettings,
    DeviceSourceOut,
    DevicesReport,
    DismissIn,
    MergeIn,
    apply_devices,
    dismiss_duplicate,
    get_device,
    host_key,
    is_missing_from,
    last_online_of,
    list_devices,
    list_duplicates,
    merge_duplicate,
    offline_days_of,
    online_now_of,
    put_settings,
)
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
        p,
        lambda db: list_devices(
            user(p),
            db,
            client_id=None,
            search=None,
            vendor=None,
            not_in_master=False,
            missing=None,
            offline=False,
            has_alerts=False,
            page=1,
            page_size=50,
        ),
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
        p,
        lambda db: list_devices(
            user(p),
            db,
            client_id=a,
            search=None,
            vendor=None,
            not_in_master=False,
            missing=None,
            offline=False,
            has_alerts=False,
            page=1,
            page_size=50,
        ),
    )
    assert len(listing.items) == 1
    assert sorted(s.vendor for s in listing.items[0].sources) == ["addigy", "ninjaone"]


async def test_each_feeds_details_come_back_with_the_device(world):
    p = world["parent"]
    item = dev("ninjaone", "5", "1", "ACME-PC", "SER-SPEC-1")
    item.details = {"memory_gb": 16, "processor": "Intel i7"}
    await session(p, lambda db: apply_devices(db, p, DevicesReport(items=[item])))
    listing = await session(
        p,
        lambda db: list_devices(
            user(p),
            db,
            client_id=world["acme"],
            search=None,
            vendor=None,
            not_in_master=False,
            missing=None,
            offline=False,
            has_alerts=False,
            page=1,
            page_size=50,
        ),
    )
    assert listing.items[0].sources[0].details == {"memory_gb": 16, "processor": "Intel i7"}


def _view(os_name, vendors):
    now = datetime.now(UTC)
    return DeviceOut(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        hostname="h",
        os=os_name,
        last_seen=now,
        first_seen=now,
        sources=[DeviceSourceOut(vendor=v, name="h", last_seen=now) for v in vendors],
    )


def test_missing_from_addigy_counts_macs_only_and_threatmate_counts_everything():
    mac = _view("macOS", ["ninjaone"])
    old_mac = _view("Mac OS X", ["ninjaone"])
    windows = _view("Microsoft Windows 11 Pro", ["ninjaone"])
    unknown = _view(None, ["ninjaone"])
    assert is_missing_from(mac, "addigy") and is_missing_from(old_mac, "addigy")
    assert not is_missing_from(windows, "addigy")
    assert not is_missing_from(unknown, "addigy")
    assert not is_missing_from(_view("macOS", ["ninjaone", "addigy"]), "addigy")
    assert is_missing_from(windows, "threatmate") and is_missing_from(mac, "threatmate")
    assert not is_missing_from(_view("macOS", ["threatmate"]), "threatmate")


def test_iphones_and_ipads_are_never_missing_from_the_rmm_or_threatmate_but_are_from_addigy():
    for os_name in ("iOS", "iPadOS"):
        phone = _view(os_name, ["addigy"])
        assert not is_missing_from(phone, "threatmate")
        assert not is_missing_from(phone, "ninjaone")
    assert not is_missing_from(_view("iOS", []), "addigy")  # Addigy only counts Macs as missing, as before
    assert is_missing_from(_view("Windows 11", ["addigy"]), "threatmate")  # ordinary machines still are


def test_last_online_is_the_newest_time_a_tool_says_the_device_was_online_not_the_sync_time():
    src = lambda **d: SimpleNamespace(details=d)  # noqa: E731
    got = last_online_of([src(last_online="2026-10-14T10:00:00+00:00"), src(last_contact="2026-10-15T09:00:00Z"), src()])
    assert got == datetime(2026, 10, 15, 9, tzinfo=UTC)
    assert last_online_of([src(), src(last_online="garbage")]) is None


def test_online_now_reads_addigy_online_and_ninja_offline_and_is_unknown_when_no_tool_says():
    src = lambda **d: SimpleNamespace(details=d)  # noqa: E731
    assert online_now_of([src(online=True)]) is True
    assert online_now_of([src(online=False)]) is False
    assert online_now_of([src(offline=False)]) is True
    assert online_now_of([src(offline=True)]) is False
    assert online_now_of([src(offline=True), src(online=True)]) is True, "any tool seeing it online wins"
    assert online_now_of([src(offline=True), src(online=False)]) is False
    assert online_now_of([src(), src(online=None, offline=None)]) is None
    assert online_now_of([src(online="yes")]) is None, "only real booleans count"


def test_host_key_ignores_case_and_domain_suffix_but_keeps_ip_addresses_whole():
    assert host_key("PC-1.Acme.Local") == host_key("pc-1") == "pc-1"
    assert host_key("  FRONT-DESK ") == "front-desk"
    assert host_key("192.168.1.20") == "192.168.1.20"
    assert host_key("fe80::1") == "fe80::1"
    assert host_key("dead.beef") == "dead", "hex-looking letters in a dotted name are a name, not an address"
    assert host_key(None) == ""


async def test_missing_filter_and_summary_counts(world):
    p = world["parent"]
    items = [
        dev("ninjaone", "5", "1", "ACME-MAC", "SER-M-1"),
        dev("ninjaone", "5", "2", "ACME-WIN", "SER-W-1"),
        dev("ninjaone", "5", "3", "ACME-BOTH", "SER-B-1"),
        dev("addigy", "a1", "9", "x", "SER-B-1"),
    ]
    items[0].os = "macOS"
    items[1].os = "Microsoft Windows 11 Pro"
    items[2].os = "macOS"
    await session(p, lambda db: apply_devices(db, p, DevicesReport(items=items)))

    async def listing(**kw):
        args = {
            "client_id": world["acme"],
            "search": None,
            "vendor": None,
            "not_in_master": False,
            "missing": None,
            "offline": False,
            "has_alerts": False,
            "page": 1,
            "page_size": 50,
        }
        args.update(kw)
        return await session(p, lambda db: list_devices(user(p), db, **args))

    full = await listing()
    assert full.summary.not_in_addigy == 1
    assert full.summary.not_in_threatmate == 3
    assert [d.hostname for d in (await listing(missing="addigy")).items] == ["ACME-MAC"]
    assert len((await listing(missing="threatmate")).items) == 3


async def test_master_flags_devices_the_master_does_not_report(world):
    p = world["parent"]
    report = DevicesReport(
        items=[dev("ninjaone", "5", "1", "IN-NINJA", "SER-A-0001"), dev("addigy", "a1", "9", "ONLY-ADDIGY", "SER-B-0002")]
    )
    await session(p, lambda db: apply_devices(db, p, report))
    assert (await session(p, lambda db: put_settings(DeviceSettings(master_vendor="ninjaone"), user(p), db))).master_vendor == "ninjaone"
    gaps = await session(
        p,
        lambda db: list_devices(
            user(p),
            db,
            client_id=None,
            search=None,
            vendor=None,
            not_in_master=True,
            missing=None,
            offline=False,
            has_alerts=False,
            page=1,
            page_size=50,
        ),
    )
    assert [d.hostname for d in gaps.items] == ["ONLY-ADDIGY"]
    assert gaps.summary.total == 2 and gaps.summary.not_in_master == 1 and gaps.master_vendor == "ninjaone"
    await session(p, lambda db: put_settings(DeviceSettings(master_vendor=None), user(p), db))
    nogaps = await session(
        p,
        lambda db: list_devices(
            user(p),
            db,
            client_id=None,
            search=None,
            vendor=None,
            not_in_master=True,
            missing=None,
            offline=False,
            has_alerts=False,
            page=1,
            page_size=50,
        ),
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
        p,
        lambda db: list_devices(
            user(p),
            db,
            client_id=None,
            search=None,
            vendor=None,
            not_in_master=False,
            missing=None,
            offline=False,
            has_alerts=False,
            page=1,
            page_size=50,
        ),
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
        p,
        lambda db: list_devices(
            user(p),
            db,
            client_id=None,
            search="front",
            vendor=None,
            not_in_master=False,
            missing=None,
            offline=False,
            has_alerts=False,
            page=1,
            page_size=50,
        ),
    )
    assert [d.hostname for d in by_name.items] == ["FRONT-DESK"]
    by_serial = await session(
        p,
        lambda db: list_devices(
            user(p),
            db,
            client_id=None,
            search="ser-ms",
            vendor=None,
            not_in_master=False,
            missing=None,
            offline=False,
            has_alerts=False,
            page=1,
            page_size=50,
        ),
    )
    assert [d.hostname for d in by_serial.items] == ["MAC-STUDIO"]
    by_tool = await session(
        p,
        lambda db: list_devices(
            user(p),
            db,
            client_id=None,
            search=None,
            vendor="addigy",
            not_in_master=False,
            missing=None,
            offline=False,
            has_alerts=False,
            page=1,
            page_size=50,
        ),
    )
    assert [d.hostname for d in by_tool.items] == ["MAC-STUDIO"]


async def test_open_alerts_naming_a_device_show_on_that_device_only(world):
    p, a = world["parent"], world["acme"]
    await session(
        p,
        lambda db: apply_devices(
            db,
            p,
            DevicesReport(items=[dev("ninjaone", "5", "1", "ACME-PC", "SER-AL-1"), dev("ninjaone", "5", "2", "ACME-OTHER", "SER-AL-2")]),
        ),
    )

    async def seed(db):
        for title, sev, status, host in [
            ("Disk almost full", "high", "new", "acme-pc"),  # lower-case in the alert, upper in the device: still the same device
            ("CPU hot", "critical", "triaging", "ACME-PC"),
            ("Old one", "high", "resolved", "ACME-PC"),  # closed: not counted
            ("Elsewhere", "low", "new", "SOME-OTHER-BOX"),  # another device
            ("Fully qualified", "medium", "new", "Acme-PC.corp.acme.local"),  # the same machine named with its domain
        ]:
            await db.execute(
                text("insert into alerts (tenant_id, title, severity, status, raw_event) values (:t, :ti, :s, :st, cast(:r as jsonb))"),
                {
                    "t": a,
                    "ti": title,
                    "s": sev,
                    "st": status,
                    "r": json.dumps({"source": "ninjaone", "unmapped": {"context": {"device_name": host}}}),
                },
            )

    await session(a, seed)
    try:
        listing = await session(
            p,
            lambda db: list_devices(
                user(p),
                db,
                client_id=a,
                search=None,
                vendor=None,
                not_in_master=False,
                missing=None,
                offline=False,
                has_alerts=False,
                page=1,
                page_size=50,
            ),
        )
        by_host = {d.hostname: d for d in listing.items}
        pc = by_host["ACME-PC"]
        assert pc.open_alerts == 3
        assert [x.title for x in pc.alerts] == ["CPU hot", "Disk almost full", "Fully qualified"]  # worst severity first
        assert pc.alerts[0].source == "ninjaone"
        assert by_host["ACME-OTHER"].open_alerts == 0
        only = await session(
            p,
            lambda db: list_devices(
                user(p),
                db,
                client_id=a,
                search=None,
                vendor=None,
                not_in_master=False,
                missing=None,
                offline=False,
                has_alerts=True,
                page=1,
                page_size=50,
            ),
        )
        assert [d.hostname for d in only.items] == ["ACME-PC"]
        assert only.summary.with_alerts == 1
    finally:
        owner = create_async_engine(PG_URL)
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(text("delete from alerts where tenant_id = :t"), {"t": a})
        await owner.dispose()


def test_offline_days_only_counts_a_device_a_tool_has_not_seen_for_a_week_and_unknown_is_not_offline():
    now = datetime(2026, 10, 15, tzinfo=UTC)
    assert offline_days_of(None, now) is None
    assert offline_days_of(now - timedelta(days=6, hours=23), now) is None
    assert offline_days_of(now - timedelta(days=7), now) == 7
    assert offline_days_of(now - timedelta(days=40), now) == 40


async def test_offline_filter_and_count_use_the_tools_last_online_not_the_sync_time(world):
    p = world["parent"]
    old = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    new = datetime.now(UTC).isoformat()
    items = [
        DeviceIn(vendor="ninjaone", vendor_client_id="5", external_id="o1", hostname="OLD-PC", details={"last_contact": old}),
        DeviceIn(vendor="ninjaone", vendor_client_id="5", external_id="o2", hostname="NEW-PC", details={"last_contact": new}),
        DeviceIn(vendor="ninjaone", vendor_client_id="5", external_id="o3", hostname="NO-TIME-PC"),  # no tool says: unknown, not offline
    ]
    await session(p, lambda db: apply_devices(db, p, DevicesReport(items=items)))
    res = await session(
        p,
        lambda db: list_devices(
            user(p),
            db,
            client_id=None,
            search=None,
            vendor=None,
            not_in_master=False,
            missing=None,
            offline=True,
            has_alerts=False,
            page=1,
            page_size=50,
        ),
    )
    assert [d.hostname for d in res.items] == ["OLD-PC"]
    assert res.items[0].offline_days >= 30
    assert res.summary.offline == 1


# ---- possible duplicates: list, "not a duplicate", merge ----------------------------------------------------------------------------------------------------------


async def _front_desk_pair(world):
    p = world["parent"]
    await session(
        p,
        lambda db: apply_devices(
            db, p, DevicesReport(items=[dev("ninjaone", "5", "1", "FRONT-DESK"), dev("addigy", "a1", "2", "front-desk")])
        ),
    )
    found = await session(p, lambda db: list_duplicates(user(p), db, client_id=None))
    assert len(found.items) == 1
    return found.items[0]


async def test_same_name_devices_with_no_serial_are_listed_with_their_client_and_tools(world):
    pair = await _front_desk_pair(world)
    assert pair.a.client_name == pair.b.client_name and pair.a.tenant_id == world["acme"]
    assert sorted(s.vendor for d in (pair.a, pair.b) for s in d.sources) == ["addigy", "ninjaone"]


async def test_dismissing_a_pair_hides_it_for_everyone_in_the_organization(world):
    p = world["parent"]
    pair = await _front_desk_pair(world)
    await session(p, lambda db: dismiss_duplicate(DismissIn(device_a=pair.a.id, device_b=pair.b.id), user(p), db))
    colleague = user(p)  # another person in the same organization: the decision is on the client, not on a person
    assert (await session(p, lambda db: list_duplicates(colleague, db, client_id=None))).items == []


async def test_merging_keeps_one_device_fed_by_both_tools(world):
    p = world["parent"]
    pair = await _front_desk_pair(world)
    kept = await session(p, lambda db: merge_duplicate(MergeIn(keep=pair.a.id, remove=pair.b.id), user(p), db))
    assert kept.id == pair.a.id and sorted(s.vendor for s in kept.sources) == ["addigy", "ninjaone"]
    assert (await session(p, lambda db: list_duplicates(user(p), db, client_id=None))).items == []
    with pytest.raises(HTTPException) as gone:
        await session(p, lambda db: get_device(pair.b.id, user(p), db))
    assert gone.value.status_code == 404


async def test_another_organization_cannot_dismiss_or_merge_these_devices(world):
    pair = await _front_desk_pair(world)
    o = world["other_parent"]
    with pytest.raises(HTTPException) as e1:
        await session(o, lambda db: dismiss_duplicate(DismissIn(device_a=pair.a.id, device_b=pair.b.id), user(o), db))
    with pytest.raises(HTTPException) as e2:
        await session(o, lambda db: merge_duplicate(MergeIn(keep=pair.a.id, remove=pair.b.id), user(o), db))
    assert (e1.value.status_code, e2.value.status_code) == (404, 404)
    assert len((await session(world["parent"], lambda db: list_duplicates(user(world["parent"]), db, client_id=None))).items) == 1


async def test_merging_two_machines_with_different_serials_is_refused_with_a_reason(world):
    p = world["parent"]
    await session(
        p,
        lambda db: apply_devices(
            db, p, DevicesReport(items=[dev("ninjaone", "5", "1", "LAB", "SER-A1111"), dev("addigy", "a1", "2", "LAB", "SER-B2222")])
        ),
    )
    both = (
        await session(
            p,
            lambda db: list_devices(
                user(p),
                db,
                client_id=None,
                search=None,
                vendor=None,
                not_in_master=False,
                missing=None,
                offline=False,
                has_alerts=False,
                page=1,
                page_size=50,
            ),
        )
    ).items
    with pytest.raises(HTTPException) as err:
        await session(p, lambda db: merge_duplicate(MergeIn(keep=both[0].id, remove=both[1].id), user(p), db))
    assert err.value.status_code == 400 and "serial" in err.value.detail
