"""Merging same-name devices that are plainly one machine, against a REAL Postgres (opt in with AISOC_TEST_PG_URL, a DISPOSABLE, fully migrated database)."""

import os
import uuid

import pytest
from app.db.rls import set_rls_context
from app.services.device_merge import auto_merge_same_name, dismiss_pair, os_kind, undo_merge
from app.services.device_upsert import DeviceReport, upsert_device
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database")


@pytest.fixture
async def tenant():
    tag = uuid.uuid4().hex[:10]
    tid = uuid.uuid4()
    engine = create_async_engine(PG_URL)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(
                text("insert into tenants (id, name, slug) values (:i, :n, :s)"), {"i": tid, "n": f"am-{tag}", "s": f"am-{tag}"}
            )
        yield tid
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(text("delete from tenants where id = :i"), {"i": tid})
        await engine.dispose()


async def run(tid, work):
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            await set_rls_context(db, tid)
            out = await work(db)
            await db.commit()
            return out
    finally:
        await engine.dispose()


async def report(tid, vendor, ext, host, **kw):
    return await run(tid, lambda db: upsert_device(db, tid, DeviceReport(vendor, ext, host, **kw)))


async def count(tid, sql="select count(*) from devices where tenant_id = :t", **p):
    async def work(db):
        return (await db.execute(text(sql), {"t": tid, **p})).scalar_one()

    return await run(tid, work)


async def merge_pass(tid):
    return await run(tid, lambda db: auto_merge_same_name(db, tid))


async def test_four_records_of_one_name_from_four_different_tools_fold_into_one_machine(tenant):
    await report(tenant, "ninjaone", "n1", "1VH94D4-WD", os="Microsoft Windows 11 Pro")
    await report(tenant, "huntress", "h1", "1vh94d4-wd", os="Microsoft Windows 11 Pro")
    await report(tenant, "threatmate", "t1", "1VH94D4-WD")
    await report(tenant, "addigy", "a1", "1VH94D4-WD.corp.local", os="Windows 11")
    assert await count(tenant) == 4
    assert await merge_pass(tenant) == 3
    assert await count(tenant) == 1
    assert await count(tenant, "select count(*) from device_sources where tenant_id = :t") == 4


async def test_three_records_of_one_name_each_from_a_different_tool_become_one_device_keeping_the_richest(tenant):
    # Two tools already matched (so that device holds two), a third tool has its own record with the same name: the shape seen in the real data.
    await report(tenant, "ninjaone", "n1", "5CD4040VG7-WL", os="Microsoft Windows 11 Pro")
    await report(tenant, "threatmate", "t1", "5CD4040VG7-WL")
    await report(tenant, "dnsfilter", "d1", "5CD4040VG7-WL", os="Microsoft Windows 11 Pro")
    await report(tenant, "addigy", "a9", "OTHER-NAME-1")
    assert await merge_pass(tenant) == 2
    assert await count(tenant) == 2
    assert await merge_pass(tenant) == 0, "nothing is left to merge"


async def test_the_pair_is_merged_keeping_the_device_with_more_tools_and_it_can_be_undone(tenant):
    await report(tenant, "ninjaone", "n1", "FRONT-DESK-7")
    await report(tenant, "huntress", "h1", "FRONT-DESK-7")  # a second device: same name, no serial, different tool
    await report(tenant, "threatmate", "t1", "OTHER-PC-1")
    assert await count(tenant) == 3
    assert await merge_pass(tenant) == 1
    assert await count(tenant) == 2
    assert await count(tenant, "select count(*) from device_sources where tenant_id = :t") == 3
    assert await count(tenant, "select count(*) from device_merge_log where tenant_id = :t and undone_at is null") == 1
    assert (
        await count(
            tenant, "select count(distinct device_id) from device_sources where tenant_id = :t and vendor in ('ninjaone','huntress')"
        )
        == 1
    )

    log_id = await count(tenant, "select id::text from device_merge_log where tenant_id = :t")
    await run(tenant, lambda db: undo_merge(db, tenant, uuid.UUID(log_id)))
    assert await count(tenant) == 3, "undo brings the removed device back"
    assert await merge_pass(tenant) == 0, "and it is not merged again by itself"


async def test_a_stock_name_is_never_merged(tenant):
    await report(tenant, "ninjaone", "n1", "SERVER")
    await report(tenant, "huntress", "h1", "server")
    await report(tenant, "ninjaone", "n2", "MacBook-Pro")
    await report(tenant, "addigy", "a2", "macbook-pro")
    assert await merge_pass(tenant) == 0
    assert await count(tenant) == 4


async def test_two_entries_from_the_same_tool_are_two_machines(tenant):
    await report(tenant, "ninjaone", "n1", "LAB-PC-22")
    await report(tenant, "ninjaone", "n2", "LAB-PC-22")
    await report(tenant, "huntress", "h1", "LAB-PC-22")
    assert await merge_pass(tenant) == 1, "the other tool joins one of them; the two NinjaOne records stay apart"
    assert await count(tenant) == 2
    assert await count(tenant, "select count(*) from devices d where tenant_id = :t and exists (select 1 from device_sources s where s.device_id = d.id and s.vendor = 'ninjaone')") == 2


async def test_a_name_on_more_devices_than_the_group_limit_is_left_alone(tenant):
    for i, vendor in enumerate(["ninjaone", "huntress", "threatmate", "addigy", "dnsfilter", "blumira", "autoelevate"]):
        await report(tenant, vendor, f"x{i}", "POPULAR-NAME-9")
    assert await merge_pass(tenant) == 0
    assert await count(tenant) == 7


async def test_a_pair_where_one_tool_sees_both_is_left_for_a_person(tenant):
    await report(tenant, "ninjaone", "n1", "LAB-PC-23")
    await report(tenant, "ninjaone", "n2", "LAB-PC-23")
    assert await merge_pass(tenant) == 0


async def test_a_windows_pc_and_a_mac_with_the_same_name_are_not_merged(tenant):
    await report(tenant, "ninjaone", "n1", "ROAMING-LAPTOP-4", os="Microsoft Windows 11 Pro")
    await report(tenant, "addigy", "a1", "ROAMING-LAPTOP-4", os="macOS 14")
    assert await merge_pass(tenant) == 0


async def test_two_different_serial_numbers_are_two_machines(tenant):
    await report(tenant, "ninjaone", "n1", "ACCOUNTING-3", serial="SN-AAAA-1111")
    await report(tenant, "huntress", "h1", "ACCOUNTING-3", serial="SN-BBBB-2222")
    assert await count(tenant) == 2
    assert await merge_pass(tenant) == 0


async def test_a_pair_marked_not_a_duplicate_is_left_alone(tenant):
    a = await report(tenant, "ninjaone", "n1", "WAREHOUSE-9")
    b = await report(tenant, "huntress", "h1", "WAREHOUSE-9")
    await run(tenant, lambda db: dismiss_pair(db, tenant, a, b))
    assert await merge_pass(tenant) == 0
    assert await count(tenant) == 2


async def test_a_serial_on_one_side_is_carried_onto_the_merged_device(tenant):
    await report(tenant, "ninjaone", "n1", "FRONT-OFFICE-2")
    await report(tenant, "addigy", "a1", "FRONT-OFFICE-2", serial="SER-77881")
    assert await merge_pass(tenant) == 1
    assert await count(tenant, "select count(*) from devices where tenant_id = :t and serial_number = 'SER-77881'") == 1


def test_the_operating_system_is_read_from_the_text_a_tool_reports():
    assert os_kind("Microsoft Windows 11 Pro") == "windows"
    assert os_kind("macOS 14.5") == "mac" and os_kind("Mac OS X") == "mac"
    assert os_kind("iPadOS 17") == "ios" and os_kind("Ubuntu 22.04") == "linux"
    assert os_kind(None) is None and os_kind("") is None and os_kind("Embedded thing") is None


async def test_the_old_company_and_name_screenconnect_record_and_the_session_record_of_the_same_machine_become_one_device(tenant):
    # Before the feed knew real session ids, ScreenConnect machines were keyed "Company::Name"; the session-id records now sit beside them as a second ScreenConnect entry.
    await report(tenant, "screenconnect", "American Legion::LARC-003", "LARC-003")
    await report(tenant, "screenconnect", "c52b1138-8d8e-4f3f-bcba-ba60a7d633fa", "LARC-003", serial="6Q10GD3")
    await report(tenant, "huntress", "h1", "DCJJYJZ2")
    await report(tenant, "screenconnect", "American Legion::DCJJYJZ2", "DCJJYJZ2")
    await report(tenant, "screenconnect", "6a9ad59f-e713-4e00-8ca3-f35180ea4690", "DCJJYJZ2", serial="CJJYJZ2")
    assert await count(tenant) == 5
    assert await merge_pass(tenant) == 3
    assert await count(tenant) == 2
    # Each machine keeps its session-id record and loses the duplicate old one.
    assert await count(tenant, "select count(*) from device_sources where tenant_id = :t and vendor = 'screenconnect' and external_id like '%::%'") == 0
    assert await count(tenant, "select count(*) from device_sources where tenant_id = :t and vendor = 'screenconnect'") == 2


async def test_two_real_session_records_with_the_same_name_are_still_left_alone(tenant):
    await report(tenant, "screenconnect", "11111111-1111-4111-8111-111111111111", "FRONT-DESK")
    await report(tenant, "screenconnect", "22222222-2222-4222-8222-222222222222", "FRONT-DESK")
    assert await merge_pass(tenant) == 0
    assert await count(tenant) == 2


async def test_two_dnsfilter_records_of_one_name_are_one_reinstalled_machine_but_two_records_of_another_tool_are_not(tenant):
    # DNSFilter keeps an old record for every agent install, so a re-imaged PC appears there twice.
    await report(tenant, "dnsfilter", "d-old", "CFGCDT293", os="Microsoft Windows 10 Pro")
    await report(tenant, "dnsfilter", "d-new", "CFGCDT293", os="Microsoft Windows 11 Pro")
    await report(tenant, "ninjaone", "n1", "OTHER-PC", os="Microsoft Windows 11 Pro")
    await report(tenant, "ninjaone", "n2", "OTHER-PC", os="Microsoft Windows 11 Pro")
    assert await count(tenant) == 4
    assert await merge_pass(tenant) == 1
    assert await count(tenant) == 3
    # Both DNSFilter records stay on the one device, so the tool does not re-create the old one on its next sync.
    assert await count(tenant, "select count(*) from device_sources where tenant_id = :t and vendor = 'dnsfilter'") == 2
    assert await count(tenant, "select count(distinct device_id) from device_sources where tenant_id = :t and vendor = 'dnsfilter'") == 1


async def test_a_dnsfilter_pair_is_still_left_alone_when_one_is_a_mac_or_the_serials_differ(tenant):
    await report(tenant, "dnsfilter", "d1", "FRONT-1", os="Microsoft Windows 11 Pro")
    await report(tenant, "dnsfilter", "d2", "FRONT-1", os="macOS 14")
    await report(tenant, "dnsfilter", "d3", "FRONT-2", serial="AAA1")
    await report(tenant, "huntress", "h3", "FRONT-2", serial="BBB2")
    assert await merge_pass(tenant) == 0


async def test_a_machine_reinstalled_many_times_does_not_look_like_a_stock_name(tenant):
    # Seven records of one name: the real device and six old DNSFilter agent records. They are one machine, not a name too common to trust.
    await report(tenant, "ninjaone", "n1", "GSCTX-JM8NLW2", serial="JM8NLW2", os="Windows 11 Pro")
    for i in range(6):
        await report(tenant, "dnsfilter", f"d{i}", "GSCTX-JM8NLW2", os="Microsoft Windows 11 Business")
    assert await count(tenant) == 7
    assert await merge_pass(tenant) == 6
    assert await count(tenant) == 1
    assert await count(tenant, "select count(*) from device_sources where tenant_id = :t and vendor = 'dnsfilter'") == 6


async def test_seven_records_from_seven_different_tools_are_still_too_common_a_name_to_merge(tenant):
    for i, tool in enumerate(["ninjaone", "huntress", "addigy", "threatmate", "autoelevate", "blumira", "screenconnect"]):
        await report(tenant, tool, f"x{i}", "SHARED-NAME-7")
    assert await merge_pass(tenant) == 0


async def test_a_persons_mac_name_merges_inside_a_client_but_a_bare_factory_name_never_does(tenant):
    from app.services.device_merge import usable_for_merge

    assert usable_for_merge("katrinas-macbook-pro") and usable_for_merge("amandas-macbook-pro-2.local".split(".")[0])
    assert not any(usable_for_merge(x) for x in ("macbook-pro", "mac", "macbook-air", "macbookpro", "imac"))
    await report(tenant, "screenconnect", "Acme::Katrinas-MacBook-Pro", "Katrinas-MacBook-Pro", os="Mac OS X")
    await report(tenant, "ninjaone", "n1", "Katrinas-MacBook-Pro.local", serial="LXMP7DC6MG", os="macOS 26.6.2 (25G83)")
    await report(tenant, "ninjaone", "n2", "MacBook-Pro", serial="AAAA111111", os="macOS 26")
    await report(tenant, "screenconnect", "s9", "MacBook-Pro", os="Mac OS X")
    assert await merge_pass(tenant) == 1
    assert await count(tenant) == 3
