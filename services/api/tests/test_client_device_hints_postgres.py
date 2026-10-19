"""Remembering the machine names of unmapped clients and using them to suggest the client, against a REAL Postgres (opt in with AISOC_TEST_PG_URL; the database needs migration 092)."""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.api.v1.endpoints import devices as ep
from app.db.rls import set_rls_context
from app.db.rls_scope import acting_as_tenant
from app.models.client_alias import ClientAlias
from app.services.client_mapping import device_overlaps, record_device_hints, suggestions_with_devices
from app.services.client_matching import Candidate
from app.services.device_upsert import DeviceReport, upsert_device
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database (with migration 092)"
)

HOSTS = ["PC-FRONT-1", "PC-FRONT-2", "PC-BACK-1", "PC-BACK-2", "SRV-FILE-1"]


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:8]
    ids = {k: uuid.uuid4() for k in ("msp", "pirkey", "acme")}
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for key, parent in (("msp", None), ("pirkey", ids["msp"]), ("acme", ids["msp"])):
            await c.execute(
                text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, :p)"),
                {"i": ids[key], "n": f"{key}-{tag}", "s": f"{key}-{tag}", "p": parent},
            )
    yield ids
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
    await engine.dispose()


async def run(owner, work):
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            await set_rls_context(db, owner)
            out = await work(db)
            await db.commit()
            return out
    finally:
        await engine.dispose()


async def seed_devices(tenant, names, vendor="ninjaone"):
    async def work(db):
        async with acting_as_tenant(db, tenant):
            for i, n in enumerate(names):
                await upsert_device(db, tenant, DeviceReport(vendor, f"{vendor}-{i}", n, ip_addresses=[]))

    await run(tenant, work)


def report(client, hosts):
    return ep.DevicesReport(
        items=[
            ep.DeviceIn(vendor="autoelevate", vendor_client_id=client, external_id=f"ae-{client}-{i}", hostname=h)
            for i, h in enumerate(hosts)
        ]
    )


async def scalar(sql, **p):
    engine = create_async_engine(PG_URL)
    try:
        async with engine.connect() as c:
            return (await c.execute(text(sql), p)).scalar_one()
    finally:
        await engine.dispose()


async def test_unmapped_machines_are_remembered_and_point_at_the_client_that_already_has_them(world):
    msp = world["msp"]
    await seed_devices(world["pirkey"], HOSTS)
    await seed_devices(world["acme"], ["ACME-1", "ACME-2", "ACME-3"])
    out = await run(msp, lambda db: ep.apply_devices(db, msp, report("ae-pirkey", [h.lower() for h in HOSTS[:4]] + ["PC-NEW-1"])))
    assert (out.accepted, out.unmapped) == (0, 5)
    assert await scalar("select count(*) from client_device_hints where tenant_id = :t and vendor_client_id = 'ae-pirkey'", t=msp) == 5

    async def work(db):
        overlaps = await device_overlaps(db, msp, [world["pirkey"], world["acme"]], lambda tid: acting_as_tenant(db, tid))
        alias = ClientAlias(
            vendor="autoelevate",
            vendor_client_id="ae-pirkey",
            vendor_client_name="Totally Different Name",
            child_tenant_id=None,
            ignored=False,
        )
        cands = [Candidate(str(world["pirkey"]), "Pirkey Barber PLLC"), Candidate(str(world["acme"]), "Acme Dental")]
        return overlaps, suggestions_with_devices(alias, cands, overlaps)

    overlaps, suggestions = await run(msp, work)
    assert [(o.tenant_id, o.shared, o.total) for o in overlaps[("autoelevate", "ae-pirkey")]] == [(str(world["pirkey"]), 4, 5)]
    assert [s.tenant_id for s in suggestions] == [str(world["pirkey"])]
    assert suggestions[0].reason == "4 of its 5 devices are already under this client"


async def test_a_mapped_client_leaves_no_hints_and_a_repeat_does_not_duplicate(world):
    msp = world["msp"]

    async def map_it(db):
        db.add(
            ClientAlias(
                tenant_id=msp,
                vendor="autoelevate",
                vendor_client_id="ae-mapped",
                vendor_client_name="Mapped",
                normalized_name="mapped",
                child_tenant_id=world["acme"],
                ignored=False,
                match_source="manual",
            )
        )

    await run(msp, map_it)
    await run(msp, lambda db: ep.apply_devices(db, msp, report("ae-mapped", ["M-1", "M-2"])))
    assert await scalar("select count(*) from client_device_hints where tenant_id = :t and vendor_client_id = 'ae-mapped'", t=msp) == 0
    await run(msp, lambda db: ep.apply_devices(db, msp, report("ae-x", ["X-1", "X-2"])))
    await run(msp, lambda db: ep.apply_devices(db, msp, report("ae-x", ["X-1", "X-2"])))
    assert await scalar("select count(*) from client_device_hints where tenant_id = :t and vendor_client_id = 'ae-x'", t=msp) == 2


async def test_at_most_three_hundred_names_per_client_are_kept_and_stale_ones_are_forgotten(world):
    msp = world["msp"]
    await run(msp, lambda db: record_device_hints(db, msp, "autoelevate", "big", [f"host-{i}" for i in range(450)]))
    assert await scalar("select count(*) from client_device_hints where tenant_id = :t and vendor_client_id = 'big'", t=msp) == 300
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(
            text(
                "update client_device_hints set seen_at = :old where tenant_id = :t and vendor_client_id = 'big' and hostname_key < 'host-2'"
            ),
            {"t": msp, "old": datetime.now(UTC) - timedelta(days=20)},
        )
    await engine.dispose()
    await run(msp, lambda db: record_device_hints(db, msp, "autoelevate", "big", ["host-0", "host-1"]))
    assert (
        await scalar(
            "select count(*) from client_device_hints where tenant_id = :t and vendor_client_id = 'big' and seen_at < now() - interval '14 days'",
            t=msp,
        )
        == 0
    ), "stale names are gone"
    assert (
        await scalar(
            "select count(*) from client_device_hints where tenant_id = :t and vendor_client_id = 'big' and hostname_key in ('host-0', 'host-1')",
            t=msp,
        )
        == 2
    ), "the ones reported again are kept"
    assert (
        await scalar("select count(*) from client_device_hints where tenant_id = :t and vendor_client_id = 'big'", t=msp) < 300
    ), "the stale ones were dropped"
