"""The client cleanup report against a REAL Postgres (opt in with AISOC_TEST_PG_URL, a DISPOSABLE, fully migrated database; the role must be allowed to write every table)."""

import os
import uuid
from types import SimpleNamespace as NS

import pytest
from app.api.v1.endpoints import mssp_clients as mc
from app.db.rls import set_rls_context
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database")


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:8]
    ids = {k: uuid.uuid4() for k in ("parent", "empty", "alerts", "mapped", "hidden")}
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for key, tid in ids.items():
            settings = '{"hidden": true}' if key == "hidden" else "{}"
            await c.execute(
                text(
                    "insert into tenants (id, name, slug, parent_tenant_id, mssp_role, settings) "
                    "values (:i, :n, :s, :p, :r, cast(:st as jsonb))"
                ),
                {
                    "i": tid,
                    "n": f"cl-{key}-{tag}",
                    "s": f"cl-{key}-{tag}",
                    "p": None if key == "parent" else ids["parent"],
                    "r": "parent" if key == "parent" else "child",
                    "st": settings,
                },
            )
        await c.execute(
            text("insert into alerts (id, tenant_id, title, severity, status) values (gen_random_uuid(), :t, 'x', 'low', 'new')"),
            {"t": ids["alerts"]},
        )
        await c.execute(
            text(
                "insert into client_aliases (id, tenant_id, vendor, vendor_client_id, vendor_client_name, normalized_name, child_tenant_id, ignored, match_source) "
                "values (gen_random_uuid(), :p, 'huntress', '1', 'Mapped', 'mapped', :c, false, 'manual')"
            ),
            {"p": ids["parent"], "c": ids["mapped"]},
        )
    yield ids
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
    await engine.dispose()


async def test_only_visible_clients_with_nothing_in_them_are_listed(world):
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            await set_rls_context(db, world["parent"])
            report = await mc.cleanup_report(NS(tenant_id=world["parent"]), db)
    finally:
        await engine.dispose()
    assert [c.id for c in report.empty] == [
        world["empty"]
    ], "one with an alert, one with a tool client mapped, and a hidden one are all left out"
    assert report.checked == 3, "the hidden client is not even counted"
    assert (report.empty[0].devices, report.empty[0].alerts, report.empty[0].cases) == (0, 0, 0)
