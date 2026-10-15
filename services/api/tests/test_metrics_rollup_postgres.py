"""The dashboard totals an MSSP parent and its clients, against a REAL Postgres (AISOC_TEST_PG_URL / AISOC_TEST_PG_APP_URL)."""

import os
import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints.metrics import get_dashboard_metrics
from app.db.rls import set_rls_context
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
    ids = {k: uuid.uuid4() for k in ("parent", "acme", "birch", "stranger")}
    owner = create_async_engine(PG_URL)
    try:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            for key, tid in ids.items():
                parent = ids["parent"] if key in ("acme", "birch") else None
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                    {"i": tid, "n": f"{key}-{tag}", "s": f"{key}-{tag}", "p": parent, "r": "child" if parent else "parent"},
                )
            for key, severity, n in [("acme", "critical", 3), ("birch", "high", 2), ("stranger", "critical", 9)]:
                for i in range(n):
                    await conn.execute(
                        text("insert into alerts (tenant_id, title, severity) values (:t, :title, :s)"),
                        {"t": ids[key], "title": f"{key}-{i}", "s": severity},
                    )
        yield ids
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(text("delete from alerts where tenant_id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
            await conn.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
        await owner.dispose()


async def dashboard_as(tenant_id):
    engine = create_async_engine(APP_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            await set_rls_context(db, tenant_id)
            return await get_dashboard_metrics(user=SimpleNamespace(tenant_id=tenant_id), db=db)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_parent_dashboard_totals_clients_but_not_strangers(world) -> None:
    result = await dashboard_as(world["parent"])
    assert result.alerts.total == 5
    assert result.alerts.critical == 3
    assert result.alerts.high == 2


@pytest.mark.asyncio
async def test_client_dashboard_stays_its_own(world) -> None:
    result = await dashboard_as(world["acme"])
    assert result.alerts.total == 3
