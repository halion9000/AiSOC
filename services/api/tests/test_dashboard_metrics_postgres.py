"""The dashboard's KPI endpoint against a REAL Postgres as the restricted role (`aisoc_app`) with fail-closed row-level security ON.

It answered 500 on a real database ("alerts.raw_event must appear in the GROUP BY clause") because the per-vendor count grouped by a second copy of a JSON expression whose bind
parameter differs from the selected one. No mocked database can show that: only Postgres parses the statement.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), as the sibling tests do. The database must be disposable.
"""

import os
import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints.metrics import get_dashboard_metrics
from app.db.rls import set_rls_context
from app.db.rls_hook import tag_session
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)


@pytest.fixture
async def world():
    tid = uuid.uuid4()
    owner = create_async_engine(PG_URL)
    app = create_async_engine(APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}})
    try:
        async with owner.begin() as conn:
            slug = f"dash-{tid.hex[:8]}"
            await conn.execute(text("insert into tenants (id, name, slug) values (:i, :n, :s)"), {"i": tid, "n": slug, "s": slug})
            await conn.execute(
                text(
                    "insert into connectors (id, tenant_id, name, connector_type, category, is_enabled, connector_config, health_status, tags, events_ingested, error_count) "
                    "values (gen_random_uuid(), :t, 'Huntress (via CORE)', 'core_feed', 'edr', true, cast('{\"vendor\": \"huntress\"}' as jsonb), 'healthy', '[]', 0, 0)"
                ),
                {"t": tid},
            )
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            for source in ("huntress", "huntress", "petra"):
                await conn.execute(
                    text(
                        "insert into alerts (id, tenant_id, title, severity, status, raw_event, created_at, event_time, first_seen, last_seen) values "
                        "(gen_random_uuid(), :t, 'a', 'high', 'new', cast(:raw as jsonb), now(), now(), now(), now())"
                    ),
                    {"t": tid, "raw": f'{{"source": "{source}"}}'},
                )
        yield {"tenant": tid, "factory": async_sessionmaker(app, expire_on_commit=False)}
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            for table in ("alerts", "connectors"):
                await conn.execute(text(f"delete from {table} where tenant_id = :t"), {"t": tid})
            await conn.execute(text("delete from tenants where id = :t"), {"t": tid})
        await app.dispose()
        await owner.dispose()


async def test_the_dashboard_answers_and_counts_each_vendor_separately(world):
    async with world["factory"]() as session:
        await tag_session(session, world["tenant"])
        await set_rls_context(session, world["tenant"])
        out = await get_dashboard_metrics(SimpleNamespace(tenant_id=world["tenant"]), session)
    assert out.alerts.total == 3 and out.alerts.high == 3
    by_name = {s.name: s.count for s in out.sources}
    assert by_name == {"Huntress (via CORE)": 2}, "the row for CORE's Huntress feed counts Huntress alerts only"
