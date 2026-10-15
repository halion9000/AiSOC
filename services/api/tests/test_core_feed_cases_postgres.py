"""Auto-opened cases for new high/critical CORE alerts, against a REAL Postgres as the restricted role (`aisoc_app`) with fail-closed row-level security ON.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), as the sibling tests do. The database must be disposable.
"""

import os
import uuid
from datetime import UTC, datetime

import pytest
from app.db.rls import set_rls_context
from app.db.rls_hook import tag_session
from app.services import core_feed_cases as cfc
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
    tag = uuid.uuid4().hex[:10]
    ids = {k: uuid.uuid4() for k in ("parent", "child")}
    owner = create_async_engine(PG_URL)
    app = create_async_engine(APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}})
    alerts: dict[str, uuid.UUID] = {}
    try:
        async with owner.begin() as conn:
            for key, tid in ids.items():
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                    {
                        "i": tid,
                        "n": f"fc-{key}-{tag}",
                        "s": f"fc-{key}-{tag}",
                        "p": None if key == "parent" else ids["parent"],
                        "r": "parent" if key == "parent" else "child",
                    },
                )
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            rows = [  # name, tenant, severity, status, source, age (hours)
                ("crit_child", "child", "critical", "new", "huntress", 1),
                ("high_parent", "parent", "high", "new", "petra", 2),
                ("low", "child", "low", "new", "huntress", 1),
                ("old", "child", "critical", "new", "huntress", 48),
                ("worked", "child", "critical", "resolved", "huntress", 1),
                ("manual", "child", "critical", "new", "aisoc-submit-api", 1),
            ]
            for name, who, sev, status, source, age in rows:
                aid = uuid.uuid4()
                alerts[name] = aid
                await conn.execute(
                    text(
                        "insert into alerts (id, tenant_id, title, severity, status, raw_event, created_at, event_time, first_seen, last_seen) "
                        "values (:id, :t, :title, :sev, :st, cast(:raw as jsonb), now() - make_interval(hours => :age), now(), now(), now())"
                    ),
                    {
                        "id": aid,
                        "t": ids[who],
                        "title": f"alert {name}",
                        "sev": sev,
                        "st": status,
                        "raw": f'{{"source": "{source}"}}',
                        "age": age,
                    },
                )
        yield {**ids, "alerts": alerts, "owner": owner, "factory": async_sessionmaker(app, expire_on_commit=False)}
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(text("delete from aisoc_cases where tenant_id = any(:t)"), {"t": list(ids.values())})
            await conn.execute(text("delete from alerts where tenant_id = any(:t)"), {"t": list(ids.values())})
            await conn.execute(text("delete from tenants where id = any(:t)"), {"t": [ids["child"], ids["parent"]]})
        await app.dispose()
        await owner.dispose()


async def _run(world):
    async with world["factory"]() as session:
        await tag_session(session, world["parent"])
        await set_rls_context(session, world["parent"])
        opened = await cfc.open_cases_for_new_alerts(session, world["parent"], now=datetime.now(UTC))
        await session.commit()
    return opened


async def test_opens_one_linked_case_per_new_high_or_critical_alert_and_only_once(world):
    assert await _run(world) == 2  # the critical alert in the client tenant and the high one in the workspace
    assert await _run(world) == 0  # nothing new the second time

    async with world["owner"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', false)"))
        cases = (
            await conn.execute(
                text(
                    "select tenant_id, title, severity, alert_ids, tags->>'vendor' from aisoc_cases where tenant_id = any(:t) order by title"
                ),
                {"t": [world["parent"], world["child"]]},
            )
        ).all()
        linked = {
            r[0]: r[1]
            for r in (
                await conn.execute(
                    text("select id, case_id from alerts where tenant_id = any(:t)"), {"t": [world["parent"], world["child"]]}
                )
            ).all()
        }
    assert [(c[0], c[1], c[2], c[4]) for c in cases] == [
        (world["child"], "alert crit_child", "critical", "huntress"),
        (world["parent"], "alert high_parent", "high", "petra"),
    ]
    assert cases[0][3] == [world["alerts"]["crit_child"]] and cases[1][3] == [world["alerts"]["high_parent"]]
    got = {name: linked[aid] is not None for name, aid in world["alerts"].items()}
    assert got == {"crit_child": True, "high_parent": True, "low": False, "old": False, "worked": False, "manual": False}
