"""SLA events for alerts CORE reports closed, against a REAL Postgres as the restricted role (`aisoc_app`) with fail-closed row-level security ON.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), as the sibling tests do. The database must be disposable.
"""

import json
import os
import uuid
from datetime import UTC, datetime

import pytest
from app.api.v1.endpoints.inbox_core_feed import ClosedItem, ClosedReport, apply_closed
from app.db.rls import set_rls_context
from app.db.rls_hook import tag_session
from app.db.rls_scope import acting_as_tenant
from app.services import sla
from app.services.core_feed_sla import record_closure_events
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
    alerts: dict[str, uuid.UUID] = {}
    owner = create_async_engine(PG_URL)
    app = create_async_engine(APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}})
    try:
        async with owner.begin() as conn:
            for key, tid in ids.items():
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                    {
                        "i": tid,
                        "n": f"sla-{key}-{tag}",
                        "s": f"sla-{key}-{tag}",
                        "p": None if key == "parent" else ids["parent"],
                        "r": "parent" if key == "parent" else "child",
                    },
                )
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            rows = [  # name, status, finding uid, severity, age (hours)
                ("closed_in_vendor", "new", "huntress:1", "high", 3),
                ("still_open", "new", "huntress:2", "high", 3),
                ("analyst_handled", "triaging", "huntress:3", "high", 3),
            ]
            for name, st, uid, sev, age in rows:
                aid = uuid.uuid4()
                alerts[name] = aid
                await conn.execute(
                    text(
                        "insert into alerts (id, tenant_id, title, severity, status, raw_event, created_at, event_time, first_seen, last_seen) values "
                        "(:id, :t, :n, :sev, :st, cast(:raw as jsonb), now() - make_interval(hours => :age), now(), now(), now())"
                    ),
                    {
                        "id": aid,
                        "t": ids["child"],
                        "n": name,
                        "sev": sev,
                        "st": st,
                        "raw": json.dumps({"finding": {"uid": uid}}),
                        "age": age,
                    },
                )
        yield {**ids, "alerts": alerts, "owner": owner, "factory": async_sessionmaker(app, expire_on_commit=False)}
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(text("delete from alert_sla_events where tenant_id = any(:t)"), {"t": list(ids.values())})
            await conn.execute(text("delete from alerts where tenant_id = any(:t)"), {"t": list(ids.values())})
            await conn.execute(text("delete from tenants where id = any(:t)"), {"t": [ids["child"], ids["parent"]]})
        await app.dispose()
        await owner.dispose()


async def _close(world, uids, now=None, force_events=False):
    now = now or datetime.now(UTC)
    report = ClosedReport(vendor="huntress", closed=[ClosedItem(uid=u, state="resolved") for u in uids])
    async with world["factory"]() as session:
        await tag_session(session, world["parent"])
        await set_rls_context(session, world["parent"])
        async with acting_as_tenant(session, world["child"]):
            resolved = await apply_closed(session, world["child"], report, now)
            written = await record_closure_events(session, world["child"], "huntress", now) if resolved or force_events else 0
        await session.commit()
    return resolved, written


async def _events(world):
    async with world["owner"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', false)"))
        return (
            await conn.execute(
                text("select alert_id, event_type, severity from alert_sla_events where tenant_id = :t order by event_type"),
                {"t": world["child"]},
            )
        ).all()


async def test_closing_in_the_vendor_writes_detected_and_resolved_once_and_the_sla_page_can_use_them(world):
    assert await _close(world, ["huntress:1", "huntress:3"]) == (1, 2)  # the one still "new"; the analyst's alert is left alone
    mine = world["alerts"]["closed_in_vendor"]
    assert [(r[0], r[1], r[2]) for r in await _events(world)] == [(mine, "detected", "high"), (mine, "resolved", "high")]

    assert await _close(world, ["huntress:1"]) == (0, 0)  # already closed: nothing new, no duplicates
    assert len(await _events(world)) == 2
    # Even if the events step is run again for the same closure (a retried request), it adds nothing.
    async with world["owner"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', false)"))
        at = (
            await conn.execute(text("select enrichment_data->'closed_in_vendor'->>'at' from alerts where id = :a"), {"a": mine})
        ).scalar_one()
    assert await _close(world, [], now=datetime.fromisoformat(at), force_events=True) == (0, 0)
    assert len(await _events(world)) == 2

    async with world["factory"]() as session:
        await tag_session(session, world["child"])
        await set_rls_context(session, world["child"])
        metrics = await sla.compute_sla_metrics(session, world["child"], days=30)
    high = metrics["per_severity"]["high"]
    assert high["total"] == 1
    assert 170 <= high["mttr_avg"] <= 190  # created 3 hours before it was reported closed
    assert high["mttd_avg"] is None  # nobody acknowledged it, and that is not made up
