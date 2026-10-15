"""The per-client numbers on the MSSP overview, computed from each client's own alerts and cases."""

import asyncio
import contextlib
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

from app.db.database import Base
from app.models.alert import Alert
from app.models.client_alias import ClientAlias
from app.models.mssp import MSSPTenantMetrics
from app.models.tenant import Tenant
from app.services import mssp_snapshots as ms
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

sqlite3.register_adapter(uuid.UUID, str)  # the raw case queries bind a UUID; Postgres takes it natively, SQLite needs this

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


@contextlib.asynccontextmanager
async def no_scope(_db, _tenant):
    yield


def run(fn):
    async def main():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as c:
            await c.run_sync(
                lambda conn: Base.metadata.create_all(conn, tables=[m.__table__ for m in (Tenant, Alert, ClientAlias, MSSPTenantMetrics)])
            )
            await c.execute(
                text(
                    "CREATE TABLE aisoc_cases (id TEXT, tenant_id TEXT, status TEXT, created_at TIMESTAMP, resolved_at TIMESTAMP, closed_at TIMESTAMP, sla_due_at TIMESTAMP)"
                )
            )
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            try:
                return await fn(s)
            finally:
                await engine.dispose()

    return asyncio.run(main())


def tenant(name, parent=None):
    return Tenant(id=uuid.uuid4(), name=name, slug=f"{name}-{uuid.uuid4().hex[:6]}".lower().replace(" ", "-"), parent_tenant_id=parent)


def alert(t, severity="medium", status="new", created=NOW - timedelta(hours=5), resolved=None):
    return Alert(
        tenant_id=t.id, title="x", severity=severity, status=status, priority=3, created_at=created, resolved_at=resolved, updated_at=created, event_time=created, first_seen=created, last_seen=created,
        mitre_tactics=[], mitre_techniques=[], ai_recommendations=[], affected_ips=[], affected_hosts=[], affected_users=[], tags=[], raw_event={},
    )  # fmt: skip


def test_each_client_gets_its_own_counts_and_nothing_made_up():
    async def body(s):
        parent, a, b = tenant("Parent"), None, None
        s.add(parent)
        await s.flush()
        a, b = tenant("A Client", parent.id), tenant("B Client", parent.id)
        s.add_all([a, b])
        await s.flush()
        s.add_all(
            [
                alert(a, "critical"),
                alert(a, "high"),
                alert(a, "high", "resolved", resolved=NOW - timedelta(hours=3)),  # 2h to resolve
                alert(b, "low"),
                ClientAlias(tenant_id=parent.id, vendor="huntress", vendor_client_id="1", vendor_client_name="A", normalized_name="a", child_tenant_id=a.id),
                ClientAlias(tenant_id=parent.id, vendor="halopsa", vendor_client_id="2", vendor_client_name="A", normalized_name="a", child_tenant_id=a.id),
            ]
        )  # fmt: skip
        await s.execute(
            text("INSERT INTO aisoc_cases VALUES ('c1', :t, 'new', :n, NULL, NULL, :due)"),
            {"t": str(a.id), "n": NOW - timedelta(days=1), "due": NOW - timedelta(hours=1)},
        )
        await s.commit()
        written = await ms.snapshot_children(s, parent.id, now=NOW, scope=no_scope)
        await s.commit()
        rows = {r.tenant_id: r for r in (await s.execute(select(MSSPTenantMetrics))).scalars()}
        return written, rows[a.id], rows[b.id]

    written, ra, rb = run(body)
    assert written == 2
    assert (ra.open_alerts, ra.critical_alerts, ra.open_cases, ra.sla_breaches, ra.connector_count) == (2, 1, 1, 1, 2)
    assert ra.mttr_minutes == 120.0 and ra.health_score is None
    assert (rb.open_alerts, rb.critical_alerts, rb.open_cases, rb.mttr_minutes, rb.connector_count) == (1, 0, 0, None, 0)


def test_a_recent_snapshot_is_refreshed_in_place_and_an_old_one_starts_a_new_row():
    async def body(s):
        parent = tenant("Parent")
        s.add(parent)
        await s.flush()
        child = tenant("Client", parent.id)
        s.add(child)
        await s.commit()
        await ms.snapshot_children(s, parent.id, now=NOW, scope=no_scope)
        await ms.snapshot_children(s, parent.id, now=NOW + timedelta(minutes=20), scope=no_scope)
        await s.commit()
        after_recent = len((await s.execute(select(MSSPTenantMetrics))).scalars().all())
        await ms.snapshot_children(s, parent.id, now=NOW + timedelta(hours=3), scope=no_scope)
        await s.commit()
        return after_recent, len((await s.execute(select(MSSPTenantMetrics))).scalars().all())

    assert run(body) == (1, 2)


def test_one_clients_failure_does_not_stop_the_others():
    async def body(s):
        parent = tenant("Parent")
        s.add(parent)
        await s.flush()
        bad, good = tenant("A Bad", parent.id), tenant("B Good", parent.id)
        s.add_all([bad, good])
        await s.commit()
        calls = []
        real = ms.compute_child_metrics

        async def flaky(db, child_id, tools, now):
            calls.append(child_id)
            if child_id == bad.id:
                raise RuntimeError("boom")
            return await real(db, child_id, tools, now)

        ms.compute_child_metrics = flaky
        try:
            written = await ms.snapshot_children(s, parent.id, now=NOW, scope=no_scope)
        finally:
            ms.compute_child_metrics = real
        await s.commit()
        return written, [r.tenant_id for r in (await s.execute(select(MSSPTenantMetrics))).scalars()], good.id

    written, saved, good_id = run(body)
    assert written == 1 and saved == [good_id]
