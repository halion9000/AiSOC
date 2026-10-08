"""The MSSP dashboard's API returns REAL tenants, never invented ones.

/mssp/overview, /mssp/tenants and /mssp/incidents used to return module-level constants: five invented tenants ("Acme Corp", "Globex Industries",
"Initech LLC", "Wayne Enterprises", "Stark Solutions"), five invented incidents assigned to invented analysts, and an overview with a fixed 23.4-minute
MTTR and "3 connectors online". Every workspace, including one with no MSSP children at all, showed them.

Now: the managed tenants are the caller's real child tenants, each with its latest metrics snapshot if there is one (``has_metrics`` False and every
metric ``None`` if not: nothing in this codebase writes snapshots yet, and a missing number must not be replaced by a made-up one), and there is
no cross-tenant incident feed yet, so that route returns an empty list. Runs against a real database engine (in-memory SQLite).
"""
import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.v1.endpoints import mssp
from app.db.database import Base
from app.models.mssp import MSSPTenantMetrics
from app.models.tenant import Tenant

TABLES = [m.__table__ for m in (Tenant, MSSPTenantMetrics)]
INVENTED = ["Acme Corp", "Globex Industries", "Initech LLC", "Wayne Enterprises", "Stark Solutions", "INC-4201", "Jordan Lee", "Morgan Chen", "t-acme"]


def run(coro_fn):
    """Run `coro_fn(session, world)` against a fresh in-memory database."""

    async def main():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as c:
            await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=TABLES))
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            await s.commit()
            try:
                return await coro_fn(s)
            finally:
                await engine.dispose()

    return asyncio.run(main())


async def tenant(s, name, parent=None):
    t = Tenant(id=uuid.uuid4(), name=name, slug=f"{name}-{uuid.uuid4().hex[:6]}".lower().replace(" ", "-"), parent_tenant_id=parent)
    s.add(t)
    await s.flush()
    return t


def snapshot(t, *, minutes_ago=0, open_alerts=0, critical=0, cases=0, mttr=None, breaches=0, connectors=0, health=None):
    return MSSPTenantMetrics(
        id=uuid.uuid4(), tenant_id=t.id, snapshot_at=datetime.now(UTC) - timedelta(minutes=minutes_ago), open_alerts=open_alerts, critical_alerts=critical,
        open_cases=cases, mttr_minutes=mttr, sla_breaches=breaches, connector_count=connectors, health_score=health, raw_data={},
    )


def caller(t):
    return SimpleNamespace(tenant_id=t.id)


def test_a_workspace_with_no_children_has_no_managed_tenants_and_no_figures():
    """The reported case: a normal workspace saw five demo tenants."""

    async def body(s):
        solo = await tenant(s, "My Workspace")
        await s.commit()
        rows = await mssp.list_managed_tenants(db=s, current_user=caller(solo))
        overview = await mssp.mssp_overview(db=s, current_user=caller(solo))
        return rows, overview

    rows, overview = run(body)
    assert rows == []
    assert overview.total_tenants == 0 and overview.tenants_reporting == 0
    for figure in (overview.total_open_alerts, overview.total_critical_alerts, overview.total_open_cases, overview.avg_health_score, overview.avg_mttr_minutes, overview.sla_breach_count):
        assert figure is None


def test_real_children_are_listed_by_name_with_no_metrics_until_a_snapshot_exists():
    async def body(s):
        parent = await tenant(s, "Parent MSSP")
        await tenant(s, "Zeta Customer", parent.id)
        await tenant(s, "Alpha Customer", parent.id)
        await s.commit()
        return await mssp.list_managed_tenants(db=s, current_user=caller(parent)), await mssp.mssp_overview(db=s, current_user=caller(parent))

    rows, overview = run(body)
    assert [r.name for r in rows] == ["Alpha Customer", "Zeta Customer"]
    for row in rows:
        assert row.has_metrics is False
        assert (row.snapshot_at, row.health_score, row.open_alerts, row.critical_alerts, row.open_cases, row.mttr_minutes, row.sla_breaches, row.connector_count) == (None,) * 8
    assert overview.total_tenants == 2 and overview.tenants_reporting == 0 and overview.total_open_alerts is None


def test_the_newest_snapshot_wins_and_totals_cover_only_tenants_that_report():
    async def body(s):
        parent = await tenant(s, "Parent MSSP")
        reporting = await tenant(s, "Reporting Customer", parent.id)
        silent = await tenant(s, "Silent Customer", parent.id)
        s.add_all(
            [
                snapshot(reporting, minutes_ago=600, open_alerts=99, critical=9, cases=9, mttr=999.0, breaches=9, connectors=9, health=10.0),  # stale: must lose
                snapshot(reporting, minutes_ago=5, open_alerts=12, critical=2, cases=4, mttr=30.0, breaches=1, connectors=3, health=80.0),
            ]
        )
        await s.commit()
        return await mssp.list_managed_tenants(db=s, current_user=caller(parent)), await mssp.mssp_overview(db=s, current_user=caller(parent)), silent

    rows, overview, silent = run(body)
    by_name = {r.name: r for r in rows}
    fresh = by_name["Reporting Customer"]
    assert fresh.has_metrics and (fresh.open_alerts, fresh.critical_alerts, fresh.open_cases, fresh.mttr_minutes, fresh.sla_breaches, fresh.connector_count, fresh.health_score) == (12, 2, 4, 30.0, 1, 3, 80.0)
    assert by_name["Silent Customer"].has_metrics is False
    assert overview.total_tenants == 2 and overview.tenants_reporting == 1
    assert (overview.total_open_alerts, overview.total_critical_alerts, overview.total_open_cases, overview.sla_breach_count) == (12, 2, 4, 1)
    assert (overview.avg_health_score, overview.avg_mttr_minutes) == (80.0, 30.0)


def test_averages_ignore_a_snapshot_that_has_no_health_or_mttr():
    async def body(s):
        parent = await tenant(s, "Parent MSSP")
        a, b = await tenant(s, "A", parent.id), await tenant(s, "B", parent.id)
        s.add_all([snapshot(a, health=60.0, mttr=20.0), snapshot(b, health=None, mttr=None, open_alerts=3)])
        await s.commit()
        return await mssp.mssp_overview(db=s, current_user=caller(parent))

    overview = run(body)
    assert overview.tenants_reporting == 2 and overview.total_open_alerts == 3
    assert overview.avg_health_score == 60.0 and overview.avg_mttr_minutes == 20.0  # not dragged down by a missing value counted as zero


def test_another_tenants_children_and_snapshots_never_appear():
    async def body(s):
        mine = await tenant(s, "My MSSP")
        mine_child = await tenant(s, "My Customer", mine.id)
        other = await tenant(s, "Other MSSP")
        other_child = await tenant(s, "Other Customer", other.id)
        stranger = await tenant(s, "Unrelated Tenant")
        s.add_all([snapshot(mine_child, open_alerts=1), snapshot(other_child, open_alerts=500), snapshot(stranger, open_alerts=700)])
        await s.commit()
        return await mssp.list_managed_tenants(db=s, current_user=caller(mine)), await mssp.mssp_overview(db=s, current_user=caller(mine))

    rows, overview = run(body)
    assert [r.name for r in rows] == ["My Customer"]
    assert overview.total_tenants == 1 and overview.total_open_alerts == 1


def test_there_is_no_cross_tenant_incident_feed_and_none_is_invented():
    async def body(s):
        parent = await tenant(s, "Parent MSSP")
        await s.commit()
        return await mssp.list_cross_tenant_incidents(severity=None, db=s, current_user=caller(parent)), await mssp.list_cross_tenant_incidents(severity="high", db=s, current_user=caller(parent))

    unfiltered, filtered = run(body)
    assert unfiltered == [] and filtered == []


def test_none_of_the_invented_demo_names_can_come_back():
    async def body(s):
        solo = await tenant(s, "Real Workspace")
        parent = await tenant(s, "Real MSSP")
        await tenant(s, "Real Customer", parent.id)
        await s.commit()
        out = []
        for who in (solo, parent):
            out += [await mssp.list_managed_tenants(db=s, current_user=caller(who)), await mssp.mssp_overview(db=s, current_user=caller(who)), await mssp.list_cross_tenant_incidents(severity=None, db=s, current_user=caller(who))]
        return repr(out)

    text = run(body)
    for name in INVENTED:
        assert name not in text, f"{name} is back"


def test_the_module_no_longer_defines_mock_data():
    assert not hasattr(mssp, "_MSSP_TENANTS_MOCK") and not hasattr(mssp, "_MSSP_INCIDENTS_MOCK")


@pytest.mark.parametrize("path", ["/tenants", "/overview", "/incidents"])
def test_the_routes_still_require_mssp_read(path):
    from fastapi.routing import APIRoute

    from route_introspect import required_permissions

    routes = [r for r in mssp.router.routes if isinstance(r, APIRoute) and r.path.endswith(path) and "GET" in r.methods]
    assert len(routes) == 1
    assert required_permissions(routes[0]) == ["mssp:read"]
