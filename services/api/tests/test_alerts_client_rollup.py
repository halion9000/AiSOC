"""The alerts list for an MSSP parent includes its client tenants' alerts, labelled and filterable by client."""

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import alerts as ep
from app.db.database import Base
from app.models.alert import Alert
from app.models.tenant import Tenant
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
scoped: list[uuid.UUID] = []


@contextlib.asynccontextmanager
async def record_scope(_db, tenant_id):
    scoped.append(tenant_id)
    yield


ep.acting_as_tenant = record_scope  # the real one sets a Postgres setting; these tests run on SQLite


def run(fn):
    async def main():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as c:
            await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[Tenant.__table__, Alert.__table__]))
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            try:
                return await fn(s)
            finally:
                await engine.dispose()

    scoped.clear()
    return asyncio.run(main())


def tenant(name, parent=None):
    return Tenant(id=uuid.uuid4(), name=name, slug=f"{name}-{uuid.uuid4().hex[:6]}".lower(), parent_tenant_id=parent)


def alert(t, title, minutes=0, severity="medium"):
    at = NOW - timedelta(minutes=minutes)
    return Alert(
        tenant_id=t.id, title=title, description="", severity=severity, status="new", priority=3, created_at=at, updated_at=at,
        event_time=at, first_seen=at, last_seen=at, mitre_tactics=[], mitre_techniques=[], ai_recommendations=[],
        affected_ips=[], affected_hosts=[], affected_users=[], tags=[], connector_type="Generic Generic JSON", raw_event={},
    )  # fmt: skip


async def seed(s):
    parent, a, b, other = tenant("Live Oak"), None, None, tenant("Unrelated")
    a, b = tenant("Setpoint", parent.id), tenant("Tecovas", parent.id)
    s.add_all([parent, a, b, other])
    await s.flush()
    s.add_all(
        [
            alert(parent, "own", 5),
            alert(a, "setpoint-new", 1),
            alert(a, "setpoint-old", 30),
            alert(b, "tecovas", 3),
            alert(other, "secret", 0),
        ]
    )
    await s.commit()
    return parent, a, b, other


def call(s, user_tenant, **kw):
    user = SimpleNamespace(tenant_id=user_tenant, user_id=uuid.uuid4())
    args = {
        "page": 1,
        "page_size": 25,
        "severity": None,
        "status": None,
        "category": None,
        "assigned_to_me": False,
        "search": None,
        "min_confidence": None,
        "confidence_label": None,
        "source": None,
        "client_id": None,
    }
    args.update(kw)
    return ep.list_alerts(user, s, **args)


def test_parent_sees_own_and_client_alerts_newest_first_with_client_names():
    async def go(s):
        parent, a, b, other = await seed(s)
        out = await call(s, parent.id)
        assert [i.title for i in out.items] == ["setpoint-new", "tecovas", "own", "setpoint-old"]
        assert {i.title: i.client_name for i in out.items} == {
            "setpoint-new": "Setpoint",
            "tecovas": "Tecovas",
            "own": None,
            "setpoint-old": "Setpoint",
        }
        assert out.total == 4  # nobody else's alert

    run(go)


def test_client_filter_narrows_and_rejects_foreign_tenants():
    async def go(s):
        parent, a, b, other = await seed(s)
        out = await call(s, parent.id, client_id=a.id)
        assert [i.title for i in out.items] == ["setpoint-new", "setpoint-old"]
        assert out.total == 2
        with pytest.raises(HTTPException) as e:
            await call(s, parent.id, client_id=other.id)
        assert e.value.status_code == 404

    run(go)


def test_pagination_across_tenants():
    async def go(s):
        parent, *_ = await seed(s)
        p1 = await call(s, parent.id, page=1, page_size=3)
        p2 = await call(s, parent.id, page=2, page_size=3)
        assert [i.title for i in p1.items] == ["setpoint-new", "tecovas", "own"]
        assert [i.title for i in p2.items] == ["setpoint-old"]
        assert p1.total == 4 and p1.pages == 2

    run(go)


def test_filters_apply_to_every_tenant():
    async def go(s):
        parent, a, b, _ = await seed(s)
        s.add(alert(b, "tecovas-critical", 2, severity="critical"))
        await s.commit()
        out = await call(s, parent.id, severity="critical")
        assert [i.title for i in out.items] == ["tecovas-critical"]

    run(go)


def test_a_client_sees_only_itself_and_a_plain_tenant_reads_unscoped():
    async def go(s):
        parent, a, b, _ = await seed(s)
        out = await call(s, a.id)
        assert [i.title for i in out.items] == ["setpoint-new", "setpoint-old"]
        assert all(i.client_name is None for i in out.items)
        assert scoped == []  # one tenant: no cross-tenant scoping needed

    run(go)


def test_each_tenant_is_read_as_itself():
    async def go(s):
        parent, a, b, _ = await seed(s)
        await call(s, parent.id)
        assert set(scoped) == {parent.id, a.id, b.id}

    run(go)


def test_summary_counts_the_whole_scope_whatever_the_severity_and_status_filters_say():
    async def go(s):
        parent, a, b, other = await seed(s)
        s.add_all([alert(a, "crit", 2, severity="critical"), alert(b, "high", 2, severity="high")])
        done = alert(b, "closed-high", 2, severity="high")
        done.status = "resolved"
        s.add(done)
        await s.commit()
        out = await call(s, parent.id, severity="critical")
        assert [i.title for i in out.items] == ["crit"]  # the list is filtered...
        # ...the tally is not: 4 + 3 new alerts across own + clients, none of them the unrelated tenant's
        assert out.summary.model_dump() == {"total": 7, "critical": 1, "high": 2, "unresolved": 6}
        narrowed = await call(s, parent.id, client_id=b.id)
        assert narrowed.summary.model_dump() == {"total": 3, "critical": 0, "high": 2, "unresolved": 2}

    run(go)
