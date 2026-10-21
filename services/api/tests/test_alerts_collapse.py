"""One row per group of repeat alerts (same rule, machines and users): the newest, with a count."""

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
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)


@contextlib.asynccontextmanager
async def no_scope(_db, _tenant_id):
    yield




@pytest.fixture(autouse=True)
def _sqlite_has_no_tenant_scope(monkeypatch):
    """The real scope sets a Postgres setting; these tests run on SQLite. Patched per test (not at import) so no other test module sees it."""
    monkeypatch.setattr(ep, "acting_as_tenant", no_scope)


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

    return asyncio.run(main())


def tenant(name, parent=None):
    return Tenant(id=uuid.uuid4(), name=name, slug=f"{name}-{uuid.uuid4().hex[:6]}".lower(), parent_tenant_id=parent)


def alert(t, title, minutes, hosts=(), users=(), rule=None):
    at = NOW - timedelta(minutes=minutes)
    return Alert(
        tenant_id=t.id, title=title, rule_name=rule, description="", severity="medium", status="new", priority=3, created_at=at, updated_at=at,
        event_time=at, first_seen=at, last_seen=at, mitre_tactics=[], mitre_techniques=[], ai_recommendations=[],
        affected_ips=[], affected_hosts=list(hosts), affected_users=list(users), tags=[], connector_type="Generic Generic JSON", raw_event={},
    )  # fmt: skip


def call(s, user_tenant, **kw):
    user = SimpleNamespace(tenant_id=user_tenant, user_id=uuid.uuid4())
    args = {
        "page": 1, "page_size": 25, "severity": None, "status": None, "category": None, "assigned_to_me": False, "search": None,
        "min_confidence": None, "confidence_label": None, "source": None, "client_id": None, "device": None, "ticket": None,
    }  # fmt: skip
    args.update(kw)
    return ep.list_alerts(user, s, **args)


async def seed(s):
    t = tenant("Live Oak")
    s.add(t)
    await s.flush()
    s.add_all(
        [
            alert(t, "Disk space low on PC-1", 1, ["PC-1"]),
            alert(t, "Disk space low on PC-1", 10, ["PC-1"]),
            alert(t, "Disk space low on PC-1", 20, ["PC-1"]),
            alert(t, "Disk space low on PC-2", 5, ["PC-2"]),  # same rule, another machine: not a repeat
            alert(t, "Impossible travel", 7, [], ["ann"]),
            alert(t, "Impossible travel", 8, [], ["bob"]),  # same rule, another user: not a repeat
            alert(t, "Impossible travel", 9, [], ["ann"]),
        ]
    )
    await s.commit()
    return t


def test_repeats_collapse_to_the_newest_with_a_count_and_different_machines_or_users_stay_apart():
    async def go(s):
        t = await seed(s)
        out = await call(s, t.id, collapse=True)
        got = [(i.title, i.affected_hosts, i.affected_users, i.repeat_count) for i in out.items]
        assert got == [
            ("Disk space low on PC-1", ["PC-1"], [], 3),
            ("Disk space low on PC-2", ["PC-2"], [], 1),
            ("Impossible travel", [], ["ann"], 2),
            ("Impossible travel", [], ["bob"], 1),
        ]
        assert out.total == 4
        # The newest of the PC-1 group is the one shown.
        assert out.items[0].created_at.replace(tzinfo=UTC) == NOW - timedelta(minutes=1)

    run(go)


def test_without_collapse_every_alert_is_listed_and_no_count_is_set():
    async def go(s):
        t = await seed(s)
        out = await call(s, t.id)
        assert out.total == 7 and len(out.items) == 7
        assert all(i.repeat_count is None for i in out.items)
        assert (await call(s, t.id, collapse=False)).total == 7

    run(go)


def test_collapsing_pages_by_group_and_respects_filters():
    async def go(s):
        t = await seed(s)
        first = await call(s, t.id, collapse=True, page_size=3)
        second = await call(s, t.id, collapse=True, page_size=3, page=2)
        assert (first.total, first.pages, len(first.items), len(second.items)) == (4, 2, 3, 1)
        only = await call(s, t.id, collapse=True, device="PC-1")
        assert [(i.title, i.repeat_count) for i in only.items] == [("Disk space low on PC-1", 3)]

    run(go)


def test_a_parent_collapses_each_client_separately() -> None:
    async def go(s):
        parent = tenant("Parent")
        s.add(parent)
        await s.flush()
        a, b = tenant("A", parent.id), tenant("B", parent.id)
        s.add_all([a, b])
        await s.flush()
        s.add_all([alert(a, "Same rule", 1, ["X"]), alert(a, "Same rule", 2, ["X"]), alert(b, "Same rule", 3, ["X"])])
        await s.commit()
        out = await call(s, parent.id, collapse=True)
        assert sorted((i.client_name, i.repeat_count) for i in out.items) == [("A", 2), ("B", 1)]
        assert out.total == 2

    run(go)
