"""What the connected tools' detections have raised, from real alerts."""

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime, timedelta

from app.db.database import Base
from app.models.alert import Alert
from app.models.tenant import Tenant
from app.services import vendor_detections as vd
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


@contextlib.asynccontextmanager
async def no_scope(_db, _tenant):
    yield


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
    return Tenant(id=uuid.uuid4(), name=name, slug=f"{name}-{uuid.uuid4().hex[:6]}".lower().replace(" ", "-"), parent_tenant_id=parent)


def alert(t, title, source, severity="medium", status="new", rule_name=None, created=NOW - timedelta(days=1)):
    return Alert(
        tenant_id=t.id, title=title, rule_name=rule_name, severity=severity, status=status, priority=3, created_at=created, updated_at=created,
        event_time=created, first_seen=created, last_seen=created, mitre_tactics=[], mitre_techniques=[], ai_recommendations=[], affected_ips=[],
        affected_hosts=[], affected_users=[], tags=[], raw_event={"source": source} if source else {},
    )  # fmt: skip


def test_source_prefers_the_tool_named_in_the_event():
    assert vd.source_of({"source": "huntress"}, "core_feed") == "huntress"
    assert vd.source_of({}, "core_feed") == "core_feed"
    assert vd.source_of(None, None) == "unknown"


def test_groups_by_tool_and_detection_across_clients_and_ignores_old_alerts():
    async def body(s):
        parent = tenant("Parent")
        s.add(parent)
        await s.flush()
        a, b = tenant("A", parent.id), tenant("B", parent.id)
        s.add_all([a, b])
        await s.flush()
        s.add_all(
            [
                alert(a, "Malicious Process", "huntress", "high"),
                alert(b, "Malicious Process", "huntress", "critical", "resolved", created=NOW - timedelta(hours=2)),
                alert(b, "Malicious Process", "petra"),  # same name, different tool: its own row
                alert(a, "Other title", "huntress", rule_name="Persistence Rule"),
                alert(a, "Too old", "huntress", created=NOW - timedelta(days=45)),
            ]
        )
        await s.flush()
        return await vd.vendor_detections(s, parent.id, now=NOW, scope=no_scope)

    got = run(body)
    assert [(g["source"], g["name"], g["count"]) for g in got] == [
        ("huntress", "Malicious Process", 2),
        ("huntress", "Persistence Rule", 1),
        ("petra", "Malicious Process", 1),
    ]
    first = got[0]
    assert first["clients"] == 2 and first["open"] == 1 and first["severity"] == "critical"
    assert first["last_seen"] == (NOW - timedelta(hours=2)).isoformat()


def test_nothing_raised_means_an_empty_list():
    async def body(s):
        parent = tenant("Parent")
        s.add(parent)
        await s.flush()
        return await vd.vendor_detections(s, parent.id, now=NOW, scope=no_scope)

    assert run(body) == []
