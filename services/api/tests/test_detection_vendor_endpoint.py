"""GET /detection/vendor-detections: the route function turns the service's rows into the response the page reads."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.api.v1.endpoints import detection_vendor as ep
from app.db.database import Base
from app.models.alert import Alert
from app.models.tenant import Tenant
from app.services.vendor_detections import WINDOW
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


def _alert(tenant_id, title, source, when):
    return Alert(
        tenant_id=tenant_id, title=title, severity="high", status="new", priority=3, created_at=when, updated_at=when,
        event_time=when, first_seen=when, last_seen=when, mitre_tactics=[], mitre_techniques=[], ai_recommendations=[], affected_ips=[],
        affected_hosts=[], affected_users=[], tags=[], raw_event={"source": source},
    )  # fmt: skip


def _run(body):
    async def main():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as c:
            await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[Tenant.__table__, Alert.__table__]))
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as db:
                return await body(db)
        finally:
            await engine.dispose()

    return asyncio.run(main())


def test_the_response_carries_the_window_and_one_row_per_tool_and_detection():
    async def body(db):
        t = Tenant(id=uuid.uuid4(), name="Solo", slug=f"solo-{uuid.uuid4().hex[:6]}")
        db.add(t)
        await db.flush()
        recent = datetime.now(UTC) - timedelta(days=1)
        db.add_all(
            [
                _alert(t.id, "Malicious Process", "huntress", recent),
                _alert(t.id, "Malicious Process", "huntress", recent),
                _alert(t.id, "Odd Login", "blumira", recent),
            ]
        )
        await db.flush()
        return await ep.list_vendor_detections(SimpleNamespace(tenant_id=t.id), db)

    got = _run(body)
    assert got.window_days == WINDOW.days == 30
    assert [(d.source, d.name, d.count, d.open, d.clients) for d in got.detections] == [
        ("huntress", "Malicious Process", 2, 2, 1),
        ("blumira", "Odd Login", 1, 1, 1),
    ]
    assert got.detections[0].severity == "high"
    assert got.detections[0].last_seen is not None


def test_a_workspace_with_no_alerts_gets_an_empty_list_not_an_error():
    async def body(db):
        t = Tenant(id=uuid.uuid4(), name="Quiet", slug=f"quiet-{uuid.uuid4().hex[:6]}")
        db.add(t)
        await db.flush()
        return await ep.list_vendor_detections(SimpleNamespace(tenant_id=t.id), db)

    got = _run(body)
    assert (got.window_days, got.detections) == (30, [])


def test_the_route_is_mounted_where_the_page_calls_it_as_a_get():
    route = {r.path: r for r in ep.router.routes}["/detection/vendor-detections"]
    assert route.methods == {"GET"}
