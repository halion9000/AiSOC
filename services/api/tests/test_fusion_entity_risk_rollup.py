"""An MSSP parent that names no tenant sees its own entities and its clients' together; anyone else's stay out of reach."""

import asyncio
import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import fusion as ep
from app.db.database import Base
from app.models.tenant import Tenant
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


def run(fn):
    async def main():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as c:
            await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[Tenant.__table__]))
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            try:
                return await fn(s)
            finally:
                await engine.dispose()

    return asyncio.run(main())


def tenant(name, parent=None):
    return Tenant(id=uuid.uuid4(), name=name, slug=f"{name}-{uuid.uuid4().hex[:6]}".lower(), parent_tenant_id=parent)


class Upstream:
    """Stands in for the fusion service: one queue and one stats answer per tenant."""

    def __init__(self, queues, stats):
        self.queues, self.stats, self.asked = queues, stats, []

    async def post(self, path, body):
        """The rollup routes: ONE request names every tenant, and fusion answers with them merged."""
        ids = body["tenant_ids"]
        self.asked.extend(ids)
        self.posts = getattr(self, "posts", 0) + 1
        if path.endswith("/queue"):
            rows = [e for t in ids for e in self.queues.get(t, [])]
            rows.sort(key=lambda e: e["score"], reverse=True)
            return {"threshold": 80.0, "entities": rows[: body["limit"]]}
        empty = {"total": 0, "promoted": 0, "bands": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
        parts = [self.stats.get(t, empty) for t in ids]
        return {
            "threshold": 80.0,
            "total": sum(p["total"] for p in parts),
            "promoted": sum(p["promoted"] for p in parts),
            "bands": {k: sum(p["bands"][k] for p in parts) for k in empty["bands"]},
        }

    async def get(self, path, params=None):
        t = params["tenant_id"]
        self.asked.append(t)
        if path.endswith("/queue"):
            return {"tenant_id": t, "threshold": 80.0, "entities": self.queues.get(t, [])}
        return {
            "tenant_id": t,
            "threshold": 80.0,
            **self.stats.get(t, {"total": 0, "promoted": 0, "bands": {"critical": 0, "high": 0, "medium": 0, "low": 0}}),
        }


def user(tid, permissions=()):
    return SimpleNamespace(tenant_id=tid, holds=lambda p: p in permissions)


async def world(s):
    parent, a, b, other = tenant("Live Oak"), None, None, tenant("Unrelated")
    a, b = tenant("Setpoint", parent.id), tenant("Tecovas", parent.id)
    s.add_all([parent, a, b, other])
    await s.commit()
    return parent, a, b, other


def ent(tid, value, score):
    return {"tenant_id": str(tid), "entity_type": "host", "entity_value": value, "score": score}


def test_parent_without_a_tenant_gets_own_and_client_entities_merged_by_score_with_client_names(monkeypatch):
    async def go(s):
        parent, a, b, other = await world(s)
        up = Upstream(
            {
                str(parent.id): [ent(parent.id, "own-pc", 10)],
                str(a.id): [ent(a.id, "sp-pc", 50)],
                str(b.id): [ent(b.id, "tc-pc", 30)],
                str(other.id): [ent(other.id, "secret", 99)],
            },
            {},
        )
        monkeypatch.setattr(ep, "_proxy_get", up.get)
        monkeypatch.setattr(ep, "_proxy_post", up.post)
        out = await ep.entity_risk_queue(user(parent.id), s, None, 25, False)
        assert [e["entity_value"] for e in out["entities"]] == ["sp-pc", "tc-pc", "own-pc"]
        assert {e["entity_value"]: e["client_name"] for e in out["entities"]} == {"sp-pc": "Setpoint", "tc-pc": "Tecovas", "own-pc": None}
        assert str(other.id) not in up.asked, "a stranger's tenant is never asked for"
        limited = await ep.entity_risk_queue(user(parent.id), s, None, 2, False)
        assert [e["entity_value"] for e in limited["entities"]] == ["sp-pc", "tc-pc"]

    run(go)


def test_naming_a_client_reads_just_that_client_and_a_stranger_is_refused(monkeypatch):
    async def go(s):
        parent, a, b, other = await world(s)
        up = Upstream({str(a.id): [ent(a.id, "sp-pc", 50)]}, {})
        monkeypatch.setattr(ep, "_proxy_get", up.get)
        out = await ep.entity_risk_queue(user(parent.id), s, a.id, 25, False)
        assert [e["entity_value"] for e in out["entities"]] == ["sp-pc"] and up.asked == [str(a.id)]
        with pytest.raises(HTTPException) as e:
            await ep.entity_risk_queue(user(parent.id), s, other.id, 25, False)
        assert e.value.status_code == 403

    run(go)


def test_a_tenant_with_no_clients_reads_only_itself(monkeypatch):
    async def go(s):
        parent, a, b, other = await world(s)
        up = Upstream({str(other.id): [ent(other.id, "x", 5)]}, {})
        monkeypatch.setattr(ep, "_proxy_get", up.get)
        out = await ep.entity_risk_queue(user(other.id), s, None, 25, False)
        assert up.asked == [str(other.id)] and "rolled_up" not in out

    run(go)


def test_stats_add_up_across_the_parent_and_its_clients(monkeypatch):
    async def go(s):
        parent, a, b, other = await world(s)
        stats = {
            str(parent.id): {"total": 1, "promoted": 0, "bands": {"critical": 0, "high": 0, "medium": 1, "low": 0}},
            str(a.id): {"total": 2, "promoted": 1, "bands": {"critical": 1, "high": 0, "medium": 0, "low": 1}},
        }
        up = Upstream({}, stats)
        monkeypatch.setattr(ep, "_proxy_get", up.get)
        monkeypatch.setattr(ep, "_proxy_post", up.post)
        out = await ep.entity_risk_stats(user(parent.id), s, None)
        assert out["total"] == 3 and out["promoted"] == 1 and out["threshold"] == 80.0
        assert out["bands"] == {"critical": 1, "high": 0, "medium": 1, "low": 1}
        assert up.posts == 1 and str(other.id) not in up.asked

    run(go)


def test_every_client_is_included_not_just_the_first_fifty(monkeypatch):
    """The rollup used to stop at 50 clients (by name), so a parent with 240 saw about a fifth of its entities, and could not open a later client's entity at all."""

    async def go(s):
        parent = tenant("Parent")
        s.add(parent)
        clients = [tenant(f"c{i:03d}", parent.id) for i in range(120)]
        s.add_all(clients)
        await s.commit()
        last = clients[-1]
        up = Upstream({str(last.id): [ent(last.id, "late-pc", 70)]}, {})
        monkeypatch.setattr(ep, "_proxy_get", up.get)
        monkeypatch.setattr(ep, "_proxy_post", up.post)
        out = await ep.entity_risk_queue(user(parent.id), s, None, 25, False)
        assert [e["entity_value"] for e in out["entities"]] == ["late-pc"]
        assert out["entities"][0]["client_name"] == last.name
        assert up.posts == 1 and len(up.asked) == 121, "one call carrying the parent and all 120 clients"
        # and a client past the old cap can be named directly
        up2 = Upstream({str(last.id): [ent(last.id, "late-pc", 70)]}, {})
        monkeypatch.setattr(ep, "_proxy_get", up2.get)
        one = await ep.entity_risk_queue(user(parent.id), s, last.id, 25, False)
        assert [e["entity_value"] for e in one["entities"]] == ["late-pc"]

    run(go)


FUSION_RECORD = {
    "tenant_id": "t1",
    "entity_type": "host",
    "entity_value": "PC-1",
    "score": 12.4,
    "alert_count": 2,
    "last_seen": "2026-10-16T20:00:00Z",
    "contributing_alerts": ["a1", "a2"],
    "severities": {"low": 2},
    "promoted_at": None,
    "contributors": [
        {"alert_id": "a1", "severity": "low", "detection": "Disk low", "points": 6.0, "at": "2026-10-16T19:00:00Z"},
        {"alert_id": "a2", "severity": "low", "detection": "Disk low again", "points": 6.4, "at": "2026-10-16T20:00:00Z"},
    ],
}


def test_a_fusion_record_gets_every_field_the_console_reads():
    out = ep._shape_entity(FUSION_RECORD, 80.0)
    assert out["display_score"] == 12 and out["threshold"] == 80.0 and out["promoted"] is False
    assert out["first_seen"] == "2026-10-16T19:00:00Z"
    assert out["severity_histogram"] == {"low": 2}
    assert [c["alert_id"] for c in out["contributions"]] == ["a2", "a1"]  # newest first
    assert out["contributions"][0] == {
        "alert_id": "a2",
        "severity": "low",
        "raw_points": 6.4,
        "observed_at": "2026-10-16T20:00:00Z",
        "title": "Disk low again",
        "source": None,
    }
    assert out["entity_value"] == "PC-1"  # nothing fusion sent is lost
    assert ep._shape_entity({**FUSION_RECORD, "promoted_at": "2026-10-16T20:00:00Z"}, 80.0)["promoted"] is True
    assert ep._shape_entity({"entity_value": "x"}, 80.0)["contributions"] == []  # a bare record does not break it


def test_fusion_stats_get_the_names_the_console_reads():
    out = ep._shape_stats(
        {"tracked_entities": 3, "promoted_entities": 1, "score_bands": {"critical": 1, "high": 0, "medium": 1, "low": 1}, "threshold": 80.0}
    )
    assert out["total"] == 3 and out["promoted"] == 1 and out["bands"]["critical"] == 1 and out["tracked_entities"] == 3


def test_the_queue_route_shapes_what_it_returns(monkeypatch):
    async def go(s):
        parent, a, b, other = await world(s)
        up = Upstream({str(parent.id): [dict(FUSION_RECORD, tenant_id=str(parent.id))]}, {})
        monkeypatch.setattr(ep, "_proxy_get", up.get)
        out = await ep.entity_risk_queue(user(other.id), s, None, 25, False)  # a tenant with no clients: the single-tenant path
        assert out["entities"] == []
        out = await ep.entity_risk_queue(user(parent.id), s, parent.id, 25, False)
        assert out["entities"][0]["contributions"][0]["alert_id"] == "a2" and out["entities"][0]["display_score"] == 12

    run(go)


def test_a_record_stored_with_an_offset_before_the_z_is_repaired():
    """Fusion used to write '...+00:00Z' for a timezone-aware alert time; a browser reads that as an Invalid Date and the entity drawer crashed."""
    bad = "2026-08-08T00:41:29+00:00Z"
    rec = {**FUSION_RECORD, "last_seen": bad, "contributors": [{**FUSION_RECORD["contributors"][0], "at": bad}]}
    out = ep._shape_entity(rec, 80.0)
    assert out["first_seen"] == "2026-08-08T00:41:29Z"
    assert out["contributions"][0]["observed_at"] == "2026-08-08T00:41:29Z"
    assert out["last_seen"] == "2026-08-08T00:41:29Z"
    assert out["contributors"][0]["at"] == "2026-08-08T00:41:29Z"
