"""Hunt search over the alerts CORE forwards."""

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.api.v1.endpoints import hunt_alert_search as hs
from app.db.database import Base
from app.models.alert import Alert
from app.models.tenant import Tenant
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


@contextlib.asynccontextmanager
async def no_scope(_db, _tenant):
    yield


hs.acting_as_tenant = no_scope  # the real one sets a Postgres setting; these tests run on SQLite


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


def alert(t, title, severity="medium", host=None, user=None, ip=None, source="huntress", at=NOW, tags=None):
    return Alert(
        tenant_id=t.id, title=title, description="", severity=severity, status="new", priority=3, created_at=at, updated_at=at,
        event_time=at, first_seen=at, last_seen=at, mitre_tactics=[], mitre_techniques=[], ai_recommendations=[],
        affected_ips=[ip] if ip else [], affected_hosts=[host] if host else [], affected_users=[user] if user else [], tags=tags or [],
        connector_type="core_feed", raw_event={"source": source},
    )  # fmt: skip


def test_parse_words_phrases_fields_and_negation():
    terms = hs.parse_query('malware severity:high -host:PC-1 "social engineering" AND foo:bar')
    assert [(t.field, t.value, t.negate) for t in terms] == [
        (None, "malware", False),
        ("severity", "high", False),
        ("host", "PC-1", True),
        (None, "social engineering", False),
        (None, "foo:bar", False),  # an unknown field is searched for as typed
    ]
    assert hs.parse_query("") == []


def test_search_covers_the_workspace_and_its_clients_newest_first_and_filters():
    async def body(s):
        parent = tenant("Parent")
        s.add(parent)
        await s.flush()
        a, b = tenant("Acme Dental", parent.id), tenant("Birch Law", parent.id)
        s.add_all([a, b])
        await s.flush()
        s.add_all(
            [
                alert(parent, "Parent alert", "low", at=NOW - timedelta(hours=3)),
                alert(a, "Malware on workstation", "high", host="PC-1", user="amy", ip="10.0.0.5", at=NOW - timedelta(hours=1)),
                alert(b, "Malware on server", "critical", host="SRV-9", source="petra", at=NOW - timedelta(hours=2)),
                alert(b, "Odd login", "low", user="bob", at=NOW - timedelta(days=9)),
            ]
        )
        await s.commit()
        user = SimpleNamespace(tenant_id=parent.id)

        async def search(q, **kw):
            return await hs.hunt_search(hs.HuntQuery(query=q, **kw), user, s)

        return {
            "all": await search(""),
            "malware": await search("malware"),
            "sev": await search("severity:critical"),
            "host": await search("host:pc-1"),
            "ip": await search("ip:10.0.0.5"),
            "source": await search("source:petra"),
            "client": await search("client:acme"),
            "not": await search("malware -host:PC-1"),
            "range": await search("", startTime=NOW - timedelta(days=2)),
            "limit": await search("", limit=2),
        }

    r = run(body)
    titles = lambda x: [h.highlight for h in x.hits]  # noqa: E731
    assert titles(r["all"]) == ["Malware on workstation", "Malware on server", "Parent alert", "Odd login"] and r["all"].total == 4
    assert titles(r["malware"]) == ["Malware on workstation", "Malware on server"]
    assert titles(r["sev"]) == ["Malware on server"]
    assert titles(r["host"]) == ["Malware on workstation"]
    assert titles(r["ip"]) == ["Malware on workstation"]
    assert titles(r["source"]) == ["Malware on server"]
    assert titles(r["client"]) == ["Malware on workstation"]
    assert titles(r["not"]) == ["Malware on server"]
    assert "Odd login" not in titles(r["range"])
    assert len(r["limit"].hits) == 2 and r["limit"].total == 4
    first = r["all"].hits[0]
    assert first.source == "huntress" and first.fields["client"] == "Acme Dental" and first.fields["hosts"] == ["PC-1"]


def test_a_client_name_fits_when_it_is_close_not_only_when_it_is_exact():
    from app.api.v1.endpoints.hunt_alert_search import client_matches as m

    assert m("sportsmans finest", "Sportsman's Finest")
    assert m("Sportsmans Finest", "Sportsman's Finest")
    assert m("live oak", "Live Oak Technologies, LLC")
    assert m("hill country christian", "Hill Country Christian School of Austin")
    assert m("sportsman finest", "Sportsman's Finest")  # a missing letter still counts
    assert not m("sportsmans finest", "Austin Gamblers")
    assert not m("", "Anyone")
    assert not m("apple", "Austin FC")


def test_parse_keeps_at_most_the_term_limit():
    q = " ".join(f"w{i}" for i in range(hs.MAX_TERMS + 5))
    assert len(hs.parse_query(q)) == hs.MAX_TERMS


def test_a_close_client_name_finds_the_client_and_a_minus_client_leaves_it_out():
    async def body(s):
        parent = tenant("Parent")
        s.add(parent)
        await s.flush()
        a, b = tenant("Sportsman's Finest", parent.id), tenant("Birch Law", parent.id)
        s.add_all([a, b])
        await s.flush()
        s.add_all([alert(a, "Suspicious login", "high", at=NOW), alert(b, "Suspicious login", "high", at=NOW - timedelta(hours=1))])
        await s.commit()
        user = SimpleNamespace(tenant_id=parent.id)

        async def search(q):
            return await hs.hunt_search(hs.HuntQuery(query=q), user, s)

        return {
            "close": await search('suspicious client:"sportsmans finest"'),
            "typo": await search("suspicious client:sportsman"),
            "minus": await search("suspicious -client:sportsmans"),
            "none": await search("suspicious client:nothing-like-it"),
        }

    r = run(body)
    clients = lambda x: [h.fields["client"] for h in x.hits]  # noqa: E731
    assert clients(r["close"]) == ["Sportsman's Finest"]
    assert clients(r["typo"]) == ["Sportsman's Finest"]
    assert clients(r["minus"]) == ["Birch Law"]
    assert r["none"].total == 0
