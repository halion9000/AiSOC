"""Storing directory audit entries and multi-factor snapshots against a REAL Postgres (opt in with AISOC_TEST_PG_URL; the database needs migration 093)."""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.api.v1.endpoints import identity as ep
from app.db.rls import set_rls_context
from app.services.signin_scoring import ScoreOutcome
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database (with migration 093)"
)

NOW = datetime(2026, 10, 19, 18, 0, tzinfo=UTC)


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:8]
    ids = {k: uuid.uuid4() for k in ("msp", "mapped")}
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for key, parent in (("msp", None), ("mapped", ids["msp"])):
            await c.execute(
                text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, :p)"),
                {"i": ids[key], "n": f"{key}-{tag}", "s": f"{key}-{tag}", "p": parent},
            )
        await c.execute(
            text(
                "insert into client_aliases (tenant_id, vendor, vendor_client_id, vendor_client_name, normalized_name, child_tenant_id, ignored, match_source) "
                "values (:t, 'cipp', 'cust-1', 'cust-1', 'cust-1', :c, false, 'manual')"
            ),
            {"t": ids["msp"], "c": ids["mapped"]},
        )
    yield ids
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
    await engine.dispose()


async def run(owner, work):
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            await set_rls_context(db, owner)
            out = await work(db)
            await db.commit()
            return out
    finally:
        await engine.dispose()


async def scalar(sql, **p):
    engine = create_async_engine(PG_URL)
    try:
        async with engine.connect() as c:
            return (await c.execute(text(sql), p)).scalar_one()
    finally:
        await engine.dispose()


def audit(aid, actor="admin@x.com", activity="Reset user password", target="bob@x.com", client="cust-1", at=NOW, **over):
    base = {
        "vendor_client_id": client,
        "id": aid,
        "at": at,
        "actor": actor,
        "activity": activity,
        "category": "UserManagement",
        "success": True,
        "target": target,
    }
    base.update(over)
    return ep.DirectoryAuditIn(**base)


def audits(*items):
    return ep.DirectoryAuditsReport(vendor="cipp", items=list(items))


def fake_scoring(monkeypatch, status="ok", anomalous=()):
    calls = []

    async def fake(events, **_):
        calls.append(events)
        if status != "ok":
            return ScoreOutcome(status=status)
        return ScoreOutcome(
            status="ok", scored={e["key"]: (4.0 if e["source_event_id"] in anomalous else None) for e in events}, anomalies=len(anomalous)
        )

    monkeypatch.setattr(ep, "score_events", fake)
    return calls


async def test_entries_are_stored_once_under_the_mapped_client_and_scored_by_actor(world, monkeypatch):
    calls = fake_scoring(monkeypatch, anomalous={"a2"})
    out = await run(
        world["msp"],
        lambda db: ep.apply_directory_audits(
            db, world["msp"], audits(audit("a1"), audit("a2", actor="Eve@x.com", activity="Add member to role"), audit("a1")), NOW
        ),
    )
    assert (out.accepted, out.duplicates, out.scored, out.anomalies, out.scoring) == (2, 1, 2, 1, "ok")
    assert await scalar("select count(*) from directory_audit_events where tenant_id = :t", t=world["mapped"]) == 2
    assert await scalar("select sensitivity from directory_audit_events where source_id = 'a2' and tenant_id = :t", t=world["mapped"]) == 3
    assert (
        await scalar("select anomaly_score from directory_audit_events where source_id = 'a2' and tenant_id = :t", t=world["mapped"]) == 4.0
    )
    by_key = {e["key"]: e for e in calls[0]}
    assert by_key["a2"]["entity_id"] == "eve@x.com" and by_key["a2"]["event_type"] == "directory_change"
    assert by_key["a2"]["features"]["role_change"] == 1.0
    again = await run(
        world["msp"], lambda db: ep.apply_directory_audits(db, world["msp"], audits(audit("a1"), audit("a2", actor="Eve@x.com")), NOW)
    )
    assert (again.accepted, again.duplicates) == (0, 2)


async def test_an_app_actor_is_stored_but_not_sent_for_scoring(world, monkeypatch):
    calls = fake_scoring(monkeypatch)
    out = await run(
        world["msp"],
        lambda db: ep.apply_directory_audits(db, world["msp"], audits(audit("p1", actor="Some App", actor_is_app=True), audit("p2")), NOW),
    )
    assert out.accepted == 2
    assert [e["key"] for e in calls[0]] == ["p2"]
    assert await scalar("select count(*) from directory_audit_events where scored_at is null and tenant_id = :t", t=world["mapped"]) == 0


async def test_an_unmapped_client_is_counted_and_not_stored(world, monkeypatch):
    fake_scoring(monkeypatch)
    out = await run(
        world["msp"],
        lambda db: ep.apply_directory_audits(db, world["msp"], audits(audit("u1", client="cust-new"), audit("u2", client="cust-new")), NOW),
    )
    assert (out.accepted, out.unmapped) == (0, 2)
    assert [(c.vendor_client_id, c.devices) for c in out.unmapped_clients] == [("cust-new", 2)]


async def test_when_scoring_is_down_entries_are_kept_unscored_and_scored_on_a_later_request(world, monkeypatch):
    fake_scoring(monkeypatch, status="unavailable")
    down = await run(world["msp"], lambda db: ep.apply_directory_audits(db, world["msp"], audits(audit("d1"), audit("d2")), NOW))
    assert (down.accepted, down.scored, down.scoring) == (2, 0, "unavailable")
    fake_scoring(monkeypatch)
    await run(world["msp"], lambda db: ep.apply_directory_audits(db, world["msp"], audits(audit("d3")), NOW))
    assert await scalar("select count(*) from directory_audit_events where scored_at is null and tenant_id = :t", t=world["mapped"]) == 0


async def test_entries_older_than_the_window_are_forgotten(world, monkeypatch):
    fake_scoring(monkeypatch)
    await run(world["msp"], lambda db: ep.apply_directory_audits(db, world["msp"], audits(audit("old", at=NOW - timedelta(days=60))), NOW))
    assert await scalar("select count(*) from directory_audit_events where source_id = 'old'") == 0


def mfa(uid, upn, **over):
    base = {"id": uid, "upn": upn, "licensed": True, "registered": True, "ca_enforced": True}
    base.update(over)
    return ep.MfaUserIn(**base)


def snapshot(snap, users, last=True, client="cust-1"):
    return ep.MfaUsersReport(vendor="cipp", vendor_client_id=client, snapshot_id=snap, last=last, items=users)


async def test_a_snapshot_replaces_the_previous_one_and_the_summary_counts_who_has_no_second_factor(world):
    first = uuid.uuid4()
    await run(
        world["msp"],
        lambda db: ep.apply_mfa_users(
            db, world["msp"], snapshot(first, [mfa("1", "A@x.com"), mfa("2", "b@x.com", registered=False), mfa("3", "gone@x.com")]), NOW
        ),
    )
    assert await scalar("select count(*) from identity_mfa_users where tenant_id = :t", t=world["mapped"]) == 3
    second = uuid.uuid4()
    out = await run(
        world["msp"],
        lambda db: ep.apply_mfa_users(
            db, world["msp"], snapshot(second, [mfa("1", "a@x.com"), mfa("2", "b@x.com", registered=False, admin=True)]), NOW
        ),
    )
    assert (out.accepted, out.removed) == (2, 1), "the person no longer listed is removed"
    assert await scalar("select count(*) from identity_mfa_users where tenant_id = :t", t=world["mapped"]) == 2
    assert (
        await scalar("select upn from identity_mfa_users where user_id = '1' and tenant_id = :t", t=world["mapped"]) == "a@x.com"
    ), "names are kept in lower case"

    class User:
        tenant_id = world["msp"]

    summary = await run(world["msp"], lambda db: ep.mfa_summary(User(), db))
    assert [(s.client_id, s.people, s.with_mfa, s.without_mfa, s.admins_without_mfa) for s in summary] == [(world["mapped"], 2, 1, 1, 1)]
    listed = await run(world["msp"], lambda db: ep.mfa_users(User(), db, client_id=world["mapped"], which="without"))
    assert [(u.upn, u.admin) for u in listed] == [("b@x.com", True)]
    assert (
        await run(world["msp"], lambda db: ep.mfa_users(User(), db, client_id=uuid.uuid4(), which="without")) == []
    ), "a client that is not this organization's is empty"


async def test_a_snapshot_in_chunks_keeps_everyone_until_the_last_chunk(world):
    snap = uuid.uuid4()
    await run(world["msp"], lambda db: ep.apply_mfa_users(db, world["msp"], snapshot(snap, [mfa("1", "a@x.com")], last=False), NOW))
    await run(world["msp"], lambda db: ep.apply_mfa_users(db, world["msp"], snapshot(snap, [mfa("2", "b@x.com")], last=True), NOW))
    assert await scalar("select count(*) from identity_mfa_users where tenant_id = :t", t=world["mapped"]) == 2


async def test_an_unmapped_client_snapshot_is_counted_and_not_stored(world):
    out = await run(
        world["msp"], lambda db: ep.apply_mfa_users(db, world["msp"], snapshot(uuid.uuid4(), [mfa("1", "a@x.com")], client="cust-new"), NOW)
    )
    assert (out.accepted, out.unmapped) == (0, 1)


async def test_the_identity_summary_counts_the_last_day(world, monkeypatch):
    fake_scoring(monkeypatch)
    await run(world["msp"], lambda db: ep.apply_directory_audits(db, world["msp"], audits(audit("s1"), audit("s2")), NOW))
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(
            text("update directory_audit_events set occurred_at = now() - interval '1 hour' where tenant_id = :t"), {"t": world["mapped"]}
        )
    await engine.dispose()

    class User:
        tenant_id = world["msp"]

    s = await run(world["msp"], lambda db: ep.identity_summary(User(), db))
    assert (s.audits_last_24h, s.audits_scored_last_24h) == (2, 2) and s.newest_received is not None
