"""Storing and scoring sign-ins against a REAL Postgres (opt in with AISOC_TEST_PG_URL, a DISPOSABLE, fully migrated database; the role must be allowed to write every table)."""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.api.v1.endpoints import signins as ep
from app.db.rls import set_rls_context
from app.services.signin_scoring import ScoreOutcome
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database (with migration 091)"
)

NOW = datetime(2026, 10, 19, 18, 0, tzinfo=UTC)


@pytest.fixture
async def world():
    """An MSP with one client mapped to CIPP customer 'cust-1', another client left unmapped, and one ignored."""
    tag = uuid.uuid4().hex[:8]
    ids = {k: uuid.uuid4() for k in ("msp", "mapped", "other", "ignored")}
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for key, parent in (("msp", None), ("mapped", ids["msp"]), ("other", ids["msp"]), ("ignored", ids["msp"])):
            await c.execute(
                text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, :p)"),
                {"i": ids[key], "n": f"{key}-{tag}", "s": f"{key}-{tag}", "p": parent},
            )
        for vid, child, ignored in (("cust-1", ids["mapped"], False), ("cust-ignored", ids["ignored"], True)):
            await c.execute(
                text(
                    "insert into client_aliases (tenant_id, vendor, vendor_client_id, vendor_client_name, normalized_name, child_tenant_id, ignored, match_source) "
                    "values (:t, 'cipp', :v, :n, :nn, :c, :ig, 'manual')"
                ),
                {"t": ids["msp"], "v": vid, "n": vid, "nn": vid, "c": child, "ig": ignored},
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


def item(sid, user="a@x.com", at=NOW, client="cust-1", **over):
    base = {
        "vendor_client_id": client,
        "id": sid,
        "at": at,
        "user": user,
        "ip": "1.1.1.1",
        "country": "US",
        "success": True,
        "interactive": True,
        "mfa": True,
    }
    base.update(over)
    return ep.SignInIn(**base)


def report(*items):
    return ep.SignInsReport(vendor="cipp", items=list(items))


def fake_scoring(monkeypatch, status="ok", anomalous=()):
    calls = []

    async def fake(events, **_):
        calls.append(events)
        if status != "ok":
            return ScoreOutcome(status=status)
        return ScoreOutcome(
            status="ok", scored={e["key"]: (5.0 if e["source_event_id"] in anomalous else None) for e in events}, anomalies=len(anomalous)
        )

    monkeypatch.setattr(ep, "score_events", fake)
    return calls


async def count(owner, sql, **p):
    return await run(owner, lambda db: db.execute(text(sql), p))


async def scalar(sql, **p):
    engine = create_async_engine(PG_URL)
    try:
        async with engine.connect() as c:
            return (await c.execute(text(sql), p)).scalar_one()
    finally:
        await engine.dispose()


async def test_sign_ins_are_stored_under_the_mapped_client_scored_and_a_repeat_changes_nothing(world, monkeypatch):
    calls = fake_scoring(monkeypatch, anomalous={"s2"})
    first = await run(
        world["msp"], lambda db: ep.apply_signins(db, world["msp"], report(item("s1"), item("s2", user="B@x.com"), item("s1")), NOW)
    )
    assert (first.accepted, first.duplicates, first.scored, first.anomalies, first.scoring) == (2, 1, 2, 1, "ok")
    assert await scalar("select count(*) from signin_events where tenant_id = :t", t=world["mapped"]) == 2
    assert (
        await scalar("select user_principal from signin_events where source_id = 's2' and tenant_id = :t", t=world["mapped"]) == "b@x.com"
    ), "user names are kept in lower case"
    assert await scalar("select anomaly_score from signin_events where source_id = 's2' and tenant_id = :t", t=world["mapped"]) == 5.0
    assert await scalar("select count(*) from signin_events where scored_at is not null and tenant_id = :t", t=world["mapped"]) == 2
    again = await run(world["msp"], lambda db: ep.apply_signins(db, world["msp"], report(item("s1"), item("s2", user="B@x.com")), NOW))
    assert (again.accepted, again.duplicates) == (0, 2)
    assert await scalar("select count(*) from signin_events where tenant_id = :t", t=world["mapped"]) == 2
    assert len(calls) >= 1


async def test_unmapped_and_ignored_clients_are_counted_and_not_stored(world, monkeypatch):
    fake_scoring(monkeypatch)
    out = await run(
        world["msp"],
        lambda db: ep.apply_signins(
            db,
            world["msp"],
            report(
                item("a", client="cust-1"), item("b", client="cust-new"), item("c", client="cust-new"), item("d", client="cust-ignored")
            ),
            NOW,
        ),
    )
    assert (out.accepted, out.unmapped, out.ignored) == (1, 2, 1)
    assert [(u.vendor_client_id, u.devices) for u in out.unmapped_clients] == [("cust-new", 2)]
    assert await scalar("select count(*) from signin_events where source_id in ('b','c','d')") == 0


async def test_a_new_country_and_address_are_judged_against_the_person_history_but_never_for_the_first_sign_in(world, monkeypatch):
    calls = fake_scoring(monkeypatch)
    await run(world["msp"], lambda db: ep.apply_signins(db, world["msp"], report(item("h1", at=NOW - timedelta(days=3))), NOW))
    first_features = calls[0][0]["features"]
    assert first_features["new_country"] == 0.0 and first_features["new_ip"] == 0.0, "the very first sign-in collected is not 'new'"
    calls.clear()
    await run(
        world["msp"],
        lambda db: ep.apply_signins(
            db,
            world["msp"],
            report(item("h2", country="CH", ip="9.9.9.9"), item("h3", country="US", ip="1.1.1.1", at=NOW + timedelta(minutes=1))),
            NOW,
        ),
    )
    by_id = {e["source_event_id"]: e["features"] for e in calls[0]}
    assert by_id["h2"]["new_country"] == 1.0 and by_id["h2"]["new_ip"] == 1.0
    assert by_id["h3"]["new_country"] == 0.0 and by_id["h3"]["new_ip"] == 0.0


async def test_when_scoring_is_unavailable_the_sign_ins_are_kept_unscored_and_scored_on_a_later_request(world, monkeypatch):
    fake_scoring(monkeypatch, status="unavailable")
    down = await run(world["msp"], lambda db: ep.apply_signins(db, world["msp"], report(item("u1"), item("u2")), NOW))
    assert (down.accepted, down.scored, down.scoring) == (2, 0, "unavailable")
    assert await scalar("select count(*) from signin_events where scored_at is null and tenant_id = :t", t=world["mapped"]) == 2
    fake_scoring(monkeypatch)
    later = await run(world["msp"], lambda db: ep.apply_signins(db, world["msp"], report(item("u3")), NOW))
    assert later.scoring == "ok"
    assert (
        await scalar("select count(*) from signin_events where scored_at is null and tenant_id = :t", t=world["mapped"]) == 0
    ), "the earlier ones were scored with the later request"


async def test_with_no_ueba_token_everything_is_stored_and_the_status_says_so(world, monkeypatch):
    fake_scoring(monkeypatch, status="not_configured")
    out = await run(world["msp"], lambda db: ep.apply_signins(db, world["msp"], report(item("n1")), NOW))
    assert (out.accepted, out.scoring) == (1, "not_configured")


async def test_sign_ins_older_than_the_history_window_are_forgotten(world, monkeypatch):
    fake_scoring(monkeypatch)
    await run(world["msp"], lambda db: ep.apply_signins(db, world["msp"], report(item("old", at=NOW - timedelta(days=60))), NOW))
    assert (
        await scalar("select count(*) from signin_events where source_id = 'old'") == 0
    ), "an old sign-in is stored and pruned in the same request, so it never sits there"


async def test_the_summary_counts_the_last_day_per_client_and_what_is_still_unscored(world, monkeypatch):
    fake_scoring(monkeypatch)
    await run(
        world["msp"],
        lambda db: ep.apply_signins(
            db,
            world["msp"],
            report(item("m1"), item("m2", user="b@x.com", success=False, error_code=50126), item("m3", at=NOW - timedelta(days=3))),
            NOW,
        ),
    )
    fake_scoring(monkeypatch, status="unavailable")
    await run(world["msp"], lambda db: ep.apply_signins(db, world["msp"], report(item("m4", user="c@x.com")), NOW))

    class User:
        tenant_id = world["msp"]

    # the summary looks at the last 24 hours from the real clock, so move the stored times into it
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(
            text("update signin_events set occurred_at = now() - interval '1 hour' where source_id in ('m1','m2','m4') and tenant_id = :t"),
            {"t": world["mapped"]},
        )
    await engine.dispose()
    s = await run(world["msp"], lambda db: ep.signin_summary(User(), db))
    assert (s.last_24h, s.failed_last_24h, s.users_last_24h) == (3, 1, 3)
    assert s.scored_last_24h == 2 and s.unscored >= 1
    assert s.newest_received is not None


async def test_top_signins_are_the_highest_scores_of_the_window_with_their_client(world, monkeypatch):
    fake_scoring(monkeypatch)
    await run(
        world["msp"],
        lambda db: ep.apply_signins(db, world["msp"], report(item("t1"), item("t2", user="b@x.com"), item("t3", user="c@x.com")), NOW),
    )
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for sid, score, age in (("t1", 0.2, timedelta(hours=1)), ("t2", 0.9, timedelta(hours=2)), ("t3", 0.99, timedelta(days=30))):
            await c.execute(
                text("update signin_events set anomaly_score = :s, occurred_at = now() - cast(:a as interval) where source_id = :i and tenant_id = :t"),
                {"s": score, "a": age, "i": sid, "t": world["mapped"]},
            )
    await engine.dispose()

    class User:
        tenant_id = world["msp"]

    top = await run(world["msp"], lambda db: ep.top_signins(User(), db, days=7, limit=10))
    assert [t.user for t in top] == ["b@x.com", "a@x.com"], "highest first; the 30-day-old one is outside the window"
    assert top[0].client_id == world["mapped"] and top[0].client_name.startswith("mapped-")
    one = await run(world["msp"], lambda db: ep.top_signins(User(), db, days=7, limit=1))
    assert len(one) == 1
