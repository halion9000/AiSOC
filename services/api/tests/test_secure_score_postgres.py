"""Storing and reading each client's Microsoft Secure Score against a REAL Postgres (opt in with AISOC_TEST_PG_URL; the database needs migration 094), plus the pure trend arithmetic."""

import os
import uuid
from datetime import UTC, datetime

import pytest
from app.api.v1.endpoints import identity as ep
from app.db.rls import set_rls_context
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
needs_pg = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database (with migration 094)")

NOW = datetime(2026, 10, 21, 18, 0, tzinfo=UTC)


def pts(*pairs):
    return [{"d": d, "c": c, "m": 267} for d, c in pairs]


def test_the_change_compares_the_newest_point_with_the_one_thirty_days_back_or_the_oldest_there_is():
    month = pts(("2026-09-20", 100), ("2026-10-01", 105), ("2026-10-20", 110), ("2026-10-21", 115))
    assert ep.change_over(month) == 15  # 09-20 is the newest point at least 30 days before 10-21
    assert ep.change_over(pts(("2026-10-10", 90), ("2026-10-21", 100))) == 10  # shorter than 30 days: against the oldest
    assert ep.change_over(pts(("2026-10-21", 100))) is None
    assert ep.change_over([]) is None
    assert ep.change_over(pts(("2026-10-20", 120), ("2026-10-21", 115))) == -5
    assert ep.change_over([{"d": "bad", "c": 1}, {"d": 5, "c": 2}, "junk"]) is None  # type: ignore[list-item]
    assert ep.change_over(pts(("2026-10-21", 100), ("2026-10-19", 90), ("2026-10-20", 95))) == 10, "order of the points does not matter"


def test_a_report_with_a_bad_date_or_too_many_points_is_refused():
    base = {"vendor": "cipp", "vendor_client_id": "c1", "taken_at": NOW, "current": 1, "max": 2}
    with pytest.raises(ValueError):
        ep.SecureScoreReport(**base, history=[{"d": "21/10/2026", "c": 1, "m": 2}])
    with pytest.raises(ValueError):
        ep.SecureScoreReport(**base, history=pts(*[(f"2026-01-{i % 28 + 1:02d}", i) for i in range(91)]))
    with pytest.raises(ValueError):
        ep.SecureScoreReport(**{**base, "max": 0})


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:8]
    ids = {k: uuid.uuid4() for k in ("msp", "mapped", "other")}
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for key, parent in (("msp", None), ("mapped", ids["msp"]), ("other", None)):
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


def report(client="cust-1", current=115.0, history=None, improvements=None, **over):
    return ep.SecureScoreReport(
        vendor="cipp",
        vendor_client_id=client,
        taken_at=NOW,
        current=current,
        max=267,
        average=54.02,
        active_users=20,
        licensed_users=25,
        history=history if history is not None else pts(("2026-09-20", 100), ("2026-10-21", current)),
        improvements=improvements
        if improvements is not None
        else [
            {"id": "mfa_admins", "title": "Require MFA for administrative roles", "missing": 10, "max": 10, "rank": 1, "status": "off"},
            {"id": "legacy", "title": "Block legacy authentication", "missing": 6, "max": 6, "category": "Identity"},
        ],
        **over,
    )


class User:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id


@needs_pg
async def test_a_mapped_clients_score_is_stored_replaced_by_the_next_report_and_read_back_with_its_trend(world):
    first = await run(world["msp"], lambda db: ep.apply_secure_score(db, world["msp"], report(current=115), NOW))
    assert (first.accepted, first.unmapped) == (1, 0)
    second = await run(world["msp"], lambda db: ep.apply_secure_score(db, world["msp"], report(current=130, improvements=[]), NOW))
    assert second.accepted == 1
    rows = await run(world["msp"], lambda db: ep.secure_score_summary(User(world["msp"]), db))
    assert len(rows) == 1, "one row per client: the second report replaced the first"
    r = rows[0]
    assert (r.client_id, r.current, r.max, r.percent, r.average) == (world["mapped"], 130.0, 267.0, 48.7, 54.02)
    assert (r.change_30d, r.active_users, r.licensed_users, r.points_available) == (30.0, 20, 25, 0.0)
    assert [p.d for p in r.history] == ["2026-09-20", "2026-10-21"]


@needs_pg
async def test_the_detail_lists_the_controls_still_missing_points_and_a_client_with_no_score_is_not_found(world):
    await run(world["msp"], lambda db: ep.apply_secure_score(db, world["msp"], report(), NOW))
    d = await run(world["msp"], lambda db: ep.secure_score_detail(world["mapped"], User(world["msp"]), db))
    assert [(i.id, i.missing, i.rank, i.status) for i in d.improvements] == [("mfa_admins", 10.0, 1.0, "off"), ("legacy", 6.0, None, None)]
    assert d.points_available == 16.0
    with pytest.raises(HTTPException) as e:
        await run(world["msp"], lambda db: ep.secure_score_detail(uuid.uuid4(), User(world["msp"]), db))
    assert e.value.status_code == 404


@needs_pg
async def test_a_customer_not_mapped_yet_is_counted_and_nothing_is_stored(world):
    out = await run(world["msp"], lambda db: ep.apply_secure_score(db, world["msp"], report(client="cust-unknown"), NOW))
    assert (out.accepted, out.unmapped) == (0, 1)
    assert await run(world["msp"], lambda db: ep.secure_score_summary(User(world["msp"]), db)) == []


@needs_pg
async def test_another_organizations_scores_are_never_listed(world):
    await run(world["msp"], lambda db: ep.apply_secure_score(db, world["msp"], report(), NOW))
    assert await run(world["other"], lambda db: ep.secure_score_summary(User(world["other"]), db)) == []
    with pytest.raises(HTTPException):
        await run(world["other"], lambda db: ep.secure_score_detail(world["mapped"], User(world["other"]), db))


@needs_pg
async def test_the_lowest_percentage_comes_first(world):
    await run(world["msp"], lambda db: ep.apply_secure_score(db, world["msp"], report(current=200), NOW))
    # The MSP's own score goes in through an alias-free report (no client id would be needed in practice; here the second client is the MSP itself).
    async def own(db):
        from app.models.signin import IdentitySecureScore

        db.add(IdentitySecureScore(tenant_id=world["msp"], source="cipp", taken_at=NOW, current_score=50, max_score=267, history=[], improvements=[]))

    await run(world["msp"], own)
    rows = await run(world["msp"], lambda db: ep.secure_score_summary(User(world["msp"]), db))
    assert [r.current for r in rows] == [50.0, 200.0]


@needs_pg
async def test_the_brief_is_the_summary_without_the_daily_points_for_assistants(world):
    await run(world["msp"], lambda db: ep.apply_secure_score(db, world["msp"], report(current=130), NOW))
    brief = await run(world["msp"], lambda db: ep.secure_score_brief(User(world["msp"]), db))
    assert len(brief) == 1
    b = brief[0].model_dump()
    assert (b["client_id"], b["current"], b["max"], b["percent"], b["change_30d"], b["points_available"]) == (world["mapped"], 130.0, 267.0, 48.7, 30.0, 16.0)
    assert "history" not in b and "improvements" not in b, "short on purpose: no daily points and no control list"
