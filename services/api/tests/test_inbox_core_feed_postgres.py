"""CORE's per-run status report (``inbox_core_feed``) against a REAL Postgres, as the restricted role (`aisoc_app`) with the fail-closed row-level-security switch
ON, running the real functions the endpoint runs.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), as the sibling tests do. The two tenants the fixture creates are deleted afterwards
(the foreign keys cascade to their tokens and connectors).
"""

import os
import uuid

import pytest
from app.api.v1.endpoints.inbox_core_feed import SourceReport, StatusReport, _verify_core_feed_token, apply_report
from app.db.rls_sessions import adopt_tenant
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:10]
    a, b = uuid.uuid4(), uuid.uuid4()
    w = {
        "a": a,
        "b": b,
        "feed_token": f"aitnb_feed_{tag}",
        "revoked_token": f"aitnb_revoked_{tag}",
        "other_label_token": f"aitnb_other_{tag}",
        "other_template_token": f"aitnb_tpl_{tag}",
        "b_feed_token": f"aitnb_bfeed_{tag}",
    }
    owner = create_async_engine(PG_URL)
    on = create_async_engine(APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}})
    try:
        async with owner.begin() as conn:
            for tid, key in ((a, "a"), (b, "b")):
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
                    {"i": tid, "n": f"cf-{key}-{tag}", "s": f"cf-{key}-{tag}"},
                )
            rows = [
                (w["feed_token"], a, "generic-json", "core-feed", None),
                (w["revoked_token"], a, "generic-json", "core-feed", "now()"),
                (w["other_label_token"], a, "generic-json", "someone-elses", None),
                (w["other_template_token"], a, "pagerduty", "core-feed", None),
                (w["b_feed_token"], b, "generic-json", "core-feed", None),
            ]
            for token, tenant, template, label, revoked in rows:
                await conn.execute(
                    text(
                        "insert into tenant_inbox_tokens (token, tenant_id, template_id, label, revoked_at) "
                        f"values (:k, :t, :tpl, :l, {'now()' if revoked else 'null'})"
                    ),
                    {"k": token, "t": tenant, "tpl": template, "l": label},
                )
        w["owner"], w["factory"] = owner, async_sessionmaker(on, expire_on_commit=False)
        yield w
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("delete from tenants where id in (:a, :b)"), {"a": a, "b": b})
        await on.dispose()
        await owner.dispose()


def report(*sources: SourceReport) -> StatusReport:
    return StatusReport(sources=list(sources))


async def run(world, token: str, rep: StatusReport) -> int:
    """Exactly what the endpoint does: resolve the token, adopt its tenant, apply, commit."""
    async with world["factory"]() as session:
        tenant = await _verify_core_feed_token(session, token)
        await adopt_tenant(session, tenant)
        applied = await apply_report(session, tenant, rep)
        await session.commit()
    return applied


async def rows(world, tenant):
    async with world["owner"].connect() as conn:
        res = await conn.execute(
            text(
                "select name, connector_type, category, is_enabled, health_status, events_ingested, error_count, last_sync, last_event_at, last_outage_at, "
                "connector_config, tags from connectors where tenant_id = :t order by name"
            ),
            {"t": tenant},
        )
        return res.all()


async def test_the_first_report_creates_a_row_that_the_connectors_page_will_show_as_healthy_with_its_count(world):
    assert (
        await run(
            world,
            world["feed_token"],
            report(SourceReport(vendor="huntress", name="Huntress", category="edr", status="ok", fetched=3, sent=3)),
        )
        == 1
    )
    (row,) = await rows(world, world["a"])
    assert row.name == "Huntress (via CORE)" and row.connector_type == "core_feed" and row.category == "edr" and row.is_enabled is True
    assert row.health_status == "healthy" and row.events_ingested == 3 and row.error_count == 0
    assert row.last_sync is not None and row.last_event_at is not None
    assert row.connector_config == {"vendor": "huntress", "managed_by": "core"} and row.tags == ["core-feed"]


async def test_later_reports_update_the_same_row_and_the_counts_add_up(world):
    for sent in (3, 0, 4):
        await run(world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="ok", sent=sent)))
    (row,) = await rows(world, world["a"])
    assert row.events_ingested == 7, "3 + 0 + 4, on one row"


async def test_an_empty_run_is_healthy_and_does_not_claim_an_event_arrived(world):
    await run(world, world["feed_token"], report(SourceReport(vendor="blumira", category="siem", status="ok", sent=0)))
    (row,) = await rows(world, world["a"])
    assert row.health_status == "healthy" and row.last_sync is not None
    assert row.last_event_at is None, "no event arrived, so 'last event' stays empty"


async def test_a_failed_run_marks_it_unhealthy_counts_the_error_and_keeps_the_first_outage_time(world):
    await run(world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="ok", sent=2)))
    await run(world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="error")))
    (first,) = await rows(world, world["a"])
    assert first.health_status == "unhealthy" and first.error_count == 1 and first.events_ingested == 2 and first.last_outage_at is not None
    await run(world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="error")))
    (second,) = await rows(world, world["a"])
    assert second.error_count == 2 and second.last_outage_at == first.last_outage_at, "a sustained outage keeps its original start"


async def test_recovery_makes_it_healthy_again_and_clears_the_outage(world):
    await run(world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="error")))
    await run(world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="ok", sent=1)))
    (row,) = await rows(world, world["a"])
    assert (
        row.health_status == "healthy" and row.last_outage_at is None and row.error_count == 1
    ), "the error count is history; the outage is over"


async def test_two_sources_in_one_report_become_two_rows(world):
    n = await run(
        world,
        world["feed_token"],
        report(
            SourceReport(vendor="huntress", name="Huntress", category="edr", status="ok", sent=1),
            SourceReport(vendor="blumira", name="Blumira", category="siem", status="ok", sent=2),
        ),
    )
    assert n == 2
    assert [(r.name, r.events_ingested) for r in await rows(world, world["a"])] == [("Blumira (via CORE)", 2), ("Huntress (via CORE)", 1)]


async def test_a_report_only_ever_touches_its_own_tenant(world):
    await run(world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="ok", sent=5)))
    await run(world, world["b_feed_token"], report(SourceReport(vendor="huntress", category="edr", status="ok", sent=1)))
    (a_row,) = await rows(world, world["a"])
    (b_row,) = await rows(world, world["b"])
    assert a_row.events_ingested == 5 and b_row.events_ingested == 1, "each tenant has its own row and its own count"


async def test_a_report_never_touches_a_connector_that_is_not_a_core_feed_row(world):
    async with world["owner"].begin() as conn:
        await conn.execute(
            text(
                "insert into connectors (id, tenant_id, name, connector_type, category, is_enabled, connector_config) "
                "values (:i, :t, 'Real Huntress', 'okta', 'iam', true, :c)"
            ),
            {"i": uuid.uuid4(), "t": world["a"], "c": '{"vendor": "huntress"}'},
        )
    await run(world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="ok", sent=9)))
    by_name = {r.name: r for r in await rows(world, world["a"])}
    assert (
        by_name["Real Huntress"].events_ingested == 0 and by_name["Real Huntress"].health_status == "unknown"
    ), "a different connector type is left alone"
    assert by_name["Huntress (via CORE)"].events_ingested == 9


@pytest.mark.parametrize("which", ["revoked_token", "other_label_token", "other_template_token"])
async def test_only_an_active_core_feed_token_is_accepted(world, which):
    with pytest.raises(HTTPException) as refused:
        await run(world, world[which], report(SourceReport(vendor="huntress", category="edr", status="ok", sent=1)))
    assert refused.value.status_code == 401
    assert await rows(world, world["a"]) == [], "nothing was written"


async def test_an_unknown_token_is_a_401_and_writes_nothing(world):
    with pytest.raises(HTTPException) as refused:
        await run(world, "aitnb_nosuchtoken", report(SourceReport(vendor="huntress", category="edr", status="ok", sent=1)))
    assert refused.value.status_code == 401
    assert await rows(world, world["a"]) == [] and await rows(world, world["b"]) == []


def test_the_report_shape_refuses_a_vendor_id_that_could_be_abused():
    for bad in ("", "Huntress", "../x", "a b", "x" * 41, "-x"):
        with pytest.raises(ValueError):
            SourceReport(vendor=bad, status="ok")
    with pytest.raises(ValueError):
        SourceReport(vendor="huntress", status="ok", sent=-1)
    with pytest.raises(ValueError):
        SourceReport(vendor="huntress", status="maybe")


async def test_a_failure_reason_is_kept_for_the_card_and_cleared_on_recovery(world):
    cfg = lambda: rows(world, world["a"])  # noqa: E731
    await run(
        world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="error", message="Huntress returned 401"))
    )
    (row,) = await cfg()
    assert row.connector_config["last_error"] == "Huntress returned 401" and row.connector_config["vendor"] == "huntress"
    assert row.connector_config["last_error_at"]

    await run(world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="error")))
    (row,) = await cfg()
    assert "last_error" not in row.connector_config, "an error with no reason does not keep (or invent) an old one"

    await run(
        world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="error", message="Huntress returned 429"))
    )
    await run(world, world["feed_token"], report(SourceReport(vendor="huntress", category="edr", status="ok", sent=1)))
    (row,) = await cfg()
    assert row.connector_config == {"vendor": "huntress", "managed_by": "core"}, "recovery clears the reason"
