"""The Run script round trip and the Microsoft 365 check ingest, through the real route functions on a REAL Postgres, as the application role with row-level security failing closed.

The flow: CORE reports which scripts are switched on -> an alert offers them -> a person queues one (single or bulk) -> CORE claims it -> CORE reports the outcome. The checks that
cannot be bypassed: a wrong token writes nothing, an ignored client's data is not stored, and a request nobody claims stops counting as in flight.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app). The database must be disposable and fully migrated (incl. 097 and 098).
"""

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS

import pytest
from app.api.v1.endpoints import alert_scripts as sc
from app.api.v1.endpoints import client_review as cr
from app.api.v1.endpoints import inbox_core_feed as feed
from app.db.rls import set_rls_context
from app.services.vendor_actions import PENDING_TTL
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
REQUEST = NS(client=NS(host="127.0.0.1"), headers={"user-agent": "pytest"}, state=NS())


@pytest.fixture
async def world(monkeypatch):
    async def no_audit(**_kw):  # the audit row needs a real user (a foreign key); these tests are about the queue
        return None

    monkeypatch.setattr(sc, "emit_audit", no_audit)
    tag = uuid.uuid4().hex[:10]
    w = {k: uuid.uuid4() for k in ("parent", "acme", "birch")}
    w["token"], w["bad_token"] = f"aitnb_scripts_{tag}", f"aitnb_nope_{tag}"
    w["alert"], w["alert2"], w["alert3"] = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    owner = create_async_engine(PG_URL, poolclass=NullPool)
    app = create_async_engine(APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}})
    try:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            for key in ("parent", "acme", "birch"):
                parent = w["parent"] if key != "parent" else None
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                    {"i": w[key], "n": f"sc-{key}-{tag}", "s": f"sc-{key}-{tag}", "p": parent, "r": "child" if parent else "parent"},
                )
            await conn.execute(
                text("insert into tenant_inbox_tokens (token, tenant_id, template_id, label) values (:k, :t, 'generic-json', 'core-feed')"),
                {"k": w["token"], "t": w["parent"]},
            )
            for aid, key, host in ((w["alert"], "acme", ["PC-01"]), (w["alert2"], "acme", ["PC-02"]), (w["alert3"], "birch", [])):
                await conn.execute(
                    text(
                        "insert into alerts (id, tenant_id, title, severity, status, affected_hosts, raw_event, dedup_hash, created_at, event_time, first_seen, last_seen) "
                        "values (:id, :t, 'Disk space low', 'high', 'new', cast(:h as jsonb), cast(:raw as jsonb), :d, now(), now(), now(), now())"
                    ),
                    {
                        "id": aid,
                        "t": w[key],
                        "h": json.dumps(host),
                        "raw": json.dumps({"finding": {"uid": f"ninjaone:{aid}"}}),
                        "d": f"d-{aid}",
                    },
                )
        w["owner"], w["factory"] = owner, async_sessionmaker(app, expire_on_commit=False)
        yield w
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            t = [str(w[k]) for k in ("parent", "acme", "birch")]
            for table in ("vendor_actions", "client_m365_checks", "client_aliases", "alerts", "tenant_inbox_tokens"):
                await conn.execute(text(f"delete from {table} where tenant_id = any(cast(:t as uuid[]))"), {"t": t})
            await conn.execute(text("delete from tenants where id = any(cast(:t as uuid[])) and parent_tenant_id is not null"), {"t": t})
            await conn.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": t})
        await app.dispose()
        await owner.dispose()


def user(w):
    return NS(tenant_id=w["parent"], user_id=uuid.uuid4())


async def signed_in(w):
    s = w["factory"]()
    await set_rls_context(s, w["parent"])
    return s


async def queued(w, **where):
    async with w["owner"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        clause = " and ".join(f"{k} = :{k}" for k in where) or "true"
        return (
            await conn.execute(
                text(
                    f"select id, tenant_id, alert_id, status, params, result_message from vendor_actions where {clause} order by created_at"
                ),
                where,
            )
        ).all()


async def core_reports_scripts(w, scripts):
    async with w["factory"]() as s:
        return await feed.report_core_feed_scripts(w["token"], feed.ScriptsReport(scripts=scripts), s)


ONE = {"id": 7, "name": "Disk Space Scan", "one_click": False}


async def test_scripts_reported_by_core_are_stored_replaced_and_offered_on_an_alert(world):
    w = world
    assert (await core_reports_scripts(w, [ONE, {"id": 9, "name": "Restart Spooler", "one_click": True}])).stored == 2
    async with await signed_in(w) as s:
        options = await sc.alert_script_options(w["alert"], user(w), s)
    assert (
        [x.name for x in options.scripts] == ["Disk Space Scan", "Restart Spooler"]
        and options.device == "PC-01"
        and options.blocked is None
    )
    await core_reports_scripts(w, [ONE])
    async with await signed_in(w) as s:
        assert [x.id for x in (await sc.alert_script_options(w["alert"], user(w), s)).scripts] == [
            7
        ], "a script switched off in CORE disappears"


async def test_the_options_say_why_nothing_can_run_against_real_rows(world):
    w = world
    async with await signed_in(w) as s:
        assert "has not shared any scripts" in (await sc.alert_script_options(w["alert"], user(w), s)).blocked
    await core_reports_scripts(w, [ONE])
    async with await signed_in(w) as s:
        assert "does not name a machine" in (await sc.alert_script_options(w["alert3"], user(w), s)).blocked


async def test_the_single_route_queues_a_run_script_row_on_a_real_database(world):
    w = world
    await core_reports_scripts(w, [ONE])
    async with await signed_in(w) as s:
        out = await sc.run_alert_script(
            w["alert"], sc.RunScriptRequest(script_id=7, ticket={"mode": "link", "number": "#0553688"}), REQUEST, user(w), s
        )
    assert out.status == "pending" and out.runs_at_once is False
    (row,) = await queued(w, alert_id=w["alert"])
    assert (row.tenant_id, row.status) == (w["acme"], "pending")
    assert row.params["device"] == "PC-01" and row.params["ticket_id"] == "553688" and row.params["script_id"] == 7


async def test_a_queued_request_goes_pending_to_claimed_to_done_and_a_second_answer_is_refused(world):
    w = world
    await core_reports_scripts(w, [ONE])
    async with await signed_in(w) as s:
        await sc.run_alert_script(w["alert"], sc.RunScriptRequest(script_id=7, ticket={"mode": "create"}), REQUEST, user(w), s)
    async with w["factory"]() as s:
        claimed = await feed.claim_core_feed_actions(w["token"], feed.ClaimRequest(vendor="core"), s)
    assert [a.action for a in claimed.actions] == ["run_script"] and claimed.actions[0].params["device"] == "PC-01"
    async with w["factory"]() as s:
        again = await feed.claim_core_feed_actions(w["token"], feed.ClaimRequest(vendor="core"), s)
    assert again.actions == [], "claimed once, never twice"
    action_id = claimed.actions[0].id
    async with w["factory"]() as s:
        assert (
            await feed.report_core_feed_action_result(
                w["token"], action_id, feed.ActionResult(status="done", message="Opened ticket 9001. Output attached."), s
            )
        ).recorded
    (row,) = await queued(w, id=action_id)
    assert row.status == "done" and "9001" in row.result_message
    async with w["factory"]() as s:
        with pytest.raises(HTTPException) as e:
            await feed.report_core_feed_action_result(w["token"], action_id, feed.ActionResult(status="failed", message="late"), s)
    assert e.value.status_code == 404


async def test_a_request_nobody_claims_stops_counting_as_waiting_after_the_time_limit(world):
    w = world
    await core_reports_scripts(w, [ONE])
    async with await signed_in(w) as s:
        await sc.run_alert_script(w["alert"], sc.RunScriptRequest(script_id=7, ticket={"mode": "create"}), REQUEST, user(w), s)
    async with await signed_in(w) as s:
        with pytest.raises(HTTPException) as e:
            await sc.run_alert_script(w["alert"], sc.RunScriptRequest(script_id=7, ticket={"mode": "create"}), REQUEST, user(w), s)
    assert e.value.status_code == 409
    async with w["owner"].begin() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await conn.execute(
            text("update vendor_actions set created_at = :t where alert_id = :a"),
            {"t": datetime.now(UTC) - PENDING_TTL - timedelta(minutes=1), "a": w["alert"]},
        )
    async with await signed_in(w) as s:
        assert (
            await sc.run_alert_script(w["alert"], sc.RunScriptRequest(script_id=7, ticket={"mode": "create"}), REQUEST, user(w), s)
        ).status == "pending"


async def test_the_bulk_route_also_skips_an_alert_whose_request_is_already_claimed(world):
    w = world
    await core_reports_scripts(w, [ONE])
    async with await signed_in(w) as s:
        await sc.run_alert_script(w["alert"], sc.RunScriptRequest(script_id=7, ticket={"mode": "create"}), REQUEST, user(w), s)
    async with w["factory"]() as s:
        await feed.claim_core_feed_actions(w["token"], feed.ClaimRequest(vendor="core"), s)
    async with await signed_in(w) as s:
        out = await sc.run_script_bulk(sc.BulkRunRequest(script_id=7, alert_ids=[w["alert"], w["alert2"]]), REQUEST, user(w), s)
    by = {i.alert_id: i for i in out.items}
    assert by[w["alert"]].outcome == "skipped" and "already waiting" in by[w["alert"]].reason
    assert by[w["alert2"]].outcome == "queued" and out.queued == 1


def checks_report(client="m365-1", vendor="cipp", checks=None):
    return cr.M365ChecksReport(vendor=vendor, vendor_client_id=client, checks=checks or [{"key": "spf", "status": "met", "evidence": "ok"}])


async def ingest(w, token, report):
    async with w["factory"]() as s:
        return await cr.report_core_feed_m365_checks(token, report, s)


async def map_client(w, client="m365-1", ignored=False, vendor="cipp", to="acme"):
    async with w["owner"].begin() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await conn.execute(
            text(
                "insert into client_aliases (tenant_id, vendor, vendor_client_id, vendor_client_name, normalized_name, child_tenant_id, ignored, match_source) "
                "values (:t, :v, :c, :n, :nn, :ch, :ig, 'manual')"
            ),
            {"t": w["parent"], "v": vendor, "c": client, "n": client, "nn": client, "ch": None if ignored else w[to], "ig": ignored},
        )


async def stored_checks(w):
    async with w["owner"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        return (
            await conn.execute(
                text("select tenant_id, source from client_m365_checks where tenant_id = any(cast(:t as uuid[]))"),
                {"t": [str(w[k]) for k in ("parent", "acme", "birch")]},
            )
        ).all()


async def test_m365_checks_with_a_wrong_token_are_refused_and_nothing_is_written(world):
    w = world
    await map_client(w)
    with pytest.raises(HTTPException) as e:
        await ingest(w, w["bad_token"], checks_report())
    assert e.value.status_code == 401
    assert await stored_checks(w) == []


async def test_m365_checks_for_an_ignored_client_are_counted_as_ignored_and_not_stored(world):
    w = world
    await map_client(w, ignored=True)
    out = await ingest(w, w["token"], checks_report())
    assert (out.accepted, out.ignored) == (0, 1)
    assert await stored_checks(w) == []


async def test_two_sources_for_one_client_keep_separate_check_lists(world):
    w = world
    await map_client(w, client="c-cipp", vendor="cipp")
    await map_client(w, client="c-other", vendor="othertool")
    await ingest(w, w["token"], checks_report(client="c-cipp", vendor="cipp"))
    await ingest(
        w, w["token"], checks_report(client="c-other", vendor="othertool", checks=[{"key": "dkim", "status": "not_met", "evidence": "x"}])
    )
    assert sorted(r[1] for r in await stored_checks(w)) == ["cipp", "othertool"]
    await ingest(
        w, w["token"], checks_report(client="c-cipp", vendor="cipp", checks=[{"key": "spf", "status": "partly", "evidence": "second"}])
    )
    assert len(await stored_checks(w)) == 2, "replacing one source's list does not touch the other's"
