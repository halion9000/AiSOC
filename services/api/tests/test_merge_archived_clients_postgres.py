"""Folding an archived client into its live twin, against a REAL Postgres (opt in with AISOC_TEST_PG_URL, a DISPOSABLE, fully migrated database; the connecting role must own the tables)."""

import json
import os
import uuid

import pytest
from app.scripts import merge_archived_clients as m
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database")


@pytest.fixture
async def world():
    """A parent with a live client and an archived twin, the twin holding two alerts, a run with events, a memory note, duplicate and custom rules, and metrics."""
    tag = uuid.uuid4().hex[:8]
    ids = {k: uuid.uuid4() for k in ("parent", "live", "old")}
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for key, name, parent in (
            ("parent", f"mspar-{tag}", None),
            ("live", f"Acme {tag}", ids["parent"]),
            ("old", f"Acme {tag} (archived)", ids["parent"]),
        ):
            await c.execute(
                text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, :p)"),
                {"i": ids[key], "n": name, "s": f"{key}-{tag}", "p": parent},
            )
        old, live = ids["old"], ids["live"]
        for title in ("old one", "old two"):
            await c.execute(text("insert into alerts (tenant_id, title) values (:t, :ti)"), {"t": old, "ti": title})
        await c.execute(text("insert into alerts (tenant_id, title) values (:t, 'live one')"), {"t": live})
        run = uuid.uuid4()
        await c.execute(text("insert into investigation_runs (id, tenant_id, case_id) values (:r, :t, 'c1')"), {"r": run, "t": old})
        for seq in (1, 2):
            await c.execute(
                text(
                    "insert into investigation_events (run_id, tenant_id, seq, kind, agent, summary) values (:r, :t, :s, 'k', 'a', 'did a thing')"
                ),
                {"r": run, "t": old, "s": seq},
            )
        await c.execute(text("insert into aisoc_institutional_memory (tenant_id, key, value) values (:t, 'k1', '{}')"), {"t": str(old)})
        for name in ("Shared rule", "Only on old"):
            await c.execute(text("insert into detection_rules (tenant_id, name) values (:t, :n)"), {"t": old, "n": name})
        await c.execute(text("insert into detection_rules (tenant_id, name) values (:t, 'Shared rule')"), {"t": live})
        await c.execute(text("insert into mssp_tenant_metrics (tenant_id) values (:t)"), {"t": old})
    yield ids, tag
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(text("alter table investigation_events disable trigger trg_inv_events_immutable"))
        try:
            await c.execute(text("delete from tenants where parent_tenant_id = :p or id = :p"), {"p": ids["parent"]})
        finally:
            await c.execute(text("alter table investigation_events enable trigger trg_inv_events_immutable"))
    await engine.dispose()


async def count(sql: str, **p) -> int:
    engine = create_async_engine(PG_URL)
    try:
        async with engine.connect() as c:
            return int((await c.execute(text(sql), p)).scalar_one())
    finally:
        await engine.dispose()


async def test_dry_run_reports_the_plan_and_changes_nothing(world, tmp_path, capsys):
    ids, tag = world
    assert await m.run(PG_URL, False, tmp_path, f"Acme {tag}") == 0
    out = capsys.readouterr().out
    assert "2 alerts" in out and "2 investigation_events" in out and "1 duplicate dropped, 1 moved" in out
    assert await count("select count(*) from tenants where id = :t", t=ids["old"]) == 1
    assert await count("select count(*) from alerts where tenant_id = :t", t=ids["old"]) == 2
    assert list(tmp_path.iterdir()) == [], "a dry run writes no backup"


async def test_apply_moves_everything_deletes_the_shell_and_leaves_the_trigger_on(world, tmp_path):
    ids, tag = world
    assert await m.run(PG_URL, True, tmp_path, f"Acme {tag}") == 0
    live = ids["live"]
    assert await count("select count(*) from tenants where id = :t", t=ids["old"]) == 0
    assert await count("select count(*) from alerts where tenant_id = :t", t=live) == 3
    assert await count("select count(*) from investigation_runs where tenant_id = :t", t=live) == 1
    assert await count("select count(*) from investigation_events where tenant_id = :t", t=live) == 2
    assert await count("select count(*) from aisoc_institutional_memory where tenant_id = :t", t=str(live)) == 1
    assert (
        await count("select count(*) from detection_rules where tenant_id = :t", t=live) == 2
    ), "the shared rule is not duplicated; the custom one moved"
    assert await count("select count(*) from detection_rules where tenant_id = :t and name = 'Only on old'", t=live) == 1
    assert (
        await count("select count(*) from pg_trigger where tgname = 'trg_inv_events_immutable' and tgenabled = 'O'") == 1
    ), "the tamper-proofing is back on"
    files = list(tmp_path.glob("archived-client-*.json"))
    assert len(files) == 1
    saved = json.loads(files[0].read_text(encoding="utf-8"))
    assert saved["tables"]["alerts"] and len(saved["tables"]["investigation_events"]) == 2 and saved["tables"]["detection_rules"]


async def test_events_stay_tamper_proof_after_the_move(world, tmp_path):
    ids, tag = world
    await m.run(PG_URL, True, tmp_path, f"Acme {tag}")
    engine = create_async_engine(PG_URL)
    try:
        with pytest.raises(Exception, match="immutable"):
            async with engine.begin() as c:
                await c.execute(text("update investigation_events set summary = 'x' where tenant_id = :t"), {"t": ids["live"]})
    finally:
        await engine.dispose()


async def test_a_client_that_owns_something_unknown_is_refused_and_left_alone(world, tmp_path, capsys):
    ids, tag = world
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(text("insert into roles (tenant_id, name) values (:t, 'Custom role')"), {"t": ids["old"]})
    await engine.dispose()
    assert await m.run(PG_URL, True, tmp_path, f"Acme {tag}") == 1
    assert "REFUSED" in capsys.readouterr().out
    assert await count("select count(*) from tenants where id = :t", t=ids["old"]) == 1
    assert await count("select count(*) from alerts where tenant_id = :t", t=ids["old"]) == 2


async def test_a_clash_with_the_live_clients_alerts_is_refused_before_anything_moves(world, tmp_path, capsys):
    ids, tag = world
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(
            text("update alerts set idempotency_key = 'same' where tenant_id in (:a, :b) and title in ('old one', 'live one')"),
            {"a": ids["old"], "b": ids["live"]},
        )
    await engine.dispose()
    assert await m.run(PG_URL, True, tmp_path, f"Acme {tag}") == 1
    assert "idempotency" in capsys.readouterr().out
    assert await count("select count(*) from alerts where tenant_id = :t", t=ids["old"]) == 2
    assert await count("select count(*) from pg_trigger where tgname = 'trg_inv_events_immutable' and tgenabled = 'O'") == 1


async def test_a_client_with_no_live_twin_is_refused(world, tmp_path, capsys):
    ids, tag = world
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(text("update tenants set name = :n where id = :i"), {"n": f"Renamed {tag}", "i": ids["live"]})
    await engine.dispose()
    assert await m.run(PG_URL, True, tmp_path, f"Acme {tag}") == 1
    assert "no live client" in capsys.readouterr().out
    assert await count("select count(*) from tenants where id = :t", t=ids["old"]) == 1
