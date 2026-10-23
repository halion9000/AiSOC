"""The bulk script route and the Microsoft 365 check storage against a REAL Postgres, as the application role (row-level security on).

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), as the sibling tests do. The database must be disposable and fully migrated (incl. migration 097).
"""

import json
import os
import uuid
from types import SimpleNamespace as NS

import pytest
from app.api.v1.endpoints import alert_scripts as sc
from app.db.rls import set_rls_context
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

REQUEST = NS(client=NS(host="127.0.0.1"), headers={"user-agent": "pytest"}, state=NS())
PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:10]
    ids = {k: uuid.uuid4() for k in ("parent", "acme", "birch", "other_parent", "stranger")}
    alerts: dict[str, uuid.UUID] = {}
    owner = create_async_engine(PG_URL, poolclass=NullPool)
    scripts = [{"id": 7, "name": "Disk Space Scan", "one_click": False}]
    try:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            for key, tid in ids.items():
                parent = ids["parent"] if key in ("acme", "birch") else ids["other_parent"] if key == "stranger" else None
                await conn.execute(
                    text(
                        "insert into tenants (id, name, slug, parent_tenant_id, mssp_role, settings) values (:i, :n, :s, :p, :r, cast(:st as jsonb))"
                    ),
                    {
                        "i": tid,
                        "n": f"{key}-{tag}",
                        "s": f"{key}-{tag}",
                        "p": parent,
                        "r": "child" if parent else "parent",
                        "st": json.dumps({"core_scripts": scripts} if key == "parent" else {}),
                    },
                )
            rows = [
                ("a1", "acme", ["PC-01"]),
                ("a2", "acme", ["PC-02"]),
                ("a2dup", "acme", ["pc-02"]),
                ("b1", "birch", ["PC-01"]),
                ("nohost", "acme", []),
                ("theirs", "stranger", ["X-1"]),
            ]
            for name, key, hosts in rows:
                alerts[name] = uuid.uuid4()
                await conn.execute(
                    text(
                        "insert into alerts (id, tenant_id, title, severity, status, affected_hosts, raw_event, dedup_hash, created_at, event_time, first_seen, last_seen) "
                        "values (:id, :t, :n, 'high', 'new', cast(:h as jsonb), cast(:raw as jsonb), :d, now(), now(), now(), now())"
                    ),
                    {
                        "id": alerts[name],
                        "t": ids[key],
                        "n": f"Disk space low {name}",
                        "h": json.dumps(hosts),
                        "raw": json.dumps({"finding": {"uid": f"ninjaone:{name}"}}),
                        "d": f"d-{tag}-{name}",
                    },
                )
        yield ids, alerts, owner
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            t = [str(x) for x in ids.values()]
            for table in ("vendor_actions", "client_m365_checks", "alerts"):
                await conn.execute(text(f"delete from {table} where tenant_id = any(cast(:t as uuid[]))"), {"t": t})
            await conn.execute(text("delete from audit_log where tenant_id = any(cast(:t as uuid[]))"), {"t": t})
            await conn.execute(text("delete from tenants where id = any(cast(:t as uuid[])) and parent_tenant_id is not null"), {"t": t})
            await conn.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": t})
        await owner.dispose()


async def test_one_clients_m365_checks_cannot_be_read_by_another_tenant(world):
    ids, _, owner = world
    async with owner.begin() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for key in ("acme", "birch"):
            await conn.execute(
                text("insert into client_m365_checks (tenant_id, source, checks) values (:t, 'cipp', cast(:c as jsonb))"),
                {"t": ids[key], "c": json.dumps([{"key": "spf", "status": "met", "evidence": key}])},
            )
    app = create_async_engine(APP_URL, poolclass=NullPool)
    try:

        async def seen_as(tid):
            async with async_sessionmaker(app, expire_on_commit=False)() as s:
                await set_rls_context(s, tid)
                return [r[0] for r in (await s.execute(text("select checks->0->>'evidence' from client_m365_checks"))).all()]

        assert await seen_as(ids["acme"]) == ["acme"]
        assert await seen_as(ids["birch"]) == ["birch"]
        assert await seen_as(ids["stranger"]) == []
    finally:
        await app.dispose()


async def test_the_bulk_route_queues_one_request_per_machine_under_one_batch_and_skips_what_it_must(world, monkeypatch):
    ids, a, owner = world
    audited = []

    async def fake_audit(**kw):  # the audit row needs a real user (a foreign key); what is audited is checked instead
        audited.append(kw)

    monkeypatch.setattr(sc, "emit_audit", fake_audit)
    app = create_async_engine(APP_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(app, expire_on_commit=False)() as s:
            await set_rls_context(s, ids["parent"])
            user = NS(tenant_id=ids["parent"], user_id=uuid.uuid4())
            body = sc.BulkRunRequest(script_id=7, alert_ids=[a["a1"], a["a2"], a["a2dup"], a["b1"], a["nohost"], a["theirs"]])
            out = await sc.run_script_bulk(body, REQUEST, user, s)
    finally:
        await app.dispose()
    by = {i.alert_id: i for i in out.items}
    assert (out.queued, out.skipped) == (3, 3), [(i.device, i.outcome, i.reason) for i in out.items]
    assert (
        by[a["a1"]].outcome == by[a["a2"]].outcome == by[a["b1"]].outcome == "queued"
    )  # the same machine name under two different clients is two machines
    assert "already covers" in (by[a["a2dup"]].reason or "") and "no machine" in (by[a["nohost"]].reason or "").lower().replace(
        "not name a", "no"
    )
    assert by[a["theirs"]].reason == "Alert not found."  # another MSP's alert is invisible
    async with owner.begin() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        rows = (
            await conn.execute(
                text("select tenant_id, params from vendor_actions where vendor = 'core' and tenant_id = any(cast(:t as uuid[]))"),
                {"t": [str(ids["acme"]), str(ids["birch"]), str(ids["stranger"])]},
            )
        ).all()
    assert len(rows) == 3 and {r[0] for r in rows} == {ids["acme"], ids["birch"]}
    assert len({r[1]["batch_id"] for r in rows}) == 1 and rows[0][1]["batch_id"] == out.batch_id
    assert all("create_ticket" in r[1] and "ticket_id" not in r[1] for r in rows)
    assert {r[1]["device"] for r in rows} == {"PC-01", "PC-02"}
    assert [k["action"] for k in audited] == ["alerts:script_requested"] * 3 and {k["changes"]["batch"] for k in audited} == {out.batch_id}

    # asking again while those are still waiting queues nothing new for those alerts
    app = create_async_engine(APP_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(app, expire_on_commit=False)() as s:
            await set_rls_context(s, ids["parent"])
            again = await sc.run_script_bulk(
                sc.BulkRunRequest(script_id=7, alert_ids=[a["a1"]]), REQUEST, NS(tenant_id=ids["parent"], user_id=uuid.uuid4()), s
            )
    finally:
        await app.dispose()
    assert again.queued == 0 and "already waiting" in (again.items[0].reason or "")
