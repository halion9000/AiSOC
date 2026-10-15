"""Moving alerts under the client they belong to, against a REAL Postgres.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), as the sibling tests do. The database must be disposable.
"""

import json
import os
import uuid

import pytest
from app.db.rls import set_rls_context
from app.services.alert_reroute import RerouteError, reroute_alerts
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)


def raw(source, **context):
    return json.dumps({"source": source, "unmapped": {"context": context}})


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:10]
    ids = {k: uuid.uuid4() for k in ("parent", "acme", "birch", "other_parent")}
    a: dict[str, uuid.UUID] = {}
    owner = create_async_engine(PG_URL)
    try:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            for key, tid in ids.items():
                parent = ids["parent"] if key in ("acme", "birch") else None
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                    {"i": tid, "n": f"{key}-{tag}", "s": f"{key}-{tag}", "p": parent, "r": "child" if parent else "parent"},
                )
            aliases = [
                ("huntress", "7", "acme", False),
                ("petra", "p9", "birch", False),
                ("ninjaone", "5", "acme", True),  # ignored: must not move
                ("blumira", "b1", "acme", False),  # a vendor with no client id in its records: must not move
            ]
            for vendor, vid, child, ignored in aliases:
                await conn.execute(
                    text(
                        "insert into client_aliases (tenant_id, vendor, vendor_client_id, vendor_client_name, normalized_name, child_tenant_id, ignored, match_source) "
                        "values (:p, :v, :i, :n, :n, :c, :ig, 'manual')"
                    ),
                    {"p": ids["parent"], "v": vendor, "i": vid, "n": f"{vendor}-{vid}", "c": ids[child], "ig": ignored},
                )
            rows = [  # name, owning tenant, raw_event, dedup hash
                ("h_acme", "parent", raw("huntress", organization_id="7"), "h1"),
                ("h_acme_int", "parent", raw("huntress", organization_id=7), "h1b"),  # the id arrives as a number
                ("p_birch", "parent", raw("petra", petra_tenant_id="p9"), "p1"),
                ("h_unmapped", "parent", raw("huntress", organization_id="999"), "h2"),
                ("h_noid", "parent", raw("huntress"), "h3"),
                ("n_ignored", "parent", raw("ninjaone", organization_id="5"), "n1"),
                ("b_vendor", "parent", raw("blumira", organization_id="b1"), "b1"),
                ("h_dup_parent", "parent", raw("huntress", organization_id="7"), "dup"),
                ("h_dup_child", "acme", raw("huntress", organization_id="7"), "dup"),  # already stored under the client
                ("h_other_parents", "other_parent", raw("huntress", organization_id="7"), "o1"),
            ]
            for name, owner_key, rawj, h in rows:
                a[name] = uuid.uuid4()
                await conn.execute(
                    text(
                        "insert into alerts (id, tenant_id, title, severity, status, raw_event, dedup_hash, created_at, event_time, first_seen, last_seen) "
                        "values (:id, :t, :n, 'high', 'new', cast(:raw as jsonb), :h, now(), now(), now(), now())"
                    ),
                    {"id": a[name], "t": ids[owner_key], "n": name, "raw": rawj, "h": h},
                )
            cases = {"case_whole": [a["h_acme"]], "case_spanning": [a["p_birch"], a["h_unmapped"]]}
            case_ids: dict[str, uuid.UUID] = {}
            for name, alert_ids in cases.items():
                case_ids[name] = uuid.uuid4()
                await conn.execute(
                    text(
                        "insert into aisoc_cases (id, tenant_id, title, severity, status, alert_ids, compliance_frameworks, tags, opened_at, created_at, updated_at, created_by) "
                        "values (:id, :t, :n, 'high', 'new', cast(:ids as uuid[]), cast('{}' as text[]), '{}'::jsonb, now(), now(), now(), 'system')"
                    ),
                    {"id": case_ids[name], "t": ids["parent"], "n": name, "ids": [str(x) for x in alert_ids]},
                )
            await conn.execute(
                text(
                    "insert into vendor_actions (tenant_id, alert_id, vendor, incident_uid, action) values (:t, :a, 'huntress', 'x', 'approve')"
                ),
                {"t": ids["parent"], "a": a["h_acme"]},
            )
        yield ids, a, case_ids, owner
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            tids = list(ids.values())
            await conn.execute(text("delete from vendor_actions where tenant_id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in tids]})
            await conn.execute(text("delete from aisoc_cases where tenant_id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in tids]})
            await conn.execute(text("delete from alerts where tenant_id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in tids]})
            await conn.execute(text("delete from client_aliases where tenant_id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in tids]})
            await conn.execute(
                text("delete from tenants where id = any(cast(:t as uuid[])) and parent_tenant_id is not null"),
                {"t": [str(x) for x in tids]},
            )
            await conn.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in tids]})
        await owner.dispose()


async def owner_of(owner, alert_id, table="alerts"):
    async with owner.begin() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        return (await conn.execute(text(f"select tenant_id from {table} where id = :i"), {"i": alert_id})).scalar_one()


async def test_existing_alerts_move_to_their_mapped_client_and_only_those(world):
    ids, a, case_ids, owner = world
    async with async_sessionmaker(owner, expire_on_commit=False)() as s:
        await s.execute(text("select set_config('app.rls_fail_closed', 'off', false)"))
        result = await reroute_alerts(s, ids["parent"])
        await s.commit()
    assert result.moved == 3 and result.left_duplicates == 1 and result.cases_moved == 1
    by = {k.split("-")[0]: v for k, v in result.by_client.items()}
    assert by == {"acme": 2, "birch": 1}

    where = {n: await owner_of(owner, a[n]) for n in a}
    assert where["h_acme"] == where["h_acme_int"] == ids["acme"]  # a numeric id matches too
    assert where["p_birch"] == ids["birch"]
    for stays in ("h_unmapped", "h_noid", "n_ignored", "b_vendor", "h_dup_parent"):
        assert where[stays] == ids["parent"], stays
    assert where["h_dup_child"] == ids["acme"] and where["h_other_parents"] == ids["other_parent"]
    assert await owner_of(owner, case_ids["case_whole"], "aisoc_cases") == ids["acme"]
    assert await owner_of(owner, case_ids["case_spanning"], "aisoc_cases") == ids["parent"]  # one of its alerts did not move
    async with owner.begin() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        assert (
            await conn.execute(text("select tenant_id from vendor_actions where alert_id = :a"), {"a": a["h_acme"]})
        ).scalar_one() == ids["acme"]


async def test_running_it_again_moves_nothing_more(world):
    ids, a, case_ids, owner = world
    async with async_sessionmaker(owner, expire_on_commit=False)() as s:
        await s.execute(text("select set_config('app.rls_fail_closed', 'off', false)"))
        await reroute_alerts(s, ids["parent"])
        await s.commit()
        again = await reroute_alerts(s, ids["parent"])
    assert again.moved == 0 and again.cases_moved == 0 and again.left_duplicates == 1


async def test_a_role_that_cannot_rewrite_tenant_gets_a_clear_error_and_nothing_changes(world):
    ids, a, case_ids, owner = world
    app = create_async_engine(APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}})
    try:
        async with async_sessionmaker(app, expire_on_commit=False)() as s:
            await set_rls_context(s, ids["parent"])
            with pytest.raises(RerouteError):
                await reroute_alerts(s, ids["parent"])
    finally:
        await app.dispose()
    assert await owner_of(owner, a["h_acme"]) == ids["parent"]
