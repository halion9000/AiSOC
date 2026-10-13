"""Shared rows (tenant_id IS NULL) are read-only for tenants (migration 082), against a REAL Postgres, as the restricted role, with fail-closed ON.

Before 082 each of twelve tables had one `FOR ALL` policy ending in `OR tenant_id IS NULL` and no WITH CHECK, so a tenant session could relabel its own
row to NULL (publishing it to every tenant), edit or delete any shared row, and insert NULL-tenant rows. These tests pin the repaired behaviour on every
one of the twelve tables, and include the negative control that the hole is real on a table the migration did not touch is NOT needed: the repaired
statements are asserted to fail with a row-level-security error specifically, so a different failure (a typo, a foreign key) cannot pass for the fix.

Opt in with AISOC_TEST_PG_URL (owner/superuser) and AISOC_TEST_PG_APP_URL (the role `aisoc_app`), as the sibling tests do. CI sets both.
"""

import datetime as dt
import json
import os
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)

TABLES = [
    "aisoc_case_comments",
    "aisoc_case_tasks",
    "aisoc_cases",
    "aisoc_compliance_evidence",
    "aisoc_hunt_runs",
    "aisoc_hunts",
    "aisoc_kb_documents",
    "aisoc_phishing_submissions",
    "detection_eval_baselines",
    "detection_rule_proposals",
    "hunt_hypotheses",
    "passkey_challenges",
]


def _values(table, **given):
    """A value for every NOT NULL column without a default, chosen by type (the rows only need to exist; foreign keys are relaxed for the seeding)."""
    out = {}
    for col in table.columns:
        if col.nullable or col.server_default is not None or col.default is not None:
            continue
        kind = col.type
        if isinstance(kind, sa.String | sa.Text):
            out[col.name] = "x" + uuid.uuid4().hex[:8]  # unique: some of these columns carry a UNIQUE constraint
        elif "JSON" in type(kind).__name__:
            out[col.name] = json.dumps({})
        elif isinstance(kind, sa.Boolean):
            out[col.name] = False
        elif isinstance(kind, sa.Integer | sa.Float | sa.Numeric):
            out[col.name] = 0
        elif isinstance(kind, sa.DateTime):
            out[col.name] = dt.datetime.now(dt.UTC)
        elif "ARRAY" in type(kind).__name__:
            out[col.name] = []
        else:
            out[col.name] = uuid.uuid4()
    out.update(given)
    return out


async def _seed(conn, table, **given):
    values = _values(table, **given)
    cols = ", ".join(f'"{k}"' for k in values)
    marks = ", ".join(f":{k}" for k in values)
    await conn.execute(text(f'insert into "{table.name}" ({cols}) values ({marks})'), values)
    return values


@pytest.fixture
async def world():
    """Two tenants; for every table one row each for tenant A, tenant B and the shared (NULL) set, seeded as the owner (foreign keys relaxed)."""
    tag = uuid.uuid4().hex[:8]
    a, b = uuid.uuid4(), uuid.uuid4()
    owner = create_async_engine(PG_URL)
    app = create_async_engine(APP_URL, poolclass=NullPool)
    meta = sa.MetaData()
    rows: dict[str, dict[str, uuid.UUID]] = {}
    try:
        async with owner.begin() as conn:
            for key, tid in (("a", a), ("b", b)):
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
                    {"i": tid, "n": f"shared-{key}-{tag}", "s": f"shared-{key}-{tag}"},
                )
            await conn.execute(text("set local session_replication_role = replica"))
            tables = {}
            for name in TABLES:
                tables[name] = await conn.run_sync(lambda c, n=name: sa.Table(n, meta, autoload_with=c))
            for name, table in tables.items():
                pk = [c.name for c in table.primary_key.columns]
                assert len(pk) == 1, f"{name}: this test assumes a single-column primary key, got {pk}"
                rows[name] = {"pk": pk[0], "tables": table}
                for label, tid in (("a", a), ("b", b), ("shared", None)):
                    pk_value = uuid.uuid4() if "UUID" in type(table.c[pk[0]].type).__name__.upper() else None
                    given = {"tenant_id": tid}
                    if pk_value is not None:
                        given[pk[0]] = pk_value
                    values = await _seed(conn, table, **given)
                    rows[name][label] = values[pk[0]]
        yield {"a": a, "b": b, "owner": owner, "app": app, "rows": rows}
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("set local session_replication_role = replica"))
            for name, info in rows.items():
                pk = info["pk"]
                for label in ("a", "b", "shared"):
                    if label in info:
                        await conn.execute(text(f'delete from "{name}" where "{pk}" = :v'), {"v": info[label]})
            await conn.execute(text("delete from tenants where id in (:a, :b)"), {"a": a, "b": b})
        await app.dispose()
        await owner.dispose()


async def _as(world, tenant, fn, *, switch="on"):
    """Run `fn(conn)` as the restricted role, in one transaction, with the switch and tenant set (tenant None = no tenant). Returns fn's result."""
    async with world["app"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', :v, false)"), {"v": switch})
        if tenant is not None:
            await conn.execute(text("select set_config('app.current_tenant_id', :t, false)"), {"t": str(tenant)})
        try:
            return await fn(conn)
        finally:
            await conn.rollback()


def _is_rls_violation(exc: BaseException) -> bool:
    return "row-level security" in str(exc)


async def _expect_rls_violation(world, tenant, sql, params, *, switch="on"):
    async def go(conn):
        with pytest.raises(DBAPIError) as info:
            await conn.execute(text(sql), params)
        assert _is_rls_violation(info.value), f"failed, but not because of row-level security: {info.value}"

    await _as(world, tenant, go, switch=switch)


@pytest.mark.parametrize("table", TABLES)
async def test_a_tenant_cannot_relabel_its_own_row_as_shared(world, table):
    info = world["rows"][table]
    await _expect_rls_violation(world, world["a"], f'update "{table}" set tenant_id = null where "{info["pk"]}" = :id', {"id": info["a"]})


@pytest.mark.parametrize("table", TABLES)
async def test_a_tenant_cannot_relabel_its_own_row_as_another_tenants(world, table):
    info = world["rows"][table]
    await _expect_rls_violation(
        world, world["a"], f'update "{table}" set tenant_id = :other where "{info["pk"]}" = :id', {"id": info["a"], "other": world["b"]}
    )


@pytest.mark.parametrize("table", TABLES)
async def test_a_tenant_cannot_insert_a_shared_row_or_one_for_another_tenant(world, table):
    tbl = world["rows"][table]["tables"]
    for tid in (None, world["b"]):
        values = _values(tbl, tenant_id=tid)
        cols = ", ".join(f'"{k}"' for k in values)
        marks = ", ".join(f":{k}" for k in values)
        await _expect_rls_violation(world, world["a"], f'insert into "{table}" ({cols}) values ({marks})', values)


@pytest.mark.parametrize("table", TABLES)
async def test_a_tenant_cannot_change_or_delete_a_shared_row(world, table):
    info = world["rows"][table]

    async def go(conn):
        upd = await conn.execute(text(f'update "{table}" set tenant_id = tenant_id where "{info["pk"]}" = :id'), {"id": info["shared"]})
        dele = await conn.execute(text(f'delete from "{table}" where "{info["pk"]}" = :id'), {"id": info["shared"]})
        return upd.rowcount, dele.rowcount

    assert await _as(world, world["a"], go) == (0, 0)


@pytest.mark.parametrize("table", TABLES)
async def test_a_tenant_cannot_touch_another_tenants_row(world, table):
    info = world["rows"][table]

    async def go(conn):
        upd = await conn.execute(text(f'update "{table}" set tenant_id = tenant_id where "{info["pk"]}" = :id'), {"id": info["b"]})
        dele = await conn.execute(text(f'delete from "{table}" where "{info["pk"]}" = :id'), {"id": info["b"]})
        return upd.rowcount, dele.rowcount

    assert await _as(world, world["a"], go) == (0, 0)


@pytest.mark.parametrize("table", TABLES)
async def test_a_tenant_sees_its_own_rows_and_the_shared_rows_but_not_another_tenants(world, table):
    info = world["rows"][table]

    async def go(conn):
        res = await conn.execute(
            text(f'select "{info["pk"]}" from "{table}" where "{info["pk"]}" in (:a, :b, :s)'),
            {"a": info["a"], "b": info["b"], "s": info["shared"]},
        )
        return {r[0] for r in res}

    assert await _as(world, world["a"], go) == {info["a"], info["shared"]}
    assert await _as(world, world["b"], go) == {info["b"], info["shared"]}


@pytest.mark.parametrize("table", TABLES)
async def test_a_tenant_can_still_change_and_delete_its_own_row(world, table):
    """Positive control: the repair must not have broken ordinary writes."""
    info = world["rows"][table]

    async def go(conn):
        upd = await conn.execute(text(f'update "{table}" set tenant_id = tenant_id where "{info["pk"]}" = :id'), {"id": info["a"]})
        dele = await conn.execute(text(f'delete from "{table}" where "{info["pk"]}" = :id'), {"id": info["a"]})
        return upd.rowcount, dele.rowcount

    assert await _as(world, world["a"], go) == (1, 1)


@pytest.mark.parametrize("table", TABLES)
async def test_the_platform_can_still_maintain_shared_rows_and_with_no_tenant_and_fail_closed_nothing_is_visible_or_writable(world, table):
    """Platform = no tenant with the switch off (what platform_session sets). With the switch ON and no tenant a session sees only shared rows
    (read) and cannot write at all."""
    info = world["rows"][table]

    async def platform(conn):
        upd = await conn.execute(text(f'update "{table}" set tenant_id = tenant_id where "{info["pk"]}" = :id'), {"id": info["shared"]})
        relabel = await conn.execute(text(f'update "{table}" set tenant_id = null where "{info["pk"]}" = :id'), {"id": info["a"]})
        return upd.rowcount, relabel.rowcount

    assert await _as(world, None, platform, switch="off") == (1, 1)

    async def closed(conn):
        res = await conn.execute(
            text(f'select "{info["pk"]}" from "{table}" where "{info["pk"]}" in (:a, :b, :s)'),
            {"a": info["a"], "b": info["b"], "s": info["shared"]},
        )
        seen = {r[0] for r in res}
        upd = await conn.execute(text(f'update "{table}" set tenant_id = tenant_id where "{info["pk"]}" = :id'), {"id": info["shared"]})
        return seen, upd.rowcount

    assert await _as(world, None, closed, switch="on") == ({info["shared"]}, 0)


async def test_every_one_of_the_twelve_tables_has_exactly_the_four_per_command_policies_and_no_for_all(world):
    async with world["owner"].connect() as conn:
        res = await conn.execute(
            text(
                "select tablename, array_agg(cmd order by cmd) from pg_policies where schemaname='public' and tablename = any(:t) group by 1"
            ),
            {"t": TABLES},
        )
        got = {r[0]: r[1] for r in res}
    assert set(got) == set(TABLES)
    assert all(cmds == ["DELETE", "INSERT", "SELECT", "UPDATE"] for cmds in got.values()), got


async def test_an_itsm_status_note_belongs_to_the_cases_tenant_and_is_not_published_to_everyone(world):
    """Regression: `_apply_status_to_case` inserted its system comment WITHOUT a tenant_id, so every ITSM-driven status change published a comment, naming the
    vendor ticket, to all tenants. Run the real helper as the restricted role with fail-closed ON and the case's tenant adopted, as the webhook does."""
    from types import SimpleNamespace

    from app.api.v1.endpoints.inbox_itsm import _apply_status_to_case
    from sqlalchemy.ext.asyncio import AsyncSession

    case_id = world["rows"]["aisoc_cases"]["a"]
    async with world["app"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'on', false)"))
        await conn.execute(text("select set_config('app.current_tenant_id', :t, false)"), {"t": str(world["a"])})
        session = AsyncSession(bind=conn, expire_on_commit=False)
        await _apply_status_to_case(
            session,
            case_row=SimpleNamespace(id=case_id),
            new_status="resolved",
            actor_label="itsm-webhook (jira)",
            external_id="AIS-1",
            vendor="jira",
        )
        owned = (await conn.execute(text("select tenant_id from aisoc_case_comments where case_id = :c"), {"c": case_id})).scalars().all()
        await conn.rollback()
    assert owned == [world["a"]], f"the note must carry the case's tenant, got {owned}"
