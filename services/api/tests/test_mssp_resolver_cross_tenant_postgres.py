"""The MSSP rule resolver against a REAL Postgres, as the restricted role, in every session state the RLS plan will put it in.

This is the tripwire for docs/security/rls-fail-closed-plan.md. The isolation flows have two ordinary tenants and no managed
(parent/child) tenant, so they cannot see a cross-tenant read that depends on the policies being fail-open. Measured with a real parent,
child, rule, pack and assignment: the resolver returned the parent's pack rule for the child on a session with no tenant set (what a
get_db session is today) but returned NOTHING once the session was tagged with the child's tenant, which is what tagging every session (or
fail-closed policies) would do. `cross_tenant_reads` is what fixes that, and these tests keep it fixed.
Opt in with TWO environment variables, because the point is the restricted role: AISOC_TEST_PG_URL (the database owner or a superuser) and
AISOC_TEST_PG_APP_URL (the role `aisoc_app`: not a superuser, no BYPASSRLS), both postgresql+asyncpg:// URLs for a DISPOSABLE, fully
migrated API database. The test creates its own tenants, rule and pack with unique names and removes them afterwards. Without them it is
skipped, as test_service_migrations_postgres.py is; CI does not set them yet.
"""

import datetime as dt
import json
import os
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)


def _required_values(table, **given):
    """A value for every NOT NULL column that has no default, chosen by type, so the row can be inserted without knowing every column."""
    values = {}
    for col in table.columns:
        if col.nullable or col.default is not None or col.server_default is not None or col.primary_key:
            continue
        kind = col.type
        if isinstance(kind, sa.String | sa.Text):
            values[col.name] = "x"
        elif "JSON" in type(kind).__name__:
            values[col.name] = json.dumps({})
        elif isinstance(kind, sa.Boolean):
            values[col.name] = False
        elif isinstance(kind, sa.Integer):
            values[col.name] = 0
        elif isinstance(kind, sa.DateTime):
            values[col.name] = dt.datetime.now(dt.UTC)
        else:
            values[col.name] = uuid.uuid4()
    values.update(given)
    return values


async def _build(owner):
    from app.models.detection_rule import DetectionRule

    tag = uuid.uuid4().hex[:8]
    parent, child, rule, pack = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    rule_name = f"probe-parent-pack-rule-{tag}"
    async with owner.begin() as conn:
        await conn.execute(
            text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
            {"i": parent, "n": f"probe-parent-{tag}", "s": f"probe-parent-{tag}"},
        )
        await conn.execute(
            text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, :p)"),
            {"i": child, "n": f"probe-child-{tag}", "s": f"probe-child-{tag}", "p": parent},
        )
        values = _required_values(DetectionRule.__table__, id=rule, tenant_id=parent, name=rule_name, status="active")
        await conn.execute(text(f"insert into detection_rules ({', '.join(values)}) values ({', '.join(':' + k for k in values)})"), values)
        await conn.execute(
            text("insert into mssp_rule_packs (id, parent_tenant_id, name) values (:k, :p, :n)"),
            {"k": pack, "p": parent, "n": f"probe-pack-{tag}"},
        )
        await conn.execute(text("insert into mssp_rule_pack_rules (pack_id, rule_id) values (:k, :r)"), {"k": pack, "r": rule})
        await conn.execute(
            text("insert into mssp_rule_pack_assignments (id, pack_id, child_tenant_id, enabled) values (gen_random_uuid(), :k, :c, true)"),
            {"k": pack, "c": child},
        )
    return {"parent": parent, "child": child, "rule": rule, "pack": pack, "rule_name": rule_name}


async def _remove(owner, ids):
    async with owner.begin() as conn:
        await conn.execute(text("delete from mssp_rule_pack_assignments where pack_id = :k"), {"k": ids["pack"]})
        await conn.execute(text("delete from mssp_rule_pack_rules where pack_id = :k"), {"k": ids["pack"]})
        await conn.execute(text("delete from mssp_rule_packs where id = :k"), {"k": ids["pack"]})
        await conn.execute(text("delete from detection_rules where id = :r"), {"r": ids["rule"]})
        await conn.execute(text("delete from tenants where id in (:c, :p)"), {"c": ids["child"], "p": ids["parent"]})


@pytest.fixture
async def world():
    owner, app = create_async_engine(PG_URL), create_async_engine(APP_URL)
    ids = await _build(owner)
    try:
        yield ids, async_sessionmaker(app, expire_on_commit=False)
    finally:
        await _remove(owner, ids)
        await owner.dispose()
        await app.dispose()


async def _effective_names(sessions, ids, tenant_setting):
    from app.services.mssp_rule_resolver import resolve_effective_rules

    async with sessions() as db:
        if tenant_setting is not None:
            await db.execute(text("select set_config('app.current_tenant_id', :t, true)"), {"t": str(tenant_setting)})
        return sorted(r.name for r in await resolve_effective_rules(db, ids["child"]))


@pytest.mark.asyncio
async def test_the_role_under_test_really_is_subject_to_row_level_security(world):
    """Guards the guard: as a superuser or a BYPASSRLS role every assertion below would pass whatever the code did."""
    _, sessions = world
    async with sessions() as db:
        row = (await db.execute(text("select rolsuper, rolbypassrls from pg_roles where rolname = current_user"))).one()
    assert row == (False, False), f"AISOC_TEST_PG_APP_URL must be a role that RLS applies to, got superuser={row[0]} bypassrls={row[1]}"


@pytest.mark.asyncio
async def test_negative_control_a_plain_read_under_the_childs_tenant_cannot_see_the_parents_rule(world):
    """If this stops being true the resolver tests below no longer prove anything: it is what makes them non-vacuous."""
    ids, sessions = world
    async with sessions() as db:
        unscoped = (await db.execute(text("select count(*) from detection_rules where id = :r"), {"r": ids["rule"]})).scalar_one()
        await db.execute(text("select set_config('app.current_tenant_id', :t, true)"), {"t": str(ids["child"])})
        as_child = (await db.execute(text("select count(*) from detection_rules where id = :r"), {"r": ids["rule"]})).scalar_one()
    assert (unscoped, as_child) == (
        1,
        0,
    ), f"expected the parent's rule visible with no tenant (1) and hidden for the child (0), got {(unscoped, as_child)}"


@pytest.mark.asyncio
async def test_with_no_tenant_set_the_child_gets_the_parents_pack_rule(world):
    """What a plain get_db session is today."""
    ids, sessions = world
    assert await _effective_names(sessions, ids, None) == [ids["rule_name"]]


@pytest.mark.asyncio
async def test_with_the_childs_tenant_set_the_child_still_gets_the_parents_pack_rule(world):
    """What tagging every session does when a child calls POST /rules/hunt. Without cross_tenant_reads this returned NOTHING."""
    ids, sessions = world
    assert await _effective_names(sessions, ids, ids["child"]) == [ids["rule_name"]]


@pytest.mark.asyncio
async def test_with_the_parents_tenant_set_the_child_still_gets_the_parents_pack_rule(world):
    """What tagging every session does when the parent calls GET /mssp/children/{id}/effective-rules."""
    ids, sessions = world
    assert await _effective_names(sessions, ids, ids["parent"]) == [ids["rule_name"]]


@pytest.mark.asyncio
async def test_the_tenant_in_force_before_the_call_is_back_after_it(world):
    """The session must not be left wider than it was: after the resolver returns, a plain read is filtered by the same tenant again."""
    from app.services.mssp_rule_resolver import resolve_effective_rules

    ids, sessions = world
    async with sessions() as db:
        await db.execute(text("select set_config('app.current_tenant_id', :t, true)"), {"t": str(ids["child"])})
        await resolve_effective_rules(db, ids["child"])
        setting = (await db.execute(text("select current_setting('app.current_tenant_id', true)"))).scalar_one()
        visible = (await db.execute(text("select count(*) from detection_rules where id = :r"), {"r": ids["rule"]})).scalar_one()
    assert setting == str(ids["child"]) and visible == 0
