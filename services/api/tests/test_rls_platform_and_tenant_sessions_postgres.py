"""`tenant_session`, `platform_session` and `cross_tenant_reads` with fail-closed row-level security SWITCHED ON, on a real Postgres as the restricted role.

Step 4b of docs/security/rls-fail-closed-plan.md. With migration 081's switch on, a session that never set a tenant sees nothing, which would silently blind every
worker and background job that opens its own session. These tests pin the two explicit alternatives (app/db/rls_sessions.py) and the bypass of
`cross_tenant_reads`, including the property that matters most and is easiest to get wrong: they must keep working AFTER a commit, because the tenant setting is
transaction-local and only the step-3 listener carries it into the next transaction.

The switch is switched on the way an operator's `ALTER DATABASE ... SET app.rls_fail_closed = 'on'` does for a new connection: as a server setting given when the
connection is opened (asyncpg `server_settings`). Opt in with AISOC_TEST_PG_URL (owner or superuser) and AISOC_TEST_PG_APP_URL (`aisoc_app`), both
postgresql+asyncpg:// URLs for a DISPOSABLE, fully migrated API database; without them the tests are skipped, and CI sets them (.github/workflows/postgres-tests.yml).
"""

import datetime as dt
import json
import os
import uuid

import pytest
import sqlalchemy as sa
from app.db.rls_scope import cross_tenant_reads
from app.db.rls_sessions import mark_platform, mark_tenant, platform_session, tenant_session
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)


def _required_values(table, **given):
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


async def _insert_rule(conn, tenant, rule_id, name):
    from app.models.detection_rule import DetectionRule

    values = _required_values(DetectionRule.__table__, id=rule_id, tenant_id=tenant, name=name, status="active")
    await conn.execute(text(f"insert into detection_rules ({', '.join(values)}) values ({', '.join(':' + k for k in values)})"), values)


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:8]
    ids = {"a": uuid.uuid4(), "b": uuid.uuid4(), "rule_a": uuid.uuid4(), "rule_b": uuid.uuid4()}
    owner = create_async_engine(PG_URL)
    # the switch ON for every connection of this engine, as ALTER DATABASE ... SET would make it for a new connection
    on = create_async_engine(APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}})
    off = create_async_engine(APP_URL, poolclass=NullPool)
    try:
        async with owner.begin() as conn:
            for key in ("a", "b"):
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
                    {"i": ids[key], "n": f"sess-{key}-{tag}", "s": f"sess-{key}-{tag}"},
                )
            await _insert_rule(conn, ids["a"], ids["rule_a"], f"sess-rule-a-{tag}")
            await _insert_rule(conn, ids["b"], ids["rule_b"], f"sess-rule-b-{tag}")
        yield {
            "ids": ids,
            "tag": tag,
            "owner": owner,
            "on": async_sessionmaker(on, expire_on_commit=False),
            "off": async_sessionmaker(off, expire_on_commit=False),
        }
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("delete from detection_rules where tenant_id in (:a, :b)"), {"a": ids["a"], "b": ids["b"]})
            await conn.execute(text("delete from tenants where id in (:a, :b)"), {"a": ids["a"], "b": ids["b"]})
        await on.dispose()
        await off.dispose()
        await owner.dispose()


async def visible(session, world):
    ids = world["ids"]
    rows = await session.execute(text("select id from detection_rules where id in (:a, :b)"), {"a": ids["rule_a"], "b": ids["rule_b"]})
    return {r[0] for r in rows}


async def test_the_switch_really_is_on_for_the_engine_under_test_and_a_plain_session_sees_nothing(world):
    """The negative control: without it none of the 'sees something' tests below proves anything."""
    async with world["on"]() as session:
        assert (await session.execute(text("select rls_fail_closed()"))).scalar_one() is True
        assert await visible(session, world) == set()
    async with world["off"]() as session:
        assert await visible(session, world) == {
            world["ids"]["rule_a"],
            world["ids"]["rule_b"],
        }  # switch unset: fail-open, as before migration 081


async def test_a_tenant_session_sees_only_its_own_tenant_and_still_does_after_a_commit(world):
    ids = world["ids"]
    async with tenant_session(ids["a"], factory=world["on"]) as session:
        assert await visible(session, world) == {ids["rule_a"]}
        await session.commit()  # the tenant setting is transaction-local: only the step-3 listener carries it into this next transaction
        assert await visible(session, world) == {ids["rule_a"]}
        await session.commit()
        assert await visible(session, world) == {ids["rule_a"]}


async def test_a_tenant_session_can_write_its_own_rows_but_not_another_tenants(world):
    ids = world["ids"]
    async with tenant_session(ids["a"], factory=world["on"]) as session:
        await _insert_rule(session, ids["a"], uuid.uuid4(), f"sess-own-{world['tag']}")
        await session.commit()
        with pytest.raises(DBAPIError, match="row-level security"):
            await _insert_rule(session, ids["b"], uuid.uuid4(), f"sess-cross-{world['tag']}")
        await session.rollback()


async def test_a_platform_session_sees_every_tenant_and_still_does_after_a_commit(world):
    ids = world["ids"]
    both = {ids["rule_a"], ids["rule_b"]}
    async with platform_session(factory=world["on"]) as session:
        assert await visible(session, world) == both
        await session.commit()
        assert await visible(session, world) == both
        await session.commit()
        assert await visible(session, world) == both


async def test_a_platform_session_can_change_rows_of_every_tenant(world):
    ids = world["ids"]
    async with platform_session(factory=world["on"]) as session:
        changed = await session.execute(
            text("update detection_rules set description = 'swept' where id in (:a, :b)"), {"a": ids["rule_a"], "b": ids["rule_b"]}
        )
        assert changed.rowcount == 2  # a sweep (oauth_refresh, retention) writes across tenants
        await session.commit()


async def test_a_platform_session_is_unchanged_by_the_switch_being_off(world):
    ids = world["ids"]
    async with platform_session(factory=world["off"]) as session:
        assert await visible(session, world) == {ids["rule_a"], ids["rule_b"]}


async def test_cross_tenant_reads_works_inside_its_block_and_puts_the_switch_back_after_it(world):
    """The documented gap of step 2: with fail-closed policies the block needed a granted bypass. A plain session is the MSSP resolver's case."""
    ids = world["ids"]
    both = {ids["rule_a"], ids["rule_b"]}
    async with world["on"]() as session:
        assert await visible(session, world) == set()
        async with cross_tenant_reads(session):
            assert await visible(session, world) == both
        assert await visible(session, world) == set(), "the bypass must end with the block"
        assert (await session.execute(text("select rls_fail_closed()"))).scalar_one() is True


async def test_cross_tenant_reads_inside_a_tenant_session_does_not_leave_it_wider_afterwards(world):
    ids = world["ids"]
    async with tenant_session(ids["a"], factory=world["on"]) as session:
        async with cross_tenant_reads(session):
            assert await visible(session, world) == {ids["rule_a"], ids["rule_b"]}
        assert await visible(session, world) == {ids["rule_a"]}
        await session.commit()
        assert await visible(session, world) == {ids["rule_a"]}, "after the block AND a commit the tenant tag must be back"


async def test_a_session_somebody_else_opened_can_be_marked(world):
    ids = world["ids"]
    async with world["on"]() as session:
        mark_tenant(session, ids["b"])
        assert await visible(session, world) == {ids["rule_b"]}
    async with world["on"]() as session:
        mark_platform(session)
        assert await visible(session, world) == {ids["rule_a"], ids["rule_b"]}


async def test_marking_a_session_as_platform_replaces_a_tenant_tag_and_the_reverse(world):
    ids = world["ids"]
    async with world["on"]() as session:
        mark_tenant(session, ids["a"])
        mark_platform(session)
        assert await visible(session, world) == {ids["rule_a"], ids["rule_b"]}
        mark_tenant(session, ids["a"])
        await session.commit()
        assert await visible(session, world) == {ids["rule_a"]}
