"""The fail-closed switch of migration 081, against a REAL Postgres, as the restricted role (step 4 of docs/security/rls-fail-closed-plan.md).

77 tenant policies used to end in `OR current_tenant_id() IS NULL`, so a session that never set a tenant saw (and could write) every row. Migration 081
rewrote each of them to `OR (current_tenant_id() IS NULL AND NOT rls_fail_closed())`, with the switch OFF by default, so nothing changed until an operator
runs `ALTER DATABASE <name> SET app.rls_fail_closed = 'on'`. These tests pin what the switch does in each state, the operator's own statement, and that no
later migration can quietly add a policy with an unswitched fail-open branch.

Measured with the isolation flows (435 steps over two tenants, as aisoc_app): switch off = 0 not as expected; switch on with no session tagging = 251 of 404
(the plan's figure for flipping the policies by hand); switch on with the step-3 hook = 0 of 435.

Opt in with TWO environment variables, as test_mssp_resolver_cross_tenant_postgres.py does, because the point is the restricted role: AISOC_TEST_PG_URL (the
database owner or a superuser) and AISOC_TEST_PG_APP_URL (the role `aisoc_app`), both postgresql+asyncpg:// URLs for a DISPOSABLE, fully migrated API
database. Without them the tests are skipped; CI sets them (.github/workflows/postgres-tests.yml, which fails if any is skipped). The one test that runs
`ALTER DATABASE` always resets it, but it is another reason the database must be disposable.
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


def _rule_values(tenant, rule_id, name):
    from app.models.detection_rule import DetectionRule

    return _required_values(DetectionRule.__table__, id=rule_id, tenant_id=tenant, name=name, status="active")


async def _insert_rule(conn, tenant, rule_id, name):
    values = _rule_values(tenant, rule_id, name)
    await conn.execute(text(f"insert into detection_rules ({', '.join(values)}) values ({', '.join(':' + k for k in values)})"), values)


@pytest.fixture
async def world():
    """Two tenants with one rule each, made as the owner; removed afterwards. `app()` opens a fresh restricted-role connection with NO pooling, so a
    session-level setting made by one test can never leak into another."""
    tag = uuid.uuid4().hex[:8]
    ids = {"a": uuid.uuid4(), "b": uuid.uuid4(), "rule_a": uuid.uuid4(), "rule_b": uuid.uuid4(), "extra": []}
    owner = create_async_engine(PG_URL)
    app = create_async_engine(APP_URL, poolclass=NullPool)
    try:
        async with owner.begin() as conn:
            for key, name in (("a", "a"), ("b", "b")):
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
                    {"i": ids[key], "n": f"switch-{name}-{tag}", "s": f"switch-{name}-{tag}"},
                )
            await _insert_rule(conn, ids["a"], ids["rule_a"], f"switch-rule-a-{tag}")
            await _insert_rule(conn, ids["b"], ids["rule_b"], f"switch-rule-b-{tag}")
        yield {"ids": ids, "owner": owner, "app": app, "tag": tag}
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("delete from detection_rules where tenant_id in (:a, :b)"), {"a": ids["a"], "b": ids["b"]})
            await conn.execute(text("delete from tenants where id in (:a, :b)"), {"a": ids["a"], "b": ids["b"]})
        await app.dispose()
        await owner.dispose()


async def _visible(world, *, switch, tenant):
    """The ids of the world's two rules that a restricted-role connection can see, with the switch and the tenant given (None = leave it unset)."""
    ids = world["ids"]
    async with world["app"].connect() as conn:
        if switch is not None:
            await conn.execute(text("select set_config('app.rls_fail_closed', :v, false)"), {"v": switch})
        if tenant is not None:
            await conn.execute(text("select set_config('app.current_tenant_id', :t, false)"), {"t": str(tenant)})
        rows = await conn.execute(text("select id from detection_rules where id in (:a, :b)"), {"a": ids["rule_a"], "b": ids["rule_b"]})
        return {r[0] for r in rows}


async def test_the_role_under_test_really_is_subject_to_row_level_security(world):
    async with world["app"].connect() as conn:
        row = (await conn.execute(text("select rolsuper, rolbypassrls from pg_roles where rolname = current_user"))).one()
    assert (row[0], row[1]) == (False, False), "the app role must not be a superuser or BYPASSRLS, or none of the below proves anything"


async def test_with_the_switch_unset_a_session_with_no_tenant_still_sees_every_row_as_before_the_migration(world):
    ids = world["ids"]
    assert await _visible(world, switch=None, tenant=None) == {ids["rule_a"], ids["rule_b"]}


async def test_with_the_switch_explicitly_off_it_is_the_same(world):
    ids = world["ids"]
    assert await _visible(world, switch="off", tenant=None) == {ids["rule_a"], ids["rule_b"]}


async def test_with_the_switch_on_a_session_with_no_tenant_sees_nothing(world):
    assert await _visible(world, switch="on", tenant=None) == set()


@pytest.mark.parametrize("value", ["on", "true", "1"])
async def test_every_documented_spelling_of_on_switches_it_on(world, value):
    assert await _visible(world, switch=value, tenant=None) == set()


async def test_an_unrecognised_value_does_not_switch_it_on(world):
    ids = world["ids"]
    assert await _visible(world, switch="yes please", tenant=None) == {ids["rule_a"], ids["rule_b"]}


async def test_with_the_switch_on_a_tenant_sees_only_its_own_rows_and_the_other_tenant_likewise(world):
    ids = world["ids"]
    assert await _visible(world, switch="on", tenant=ids["a"]) == {ids["rule_a"]}
    assert await _visible(world, switch="on", tenant=ids["b"]) == {ids["rule_b"]}


async def test_the_switch_does_not_change_what_a_tenant_scoped_session_sees(world):
    ids = world["ids"]
    for switch in (None, "off", "on"):
        assert await _visible(world, switch=switch, tenant=ids["a"]) == {ids["rule_a"]}


async def test_with_the_switch_on_a_write_with_no_tenant_is_rejected_and_off_it_is_accepted(world):
    ids = world["ids"]
    rejected = uuid.uuid4()
    async with world["app"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'on', false)"))
        with pytest.raises(DBAPIError, match="row-level security"):
            await _insert_rule(conn, ids["a"], rejected, f"switch-rejected-{world['tag']}")
        await conn.rollback()
    accepted = uuid.uuid4()
    async with world["app"].connect() as conn:
        await _insert_rule(conn, ids["a"], accepted, f"switch-accepted-{world['tag']}")  # off (unset): the old fail-open behaviour
        await conn.commit()
    async with world["owner"].connect() as conn:  # the write really happened (checked as the owner, by the new row's own id)
        assert (await conn.execute(text("select count(*) from detection_rules where id = :i"), {"i": accepted})).scalar_one() == 1


async def test_a_tenant_cannot_write_another_tenants_row_whatever_the_switch(world):
    ids = world["ids"]
    for switch in (None, "on"):
        async with world["app"].connect() as conn:
            if switch:
                await conn.execute(text("select set_config('app.rls_fail_closed', :v, false)"), {"v": switch})
            await conn.execute(text("select set_config('app.current_tenant_id', :t, false)"), {"t": str(ids["a"])})
            with pytest.raises(DBAPIError, match="row-level security"):
                await _insert_rule(conn, ids["b"], uuid.uuid4(), f"switch-cross-{world['tag']}")
            await conn.rollback()


async def test_the_operators_statement_works_on_new_connections_and_resetting_it_undoes_it(world):
    """`ALTER DATABASE <name> SET app.rls_fail_closed = 'on'` is what a deployer runs; a NEW connection must see it, RESET must undo it. Always reset."""
    ids = world["ids"]
    both = {ids["rule_a"], ids["rule_b"]}
    admin = create_async_engine(
        PG_URL, isolation_level="AUTOCOMMIT", poolclass=NullPool
    )  # ALTER DATABASE cannot run inside a transaction block
    try:
        async with admin.connect() as conn:
            await conn.execute(
                text("DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET app.rls_fail_closed = ''on''', current_database()); END $$")
            )
        assert (
            await _visible(world, switch=None, tenant=None) == set()
        ), "a new connection should be fail-closed once the database setting is on"
    finally:
        async with admin.connect() as conn:
            await conn.execute(
                text("DO $$ BEGIN EXECUTE format('ALTER DATABASE %I RESET app.rls_fail_closed', current_database()); END $$")
            )
        await admin.dispose()
    assert await _visible(world, switch=None, tenant=None) == both, "RESET must restore the old behaviour"


async def test_no_policy_has_an_unswitched_fail_open_branch(world):
    """The ratchet: a later migration that adds a policy of the old shape would be fail-open for ever, whatever the switch says."""
    async with world["owner"].connect() as conn:
        unswitched = [
            tuple(r)
            for r in await conn.execute(
                text(
                    "select tablename, policyname from pg_policies where schemaname = 'public' "
                    "and (qual like '%current_tenant_id() IS NULL%' or with_check like '%current_tenant_id() IS NULL%') "
                    "and coalesce(qual, '') not like '%rls_fail_closed%' order by 1, 2"
                )
            )
        ]
        switched = (
            await conn.execute(text("select count(*) from pg_policies where schemaname = 'public' and qual like '%rls_fail_closed%'"))
        ).scalar_one()
    assert (
        unswitched == []
    ), f"these policies are fail-open whatever app.rls_fail_closed says; make them honour it (see migration 081): {unswitched}"
    assert switched >= 77, f"migration 081 should have switched at least the 77 policies it found, found {switched}"
