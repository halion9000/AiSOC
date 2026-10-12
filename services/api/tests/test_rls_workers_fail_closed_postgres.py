"""The cross-tenant workers still WORK when fail-closed row-level security is switched on (step 4b of docs/security/rls-fail-closed-plan.md).

Migration 081's switch makes a session with no tenant see nothing. The retention sweeper and the oauth refresh worker open their own sessions and legitimately
act on every tenant, so without an explicit mechanism they would go blind the moment the switch is turned on, silently: no error, just zero rows. They now mark their
session as a PLATFORM session (app/db/rls_sessions.py), which keeps the switch off for its transactions. These tests run the REAL worker entry points against a
real Postgres as the restricted role with the switch ON, each beside a negative control that proves the data really is invisible to a plain session.

Collateral damage is avoided on purpose: the retention test plants rows dated 1990 and passes a `now` in mid-2000, so nothing else in a shared database
qualifies as expired; the oauth test never refreshes anything (`_refresh_one` is replaced by a recorder).

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (`aisoc_app`), both postgresql+asyncpg:// URLs for a DISPOSABLE, fully migrated API database; without
them the tests are skipped, and CI sets them (.github/workflows/postgres-tests.yml).
"""

import datetime as dt
import json
import os
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)

LONG_AGO = dt.datetime(1990, 1, 1, tzinfo=dt.UTC)  # older than every retention window below (the longest default is 730 days)
NOW = dt.datetime(
    2000, 6, 1, tzinfo=dt.UTC
)  # `now` for the retention pass: only rows dated before 2000 can be older than its cutoff, so nothing real qualifies


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


async def _insert(conn, table, **given):
    values = _required_values(table, **given)
    await conn.execute(text(f"insert into {table.name} ({', '.join(values)}) values ({', '.join(':' + k for k in values)})"), values)


@pytest.fixture
async def world():
    from app.models.connector import Connector
    from app.models.detection_suggestion import DetectionSuggestion

    tag = uuid.uuid4().hex[:8]
    ids = {k: uuid.uuid4() for k in ("a", "b", "sug_a", "sug_b", "conn_a", "conn_b")}
    owner = create_async_engine(PG_URL)
    on = create_async_engine(
        APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}}
    )  # as ALTER DATABASE ... SET does
    try:
        async with owner.begin() as conn:
            for key in ("a", "b"):
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
                    {"i": ids[key], "n": f"wrk-{key}-{tag}", "s": f"wrk-{key}-{tag}"},
                )
            for key in ("a", "b"):
                await _insert(conn, DetectionSuggestion.__table__, id=ids[f"sug_{key}"], tenant_id=ids[key], created_at=LONG_AGO)
                await _insert(
                    conn,
                    Connector.__table__,
                    id=ids[f"conn_{key}"],
                    tenant_id=ids[key],
                    oauth_provisioned=True,
                    is_enabled=True,
                    name=f"wrk-conn-{key}-{tag}",
                )
        yield {"ids": ids, "owner": owner, "factory": async_sessionmaker(on, expire_on_commit=False)}
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("delete from detection_suggestions where tenant_id in (:a, :b)"), {"a": ids["a"], "b": ids["b"]})
            await conn.execute(text("delete from connectors where tenant_id in (:a, :b)"), {"a": ids["a"], "b": ids["b"]})
            await conn.execute(text("delete from tenants where id in (:a, :b)"), {"a": ids["a"], "b": ids["b"]})
        await on.dispose()
        await owner.dispose()


async def count_as_owner(world, table, ids):
    async with world["owner"].connect() as conn:
        return (
            await conn.execute(
                text(f"select count(*) from {table} where id in :ids").bindparams(sa.bindparam("ids", expanding=True)),
                {"ids": [str(i) for i in ids]},
            )
        ).scalar_one()


async def test_control_a_plain_session_with_the_switch_on_cannot_see_the_planted_rows(world):
    ids = world["ids"]
    async with world["factory"]() as session:
        for table, keys in (("detection_suggestions", ("sug_a", "sug_b")), ("connectors", ("conn_a", "conn_b"))):
            seen = (
                await session.execute(text(f"select count(*) from {table} where id in (:a, :b)"), {"a": ids[keys[0]], "b": ids[keys[1]]})
            ).scalar_one()
            assert seen == 0, f"{table}: without this control the worker tests below prove nothing"
    assert await count_as_owner(world, "detection_suggestions", [ids["sug_a"], ids["sug_b"]]) == 2  # they exist: the owner sees them


async def test_the_retention_sweeper_counts_the_expired_rows_of_every_tenant_in_a_dry_run(world):
    from app.workers import retention_sweeper

    result = await retention_sweeper.sweep_once(session_factory=world["factory"], now=NOW, dry_run=True)
    assert result.errors == {}, result.errors
    suggestions = next(v for k, v in result.counts.items() if "suggest" in k)
    assert suggestions == 2, f"the sweeper saw {suggestions} of the 2 expired suggestions (one per tenant): {result.counts}"
    assert (
        await count_as_owner(world, "detection_suggestions", [world["ids"]["sug_a"], world["ids"]["sug_b"]]) == 2
    )  # a dry run deletes nothing


async def test_the_retention_sweeper_deletes_the_expired_rows_of_every_tenant(world):
    from app.workers import retention_sweeper

    ids = world["ids"]
    result = await retention_sweeper.sweep_once(session_factory=world["factory"], now=NOW, dry_run=False)
    assert result.errors == {}, result.errors
    assert next(v for k, v in result.counts.items() if "suggest" in k) == 2
    assert await count_as_owner(world, "detection_suggestions", [ids["sug_a"], ids["sug_b"]]) == 0


async def test_the_oauth_refresh_worker_finds_the_due_connectors_of_every_tenant(world, monkeypatch):
    from app.security.credential_vault import CredentialVaultError
    from app.workers import oauth_refresh

    class UndecryptableVault:  # every candidate connector is then 'due': what is being tested is that the worker can SEE them
        def decrypt_dict(self, _):
            raise CredentialVaultError("test")

    refreshed = []

    async def record(db, *, connector, **_):
        refreshed.append(connector.id)
        return True

    monkeypatch.setattr(oauth_refresh, "get_vault", lambda: UndecryptableVault())
    monkeypatch.setattr(oauth_refresh, "AsyncSessionLocal", world["factory"])
    monkeypatch.setattr(oauth_refresh, "_refresh_one", record)

    await oauth_refresh.run_once()
    ids = world["ids"]
    assert ids["conn_a"] in refreshed and ids["conn_b"] in refreshed, "the sweep must see the connectors of BOTH tenants, not none"
