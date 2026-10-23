"""Every table created by a migration from 083 on keeps one client's rows from another's and is usable by the application role, on a REAL Postgres.

For each table those migrations create, when it has a ``tenant_id`` column: row-level security is switched on, a policy exists, and the application role (``aisoc_app``, which
is what the running API connects as) may select, insert, update and delete. A table added without the isolation policy, or one the role cannot reach, fails here instead of in
front of a customer.

Opt in with AISOC_TEST_PG_URL (a role that can read the catalog; the database must be fully migrated, the application role present).
"""

import os
import re
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database")

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
APP_ROLE = "aisoc_app"
CREATE = re.compile(r"CREATE TABLE IF NOT EXISTS\s+(?:public\.)?([a-z_][a-z0-9_]*)", re.IGNORECASE)


def tables_created_since_083() -> list[str]:
    found: list[str] = []
    for f in sorted(MIGRATIONS.glob("*.sql")):
        if int(f.name[:3]) >= 83:
            found += CREATE.findall(f.read_text(encoding="utf-8"))
    return sorted(set(found))


TABLES = tables_created_since_083()


async def catalog(sql: str, **params):
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return (await conn.execute(text(sql), params)).all()
    finally:
        await engine.dispose()


def test_the_migrations_since_083_were_found():
    assert len(TABLES) >= 8, TABLES
    assert {"vendor_actions", "client_m365_checks", "client_vcio_proposals", "devices"} <= set(TABLES)


@pytest.mark.parametrize("table", TABLES)
async def test_a_table_with_a_tenant_id_isolates_rows_and_the_application_role_can_use_it(table):
    cols = {
        r[0]
        for r in await catalog(
            "select column_name from information_schema.columns where table_schema = 'public' and table_name = :t", t=table
        )
    }
    assert cols, f"{table} is created by a migration but does not exist in the database"
    for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        ok = (await catalog("select has_table_privilege(:r, :t, :p)", r=APP_ROLE, t=f"public.{table}", p=privilege))[0][0]
        assert ok, f"{APP_ROLE} cannot {privilege} {table}"
    if "tenant_id" not in cols:
        return
    rls = (await catalog("select relrowsecurity from pg_class where oid = cast(:t as regclass)", t=f"public.{table}"))[0][0]
    assert rls, f"{table} has a tenant_id but row-level security is off"
    policies = [r[0] for r in await catalog("select polname from pg_policy where polrelid = cast(:t as regclass)", t=f"public.{table}")]
    assert policies, f"{table} has row-level security on but no policy"
