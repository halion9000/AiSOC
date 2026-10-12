"""Every API migration must be applicable TWICE: once by Postgres's init directory, then again by the migration runner.

On the docker-compose stack `./services/api/migrations` is mounted into `/docker-entrypoint-initdb.d`, so Postgres applies every file when the database is
first created, and then the API's migration runner (and `app.scripts.bootstrap_production`) applies every file again, because none of them is recorded yet.
A file that cannot be applied to a database that already has its effects fails the second time, is never recorded, the API logs "1 migrations failed" at
every start, and the production bootstrap (which insists every file is recorded) refuses to run.

That is exactly what happened to 001_init.sql: it seeds the default admin with `INSERT ... ON CONFLICT (email) DO NOTHING`, PostgreSQL checks NOT NULL
BEFORE it looks for a conflict, and migration 071 had since made users.account_name NOT NULL, so the second application failed with `null value in column
"account_name"`. It was found by the Integration workflow's spine job (annotation: `1 migration(s) did not apply: 001_init.sql`) and reproduced in seconds
here. This test keeps the whole class of bug from coming back.

Opt in with AISOC_TEST_PG_URL (the database owner or a superuser; a postgresql+asyncpg:// URL). It creates and drops its OWN database, so it does not touch
the one the URL names; roles are cluster-wide, but every statement that creates one is guarded (`IF NOT EXISTS`), so nothing here resets a role's password.
Without the variable it is skipped; CI sets it (.github/workflows/postgres-tests.yml, which fails if any such test is skipped).
"""

import os
import uuid
from pathlib import Path

import asyncpg
import pytest
from sqlalchemy.engine import make_url

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set AISOC_TEST_PG_URL (owner or superuser) to a Postgres server the test may create a throwaway database on"
)

MIGRATIONS = sorted((Path(__file__).resolve().parents[1] / "migrations").glob("*.sql"))


def dsn(database: str) -> str:
    url = make_url(PG_URL).set(drivername="postgresql", database=database)
    return url.render_as_string(hide_password=False)


async def apply_all(database: str) -> list[tuple[str, str]]:
    """Apply every migration file, in order, in one connection each; return (file, first line of the error) for every file that failed."""
    failures: list[tuple[str, str]] = []
    conn = await asyncpg.connect(dsn(database))
    try:
        for path in MIGRATIONS:
            try:
                await conn.execute(path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001 - the point is to collect every failure, not stop at the first
                failures.append((path.name, " ".join(str(exc).split())[:240]))
    finally:
        await conn.close()
    return failures


@pytest.fixture
async def throwaway_database():
    name = f"aisoc_rerun_{uuid.uuid4().hex[:10]}"
    admin = await asyncpg.connect(dsn(make_url(PG_URL).database or "postgres"))
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
        yield name
    finally:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.close()


def test_there_are_migrations_to_apply():
    assert len(MIGRATIONS) > 80, "the migrations directory looks empty or moved"


async def test_every_migration_applies_on_a_fresh_database(throwaway_database):
    """The first pass is what Postgres's init directory does."""
    assert await apply_all(throwaway_database) == []


async def test_every_migration_applies_again_on_a_database_that_already_has_them(throwaway_database):
    """The second pass is what the migration runner does on a compose stack, and what the production bootstrap requires to succeed."""
    assert await apply_all(throwaway_database) == []
    again = await apply_all(throwaway_database)
    assert again == [], (
        "these migrations cannot be applied to a database that already has their effects (make them re-runnable): "
        + "; ".join(f"{name}: {why}" for name, why in again)
    )
