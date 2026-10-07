"""purple-team: its migrations build every table and column its models use, in its OWN version table, and the image runs them at start.

Nothing used to run this service's migration, so its tables never existed. Making the migrations run exposed more:
  - purple-team, honeytokens and purple-team share ONE database and all use revision id "0001". With Alembic's default shared `alembic_version`
    table the first service to migrate recorded 0001 and every later one saw "already applied" and created NOTHING (purple-team got only its
    0002 table; honeytokens got none). Each service now keeps its own version table.
  - a migration can drift from its model (ueba's baselines table lacked a column the model selects, so every query on it failed).
These tests generate the migration's SQL offline (no database needed) and compare it with the models, and, when AISOC_TEST_PG_URL points at a
disposable Postgres, run it for real.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from app.models.purple_team import Base

SERVICE = Path(__file__).resolve().parents[1]
VERSION_TABLE = "alembic_version_purple_team"
PORT = 8006
PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")


def _alembic(*argv: str, url: str = "postgresql+asyncpg://u:p@localhost:5432/db") -> subprocess.CompletedProcess:
    """Run Alembic exactly as the container does: the `alembic` entry point from the service directory (never `python -m alembic`, where
    the local ./alembic migrations folder would shadow the real package)."""
    env = {**os.environ, "DATABASE_URL": url}
    for key in ("HONEYTOKEN_DATABASE_URL", "PURPLE_TEAM_DATABASE_URL", "UEBA_DATABASE_URL"):
        env.pop(key, None)
    # A relative PYTHONPATH entry (".") would resolve to THIS service folder inside the subprocess and let ./alembic shadow the real package.
    env["PYTHONPATH"] = os.pathsep.join(p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p and os.path.isabs(p))
    code = f"from alembic.config import main; main(argv={list(argv)!r})"
    return subprocess.run([sys.executable, "-P", "-c", code], cwd=SERVICE, env=env, capture_output=True, text=True, timeout=180)


def _offline_sql() -> str:
    result = _alembic("upgrade", "head", "--sql")
    assert result.returncode == 0, result.stderr[-1000:]
    return result.stdout


def _columns_by_table(sql: str) -> dict[str, set[str]]:
    cols: dict[str, set[str]] = {}
    for m in re.finditer(r"CREATE TABLE (\w+) \((.*?)\n\)", sql, re.S):
        names = set()
        for line in m.group(2).split("\n"):
            token = line.strip().split(" ")[0].strip('",')
            if token and token.upper() not in {"PRIMARY", "CONSTRAINT", "UNIQUE", "FOREIGN", "CHECK"} and not token.startswith("--"):
                names.add(token)
        cols[m.group(1)] = names
    for m in re.finditer(r"ALTER TABLE (\w+) ADD COLUMN (\w+)", sql):
        cols.setdefault(m.group(1), set()).add(m.group(2))
    return cols


def test_the_migrations_create_every_table_the_models_use():
    created = set(_columns_by_table(_offline_sql()))
    missing = sorted(set(Base.metadata.tables) - created)
    assert not missing, f"no migration creates: {missing}"


def test_every_model_column_exists_after_the_migrations():
    """The drift that bit ueba: the model selected a column no migration had created, so the first query on the table failed."""
    cols = _columns_by_table(_offline_sql())
    for name, table in Base.metadata.tables.items():
        absent = sorted(set(table.columns.keys()) - cols.get(name, set()))
        assert not absent, f"{name}: the models use {absent} but the migrations never create it"


def test_the_service_keeps_its_own_version_table():
    sql = _offline_sql()
    assert re.search(rf"CREATE TABLE {VERSION_TABLE} \(", sql), f"{VERSION_TABLE} is not used"
    assert not re.search(r"CREATE TABLE alembic_version \(", sql), "the shared alembic_version table is back: services will skip each other's migrations"


def test_there_is_exactly_one_head():
    result = _alembic("heads")
    assert result.returncode == 0, result.stderr[-500:]
    assert len(re.findall(r"\(head\)", result.stdout)) == 1, result.stdout


def test_the_image_applies_the_migrations_before_serving():
    cmd = next(line for line in (SERVICE / "Dockerfile").read_text(encoding="utf-8").splitlines() if line.startswith("CMD"))
    assert "alembic upgrade head" in cmd and "&&" in cmd, cmd
    assert cmd.index("alembic upgrade head") < cmd.index("uvicorn"), "migrate first, then serve"
    assert "exec uvicorn" in cmd and f"--port {PORT}" in cmd, cmd


@pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE postgresql+asyncpg:// database to run the migrations for real")
def test_against_a_real_postgres_the_tables_and_columns_match_the_models_and_a_second_run_changes_nothing():
    import asyncio

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    async def inspect() -> dict[str, set[str]]:
        engine = create_async_engine(PG_URL)
        async with engine.connect() as conn:
            rows = (await conn.execute(text("select table_name, column_name from information_schema.columns where table_schema = 'public'"))).all()
        await engine.dispose()
        out: dict[str, set[str]] = {}
        for table, column in rows:
            out.setdefault(table, set()).add(column)
        return out

    async def reset() -> None:
        engine = create_async_engine(PG_URL, isolation_level="AUTOCOMMIT")
        async with engine.connect() as conn:
            await conn.execute(text("drop schema public cascade"))
            await conn.execute(text("create schema public"))
        await engine.dispose()

    asyncio.run(reset())
    first = _alembic("upgrade", "head", url=PG_URL)
    assert first.returncode == 0, first.stderr[-1000:]
    after_first = asyncio.run(inspect())
    for name, table in Base.metadata.tables.items():
        assert name in after_first, f"{name} was not created"
        assert set(table.columns.keys()) <= after_first[name], f"{name} lacks {sorted(set(table.columns.keys()) - after_first[name])}"
    assert VERSION_TABLE in after_first
    second = _alembic("upgrade", "head", url=PG_URL)
    assert second.returncode == 0, second.stderr[-1000:]
    assert asyncio.run(inspect()) == after_first, "a second run changed the schema"
