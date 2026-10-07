"""The three services that share one database each get THEIR tables, migrated in sequence the way the stack does it.

The case that went wrong: ueba, honeytokens and purple-team all use revision id "0001" in one database. With the shared default version table
only the first service's migration ran in full. Set AISOC_TEST_PG_URL to a DISPOSABLE postgresql+asyncpg:// database to run this for real.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
SERVICES = Path(__file__).resolve().parents[2]
EXPECTED = {
    "ueba": {"ueba_anomalies", "ueba_entity_baselines", "ueba_peer_groups", "alembic_version_ueba"},
    "honeytokens": {"honeytokens", "honeytoken_triggers", "alembic_version_honeytokens"},
    "purple-team": {"purple_team_atomic_tests", "purple_team_executions", "purple_team_tabletop_sessions", "purple_team_detection_drift_snapshots", "alembic_version_purple_team"},
}
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE postgresql+asyncpg:// database")


def _migrate(service: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "DATABASE_URL": PG_URL}
    for key in ("HONEYTOKEN_DATABASE_URL", "PURPLE_TEAM_DATABASE_URL", "UEBA_DATABASE_URL"):
        env.pop(key, None)
    # A relative PYTHONPATH entry (".") would resolve to the SERVICE folder inside the subprocess and let ./alembic shadow the real package.
    env["PYTHONPATH"] = os.pathsep.join(p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p and os.path.isabs(p))
    code = "from alembic.config import main; main(argv=['upgrade','head'])"
    return subprocess.run([sys.executable, "-P", "-c", code], cwd=SERVICES / service, env=env, capture_output=True, text=True, timeout=180)


async def _tables() -> set[str]:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(PG_URL)
    async with engine.connect() as conn:
        rows = (await conn.execute(text("select table_name from information_schema.tables where table_schema = 'public'"))).scalars().all()
    await engine.dispose()
    return set(rows)


async def _reset() -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(PG_URL, isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        await conn.execute(text("drop schema public cascade"))
        await conn.execute(text("create schema public"))
    await engine.dispose()


def test_all_three_services_migrated_into_one_database_each_get_all_their_tables():
    asyncio.run(_reset())
    for service in EXPECTED:
        result = _migrate(service)
        assert result.returncode == 0, f"{service}: {result.stderr[-600:]}"
    tables = asyncio.run(_tables())
    for service, wanted in EXPECTED.items():
        assert wanted <= tables, f"{service} is missing {sorted(wanted - tables)}"
    assert "alembic_version" not in tables, "the shared version table is back"


def test_the_order_the_services_migrate_in_does_not_matter():
    for order in (["purple-team", "honeytokens", "ueba"], ["honeytokens", "ueba", "purple-team"]):
        asyncio.run(_reset())
        for service in order:
            assert _migrate(service).returncode == 0, service
        tables = asyncio.run(_tables())
        for service, wanted in EXPECTED.items():
            assert wanted <= tables, f"order {order}: {service} is missing {sorted(wanted - tables)}"


def test_running_every_migration_again_changes_nothing():
    asyncio.run(_reset())
    for service in EXPECTED:
        assert _migrate(service).returncode == 0
    before = asyncio.run(_tables())
    for service in EXPECTED:
        assert _migrate(service).returncode == 0
    assert asyncio.run(_tables()) == before
