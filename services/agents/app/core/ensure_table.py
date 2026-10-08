"""Create a table only if it is MISSING, and never hide that a configured database cannot be used.

These modules used to run `CREATE TABLE IF NOT EXISTS` (and `CREATE INDEX IF NOT EXISTS`) at runtime, although migrations 020/022 already create the tables and indexes. As a NON-superuser role (aisoc_app, which has no CREATE on the schema)
those statements fail EVEN WHEN THE TABLE EXISTS ("permission denied for schema public"), and the failure was handled badly three ways: the freshly created pool was never closed (so every call leaked a connection, unbounded, until Postgres
refused new ones); the module silently fell back to an in-memory dict (so it looked like it worked but persisted nothing and shared nothing); and the only trace was a DEBUG log line. Now: DDL runs only if the table is missing (a bare database
still works), the pool is closed on failure, and the failure is logged at WARNING once per process, saying what it costs.
"""

from __future__ import annotations

from typing import Any

_warned: set[str] = set()


async def ensure_table(pool: Any, table: str, ddl: str) -> None:
    """Run `ddl` only if `public.<table>` does not exist. The name is a bound parameter, never interpolated."""
    async with pool.acquire() as conn:
        if not await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", f"public.{table}"):
            await conn.execute(ddl)


async def close_quietly(pool: Any) -> None:
    """Release a pool that could not be used. Failing to close it must not mask the original error."""
    if pool is None:
        return
    try:
        await pool.close()
    except Exception:  # noqa: BLE001
        pass


def report_unavailable(logger: Any, event: str, error: str, consequence: str) -> None:
    """WARNING the first time per process, DEBUG after: the caller retries on every call, so warning each time would flood the log."""
    if event in _warned:
        logger.debug(event, error=error)
        return
    _warned.add(event)
    logger.warning(event, error=error, consequence=consequence)
