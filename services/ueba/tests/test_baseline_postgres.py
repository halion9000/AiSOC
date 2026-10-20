"""One baseline per person, against a REAL Postgres (opt in with AISOC_TEST_PG_URL, a DISPOSABLE postgresql+asyncpg:// database that is wiped and rebuilt by these tests).

Seen on the live stack: two score requests for the same new person each created a baseline row, and from then on every request for that person failed with MultipleResultsFound.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from app.services.baseline import BaselineService
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from .test_migrations import _alembic

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE postgresql+asyncpg:// database")

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


async def _reset() -> None:
    engine = create_async_engine(PG_URL, isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        await conn.execute(text("drop schema public cascade"))
        await conn.execute(text("create schema public"))
    await engine.dispose()


async def _scalar(sql: str, **params):
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return (await conn.execute(text(sql), params)).scalar_one()
    finally:
        await engine.dispose()


async def _insert_baseline(entity: str, stats: str, updated: str = "now()") -> None:
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "insert into ueba_entity_baselines (tenant_id, entity_type, entity_id, feature_stats, window_start, window_end, updated_at) "
                    f"values (:t, 'user', :e, cast(:s as jsonb), now(), now(), {updated})"
                ),
                {"t": TENANT, "e": entity, "s": stats},
            )
    finally:
        await engine.dispose()


def test_the_migration_keeps_the_richest_baseline_of_a_duplicated_person_and_forbids_a_second():
    asyncio.run(_reset())
    assert _alembic("upgrade", "0002", url=PG_URL).returncode == 0
    asyncio.run(_insert_baseline("dup@x.com", '{"hour": {"mean": 3, "std": 1, "count": 2}}', "now() - interval '1 hour'"))
    asyncio.run(
        _insert_baseline(
            "dup@x.com",
            '{"hour": {"mean": 9, "std": 1, "count": 40}, "failed": {"mean": 0, "std": 0, "count": 40}}',
            "now() - interval '2 hours'",
        )
    )
    asyncio.run(_insert_baseline("dup@x.com", "{}"))
    asyncio.run(_insert_baseline("single@x.com", '{"hour": {"count": 1}}'))
    assert asyncio.run(_scalar("select count(*) from ueba_entity_baselines")) == 4

    result = _alembic("upgrade", "head", url=PG_URL)
    assert result.returncode == 0, result.stderr[-1000:]

    assert asyncio.run(_scalar("select count(*) from ueba_entity_baselines where entity_id = 'dup@x.com'")) == 1
    assert asyncio.run(_scalar("select count(*) from ueba_entity_baselines where entity_id = 'single@x.com'")) == 1
    kept = asyncio.run(
        _scalar("select (feature_stats -> 'hour' ->> 'count')::int from ueba_entity_baselines where entity_id = 'dup@x.com'")
    )
    assert kept == 40, "the row that had seen the most observations is the one kept, not the newest"
    with pytest.raises(Exception, match="duplicate key|unique"):
        asyncio.run(_insert_baseline("dup@x.com", "{}"))


def test_many_requests_for_the_same_new_person_at_once_leave_exactly_one_baseline():
    asyncio.run(_reset())
    assert _alembic("upgrade", "head", url=PG_URL).returncode == 0

    async def one_request() -> uuid.UUID:
        engine = create_async_engine(PG_URL, poolclass=NullPool)
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as db:
                row = await BaselineService(db).get_or_create(TENANT, "user", "racer@x.com")
                await db.commit()
                return row.id
        finally:
            await engine.dispose()

    async def run() -> list[uuid.UUID]:
        return list(await asyncio.gather(*(one_request() for _ in range(12))))

    ids = asyncio.run(run())
    assert len(set(ids)) == 1, "every request must see the same baseline"
    assert asyncio.run(_scalar("select count(*) from ueba_entity_baselines where entity_id = 'racer@x.com'")) == 1

    async def later() -> uuid.UUID:
        engine = create_async_engine(PG_URL, poolclass=NullPool)
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as db:
                return (await BaselineService(db).get_or_create(TENANT, "user", "racer@x.com")).id
        finally:
            await engine.dispose()

    assert asyncio.run(later()) == ids[0], "a later request finds the same row"


def test_a_person_scored_several_times_in_a_row_keeps_learning():
    """Every update after the first used to be lost (the baseline stayed at count 1), so nothing was ever flagged."""
    from app.services.scoring import ScoringService

    asyncio.run(_reset())
    assert _alembic("upgrade", "head", url=PG_URL).returncode == 0

    async def one(hour: float) -> None:
        engine = create_async_engine(PG_URL, poolclass=NullPool)
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as db:
                async with db.begin():
                    await ScoringService(db).score_event(
                        TENANT, "user", "learner@x.com", "login", {"hour_of_day": hour, "failed": 0.0}, f"e{hour}"
                    )
        finally:
            await engine.dispose()

    async def run() -> None:
        for hour in (8.0, 9.0, 10.0, 11.0, 12.0):
            await one(hour)

    asyncio.run(run())
    count = asyncio.run(
        _scalar("select (feature_stats -> 'hour_of_day' ->> 'count')::int from ueba_entity_baselines where entity_id = 'learner@x.com'")
    )
    mean = asyncio.run(
        _scalar("select (feature_stats -> 'hour_of_day' ->> 'mean')::float from ueba_entity_baselines where entity_id = 'learner@x.com'")
    )
    assert count == 5, f"only {count} of 5 observations were kept"
    assert mean == 10.0
