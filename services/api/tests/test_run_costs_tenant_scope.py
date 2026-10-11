"""Per-run model costs are read for the caller's tenant ONLY, by the query itself.

aisoc_run_costs has no row-level security, and its key is (run_id, tenant_id, model): the same run_id may exist under more than one tenant.
The read used to be `WHERE run_id = :run_id` and relied on the caller having checked the run's tenant first (get_run still does). Nothing
leaked, but the safety was a call order and a docstring.
Found by sweeping every statement that touches a table without row-level security for one with no tenant predicate (1 of 21).
"""

import asyncio
import inspect
import uuid

import pytest
from app.api.v1.endpoints import investigations as inv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

A, B = uuid.uuid4(), uuid.uuid4()
RUN = uuid.uuid4()


def _run(db_path, fn):
    async def main():
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", poolclass=NullPool)
        try:
            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS aisoc_run_costs (run_id TEXT, tenant_id TEXT, model TEXT, total_prompt_tokens INT, total_completion_tokens INT, total_cost_usd REAL, total_latency_ms REAL, call_count INT)"  # noqa: E501
                    )
                )
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                return await fn(session)
        finally:
            await engine.dispose()

    return asyncio.run(main())


async def _seed(session, rows):
    for run_id, tenant, model, cost in rows:
        await session.execute(
            text("INSERT INTO aisoc_run_costs VALUES (:r, :t, :m, 10, 5, :c, 100.0, 1)"),
            {"r": str(run_id), "t": str(tenant), "m": model, "c": cost},
        )
    await session.commit()


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "costs.db")


class TestTheQueryScopesItselfToTheTenant:
    def test_two_tenants_with_the_same_run_id_each_read_only_their_own_rows(self, db):
        async def go(s):
            await _seed(s, [(RUN, A, "model-of-A", 1.0), (RUN, B, "model-of-B-SECRET", 9.0)])
            return await inv._fetch_model_costs(s, RUN, A), await inv._fetch_model_costs(s, RUN, B)

        mine, theirs = _run(db, go)
        assert [r.model for r in mine] == ["model-of-A"] and [r.model for r in theirs] == ["model-of-B-SECRET"]

    def test_a_tenant_with_no_rows_for_the_run_gets_an_empty_list_not_anothers(self, db):
        async def go(s):
            await _seed(s, [(RUN, B, "model-of-B-SECRET", 9.0)])
            return await inv._fetch_model_costs(s, RUN, A)

        assert _run(db, go) == []

    def test_other_runs_of_the_same_tenant_are_not_mixed_in(self, db):
        async def go(s):
            await _seed(s, [(RUN, A, "this-run", 1.0), (uuid.uuid4(), A, "another-run", 2.0)])
            return await inv._fetch_model_costs(s, RUN, A)

        assert [r.model for r in _run(db, go)] == ["this-run"]

    def test_the_breakdown_is_still_mapped_and_ordered_by_cost(self, db):
        async def go(s):
            await _seed(s, [(RUN, A, "cheap", 1.0), (RUN, A, "dear", 5.0)])
            return await inv._fetch_model_costs(s, RUN, A)

        rows = _run(db, go)
        assert (
            [r.model for r in rows] == ["dear", "cheap"]
            and rows[0].total_cost_usd == 5.0
            and rows[0].total_prompt_tokens == 10
            and rows[0].call_count == 1
        )


class TestTheCallerPassesTheAuthenticatedTenant:
    def test_get_run_hands_the_users_own_tenant_to_the_query(self):
        source = inspect.getsource(inv.get_run)
        assert "_fetch_model_costs(db, run_id, current_user.tenant_id)" in source

    def test_the_sql_filters_on_the_tenant_and_the_tenant_is_a_bound_parameter(self):
        source = inspect.getsource(inv._fetch_model_costs)
        assert "WHERE run_id = :run_id AND tenant_id = :tenant_id" in source and '"tenant_id": str(tenant_id)' in source

    def test_there_is_exactly_one_caller_so_none_can_skip_it(self):
        full = inspect.getsource(inv)
        assert full.count("_fetch_model_costs(") == 2  # the definition and get_run's one call
