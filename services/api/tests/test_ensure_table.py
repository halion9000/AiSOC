"""The API's copy of cost telemetry had the same runtime DDL (see the agents test of the same name for the full story): as aisoc_app it leaked a pool per call and silently stopped recording run costs, which a READ-ONLY differential
of the API under both roles could not show. Also: the eval subprocess no longer inherits the database connection."""
from pathlib import Path

import sys
from types import SimpleNamespace

import pytest

from app.core import ensure_table as et

MIGRATIONS = Path(__file__).resolve().parents[2] / "api" / "migrations"


class Spy:
    def __init__(self):
        self.records = []

    def __getattr__(self, level):
        if level in ("debug", "info", "warning", "error"):
            return lambda event, **kw: self.records.append((level, event, kw))
        raise AttributeError(level)

    def levels(self, event):
        return [lvl for lvl, ev, _ in self.records if ev == event]


class FakeConn:
    def __init__(self, exists=True, fail=None):
        self.exists, self.fail = exists, fail
        self.fetched: list[tuple] = []
        self.executed: list[str] = []

    async def fetchval(self, sql, *params):
        self.fetched.append((sql, params))
        return self.exists

    async def execute(self, sql):
        self.executed.append(sql)
        if self.fail:
            raise self.fail


class FakePool:
    def __init__(self, conn, close_fails=False):
        self.conn, self.closed, self.close_fails = conn, False, close_fails

    def acquire(self):
        pool = self

        class Acq:
            async def __aenter__(self_):
                return pool.conn

            async def __aexit__(self_, *a):
                return False

        return Acq()

    async def close(self):
        self.closed = True
        if self.close_fails:
            raise RuntimeError("close failed")


@pytest.fixture(autouse=True)
def fresh():
    et._warned.clear()
    yield
    et._warned.clear()


class TestEnsureTable:
    @pytest.mark.anyio
    async def test_an_existing_table_runs_no_ddl_at_all(self):
        conn = FakeConn(exists=True)
        await et.ensure_table(FakePool(conn), "some_table", "CREATE TABLE some_table (x int)")
        assert conn.executed == []

    @pytest.mark.anyio
    async def test_a_missing_table_gets_created_once(self):
        conn = FakeConn(exists=False)
        await et.ensure_table(FakePool(conn), "some_table", "CREATE TABLE some_table (x int)")
        assert conn.executed == ["CREATE TABLE some_table (x int)"]

    @pytest.mark.anyio
    async def test_the_table_name_is_a_bound_parameter_never_interpolated(self):
        conn = FakeConn()
        await et.ensure_table(FakePool(conn), "weird'; DROP TABLE x; --", "ddl")
        sql, params = conn.fetched[0]
        assert "$1" in sql and "DROP" not in sql and params == ("public.weird'; DROP TABLE x; --",)

    @pytest.mark.anyio
    async def test_a_ddl_failure_propagates_so_the_caller_can_fall_back(self):
        with pytest.raises(PermissionError):
            await et.ensure_table(FakePool(FakeConn(exists=False, fail=PermissionError("denied"))), "t", "ddl")


class TestCloseQuietly:
    @pytest.mark.anyio
    async def test_it_closes_the_pool(self):
        pool = FakePool(FakeConn())
        await et.close_quietly(pool)
        assert pool.closed

    @pytest.mark.anyio
    async def test_none_is_fine_and_a_failing_close_does_not_mask_the_original_error(self):
        await et.close_quietly(None)
        await et.close_quietly(FakePool(FakeConn(), close_fails=True))


class TestReportUnavailable:
    def test_first_a_warning_that_names_the_consequence_then_debug(self):
        spy = Spy()
        for _ in range(4):
            et.report_unavailable(spy, "x.unavailable", "denied", "nothing is saved")
        assert spy.levels("x.unavailable") == ["warning", "debug", "debug", "debug"]
        assert spy.records[0][2] == {"error": "denied", "consequence": "nothing is saved"}

    def test_each_event_warns_once_independently(self):
        spy = Spy()
        et.report_unavailable(spy, "a", "e", "c")
        et.report_unavailable(spy, "b", "e", "c")
        et.report_unavailable(spy, "a", "e", "c")
        assert spy.levels("a") == ["warning", "debug"] and spy.levels("b") == ["warning"]

MODULES = [("app.core.cost_telemetry", "aisoc_run_costs", "cost_telemetry.db_unavailable", "aisoc_run_costs_tenant_run")]


def install(monkeypatch, mod, conn):
    """Make `import asyncpg` inside the module return a fake whose create_pool hands out pools over `conn`; record them all."""
    pools: list[FakePool] = []

    async def create_pool(*args, **kwargs):
        pool = FakePool(conn)
        pools.append(pool)
        return pool

    monkeypatch.setitem(sys.modules, "asyncpg", SimpleNamespace(create_pool=create_pool))
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@h/db")
    monkeypatch.setattr(mod, "_POOL", None)
    spy = Spy()
    monkeypatch.setattr(mod, "logger", spy)
    return pools, spy


@pytest.mark.parametrize("modname,table,event,index", MODULES)
@pytest.mark.anyio
class TestThePoolOfEachModule:
    def mod(self, modname):
        import importlib

        return importlib.import_module(modname)

    async def test_with_the_table_present_no_ddl_runs_and_the_pool_is_kept(self, monkeypatch, modname, table, event, index):
        mod, conn = self.mod(modname), FakeConn(exists=True)
        pools, _ = install(monkeypatch, mod, conn)
        assert await mod._get_pool() is pools[0] and conn.executed == [] and not pools[0].closed

    async def test_with_the_table_missing_the_ddl_runs_so_a_bare_database_still_works(self, monkeypatch, modname, table, event, index):
        mod, conn = self.mod(modname), FakeConn(exists=False)
        pools, _ = install(monkeypatch, mod, conn)
        assert await mod._get_pool() is pools[0]
        assert len(conn.executed) == 1 and f"CREATE TABLE IF NOT EXISTS {table}" in conn.executed[0]

    async def test_a_ddl_failure_closes_the_pool_it_created_and_returns_none(self, monkeypatch, modname, table, event, index):
        """It used to leak: every failed call left a pool (and its connection) open for ever."""
        mod = self.mod(modname)
        pools, _ = install(monkeypatch, mod, FakeConn(exists=False, fail=PermissionError("permission denied for schema public")))
        assert await mod._get_pool() is None and mod._POOL is None
        assert len(pools) == 1 and pools[0].closed

    async def test_repeated_failures_never_leak_a_pool_each_and_warn_only_once(self, monkeypatch, modname, table, event, index):
        mod = self.mod(modname)
        pools, spy = install(monkeypatch, mod, FakeConn(exists=False, fail=PermissionError("denied")))
        for _ in range(5):
            assert await mod._get_pool() is None
        assert len(pools) == 5 and all(p.closed for p in pools), "a pool created by a failed attempt was left open"
        assert spy.levels(event) == ["warning", "debug", "debug", "debug", "debug"]

    async def test_the_warning_says_what_it_costs(self, monkeypatch, modname, table, event, index):
        mod = self.mod(modname)
        _, spy = install(monkeypatch, mod, FakeConn(exists=False, fail=PermissionError("denied")))
        await mod._get_pool()
        warning = next(kw for lvl, ev, kw in spy.records if lvl == "warning" and ev == event)
        assert warning["error"] == "denied" and "NOT" in warning["consequence"]

    async def test_a_failing_pool_creation_itself_is_handled_too(self, monkeypatch, modname, table, event, index):
        mod = self.mod(modname)
        monkeypatch.setattr(mod, "_POOL", None)

        async def refuse(*a, **k):
            raise ConnectionRefusedError("down")

        monkeypatch.setitem(sys.modules, "asyncpg", SimpleNamespace(create_pool=refuse))
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@h/db")
        monkeypatch.setattr(mod, "logger", Spy())
        assert await mod._get_pool() is None

    async def test_without_a_database_url_no_pool_is_created(self, monkeypatch, modname, table, event, index):
        mod = self.mod(modname)
        pools, _ = install(monkeypatch, mod, FakeConn())
        monkeypatch.delenv("DATABASE_URL")
        assert await mod._get_pool() is None and pools == []

    def test_the_fallback_ddl_names_a_table_and_index_the_migrations_already_create(self, modname, table, event, index):
        """The runtime DDL is only a fallback for a bare database: it must not drift from the migrations."""
        mod = self.mod(modname)
        migrations = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in sorted(MIGRATIONS.glob("*.sql")))
        assert f"CREATE TABLE IF NOT EXISTS {table}" in mod._DDL and f"CREATE TABLE IF NOT EXISTS {table}" in migrations
        assert f"CREATE INDEX IF NOT EXISTS {index}" in mod._DDL and f"CREATE INDEX IF NOT EXISTS {index}" in migrations


class TestTheEvalSubprocessDoesNotInheritTheDatabase:
    """POST /detection-proposals/run-eval shells out to scripts/run_evals.py, which runs the agents' memory suites. With DATABASE_URL inherited they wrote fixture tenants (t-search, tenant-C, analyst_override:ALT-100...) into the live
    aisoc_institutional_memory and never cleaned them up. Found because the row counts differed between two databases the same requests had been sent to."""

    def captured_env(self, monkeypatch, tmp_path):
        from app.api.v1.endpoints import detection_proposals as dp

        seen = {}

        def fake_run(argv, **kwargs):
            seen.update(kwargs.get("env") or {})
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(dp.subprocess, "run", fake_run)
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://svc:secret@db/aisoc")
        monkeypatch.setenv("MIGRATION_DATABASE_URL", "postgresql+asyncpg://owner:secret@db/aisoc")
        monkeypatch.setenv("SOME_OTHER_SETTING", "kept")
        dp._run_eval_subprocess(baseline_path=None, out_path=tmp_path / "out.json", max_regression_pp=1.0, timeout_seconds=5)
        return seen

    def test_neither_database_url_reaches_the_eval(self, monkeypatch, tmp_path):
        env = self.captured_env(monkeypatch, tmp_path)
        assert "DATABASE_URL" not in env and "MIGRATION_DATABASE_URL" not in env
        assert "secret" not in " ".join(env.values())

    def test_the_rest_of_the_environment_is_kept_and_the_agents_path_is_added(self, monkeypatch, tmp_path):
        env = self.captured_env(monkeypatch, tmp_path)
        assert env.get("SOME_OTHER_SETTING") == "kept" and "agents" in env.get("PYTHONPATH", "")

    def test_the_stripped_names_are_exactly_the_connection_settings(self):
        from app.api.v1.endpoints import detection_proposals as dp

        assert dp._EVAL_ENV_STRIPPED == ("DATABASE_URL", "MIGRATION_DATABASE_URL")
