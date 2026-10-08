"""The API says, once, when its database role bypasses row-level security.

PostgreSQL superusers and BYPASSRLS roles ignore every RLS policy. The default compose connects every service as the bootstrap superuser `aisoc`, so there RLS protects nothing and tenant isolation rests on the
application's own tenant filters. Nothing said so. These tests pin the behaviour of the startup check: it reports the fact, once, and never raises or blocks.
"""
import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.db import role_check as rc

class Spy:
    def __init__(self):
        self.records = []

    def _rec(self, level):
        return lambda event, **kw: self.records.append((level, event, kw))

    def __getattr__(self, name):
        if name in ("debug", "info", "warning", "error"):
            return self._rec(name)
        raise AttributeError(name)

    def events(self, level=None):
        return [r[1] for r in self.records if level in (None, r[0])]

    def find(self, event):
        return next(r[2] for r in self.records if r[1] == event)


class FakeEngine:
    def __init__(self, row=("aisoc", True, False), dialect="postgresql", fail=None, hang=False):
        self.dialect = SimpleNamespace(name=dialect)
        self.row, self.fail, self.hang = row, fail, hang
        self.sql: list[str] = []
        self.connects = 0

    def connect(self):
        engine = self

        class Cm:
            async def __aenter__(self_):
                engine.connects += 1
                if engine.fail:
                    raise engine.fail
                if engine.hang:
                    await asyncio.sleep(30)

                class Conn:
                    async def execute(self__, stmt):
                        engine.sql.append(str(stmt))
                        return SimpleNamespace(one=lambda: engine.row)

                return Conn()

            async def __aexit__(self_, *a):
                return False

        return Cm()


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    rc._warned = False
    spy = Spy()
    monkeypatch.setattr(rc, "logger", spy)
    return spy


@pytest.mark.anyio
class TestWhatItReports:
    async def test_a_superuser_gets_a_warning_that_says_what_it_means(self, fresh):
        role = await rc.check_db_role(FakeEngine(("aisoc", True, False)))
        assert role == rc.DbRole("aisoc", True, False) and role.bypasses_rls
        rec = fresh.find("db.rls_bypassed")
        assert rec["role"] == "aisoc" and rec["superuser"] is True and rec["bypassrls"] is False
        assert "application-level tenant filters" in rec["consequence"] and "aisoc_app" in rec["consequence"]

    async def test_a_bypassrls_only_role_gets_the_warning_too(self, fresh):
        await rc.check_db_role(FakeEngine(("svc", False, True)))
        assert fresh.events("warning") == ["db.rls_bypassed"] and fresh.find("db.rls_bypassed")["bypassrls"] is True

    async def test_an_ordinary_role_gets_no_warning_only_an_info_line(self, fresh):
        role = await rc.check_db_role(FakeEngine(("aisoc_app", False, False)))
        assert role is not None and not role.bypasses_rls
        assert fresh.events("warning") == [] and fresh.events("info") == ["db.rls_enforced"] and fresh.find("db.rls_enforced")["role"] == "aisoc_app"

    async def test_it_warns_once_per_process_but_still_reports_each_time(self, fresh):
        engine = FakeEngine(("aisoc", True, False))
        first, second = await rc.check_db_role(engine), await rc.check_db_role(engine)
        assert first == second and fresh.events("warning") == ["db.rls_bypassed"]

    async def test_it_only_ever_reads_the_connected_roles_own_row(self, fresh):
        engine = FakeEngine()
        await rc.check_db_role(engine)
        assert len(engine.sql) == 1 and "FROM pg_roles WHERE rolname = current_user" in engine.sql[0] and "rolsuper" in engine.sql[0] and "rolbypassrls" in engine.sql[0]


@pytest.mark.anyio
class TestItNeverGetsInTheWay:
    async def test_a_database_error_is_swallowed_and_logged_quietly(self, fresh):
        assert await rc.check_db_role(FakeEngine(fail=ConnectionRefusedError("down"))) is None
        assert fresh.events("warning") == [] and fresh.events("debug") == ["db.role_check_failed"]

    async def test_a_non_postgres_database_is_skipped_without_connecting(self, fresh):
        engine = FakeEngine(dialect="sqlite")
        assert await rc.check_db_role(engine) is None and engine.connects == 0

    async def test_the_background_task_never_raises_even_on_failure(self, fresh):
        await rc.schedule_role_check(FakeEngine(fail=RuntimeError("boom")))
        assert fresh.events("warning") == []

    async def test_the_background_task_gives_up_after_its_timeout_instead_of_hanging(self, fresh):
        task = rc.schedule_role_check(FakeEngine(hang=True), timeout=0.05)
        await asyncio.wait_for(task, 2)
        assert task.done() and "db.role_check_skipped" in fresh.events("debug")

    async def test_the_background_task_reports_for_a_working_database_and_is_then_forgotten(self, fresh):
        task = rc.schedule_role_check(FakeEngine(("aisoc", True, False)))
        await task
        await asyncio.sleep(0)
        assert fresh.events("warning") == ["db.rls_bypassed"] and task not in rc._tasks

    async def test_scheduling_returns_immediately_so_startup_is_not_delayed(self, fresh):
        task = rc.schedule_role_check(FakeEngine(hang=True), timeout=5)
        assert not task.done()  # it has not waited for the database
        task.cancel()


def test_startup_runs_the_check_right_after_the_secure_defaults_check():
    src = (Path(__file__).resolve().parent.parent / "app" / "main.py").read_text(encoding="utf-8")
    life = src.index("async def lifespan(")  # `create_all` also appears in a docstring and in the demo bootstrap above it, so look only inside the lifespan
    assert life < src.index("enforce_secure_defaults(settings)", life) < src.index("schedule_role_check(engine)", life) < src.index("create_all", life)
