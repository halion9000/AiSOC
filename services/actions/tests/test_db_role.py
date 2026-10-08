"""The actions service says, once, when its database role bypasses row-level security (see the API's test of the same name)."""
from types import SimpleNamespace

import pytest

from app import db_role

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


class FakeFactory:
    def __init__(self, row=("aisoc", True, False), dialect="postgresql", fail=None):
        self.row, self.dialect, self.fail, self.sql = row, dialect, fail, []

    def __call__(self):
        f = self

        class Session:
            bind = SimpleNamespace(dialect=SimpleNamespace(name=f.dialect))

            async def __aenter__(self_):
                if f.fail:
                    raise f.fail
                return self_

            async def __aexit__(self_, *a):
                return False

            async def execute(self_, stmt):
                f.sql.append(str(stmt))
                return SimpleNamespace(one=lambda: f.row)

        return Session()


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    db_role._warned = False
    spy = Spy()
    monkeypatch.setattr(db_role, "logger", spy)
    return spy


def use(monkeypatch, factory):
    monkeypatch.setattr(db_role, "get_session_factory", lambda: factory)


@pytest.mark.anyio
class TestDbRole:
    async def test_a_superuser_is_warned_about(self, monkeypatch, fresh):
        use(monkeypatch, FakeFactory(("aisoc", True, False)))
        assert await db_role.warn_if_rls_bypassed() is True
        rec = fresh.find("db.rls_bypassed")
        assert rec["role"] == "aisoc" and rec["superuser"] is True and "application-level tenant filters" in rec["consequence"]

    async def test_a_bypassrls_role_is_warned_about(self, monkeypatch, fresh):
        use(monkeypatch, FakeFactory(("svc", False, True)))
        assert await db_role.warn_if_rls_bypassed() is True and fresh.events("warning") == ["db.rls_bypassed"]

    async def test_an_ordinary_role_is_not(self, monkeypatch, fresh):
        use(monkeypatch, FakeFactory(("aisoc_app", False, False)))
        assert await db_role.warn_if_rls_bypassed() is False
        assert fresh.events("warning") == [] and fresh.find("db.rls_enforced")["role"] == "aisoc_app"

    async def test_it_warns_once(self, monkeypatch, fresh):
        use(monkeypatch, FakeFactory())
        await db_role.warn_if_rls_bypassed()
        await db_role.warn_if_rls_bypassed()
        assert fresh.events("warning") == ["db.rls_bypassed"]

    async def test_it_only_reads_the_connected_roles_own_row(self, monkeypatch, fresh):
        f = FakeFactory()
        use(monkeypatch, f)
        await db_role.warn_if_rls_bypassed()
        assert len(f.sql) == 1 and "WHERE rolname = current_user" in f.sql[0]

    async def test_no_database_configured_is_none_and_silent(self, monkeypatch, fresh):
        use(monkeypatch, None)
        assert await db_role.warn_if_rls_bypassed() is None and fresh.records == []

    async def test_a_database_error_never_raises(self, monkeypatch, fresh):
        use(monkeypatch, FakeFactory(fail=ConnectionRefusedError("down")))
        assert await db_role.warn_if_rls_bypassed() is None and fresh.events("warning") == []

    async def test_a_non_postgres_database_is_skipped(self, monkeypatch, fresh):
        f = FakeFactory(dialect="sqlite")
        use(monkeypatch, f)
        assert await db_role.warn_if_rls_bypassed() is None and f.sql == []


def test_the_warning_runs_once_the_store_is_ready_and_not_before():
    from pathlib import Path

    src = (Path(__file__).resolve().parent.parent / "app" / "main.py").read_text(encoding="utf-8")
    ready = src.index("app.state.mark_ready()\n        await warn_if_rls_bypassed()")
    assert ready > src.index("check_action_store()")
