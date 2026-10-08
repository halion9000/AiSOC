"""The agents service says, once, when its database role bypasses row-level security (see the API's test of the same name)."""
import pytest

from app.core import db_role

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


class FakePool:
    def __init__(self, row=None, fail=None):
        self.row, self.fail, self.sql = row, fail, []

    def acquire(self):
        pool = self

        class Acq:
            async def __aenter__(self_):
                if pool.fail:
                    raise pool.fail

                class Conn:
                    async def fetchrow(self__, sql):
                        pool.sql.append(" ".join(sql.split()))
                        return pool.row

                return Conn()

            async def __aexit__(self_, *a):
                return False

        return Acq()


def row(name="aisoc", superuser=True, bypassrls=False):
    return {"name": name, "rolsuper": superuser, "rolbypassrls": bypassrls}


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    db_role._warned = False
    spy = Spy()
    monkeypatch.setattr(db_role, "logger", spy)
    return spy


@pytest.mark.anyio
class TestDbRole:
    async def test_a_superuser_is_warned_about(self, fresh):
        assert await db_role.warn_if_rls_bypassed(FakePool(row())) is True
        rec = fresh.find("db.rls_bypassed")
        assert rec["role"] == "aisoc" and rec["superuser"] is True and "application-level tenant filters" in rec["consequence"]

    async def test_a_bypassrls_role_is_warned_about(self, fresh):
        assert await db_role.warn_if_rls_bypassed(FakePool(row("svc", False, True))) is True and fresh.events("warning") == ["db.rls_bypassed"]

    async def test_an_ordinary_role_is_not(self, fresh):
        assert await db_role.warn_if_rls_bypassed(FakePool(row("aisoc_app", False, False))) is False
        assert fresh.events("warning") == [] and fresh.find("db.rls_enforced")["role"] == "aisoc_app"

    async def test_it_warns_once(self, fresh):
        pool = FakePool(row())
        await db_role.warn_if_rls_bypassed(pool)
        await db_role.warn_if_rls_bypassed(pool)
        assert fresh.events("warning") == ["db.rls_bypassed"]

    async def test_it_only_reads_the_connected_roles_own_row(self, fresh):
        pool = FakePool(row())
        await db_role.warn_if_rls_bypassed(pool)
        assert len(pool.sql) == 1 and "FROM pg_roles WHERE rolname = current_user" in pool.sql[0]

    async def test_a_database_error_never_raises(self, fresh):
        assert await db_role.warn_if_rls_bypassed(FakePool(fail=ConnectionRefusedError("down"))) is None and fresh.events("warning") == []

    async def test_an_empty_answer_is_none(self, fresh):
        assert await db_role.warn_if_rls_bypassed(FakePool(None)) is None and fresh.events("warning") == []

    async def test_the_shared_pool_checks_the_role_when_it_is_created(self, monkeypatch):
        from app.investigator import ledger

        called = []

        async def fake_create_pool(**kw):
            return FakePool(row())

        async def fake_warn(pool):
            called.append(pool)

        monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h/db")
        monkeypatch.setattr(ledger, "_POOL", None)
        monkeypatch.setattr(ledger.asyncpg, "create_pool", fake_create_pool)
        monkeypatch.setattr(ledger, "warn_if_rls_bypassed", fake_warn)
        pool = await ledger.get_pool()
        assert called == [pool]
        monkeypatch.setattr(ledger, "_POOL", None)
