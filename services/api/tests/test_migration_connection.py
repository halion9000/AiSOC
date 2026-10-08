"""Migrations can run on their own connection, so the services can run as the NON-superuser role.

The migration runner used the API's own DATABASE_URL, and the API runs it at startup. As the non-superuser `aisoc_app` it fails with "permission denied for schema public" EVEN WHEN NOTHING IS PENDING (it always runs
CREATE TABLE IF NOT EXISTS aisoc_schema_migrations), so the API could not run as that role. MIGRATION_DATABASE_URL (empty by default = use DATABASE_URL, so nothing changes unless set) lets migrations use the database owner while
requests are served by the restricted role. The audit tool must NOT follow it: it reports on the role the services run as.
"""
import asyncio
import importlib
import logging
from pathlib import Path

import pytest

from app.core.config import Settings
from app.scripts import rls_audit as ra
from app.scripts import run_migrations as rm

SERVICE = "postgresql+asyncpg://aisoc_app:svc-secret@db:5432/aisoc"
OWNER = "postgresql+asyncpg://aisoc:owner-secret@db:5432/aisoc"


@pytest.fixture
def urls(monkeypatch):
    """Patch EVERY live settings object the code under test could read. The runner binds `settings` when it is imported, but the audit tool imports it inside main(), and another test module (test_graphql.py sets DATABASE_URL in the
    environment at import time and reloads modules) can leave the module imported at collection time and the one in sys.modules as two different objects, each with its own settings: patching only one made two of these tests pass
    alone and fail in the full suite."""

    def set_urls(service=SERVICE, migration=""):
        live = importlib.import_module("app.core.config").settings  # looked up NOW, from sys.modules: what a lazy `from app.core.config import settings` will see
        for obj in {id(o): o for o in (rm.settings, live)}.values():
            monkeypatch.setattr(obj, "DATABASE_URL", service)
            monkeypatch.setattr(obj, "MIGRATION_DATABASE_URL", migration)

    return set_urls


@pytest.fixture
def dsns(monkeypatch):
    """Record the DSN asyncpg is asked to connect with."""
    seen: list[str] = []

    class Conn:
        async def close(self):
            pass

    async def fake_connect(dsn, **kwargs):
        seen.append(dsn)
        return Conn()

    monkeypatch.setattr(rm.asyncpg, "connect", fake_connect)
    return seen


class TestWhichUrlMigrationsUse:
    def test_by_default_the_services_own_connection_is_used_so_nothing_changes(self, urls, dsns):
        urls()
        asyncio.run(rm._connect())
        assert dsns == ["postgresql://aisoc_app:svc-secret@db:5432/aisoc"]

    def test_when_set_the_migration_connection_is_used_and_the_services_is_not(self, urls, dsns):
        urls(migration=OWNER)
        asyncio.run(rm._connect())
        assert dsns == ["postgresql://aisoc:owner-secret@db:5432/aisoc"]

    @pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
    def test_a_blank_value_counts_as_unset(self, urls, dsns, blank):
        urls(migration=blank)
        asyncio.run(rm._connect())
        assert dsns == ["postgresql://aisoc_app:svc-secret@db:5432/aisoc"]

    def test_an_explicit_url_beats_both(self, urls, dsns):
        urls(migration=OWNER)
        asyncio.run(rm._connect("postgresql+asyncpg://x:y@h:1/d"))
        assert dsns == ["postgresql://x:y@h:1/d"]

    def test_the_sqlalchemy_driver_suffix_is_stripped_for_the_migration_url_too(self, urls, dsns):
        urls(migration="postgresql+asyncpg://aisoc:s@db/aisoc?sslmode=disable")
        asyncio.run(rm._connect())
        assert dsns == ["postgresql://aisoc:s@db/aisoc"]

    def test_the_helper_agrees_with_the_connection(self, urls):
        urls(migration=OWNER)
        assert rm.migration_url() == OWNER
        urls()
        assert rm.migration_url() == SERVICE
        assert rm.migration_url("  explicit  ") == "explicit"

    def test_the_main_entry_point_connects_through_it(self, urls, dsns, monkeypatch):
        urls(migration=OWNER)
        monkeypatch.setattr(rm, "MIGRATIONS_DIR", Path("/nonexistent-migrations"))
        asyncio.run(rm.main())  # no migrations dir: returns before connecting
        assert dsns == []
        src = Path(rm.__file__).read_text(encoding="utf-8")
        assert "conn = await _connect()" in src  # main() takes no URL: the setting is what decides


class TestNothingSecretIsLogged:
    def test_a_failing_connect_never_logs_either_password(self, urls, monkeypatch, caplog):
        urls(migration=OWNER)

        async def failing(dsn, **kwargs):
            raise OSError("connection refused")

        async def no_sleep(_):
            pass

        monkeypatch.setattr(rm.asyncpg, "connect", failing)
        monkeypatch.setattr(rm.asyncio, "sleep", no_sleep)
        with caplog.at_level(logging.DEBUG), pytest.raises(OSError):
            asyncio.run(rm._connect())
        assert caplog.records
        text = " ".join(r.getMessage() for r in caplog.records)
        assert "owner-secret" not in text and "svc-secret" not in text


class TestTheAuditFollowsTheServiceNotTheMigrationRole:
    """The audit reports on the role the SERVICES run as. If it followed MIGRATION_DATABASE_URL (the owner) it would say "RLS is bypassed" about the wrong role."""

    def run(self, urls, monkeypatch, capsys, service, migration):
        urls(service, migration)
        asked: list[str | None] = []

        class FakeConn:
            async def fetchrow(self, sql):
                return {"name": "x", "rolsuper": False, "rolbypassrls": False}

            async def fetch(self, sql):
                return []

            async def fetchval(self, sql, *params):
                return None

            async def close(self):
                pass

        async def connect(url=None):
            asked.append(url)
            return FakeConn()

        monkeypatch.setattr(rm, "_connect", connect)
        asyncio.run(ra.main([]))
        capsys.readouterr()
        return asked

    def test_the_audit_connects_with_the_service_url_even_when_a_migration_url_is_set(self, urls, monkeypatch, capsys):
        assert self.run(urls, monkeypatch, capsys, SERVICE, OWNER) == [SERVICE]

    def test_and_with_no_migration_url_too(self, urls, monkeypatch, capsys):
        assert self.run(urls, monkeypatch, capsys, SERVICE, "") == [SERVICE]


class TestTheSetting:
    def test_it_defaults_to_empty_so_nothing_changes(self):
        assert Settings().MIGRATION_DATABASE_URL == ""

    def test_it_is_read_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("MIGRATION_DATABASE_URL", OWNER)
        assert Settings().MIGRATION_DATABASE_URL == OWNER

    def test_the_api_runs_migrations_only_through_the_runners_main(self):
        """Both startup call sites go through run_migrations.main(), so one setting governs both."""
        src = (Path(__file__).resolve().parent.parent / "app" / "main.py").read_text(encoding="utf-8")
        assert src.count("from app.scripts.run_migrations import main as run_sql_migrations") == 2 and src.count("await run_sql_migrations()") == 2
        assert "run_migrations import _connect" not in src
