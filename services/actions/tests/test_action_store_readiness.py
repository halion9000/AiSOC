"""/readyz reports ready only when the action store works: DATABASE_URL is set AND migration 055 has been applied.

Without this, a deploy that started the new image before the migration ran (or without DATABASE_URL) would be reported healthy, then fail every response action at request time with a bare 500, during
whatever incident prompted them. Instead /readyz stays 503 so the deploy visibly fails its healthcheck, and a watcher marks the service ready the moment the store answers (no restart needed).
"""
import asyncio
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from app import db as db_module
from app import store_readiness
from app.core import config as config_module
from app.db import Base
from app.models.action_record import ActionRecord


@pytest.fixture
def database(tmp_path, monkeypatch):
    """Point the service at a throwaway SQLite file; returns (url, create_table)."""
    path = tmp_path / "ready.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{path}")
    config_module.get_settings.cache_clear()
    monkeypatch.setattr(db_module, "_factory", None)
    monkeypatch.setattr(db_module, "_engine", None)

    def create_table():
        engine = create_engine(f"sqlite:///{path}")
        Base.metadata.create_all(engine, tables=[ActionRecord.__table__])
        engine.dispose()

    yield create_table
    config_module.get_settings.cache_clear()


@pytest.fixture
def unconfigured(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "")
    config_module.get_settings.cache_clear()
    monkeypatch.setattr(db_module, "_factory", None)
    monkeypatch.setattr(db_module, "_engine", None)
    yield
    config_module.get_settings.cache_clear()


def wait_for_ready(client, timeout=5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if client.get("/readyz").status_code == 200:
            return True
        time.sleep(0.05)
    return False


class TestCheckActionStore:
    def test_not_configured(self, unconfigured):
        assert asyncio.run(store_readiness.check_action_store()) == (False, "DATABASE_URL is not configured")

    def test_configured_and_migrated(self, database):
        database()
        assert asyncio.run(store_readiness.check_action_store()) == (True, "ok")

    def test_configured_but_the_table_is_missing_names_the_problem(self, database):
        ready, reason = asyncio.run(store_readiness.check_action_store())
        assert ready is False
        assert "OperationalError" in reason and "response_actions" in reason  # says WHICH table, so the operator knows migration 055 is missing

    def test_an_unreachable_database_is_not_ready(self, monkeypatch, tmp_path):
        monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/no/such/dir/x.db")
        config_module.get_settings.cache_clear()
        monkeypatch.setattr(db_module, "_factory", None)
        monkeypatch.setattr(db_module, "_engine", None)
        try:
            ready, reason = asyncio.run(store_readiness.check_action_store())
        finally:
            config_module.get_settings.cache_clear()
        assert ready is False and reason


class TestTheRealServiceStartup:
    def test_ready_when_the_store_works(self, database):
        from app.main import app

        database()
        with TestClient(app) as client:
            assert client.get("/readyz").status_code == 200
            assert client.get("/livez").status_code == 200

    def test_not_ready_without_a_database_url_but_still_alive(self, unconfigured):
        from app.main import app

        with TestClient(app) as client:
            r = client.get("/readyz")
            assert r.status_code == 503 and r.json()["status"] == "starting"
            assert client.get("/livez").status_code == 200  # the process is fine: it must not be restarted, only held out of rotation

    def test_not_ready_when_the_migration_has_not_run(self, database):
        from app.main import app

        with TestClient(app) as client:
            assert client.get("/readyz").status_code == 503

    def test_becomes_ready_without_a_restart_once_the_migration_is_applied(self, database, monkeypatch):
        """The deploy-ordering mistake heals itself: the watcher notices the table appear."""
        from app.main import app

        monkeypatch.setattr(store_readiness, "RECHECK_INTERVAL_SECONDS", 0.05)
        with TestClient(app) as client:
            assert client.get("/readyz").status_code == 503
            database()  # the migration lands
            assert wait_for_ready(client), "the service never became ready after the store started working"

    def test_the_shutdown_hook_itself_stops_the_watcher(self, database, monkeypatch):
        """Observe the hook, not the outcome: TestClient's teardown cancels every leftover task on the loop anyway, so `watch.done()` after exit is true even if the hook never cancelled it."""
        from app.main import app

        class Spy:
            def __init__(self, task):
                self.task, self.cancelled_by_the_hook = task, False

            def cancel(self):
                self.cancelled_by_the_hook = True
                return self.task.cancel()

        monkeypatch.setattr(store_readiness, "RECHECK_INTERVAL_SECONDS", 0.05)
        with TestClient(app) as client:
            client.get("/readyz")
            spy = Spy(app.state.store_watch)
            app.state.store_watch = spy
        assert spy.cancelled_by_the_hook

    def test_the_action_routes_still_answer_503_not_500_while_not_ready(self, unconfigured):
        from app.main import app

        with TestClient(app) as client:
            r = client.get("/api/v1/actions/00000000-0000-0000-0000-000000000000", headers={"Authorization": "Bearer x"})
            assert r.status_code in (401, 503)  # refused cleanly (auth or unconfigured store), never an unhandled 500
