"""Marketplace installs are stored in the database: they survive an API restart and each tenant sees, repeats and removes only its own.

They were a module-level dict, so every restart silently uninstalled everything, and with several workers each held its own copy (a tenant's "installed" list depended on which process answered). Each call here uses its own session on a BRAND-NEW
engine over the same database file, so "did X, then read it back" is genuinely "did X, then the process restarted". SQLite has no row-level security, so the isolation tests prove the endpoints' own tenant filters (the database policy itself
was checked on real Postgres as the non-superuser role, by the isolation flows).
"""
import asyncio
import hashlib
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1.endpoints import marketplace as mp
from app.db.database import Base
from app.models.marketplace import MarketplaceInstall
from app.models.tenant import Tenant

CONTENT = b"title: a detection\n"
ITEM = {"id": "det-1", "type": "detection", "name": "Detection One", "version": "2.1.0", "path": "detections/one.yml"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    db_path = tmp_path / "marketplace.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine, tables=[Tenant.__table__, MarketplaceInstall.__table__])
    engine.dispose()
    content = tmp_path / "one.yml"
    content.write_bytes(CONTENT)
    index = {"items": [ITEM, {"id": "det-2", "type": "detection", "name": "Detection Two", "path": "detections/two.yml"}, {"id": "pb-1", "type": "playbook", "path": "playbooks/p.yml"}, {"id": "det-1", "type": "plugin", "name": "Same id, other type", "path": "plugins/x"}], "stats": {}, "mitre_coverage": {}}
    monkeypatch.setattr(mp, "_load_index", lambda: index)
    monkeypatch.setattr(mp, "_resolve_item_path", lambda item: content)
    return SimpleNamespace(db_path=db_path, content=content)


def run(env, fn):
    """Run `fn(session)` in its own session on a BRAND-NEW engine: a separate request, or a restarted process."""

    async def main():
        engine = create_async_engine(f"sqlite+aiosqlite:///{env.db_path}", poolclass=NullPool)
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                return await fn(session)
        finally:
            await engine.dispose()

    return asyncio.run(main())


def instant(text: str):
    """The moment a timestamp names. SQLite does not store time zones (a stored value comes back naive); Postgres does (it comes back aware), so compare the instant, not the text."""
    from datetime import UTC, datetime

    d = datetime.fromisoformat(text)
    return d.replace(tzinfo=UTC) if d.tzinfo is None else d


def person(tenant_id=None, email="admin@example.com"):
    return SimpleNamespace(user_id=uuid.uuid4(), tenant_id=tenant_id or uuid.uuid4(), email=email, role="admin")


def install(env, u, type="detection", id="det-1"):
    return run(env, lambda s: mp.install_marketplace_item(mp.InstallRequest(type=type, id=id), current_user=u, db=s))


def uninstall(env, u, type="detection", id="det-1"):
    return run(env, lambda s: mp.uninstall_marketplace_item(type=type, id=id, current_user=u, db=s))


def installed(env, u):
    return run(env, lambda s: mp.list_installed(current_user=u, db=s))


def catalogue_installed_ids(env, u):
    return run(env, lambda s: mp.list_marketplace(current_user=u, db=s, type_filter=None, mitre=None, severity=None, category=None, source=None, sdk=None, search=None)).installed_ids


def rows(env):
    engine = create_engine(f"sqlite:///{env.db_path}")
    try:
        with Session(engine) as s:
            return s.execute(select(MarketplaceInstall)).scalars().all()
    finally:
        engine.dispose()


class TestInstallsSurviveARestart:
    def test_an_install_is_still_there_after_the_process_restarts_with_every_field(self, env):
        u = person()
        first = install(env, u)
        record = installed(env, u)["items"]  # a brand-new engine: the "restarted" process
        assert [(r["id"], r["type"], r["name"], r["version"], r["path"], r["installed_by"], r["tenant_id"]) for r in record] == [("det-1", "detection", "Detection One", "2.1.0", "detections/one.yml", "admin@example.com", str(u.tenant_id))]
        assert record[0]["content_sha256"] == first.content_sha256 == hashlib.sha256(CONTENT).hexdigest()
        assert instant(record[0]["installed_at"]) == instant(first.installed_at)

    def test_the_catalogue_marks_it_installed_after_a_restart(self, env):
        u = person()
        install(env, u)
        assert catalogue_installed_ids(env, u) == ["det-1"]

    def test_an_uninstall_survives_a_restart_too(self, env):
        u = person()
        install(env, u)
        uninstall(env, u)
        assert installed(env, u) == {"total": 0, "items": []} and catalogue_installed_ids(env, u) == []

    def test_what_the_response_says_matches_what_is_stored(self, env):
        u = person()
        r = install(env, u)
        (row,) = rows(env)
        assert (r.id, r.type, r.name, r.version, r.installed_by) == (row.item_id, row.item_type, row.name, row.version, row.installed_by)
        assert instant(r.installed_at) == instant(row.installed_at.isoformat())

    def test_an_item_without_a_name_or_version_gets_the_documented_defaults(self, env):
        u = person()
        r = install(env, u, type="playbook", id="pb-1")
        assert (r.name, r.version) == ("pb-1", "1.0.0")

    def test_the_installer_falls_back_to_the_user_id_when_there_is_no_email(self, env):
        u = person(email=None)
        assert install(env, u).installed_by == str(u.user_id)


class TestReinstalling:
    def test_it_is_idempotent_one_row_and_the_second_answer_says_so(self, env):
        u = person()
        a, b = install(env, u), install(env, u)
        assert (a.already_installed, b.already_installed) == (False, True) and len(rows(env)) == 1

    def test_it_keeps_the_original_installer_and_refreshes_the_hash_and_the_time(self, env):
        first_user, second_user = person(email="first@example.com"), person(tenant_id=None, email="second@example.com")
        second_user.tenant_id = first_user.tenant_id
        a = install(env, first_user)
        env.content.write_bytes(b"title: edited\n")
        b = install(env, second_user)
        assert b.installed_by == "first@example.com"
        assert b.content_sha256 == hashlib.sha256(b"title: edited\n").hexdigest() != a.content_sha256
        assert instant(b.installed_at) >= instant(a.installed_at)
        (row,) = rows(env)
        assert row.content_sha256 == b.content_sha256 and row.installed_by == "first@example.com"

    def test_an_install_that_loses_a_race_for_the_same_item_is_the_already_installed_case_not_an_error(self, env):
        u = person()
        install(env, u)

        class BlindOnce:
            """The first lookup reports 'not installed' (the other request had not committed yet); the insert then collides with the primary key."""

            def __init__(self, session):
                self.s, self.blind = session, True

            async def execute(self, stmt):
                if self.blind:
                    self.blind = False
                    return SimpleNamespace(scalar_one_or_none=lambda: None)
                return await self.s.execute(stmt)

            def __getattr__(self, name):
                return getattr(self.s, name)

        r = run(env, lambda s: mp.install_marketplace_item(mp.InstallRequest(type="detection", id="det-1"), current_user=SimpleNamespace(**{**vars(u)}), db=BlindOnce(s)))
        assert r.already_installed is True and len(rows(env)) == 1

    def test_a_conflict_that_leaves_no_row_behind_is_raised_not_swallowed(self, env):
        class AlwaysConflicts:
            def __init__(self):
                self.rolled_back = False

            async def execute(self, stmt):
                return SimpleNamespace(scalar_one_or_none=lambda: None)

            def add(self, row):
                pass

            async def commit(self):
                raise IntegrityError("insert", {}, Exception("boom"))

            async def rollback(self):
                self.rolled_back = True

        db = AlwaysConflicts()
        with pytest.raises(IntegrityError):
            asyncio.run(mp.install_marketplace_item(mp.InstallRequest(type="detection", id="det-1"), current_user=person(), db=db))
        assert db.rolled_back


class TestEachTenantSeesAndChangesOnlyItsOwn:
    def test_another_tenants_install_is_in_neither_its_installed_list_nor_the_catalogue_marks(self, env):
        a, b = person(), person()
        install(env, a)
        assert installed(env, b) == {"total": 0, "items": []} and catalogue_installed_ids(env, b) == []

    def test_a_tenant_cannot_uninstall_another_tenants_install(self, env):
        a, b = person(), person()
        install(env, a)
        with pytest.raises(HTTPException) as e:
            uninstall(env, b)
        assert e.value.status_code == 404 and installed(env, a)["total"] == 1

    def test_the_same_item_installed_by_two_tenants_is_two_independent_rows(self, env):
        a, b = person(), person()
        install(env, a), install(env, b)
        assert len(rows(env)) == 2
        uninstall(env, a)
        assert installed(env, a)["total"] == 0 and installed(env, b)["total"] == 1
        assert install(env, a).already_installed is False and install(env, b).already_installed is True

    def test_an_install_by_one_tenant_is_not_already_installed_for_another(self, env):
        a, b = person(), person()
        install(env, a)
        assert install(env, b).already_installed is False

    def test_the_list_returns_only_the_callers_rows_when_the_table_holds_many_tenants(self, env):
        tenants = [person() for _ in range(3)]
        for t in tenants:
            install(env, t), install(env, t, type="playbook", id="pb-1")
        for t in tenants:
            got = installed(env, t)["items"]
            assert len(got) == 2 and {r["tenant_id"] for r in got} == {str(t.tenant_id)}
            assert catalogue_installed_ids(env, t) == ["det-1", "pb-1"] or sorted(catalogue_installed_ids(env, t)) == ["det-1", "pb-1"]

    def test_every_query_an_endpoint_runs_is_restricted_to_the_callers_tenant(self, env):
        """Defence in depth: the explicit filter holds even where row-level security is not in force (the default deployment connects as a superuser)."""
        a, b = person(), person()
        install(env, a), install(env, b)
        statements: list[str] = []

        async def go(s):
            def spy(conn, cursor, statement, *a, **kw):
                statements.append(statement)

            event.listen(s.bind.sync_engine, "before_cursor_execute", spy)
            await mp.list_installed(current_user=a, db=s)
            await mp.list_marketplace(current_user=a, db=s, type_filter=None, mitre=None, severity=None, category=None, source=None, sdk=None, search=None)
            await mp.install_marketplace_item(mp.InstallRequest(type="detection", id="det-1"), current_user=a, db=s)
            await mp.uninstall_marketplace_item(type="detection", id="det-1", current_user=a, db=s)

        run(env, go)
        touching = [q for q in statements if "marketplace_installs" in q and q.lstrip().upper().startswith(("SELECT", "UPDATE", "DELETE"))]
        assert len(touching) >= 5
        assert all("marketplace_installs.tenant_id = ?" in q or "tenant_id = ?" in q for q in touching), touching
        assert len(rows(env)) == 1 and rows(env)[0].tenant_id == b.tenant_id, "only the caller's own row changed"


class TestTheItemTypeIsPartOfTheKey:
    def test_the_same_id_under_two_types_is_two_installs(self, env):
        u = person()
        install(env, u, type="detection", id="det-1"), install(env, u, type="plugin", id="det-1")
        assert [(r["type"], r["id"]) for r in installed(env, u)["items"]] == [("detection", "det-1"), ("plugin", "det-1")]

    def test_uninstalling_the_wrong_type_is_a_404_and_removes_nothing(self, env):
        u = person()
        install(env, u, type="detection", id="det-1")
        with pytest.raises(HTTPException) as e:
            uninstall(env, u, type="plugin", id="det-1")
        assert e.value.status_code == 404 and installed(env, u)["total"] == 1

    def test_the_list_is_sorted_by_type_then_id(self, env):
        u = person()
        install(env, u, type="playbook", id="pb-1"), install(env, u, type="plugin", id="det-1"), install(env, u, type="detection", id="det-1")
        assert [(r["type"], r["id"]) for r in installed(env, u)["items"]] == [("detection", "det-1"), ("playbook", "pb-1"), ("plugin", "det-1")]

    def test_the_sorting_is_asked_of_the_database_because_without_it_postgres_returns_rows_in_any_order(self, env):
        """SQLite happens to return rows in primary-key order, so the result alone cannot show whether the query sorts; the SQL does."""
        statements: list[str] = []

        async def go(s):
            event.listen(s.bind.sync_engine, "before_cursor_execute", lambda conn, cursor, statement, *a, **kw: statements.append(statement))
            await mp.list_installed(current_user=person(), db=s)

        run(env, go)
        (q,) = [x for x in statements if "marketplace_installs" in x]
        assert "ORDER BY marketplace_installs.item_type, marketplace_installs.item_id" in q


class TestUninstall:
    def test_it_removes_only_the_item_asked_for_not_the_tenants_other_installs_of_that_type(self, env):
        u = person()
        install(env, u, id="det-1"), install(env, u, id="det-2")
        uninstall(env, u, id="det-1")
        assert [r["id"] for r in installed(env, u)["items"]] == ["det-2"]

    def test_it_answers_with_what_was_removed(self, env):
        u = person()
        install(env, u)
        assert uninstall(env, u) == {"status": "uninstalled", "id": "det-1", "type": "detection"}

    def test_removing_what_is_not_installed_is_a_404_with_the_item_named(self, env):
        with pytest.raises(HTTPException) as e:
            uninstall(env, person())
        assert e.value.status_code == 404 and "detection:det-1" in e.value.detail

    def test_it_cannot_be_done_twice(self, env):
        u = person()
        install(env, u), uninstall(env, u)
        with pytest.raises(HTTPException) as e:
            uninstall(env, u)
        assert e.value.status_code == 404


class TestInstallingSomethingThatIsNotInTheCatalogue:
    def test_an_unknown_item_is_a_404_and_stores_nothing(self, env):
        with pytest.raises(HTTPException) as e:
            install(env, person(), id="not-in-the-index")
        assert e.value.status_code == 404 and rows(env) == []


class TestNoInstallStateLivesInTheProcessAnyMore:
    def test_the_module_has_no_install_store_or_lock(self):
        assert not hasattr(mp, "_installed") and not hasattr(mp, "_installed_lock")

    def test_no_module_level_dict_holds_installs(self):
        import re
        import inspect

        src = inspect.getsource(mp)
        assert not re.search(r"^_\w*install\w*\s*(:[^=\n]+)?=\s*\{\}", src, re.M), "a module-level mapping of installs is back"

    def test_every_handler_that_reads_or_writes_installs_uses_the_tenant_context_session(self):
        import inspect

        for fn in (mp.list_marketplace, mp.install_marketplace_item, mp.uninstall_marketplace_item, mp.list_installed):
            assert "db" in inspect.signature(fn).parameters, fn.__name__

    def test_the_model_and_the_migration_agree_on_the_key_and_the_policy(self):
        from pathlib import Path

        sql = (Path(__file__).resolve().parent.parent / "migrations" / "068_marketplace_installs.sql").read_text()
        assert [c.name for c in MarketplaceInstall.__table__.primary_key.columns] == ["tenant_id", "item_type", "item_id"]
        assert "PRIMARY KEY (tenant_id, item_type, item_id)" in sql and "ENABLE ROW LEVEL SECURITY" in sql
        assert "USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)" in " ".join(sql.split())
        assert "REFERENCES tenants (id) ON DELETE CASCADE" in sql
        for column in MarketplaceInstall.__table__.columns:
            assert column.name in sql, column.name
