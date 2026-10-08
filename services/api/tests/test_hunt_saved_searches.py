"""Saved hunt SEARCHES (the raw-query bookmarks on the /hunt page) are persisted and scoped to a tenant.

They were one module-level dict in the AGENTS service, reached through a Next.js rewrite that bypasses the API:
  * lost on every restart, and
  * NOT tenant-scoped: GET /api/v1/hunt/saved returned every tenant's saved searches (hostnames, usernames, IOCs) to anyone, and any caller could delete any of them.
They now live in the API: a real table, an explicit tenant filter (plus RLS in Postgres), and a permission check. These tests run against a real file-backed SQLite database, which has no RLS, so what they prove
is the explicit tenant scoping in the endpoint itself.
"""
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from app.api.v1.endpoints import hunt_saved_searches as saved
from app.db.database import Base
from app.db.rls import get_tenant_db
from app.models.saved_hunt_search import SavedHuntSearch
from app.models.tenant import Tenant

PREFIX = saved.router.prefix
DB = SimpleNamespace(factory=None, sync=None, path=None)


def client_as(role="soc_analyst", tenant_id=None, user_id=None) -> TestClient:
    app = FastAPI()
    app.include_router(saved.router)
    tenant_id = tenant_id or uuid.uuid4()
    app.dependency_overrides[deps.get_current_user] = lambda: deps.CurrentUser(user_id=user_id or uuid.uuid4(), tenant_id=tenant_id, role=role, email=f"{role}@example.test")

    async def real_session():
        async with DB.factory() as session:
            yield session

    app.dependency_overrides[get_tenant_db] = real_session
    client = TestClient(app)
    client.tenant_id = tenant_id
    return client


def rows() -> list[SavedHuntSearch]:
    with Session(DB.sync) as s:
        found = s.query(SavedHuntSearch).order_by(SavedHuntSearch.created_at).all()
        for r in found:
            s.expunge(r)
        return found


@pytest.fixture(autouse=True)
def database(tmp_path):
    path = tmp_path / "hunt_saved.db"
    DB.path = path
    DB.sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(DB.sync, tables=[Tenant.__table__, SavedHuntSearch.__table__])
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool)
    DB.factory = async_sessionmaker(engine, expire_on_commit=False)
    yield
    DB.sync.dispose()


def save(c, name="Encoded PowerShell", query="process.name:powershell.exe AND process.args:*-enc*", **extra):
    return c.post(PREFIX, json={"name": name, "query": query, **extra})


class TestSaving:
    def test_an_empty_tenant_has_no_saved_searches(self):
        assert client_as().get(PREFIX).json() == {"searches": []}

    def test_a_saved_search_is_returned_in_the_shape_the_web_client_expects(self):
        c = client_as()
        r = save(c)
        assert r.status_code == 201
        body = r.json()
        assert set(body) == {"id", "name", "query", "language", "createdAt", "pinned"}  # unchanged from the agents endpoint, so the web client needs no change
        assert body["name"] == "Encoded PowerShell" and body["language"] == "lucene" and body["pinned"] is False
        uuid.UUID(body["id"])
        datetime.fromisoformat(body["createdAt"])
        assert c.get(PREFIX).json()["searches"] == [body]

    def test_it_is_stored_in_the_database_with_its_tenant_and_author(self):
        user = uuid.uuid4()
        c = client_as(user_id=user)
        save(c)
        (row,) = rows()
        assert row.tenant_id == c.tenant_id and row.created_by == user and row.name == "Encoded PowerShell"

    def test_a_search_survives_a_restart(self):
        """The in-memory dict lost everything on restart: here every request is a new session on a new engine over the same database."""
        c = client_as()
        created = save(c).json()
        engine = create_async_engine(f"sqlite+aiosqlite:///{DB.path}", poolclass=NullPool)
        DB.factory = async_sessionmaker(engine, expire_on_commit=False)  # a "restarted" process: nothing carried over in memory
        again = client_as(tenant_id=c.tenant_id)
        assert [s["id"] for s in again.get(PREFIX).json()["searches"]] == [created["id"]]

    def test_newest_first(self):
        c = client_as()
        first = save(c, name="first").json()
        with Session(DB.sync) as s:  # make the first clearly older
            s.get(SavedHuntSearch, uuid.UUID(first["id"])).created_at = datetime.now(UTC) - timedelta(hours=1)
            s.commit()
        second = save(c, name="second").json()
        assert [s["name"] for s in c.get(PREFIX).json()["searches"]] == ["second", "first"]
        assert second["id"] != first["id"]

    def test_surrounding_whitespace_is_trimmed(self):
        c = client_as()
        body = save(c, name="  hunt  ", query="  user:bob  ").json()
        assert body["name"] == "hunt" and body["query"] == "user:bob"

    @pytest.mark.parametrize("language", ["lucene", "kql", "sql", "esql", "spl"])
    def test_every_supported_language_is_accepted(self, language):
        assert save(client_as(), language=language).json()["language"] == language


class TestValidation:
    @pytest.mark.parametrize("payload", [{"name": "", "query": "q"}, {"name": "   ", "query": "q"}, {"name": "n", "query": ""}, {"name": "n", "query": "    "}, {"name": "n"}, {"query": "q"}, {}])
    def test_blank_or_missing_fields_are_refused_and_nothing_is_stored(self, payload):
        assert client_as().post(PREFIX, json=payload).status_code == 422
        assert rows() == []

    def test_an_unknown_language_is_refused(self):
        r = save(client_as(), language="cobol")
        assert r.status_code == 422 and "language must be one of" in r.json()["detail"]
        assert rows() == []

    def test_oversized_fields_are_refused(self):
        assert save(client_as(), name="n" * 201).status_code == 422
        assert save(client_as(), query="q" * 8001).status_code == 422
        assert save(client_as(), query="q" * 8000).status_code == 201

    def test_a_tenant_is_capped(self):
        c = client_as()
        with Session(DB.sync) as s:
            s.add_all([SavedHuntSearch(id=uuid.uuid4(), tenant_id=c.tenant_id, name=f"s{i}", query="q", language="lucene", pinned=False) for i in range(saved.MAX_PER_TENANT)])
            s.commit()
        r = save(c, name="one too many")
        assert r.status_code == 409 and str(saved.MAX_PER_TENANT) in r.json()["detail"]
        assert len(rows()) == saved.MAX_PER_TENANT
        assert save(client_as(), name="a different tenant is unaffected").status_code == 201  # the cap is per tenant


class TestTenantIsolation:
    """THE leak: GET /hunt/saved returned every tenant's searches to anyone, and any caller could delete any of them."""

    def test_a_tenant_never_sees_another_tenants_searches(self):
        a, b = client_as(), client_as()
        save(a, name="A's secret hunt", query="host:payroll-db-01 AND user:cfo")
        assert b.get(PREFIX).json() == {"searches": []}
        assert [s["name"] for s in a.get(PREFIX).json()["searches"]] == ["A's secret hunt"]

    def test_each_tenant_sees_only_its_own_when_both_have_some(self):
        a, b = client_as(), client_as()
        save(a, name="a1")
        save(a, name="a2")
        save(b, name="b1")
        assert sorted(s["name"] for s in a.get(PREFIX).json()["searches"]) == ["a1", "a2"]
        assert [s["name"] for s in b.get(PREFIX).json()["searches"]] == ["b1"]

    def test_another_tenant_cannot_delete_a_search_and_gets_a_404_not_a_hint_that_it_exists(self):
        a, b = client_as(), client_as()
        victim = save(a).json()["id"]
        r = b.delete(f"{PREFIX}/{victim}")
        assert r.status_code == 404 and r.json()["detail"] == "saved search not found"
        assert client_as().delete(f"{PREFIX}/{uuid.uuid4()}").json() == r.json()  # indistinguishable from an id that does not exist
        assert [s["id"] for s in a.get(PREFIX).json()["searches"]] == [victim]  # still there

    def test_analysts_in_the_same_tenant_share_searches(self):
        tenant = uuid.uuid4()
        one, two = client_as(tenant_id=tenant), client_as(tenant_id=tenant)
        created = save(one).json()
        assert [s["id"] for s in two.get(PREFIX).json()["searches"]] == [created["id"]]
        assert two.delete(f"{PREFIX}/{created['id']}").status_code == 204


class TestDeleting:
    def test_delete_removes_it(self):
        c = client_as()
        sid = save(c).json()["id"]
        assert c.delete(f"{PREFIX}/{sid}").status_code == 204
        assert c.get(PREFIX).json() == {"searches": []} and rows() == []

    def test_deleting_twice_is_a_404(self):
        c = client_as()
        sid = save(c).json()["id"]
        c.delete(f"{PREFIX}/{sid}")
        assert c.delete(f"{PREFIX}/{sid}").status_code == 404

    @pytest.mark.parametrize("bad", ["not-a-uuid", "123", "1; DROP TABLE saved_hunt_searches", "../../etc/passwd"])
    def test_a_malformed_id_is_a_404_not_a_500(self, bad):
        assert client_as().delete(f"{PREFIX}/{bad}").status_code == 404

    def test_delete_removes_only_the_named_search(self):
        c = client_as()
        keep, drop = save(c, name="keep").json()["id"], save(c, name="drop").json()["id"]
        c.delete(f"{PREFIX}/{drop}")
        assert [s["id"] for s in c.get(PREFIX).json()["searches"]] == [keep]


class TestPermissions:
    @pytest.mark.parametrize("role", ["viewer", "api_service"])
    def test_a_caller_without_lake_query_is_refused_on_every_route_and_nothing_changes(self, role):
        owner = client_as()
        sid = save(owner).json()["id"]
        denied = client_as(role=role, tenant_id=owner.tenant_id)
        assert denied.get(PREFIX).status_code == 403
        assert save(denied, name="should not be stored").status_code == 403
        assert denied.delete(f"{PREFIX}/{sid}").status_code == 403
        assert [r.name for r in rows()] == ["Encoded PowerShell"]  # nothing created, nothing deleted

    @pytest.mark.parametrize("role", ["soc_analyst", "threat_hunter", "soc_lead", "tenant_admin", "admin", "platform_admin"])
    def test_every_role_that_holds_lake_query_can_use_it(self, role):
        c = client_as(role=role)
        assert save(c).status_code == 201 and len(c.get(PREFIX).json()["searches"]) == 1

    def test_an_unauthenticated_caller_is_refused(self, monkeypatch):
        # Pin the environment: in a dev-class ENV an anonymous request is given a demo user (app.api.v1.dev_auth reads ENV at call time), and an earlier test in a full run can leave it set that way.
        # Without this the test passed alone and failed in the full suite.
        monkeypatch.setenv("ENV", "production")
        app = FastAPI()
        app.include_router(saved.router)

        async def real_session():
            async with DB.factory() as session:
                yield session

        app.dependency_overrides[get_tenant_db] = real_session
        c = TestClient(app)
        assert c.get(PREFIX).status_code in (401, 403)
        assert c.post(PREFIX, json={"name": "n", "query": "q"}).status_code in (401, 403)
        assert c.delete(f"{PREFIX}/{uuid.uuid4()}").status_code in (401, 403)
        assert rows() == []


class TestWiring:
    def test_the_routes_are_mounted_on_the_real_api(self):
        """/api/v1/hunt/saved is what the web client calls (through a rewrite that now points at the API instead of the agents service)."""
        from app.main import app

        paths = app.openapi()["paths"]
        assert {m.upper() for m in paths["/api/v1/hunt/saved"]} == {"GET", "POST"}
        assert {m.upper() for m in paths["/api/v1/hunt/saved/{search_id}"]} == {"DELETE"}


def test_the_stored_table_matches_the_migration():
    """The ORM columns and the migration must agree, or production breaks where SQLite cannot show it."""
    import pathlib

    sql = (pathlib.Path(__file__).resolve().parent.parent / "migrations" / "056_saved_hunt_searches.sql").read_text(encoding="utf-8")
    for column in SavedHuntSearch.__table__.columns:
        assert f"    {column.name} " in sql, f"column {column.name} is in the model but not in migration 056"
    for language in saved.LANGUAGES:
        assert f"'{language}'" in sql, f"language {language} is accepted by the endpoint but rejected by the migration's CHECK"
