"""Detection-loop suggestions are persisted, tenant-scoped, and a failed proposal insert is no longer silent.

POST /detection-loop/suggest kept each suggestion in a process-wide dict, so a restart emptied GET /detection-loop/suggestions even though the draft proposals it had created were still in
detection_rule_proposals. That row carries neither the alert id nor the suggestion id, so a suggestion cannot be rebuilt from it. They are rows in `detection_suggestions` now (migration 058).
The proposal insert was also wrapped in `except Exception: proposal_id = None` in a module with no logger: every database error there vanished without a trace. It now runs in a savepoint and is logged.
list/get run against a real file-backed SQLite database here (which has no RLS, so what is proven is the endpoint's own explicit tenant filtering). The POST path stays covered in
test_detection_loop_tenant_isolation.py with a mocked session (its raw SQL binds uuid.UUID objects, which asyncpg accepts and SQLite does not), and end to end against real Postgres.
"""
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from app.api.v1.endpoints import detection_loop as dl
from app.db.database import Base
from app.db.rls import get_tenant_db
from app.models.detection_suggestion import DetectionSuggestion
from app.models.tenant import Tenant

PREFIX = dl.router.prefix
DB = SimpleNamespace(factory=None, sync=None, path=None)


def client_as(role="soc_analyst", tenant_id=None, user_id=None) -> TestClient:
    app = FastAPI()
    app.include_router(dl.router)
    tenant_id = tenant_id or uuid.uuid4()
    app.dependency_overrides[deps.get_current_user] = lambda: deps.CurrentUser(user_id=user_id or uuid.uuid4(), tenant_id=tenant_id, role=role, email=f"{role}@example.test")

    async def real_session():
        async with DB.factory() as session:
            yield session

    app.dependency_overrides[get_tenant_db] = real_session
    c = TestClient(app)
    c.tenant_id = tenant_id
    return c


@pytest.fixture(autouse=True)
def database(tmp_path):
    path = tmp_path / "suggestions.db"
    DB.path, DB.sync = path, create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(DB.sync, tables=[Tenant.__table__, DetectionSuggestion.__table__])
    DB.factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool), expire_on_commit=False)
    yield
    DB.sync.dispose()


def seed(tenant_id, name="fp-fix-draft", created_at=None, **over) -> uuid.UUID:
    sid = uuid.uuid4()
    with Session(DB.sync) as s:
        s.add(
            DetectionSuggestion(
                id=sid, tenant_id=tenant_id, alert_id=uuid.uuid4(), base_rule_id=uuid.uuid4(), draft_rule_name=name, draft_sigma_yaml="title: x\n", rationale="because", proposal_id=uuid.uuid4(),
                created_at=created_at or datetime.now(UTC), **over,
            )
        )
        s.commit()
    return sid


class TestListing:
    def test_a_tenant_with_none_gets_an_empty_list(self):
        assert client_as().get(f"{PREFIX}/suggestions").json() == {"suggestions": [], "total": 0}

    def test_it_lists_only_the_callers_tenant(self):
        a, b = client_as(), client_as()
        seed(a.tenant_id, "a-draft")
        seed(b.tenant_id, "b-draft")
        assert [s["draft_rule_name"] for s in a.get(f"{PREFIX}/suggestions").json()["suggestions"]] == ["a-draft"]
        assert [s["draft_rule_name"] for s in b.get(f"{PREFIX}/suggestions").json()["suggestions"]] == ["b-draft"]

    def test_the_response_shape_is_unchanged_and_leaks_no_internal_fields(self):
        c = client_as()
        seed(c.tenant_id)
        (item,) = c.get(f"{PREFIX}/suggestions").json()["suggestions"]
        assert set(item) == {"suggestion_id", "alert_id", "base_rule_id", "draft_rule_name", "draft_sigma_yaml", "rationale", "proposal_id", "created_at"}
        assert "tenant_id" not in item and "created_by" not in item

    def test_newest_first(self):
        c = client_as()
        now = datetime.now(UTC)
        seed(c.tenant_id, "old", created_at=now - timedelta(hours=2))
        seed(c.tenant_id, "new", created_at=now)
        seed(c.tenant_id, "mid", created_at=now - timedelta(hours=1))
        assert [s["draft_rule_name"] for s in c.get(f"{PREFIX}/suggestions").json()["suggestions"]] == ["new", "mid", "old"]

    def test_the_list_is_capped_but_the_total_is_honest(self, monkeypatch):
        monkeypatch.setattr(dl, "MAX_LISTED", 3)
        c = client_as()
        for i in range(5):
            seed(c.tenant_id, f"s{i}")
        body = c.get(f"{PREFIX}/suggestions").json()
        assert len(body["suggestions"]) == 3 and body["total"] == 5  # total is the real count, not the page

    def test_the_total_counts_only_the_callers_tenant(self):
        a, b = client_as(), client_as()
        for _ in range(2):
            seed(a.tenant_id)
        seed(b.tenant_id)
        assert a.get(f"{PREFIX}/suggestions").json()["total"] == 2


class TestFetchingOne:
    def test_the_owner_can_fetch_it(self):
        c = client_as()
        sid = seed(c.tenant_id, "mine")
        body = c.get(f"{PREFIX}/suggestions/{sid}").json()
        assert body["suggestion_id"] == str(sid) and body["draft_rule_name"] == "mine"

    def test_another_tenant_gets_a_404_indistinguishable_from_a_missing_id(self):
        a, b = client_as(), client_as()
        sid = seed(a.tenant_id)
        cross = b.get(f"{PREFIX}/suggestions/{sid}")
        missing = b.get(f"{PREFIX}/suggestions/{uuid.uuid4()}")
        assert cross.status_code == missing.status_code == 404
        assert cross.json() == missing.json() == {"detail": "Suggestion not found"}  # no hint that it exists

    def test_a_malformed_id_is_a_validation_error_not_a_500(self):
        assert client_as().get(f"{PREFIX}/suggestions/not-a-uuid").status_code == 422


class TestItSurvivesARestart:
    def test_a_stored_suggestion_is_still_there_after_the_process_restarts(self):
        """The dict emptied on every restart."""
        c = client_as()
        sid = seed(c.tenant_id, "survivor")
        DB.factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{DB.path}", poolclass=NullPool), expire_on_commit=False)  # a new process: nothing in memory
        again = client_as(tenant_id=c.tenant_id)
        assert [s["suggestion_id"] for s in again.get(f"{PREFIX}/suggestions").json()["suggestions"]] == [str(sid)]
        assert again.get(f"{PREFIX}/suggestions/{sid}").status_code == 200


class TestPermissions:
    """Derived from the real role table, so it stays true if the table changes (a hard-coded list of 'roles without the permission' was vacuous: every role I named held alerts:read)."""

    def test_every_role_is_checked_against_alerts_read_in_both_directions(self):
        from app.core.security import ROLE_PERMISSIONS, has_permission

        roles = sorted(ROLE_PERMISSIONS)
        allowed = [r for r in roles if has_permission(r, "alerts:read")]
        denied = [r for r in roles if not has_permission(r, "alerts:read")]
        assert allowed, "no role holds alerts:read: the table changed shape"
        for role in allowed:
            c = client_as(role=role)
            sid = seed(c.tenant_id)
            assert c.get(f"{PREFIX}/suggestions").status_code == 200 and c.get(f"{PREFIX}/suggestions/{sid}").status_code == 200, role
        for role in denied:  # (empty in this build: every role can read; this loop is the check should that ever change)
            c = client_as(role=role)
            sid = seed(c.tenant_id)
            assert c.get(f"{PREFIX}/suggestions").status_code == 403 and c.get(f"{PREFIX}/suggestions/{sid}").status_code == 403, role

    def test_suggesting_requires_alerts_write(self):
        from app.core.security import ROLE_PERMISSIONS, has_permission

        denied = [r for r in sorted(ROLE_PERMISSIONS) if not has_permission(r, "alerts:write")]
        allowed = [r for r in sorted(ROLE_PERMISSIONS) if has_permission(r, "alerts:write")]
        assert allowed and denied  # meaningful both ways
        for role in denied:
            assert client_as(role=role).post(f"{PREFIX}/suggest", json={"alert_id": str(uuid.uuid4())}).status_code == 403, role


class TestTheProposalInsertIsNoLongerSilent:
    """POST path with a mocked session (its raw SQL binds uuid.UUID objects, which SQLite cannot take)."""

    @staticmethod
    def make_db(fail_proposal: bool):
        alert = MagicMock(rule_id=None, evidence={"process_name": "powershell.exe"}, tenant_id=uuid.uuid4())
        db = MagicMock()
        db.added = []
        db.add = MagicMock(side_effect=db.added.append)
        calls = {"n": 0}

        async def execute(clause, *a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                r = MagicMock()
                r.fetchone = MagicMock(return_value=alert)
                return r
            if fail_proposal:
                raise RuntimeError("relation detection_rule_proposals does not exist")
            return MagicMock()

        class Savepoint:
            async def __aenter__(self):
                return None

            async def __aexit__(self, *exc):
                return False

        db.execute = AsyncMock(side_effect=execute)
        db.commit = AsyncMock()
        db.rollback = AsyncMock()
        db.begin_nested = MagicMock(side_effect=lambda: Savepoint())
        return db

    @pytest.fixture(autouse=True)
    def stub_llm(self, monkeypatch):
        monkeypatch.setattr(dl, "_llm_draft_sigma", AsyncMock(return_value={"rule_name": "fp-draft", "sigma_yaml": "title: x\n", "rationale": "because"}))

    def user(self):
        return deps.CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="soc_analyst", email="a@example.test")

    async def test_a_failed_proposal_insert_is_logged_and_the_suggestion_is_still_stored_without_a_proposal(self, monkeypatch):
        warnings = []
        monkeypatch.setattr(dl.logger, "warning", lambda event, **kw: warnings.append((event, kw)))
        user, db = self.user(), self.make_db(fail_proposal=True)
        out = await dl.suggest_fp_fix(body=dl.SuggestRequest(alert_id=uuid.uuid4()), db=db, user=user)
        assert out.proposal_id is None
        (stored,) = db.added
        assert stored.proposal_id is None and stored.tenant_id == user.tenant_id  # still stored: the draft is not lost
        assert [w[0] for w in warnings] == ["detection_loop.proposal_insert_failed"]  # and it is VISIBLE
        assert warnings[0][1]["tenant_id"] == str(user.tenant_id)
        db.commit.assert_awaited_once()

    async def test_a_successful_proposal_is_linked_and_nothing_is_logged(self, monkeypatch):
        warnings = []
        monkeypatch.setattr(dl.logger, "warning", lambda event, **kw: warnings.append(event))
        db = self.make_db(fail_proposal=False)
        out = await dl.suggest_fp_fix(body=dl.SuggestRequest(alert_id=uuid.uuid4()), db=db, user=self.user())
        assert out.proposal_id is not None and db.added[0].proposal_id == out.proposal_id and warnings == []

    async def test_the_proposal_insert_runs_inside_a_savepoint(self):
        db = self.make_db(fail_proposal=False)
        await dl.suggest_fp_fix(body=dl.SuggestRequest(alert_id=uuid.uuid4()), db=db, user=self.user())
        db.begin_nested.assert_called_once()

    async def test_a_failure_to_STORE_the_suggestion_is_not_swallowed(self):
        """Only the optional proposal is best-effort; losing the suggestion itself must be loud."""
        db = self.make_db(fail_proposal=False)
        db.commit = AsyncMock(side_effect=RuntimeError("could not commit"))
        with pytest.raises(RuntimeError, match="could not commit"):
            await dl.suggest_fp_fix(body=dl.SuggestRequest(alert_id=uuid.uuid4()), db=db, user=self.user())

    async def test_a_cross_tenant_alert_is_still_a_404_and_stores_nothing(self):
        db = self.make_db(fail_proposal=False)

        async def none(clause, *a, **k):
            r = MagicMock()
            r.fetchone = MagicMock(return_value=None)
            return r

        db.execute = AsyncMock(side_effect=none)
        with pytest.raises(HTTPException) as err:
            await dl.suggest_fp_fix(body=dl.SuggestRequest(alert_id=uuid.uuid4()), db=db, user=self.user())
        assert err.value.status_code == 404 and db.added == []


class TestWiringAndMigration:
    def test_the_routes_are_mounted_on_the_real_api(self):
        from app.main import app

        paths = app.openapi()["paths"]
        assert "/api/v1/detection-loop/suggestions" in paths and "/api/v1/detection-loop/suggestions/{suggestion_id}" in paths and "/api/v1/detection-loop/suggest" in paths

    def test_the_model_and_migration_agree(self):
        import pathlib

        sql = (pathlib.Path(__file__).resolve().parent.parent / "migrations" / "058_detection_suggestions.sql").read_text(encoding="utf-8")
        for column in DetectionSuggestion.__table__.columns:
            assert f"    {column.name} " in sql, f"column {column.name} is in the model but not in migration 058"

    def test_the_old_in_memory_store_is_gone(self):
        assert not hasattr(dl, "_SUGGESTIONS")
