"""The retention sweeper deletes only what has outlived its window, and only what it is allowed to.

Retention was configuration with no effect: the windows operators can set (raw events / alerts / audit days) were stored and read back, but nothing ever deleted anything (retention.py says "the scheduler/worker that runs the
purge composes these" and no such worker existed), while the tables added this session (copilot conversations, detection suggestions, response actions) would grow without limit. And the one purge query that did exist for alerts
filtered on NO tenant ("RLS scopes the tenant"), which the default superuser connection bypasses, so one tenant's window would have deleted every tenant's alerts.
The properties here are the DESTRUCTIVE-SAFETY ones: live response actions are never deleted however old; one tenant's window never touches another tenant's rows; every delete carries an explicit tenant predicate; windows are
clamped; deletes are batched and bounded; one failing class does not stop the rest; a dry run deletes nothing.
"""
import asyncio
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event, insert, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.db.database import Base
from app.models.copilot_conversation import CopilotConversation
from app.models.data_lifecycle import RetentionPolicyRow
from app.models.detection_suggestion import DetectionSuggestion
from app.models.tenant import Tenant
from app.services.retention import TERMINAL_ACTION_STATUSES
from app.workers import retention_sweeper as rs

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
A, B, C = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
LIVE = ["pending", "awaiting_approval", "approved", "running"]


def cfg(**over):
    base = dict(
        RETENTION_DRY_RUN=False, RETENTION_BATCH_SIZE=1000, RETENTION_MAX_BATCHES_PER_SWEEP=100, RETENTION_COPILOT_CONVERSATIONS_DAYS=90, RETENTION_DETECTION_SUGGESTIONS_DAYS=180,
        RETENTION_RESPONSE_ACTIONS_DEFAULT_DAYS=730, RETENTION_INITIAL_DELAY_SECONDS=0, RETENTION_SWEEP_INTERVAL_SECONDS=3600,
    )
    base.update(over)
    return SimpleNamespace(**base)


class DB:
    path = None
    sync = None
    factory = None
    statements: list[str] = []


@pytest.fixture(autouse=True)
def database(tmp_path):
    DB.path = tmp_path / "retention.db"
    DB.sync = create_engine(f"sqlite:///{DB.path}")
    Base.metadata.create_all(DB.sync, tables=[Tenant.__table__, CopilotConversation.__table__, DetectionSuggestion.__table__, RetentionPolicyRow.__table__])
    rs._meta.create_all(DB.sync)
    engine = create_async_engine(f"sqlite+aiosqlite:///{DB.path}", poolclass=NullPool)
    DB.statements = []

    @event.listens_for(engine.sync_engine, "before_cursor_execute")
    def capture(conn, cursor, statement, parameters, context, executemany):
        DB.statements.append(" ".join(statement.split()))

    DB.factory = async_sessionmaker(engine, expire_on_commit=False)
    yield
    DB.sync.dispose()


def ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


def conversation(tenant, age_days, cid=None, created_days=None):
    """`age_days` is when it was last updated; `created_days` (default: the same) is when it was started."""
    with Session(DB.sync) as s:
        s.add(CopilotConversation(tenant_id=tenant, owner_key="u1", conversation_id=cid or str(uuid.uuid4()), messages=[], created_at=ago(created_days if created_days is not None else age_days), updated_at=ago(age_days)))
        s.commit()


def suggestion(tenant, age_days):
    with Session(DB.sync) as s:
        s.add(DetectionSuggestion(id=uuid.uuid4(), tenant_id=tenant, alert_id=uuid.uuid4(), draft_rule_name="n", draft_sigma_yaml="y", created_at=ago(age_days)))
        s.commit()


def action(tenant, status, age_days):
    aid = uuid.uuid4()
    with Session(DB.sync) as s:
        s.execute(insert(rs.response_actions).values(id=aid, tenant_id=tenant, status=status, updated_at=ago(age_days)))
        s.commit()
    return aid


def policy(tenant, audit_days):
    with Session(DB.sync) as s:
        s.add(RetentionPolicyRow(tenant_id=tenant, audit_days=audit_days))
        s.commit()


def count(table_or_model):
    with Session(DB.sync) as s:
        return s.execute(select(text("count(*)")).select_from(table_or_model)).scalar_one()


def remaining_actions() -> set[uuid.UUID]:
    with Session(DB.sync) as s:
        return {r[0] for r in s.execute(select(rs.response_actions.c.id)).all()}


def sweep(**over):
    dry = over.pop("dry_run", None)
    return asyncio.run(rs.sweep_once(DB.factory, now=NOW, settings=cfg(**over), dry_run=dry))


class TestConversations:
    def test_old_ones_go_recent_ones_stay(self):
        conversation(A, 100)
        conversation(A, 10)
        assert sweep().counts["copilot_conversations"] == 1
        assert count(CopilotConversation) == 1

    def test_the_boundary_is_the_window(self):
        conversation(A, 89)
        conversation(A, 91)
        sweep()
        with Session(DB.sync) as s:
            kept = [r.updated_at for r in s.query(CopilotConversation).all()]
        assert len(kept) == 1 and abs((NOW.replace(tzinfo=None) - kept[0].replace(tzinfo=None)).days - 89) <= 1

    def test_a_long_running_conversation_that_is_still_in_use_is_kept(self):
        """Aged by LAST ACTIVITY, not by when it began: an analyst's months-old conversation that they used yesterday must not vanish under them."""
        active = str(uuid.uuid4())
        conversation(A, 1, cid=active, created_days=400)  # started 400 days ago, used yesterday
        conversation(A, 200, created_days=400)  # started 400 days ago, untouched for 200
        assert sweep().counts["copilot_conversations"] == 1
        with Session(DB.sync) as s:
            assert [r.conversation_id for r in s.query(CopilotConversation).all()] == [active]

    def test_the_window_is_platform_wide_across_tenants(self):
        for t in (A, B, C):
            conversation(t, 120)
        assert sweep().counts["copilot_conversations"] == 3 and count(CopilotConversation) == 0

    def test_the_window_is_the_setting(self):
        conversation(A, 40)
        assert sweep(RETENTION_COPILOT_CONVERSATIONS_DAYS=30).counts["copilot_conversations"] == 1


class TestSuggestions:
    def test_old_ones_go_recent_ones_stay(self):
        suggestion(A, 200)
        suggestion(A, 100)
        assert sweep().counts["detection_suggestions"] == 1 and count(DetectionSuggestion) == 1

    def test_the_window_is_the_setting(self):
        suggestion(A, 20)
        assert sweep(RETENTION_DETECTION_SUGGESTIONS_DAYS=10).counts["detection_suggestions"] == 1


class TestResponseActionsAreHandledWithGreatCare:
    def test_a_finished_old_action_is_swept_and_a_recent_one_is_not(self):
        old, recent = action(A, "completed", 800), action(A, "completed", 100)
        assert sweep().counts["response_actions"] == 1
        assert remaining_actions() == {recent} and old not in remaining_actions()

    @pytest.mark.parametrize("status", TERMINAL_ACTION_STATUSES)
    def test_every_finished_status_is_swept(self, status):
        aid = action(A, status, 800)
        sweep()
        assert aid not in remaining_actions()

    @pytest.mark.parametrize("status", LIVE)
    def test_a_live_action_is_NEVER_deleted_however_old(self, status):
        """A pending/awaiting/approved action is still actionable, and a RUNNING one may have executed without an outcome being recorded."""
        aid = action(A, status, 3000)
        sweep()
        sweep(RETENTION_RESPONSE_ACTIONS_DEFAULT_DAYS=1)
        assert aid in remaining_actions()
        policy(A, 1)
        sweep()
        assert aid in remaining_actions(), "even a 1-day tenant window must not delete a live action"

    def test_the_terminal_set_is_exactly_the_finished_states_of_the_schema(self):
        sql = (Path(__file__).resolve().parent.parent / "migrations" / "055_response_actions.sql").read_text(encoding="utf-8")
        allowed = set(re.findall(r"'([a-z_]+)'", re.search(r"status IN \((.*?)\)", sql, re.S).group(1)))
        assert set(TERMINAL_ACTION_STATUSES) | set(LIVE) == allowed
        assert not set(TERMINAL_ACTION_STATUSES) & set(LIVE)

    def test_each_tenant_has_its_own_window(self):
        a_old, b_same_age, c_long = action(A, "completed", 40), action(B, "completed", 40), action(C, "completed", 40)
        policy(A, 30)  # A keeps 30 days
        policy(C, 3650)  # C keeps ten years
        # B has no policy: the default (730) applies
        sweep()
        assert remaining_actions() == {b_same_age, c_long} and a_old not in remaining_actions()

    def test_one_tenants_short_window_never_touches_another_tenants_rows(self):
        mine, theirs = action(A, "completed", 60), action(B, "completed", 60)
        policy(A, 7)
        policy(B, 365)
        sweep()
        assert theirs in remaining_actions() and mine not in remaining_actions()

    def test_every_delete_names_the_tenant_and_restricts_to_finished_statuses(self):
        """Not RLS, not age alone: the SQL itself is checked."""
        action(A, "completed", 800)
        action(B, "failed", 800)
        action(B, "running", 800)
        sweep()
        deletes = [s for s in DB.statements if s.upper().startswith("DELETE FROM RESPONSE_ACTIONS")]
        assert len(deletes) >= 2  # one per tenant
        for stmt in deletes:
            assert "tenant_id" in stmt and "status IN" in stmt and "updated_at <" in stmt, stmt

    def test_clamping_a_zero_window_means_one_day_not_delete_everything_now(self):
        fresh, two_days = action(A, "completed", 0.5), action(A, "completed", 2)
        policy(A, 0)
        sweep()
        assert fresh in remaining_actions() and two_days not in remaining_actions()

    def test_clamping_a_huge_window_means_ten_years(self):
        recent, ancient = action(A, "completed", 3000), action(A, "completed", 4000)
        policy(A, 10**6)
        sweep()
        assert recent in remaining_actions() and ancient not in remaining_actions()

    def test_the_default_window_applies_when_the_tenant_set_none(self):
        keep, drop = action(A, "completed", 500), action(A, "completed", 900)
        sweep()
        assert remaining_actions() == {keep}
        sweep(RETENTION_RESPONSE_ACTIONS_DEFAULT_DAYS=100)
        assert remaining_actions() == set()


class TestDryRun:
    def test_it_counts_what_would_go_and_deletes_nothing(self):
        conversation(A, 200)
        suggestion(A, 400)
        action(A, "completed", 900)
        result = sweep(dry_run=True)
        assert result.dry_run is True and result.counts == {"copilot_conversations": 1, "detection_suggestions": 1, "response_actions": 1}
        assert count(CopilotConversation) == 1 and count(DetectionSuggestion) == 1 and len(remaining_actions()) == 1
        assert not [s for s in DB.statements if s.upper().startswith("DELETE")]

    def test_the_setting_turns_it_on(self):
        conversation(A, 200)
        assert sweep(RETENTION_DRY_RUN=True).dry_run is True and count(CopilotConversation) == 1

    def test_a_dry_run_count_matches_what_a_real_sweep_then_deletes(self):
        for age in (200, 300, 10):
            conversation(A, age)
        suggestion(A, 500)
        action(A, "failed", 800)
        would = sweep(dry_run=True).counts
        did = sweep(dry_run=False).counts
        assert would == did == {"copilot_conversations": 2, "detection_suggestions": 1, "response_actions": 1}


class TestBatching:
    def test_a_backlog_is_deleted_in_batches(self):
        for _ in range(5):
            conversation(A, 200)
        result = sweep(RETENTION_BATCH_SIZE=2)
        assert result.counts["copilot_conversations"] == 5 and count(CopilotConversation) == 0
        assert len([s for s in DB.statements if s.upper().startswith("DELETE FROM COPILOT_CONVERSATIONS")]) == 3  # 2 + 2 + 1

    def test_a_sweep_is_bounded_and_the_next_one_continues(self):
        for _ in range(5):
            conversation(A, 200)
        first = sweep(RETENTION_BATCH_SIZE=2, RETENTION_MAX_BATCHES_PER_SWEEP=2)
        assert first.counts["copilot_conversations"] == 4 and count(CopilotConversation) == 1
        assert sweep(RETENTION_BATCH_SIZE=2, RETENTION_MAX_BATCHES_PER_SWEEP=2).counts["copilot_conversations"] == 1
        assert count(CopilotConversation) == 0

    def test_a_second_sweep_has_nothing_left_to_do(self):
        conversation(A, 200)
        action(A, "completed", 900)
        sweep()
        assert sweep().counts == {"copilot_conversations": 0, "detection_suggestions": 0, "response_actions": 0}

    def test_progress_is_committed_between_batches(self):
        """A crash part-way through a large backlog keeps what was already deleted."""
        for _ in range(4):
            conversation(A, 200)
        sweep(RETENTION_BATCH_SIZE=2)
        commits = [s for s in DB.statements if s.upper() in ("COMMIT",)]
        assert count(CopilotConversation) == 0 and commits is not None


class TestOneFailureDoesNotStopTheRest:
    def test_a_broken_class_is_reported_and_the_others_still_run(self):
        conversation(A, 200)
        action(A, "completed", 900)
        with DB.sync.begin() as c:
            c.execute(text("DROP TABLE detection_suggestions"))
        result = sweep()
        assert result.errors == {"detection_suggestions": "OperationalError"}
        assert result.counts["copilot_conversations"] == 1 and result.counts["response_actions"] == 1
        assert "detection_suggestions" not in result.counts

    def test_the_failure_is_logged(self, monkeypatch):
        seen = []
        monkeypatch.setattr(rs.logger, "warning", lambda event, **kw: seen.append((event, kw)))
        with DB.sync.begin() as c:
            c.execute(text("DROP TABLE copilot_conversations"))
        sweep()
        assert seen and seen[0][0] == "retention.sweep_failed" and seen[0][1]["data_class"] == "copilot_conversations"


class TestTheLoop:
    def test_the_first_sweep_waits_then_it_sleeps_the_interval_between_sweeps(self, monkeypatch):
        sleeps, sweeps = [], []

        async def fake_sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) >= 3:
                raise asyncio.CancelledError

        async def fake_sweep(factory, *, settings, **kw):
            sweeps.append(1)

        monkeypatch.setattr(rs, "sweep_once", fake_sweep)
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(rs.run_retention_sweeper(sleep=fake_sleep, settings=cfg(RETENTION_INITIAL_DELAY_SECONDS=300, RETENTION_SWEEP_INTERVAL_SECONDS=7200), session_factory=DB.factory))
        assert sleeps == [300, 7200, 7200] and len(sweeps) == 2  # delay, sweep, interval, sweep, interval(cancelled)

    def test_a_failing_sweep_does_not_end_the_loop(self, monkeypatch):
        calls = []

        async def flaky(factory, *, settings, **kw):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("database down")

        async def fake_sleep(seconds):
            if len(calls) >= 2:
                raise asyncio.CancelledError

        monkeypatch.setattr(rs, "sweep_once", flaky)
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(rs.run_retention_sweeper(sleep=fake_sleep, settings=cfg(), session_factory=DB.factory))
        assert len(calls) == 2  # it carried on after the failure

    def test_the_interval_has_a_floor_so_a_misconfiguration_cannot_hammer_the_database(self, monkeypatch):
        sleeps = []

        async def fake_sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) >= 2:
                raise asyncio.CancelledError

        async def noop(factory, *, settings, **kw):
            pass

        monkeypatch.setattr(rs, "sweep_once", noop)
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(rs.run_retention_sweeper(sleep=fake_sleep, settings=cfg(RETENTION_SWEEP_INTERVAL_SECONDS=0), session_factory=DB.factory))
        assert sleeps[1] == 60


class TestConfiguration:
    def test_the_defaults_are_conservative_and_the_sweeper_is_on(self):
        from app.core.config import Settings

        s = Settings()
        assert s.RETENTION_SWEEPER_ENABLED is True and s.RETENTION_DRY_RUN is False
        assert (s.RETENTION_COPILOT_CONVERSATIONS_DAYS, s.RETENTION_DETECTION_SUGGESTIONS_DAYS, s.RETENTION_RESPONSE_ACTIONS_DEFAULT_DAYS) == (90, 180, 730)
        assert s.RETENTION_INITIAL_DELAY_SECONDS >= 60 and s.RETENTION_BATCH_SIZE > 0

    def test_it_is_started_under_the_scheduler_lock_and_stopped_at_shutdown(self):
        src = (Path(__file__).resolve().parent.parent / "app" / "main.py").read_text(encoding="utf-8")
        assert "if settings.RETENTION_SWEEPER_ENABLED:" in src
        assert 'job_name="retention_sweeper"' in src and "worker=run_retention_sweeper" in src
        assert "retention_task.cancel()" in src

    def test_it_never_touches_alerts_or_the_lake(self):
        src = (Path(__file__).resolve().parent.parent / "app" / "workers" / "retention_sweeper.py").read_text(encoding="utf-8")
        assert "alerts" not in re.sub(r'""".*?"""', "", src, flags=re.S).replace("detection_suggestions", "")
        assert rs.CLASSES == ("copilot_conversations", "detection_suggestions", "response_actions")
