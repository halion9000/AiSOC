"""Retention sweeper: delete data that has outlived its window from the tables that would otherwise grow without limit.

What it sweeps, and the rule for each:
  * copilot_conversations  - last updated more than RETENTION_COPILOT_CONVERSATIONS_DAYS ago (platform-wide setting).
  * detection_suggestions  - created more than RETENTION_DETECTION_SUGGESTIONS_DAYS ago (platform-wide setting).
  * response_actions       - ONLY finished ones (completed / failed / rejected / rolled_back), last updated more than the tenant's `audit_days` ago
                             (RETENTION_RESPONSE_ACTIONS_DEFAULT_DAYS if the tenant has set none). Pending, awaiting-approval, approved and RUNNING actions are never deleted, however old.
What it does NOT sweep: alerts and the raw-event lake. Those windows can be configured but nothing enforces them; that is a separate, destructive decision.

Safety:
  * Every per-tenant delete carries an EXPLICIT tenant predicate. Nothing here relies on row-level security for tenant scoping (the services connect as a superuser by default, which bypasses it).
  * Deletes run in small batches (RETENTION_BATCH_SIZE) with a cap on batches per sweep, committing between them, so a first sweep over a large backlog cannot hold a long lock; the next sweep continues.
  * Every window is clamped to 1..3650 days.
  * One class failing does not stop the others, and a failure never kills the loop.
  * RETENTION_DRY_RUN counts and logs without deleting.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import Column, DateTime, MetaData, String, Table, Uuid, delete, func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as default_settings
from app.db.database import AsyncSessionLocal
from app.models.copilot_conversation import CopilotConversation
from app.models.data_lifecycle import RetentionPolicyRow
from app.models.detection_suggestion import DetectionSuggestion
from app.services.retention import TERMINAL_ACTION_STATUSES, clamp_days

logger = structlog.get_logger()

# response_actions is owned by the actions service (its ORM model lives there); this is just the columns the sweeper needs.
_meta = MetaData()
response_actions = Table(
    "response_actions",
    _meta,
    Column("id", Uuid, primary_key=True),
    Column("tenant_id", Uuid, nullable=False),
    Column("status", String, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

CLASSES = ("copilot_conversations", "detection_suggestions", "response_actions")


@dataclass
class SweepResult:
    dry_run: bool
    counts: dict[str, int] = field(default_factory=dict)  # rows deleted (or, in a dry run, that WOULD be deleted)
    errors: dict[str, str] = field(default_factory=dict)  # exception class per failed class


async def _batched_delete(session: AsyncSession, *, count_stmt: Any, ids_stmt: Any, delete_for: Callable[[Any], Any], batch: int, max_batches: int, dry_run: bool) -> int:
    """Count (dry run) or delete in batches. `ids_stmt` selects the keys of matching rows; `delete_for(subquery)` builds the DELETE for them."""
    if dry_run:
        return int((await session.execute(count_stmt)).scalar_one())
    total = 0
    for _ in range(max_batches):
        result = await session.execute(delete_for(ids_stmt.limit(batch)))
        await session.commit()  # between batches: no long-held lock, and progress survives a crash
        deleted = result.rowcount or 0
        total += deleted
        if deleted < batch:
            break
    return total


async def sweep_conversations(session: AsyncSession, *, now: datetime, days: int, batch: int, max_batches: int, dry_run: bool) -> int:
    cutoff = now - timedelta(days=clamp_days(days))
    pk = (CopilotConversation.tenant_id, CopilotConversation.owner_key, CopilotConversation.conversation_id)
    old = CopilotConversation.updated_at < cutoff
    return await _batched_delete(
        session,
        count_stmt=select(func.count()).select_from(CopilotConversation).where(old),
        ids_stmt=select(*pk).where(old),
        delete_for=lambda sub: delete(CopilotConversation).where(tuple_(*pk).in_(sub)),
        batch=batch, max_batches=max_batches, dry_run=dry_run,
    )


async def sweep_suggestions(session: AsyncSession, *, now: datetime, days: int, batch: int, max_batches: int, dry_run: bool) -> int:
    cutoff = now - timedelta(days=clamp_days(days))
    old = DetectionSuggestion.created_at < cutoff
    return await _batched_delete(
        session,
        count_stmt=select(func.count()).select_from(DetectionSuggestion).where(old),
        ids_stmt=select(DetectionSuggestion.id).where(old),
        delete_for=lambda sub: delete(DetectionSuggestion).where(DetectionSuggestion.id.in_(sub)),
        batch=batch, max_batches=max_batches, dry_run=dry_run,
    )


async def sweep_response_actions(session: AsyncSession, *, now: datetime, default_days: int, batch: int, max_batches: int, dry_run: bool) -> int:
    """Per tenant, because each tenant has its own window. Every delete names the tenant AND restricts to finished statuses: never RLS, never age alone."""
    windows = {t: d for t, d in (await session.execute(select(RetentionPolicyRow.tenant_id, RetentionPolicyRow.audit_days))).all()}
    finished = response_actions.c.status.in_(TERMINAL_ACTION_STATUSES)
    tenants = [t for (t,) in (await session.execute(select(response_actions.c.tenant_id).where(finished).distinct())).all()]
    total = 0
    for tenant in tenants:
        # `windows.get(t) or default` would treat a stored 0 as "no policy" and quietly apply the 730-day default instead of clamping it to the 1-day minimum.
        days = windows[tenant] if windows.get(tenant) is not None else default_days
        cutoff = now - timedelta(days=clamp_days(days))
        match = (response_actions.c.tenant_id == tenant) & finished & (response_actions.c.updated_at < cutoff)
        total += await _batched_delete(
            session,
            count_stmt=select(func.count()).select_from(response_actions).where(match),
            ids_stmt=select(response_actions.c.id).where(match),
            delete_for=lambda sub: delete(response_actions).where(response_actions.c.id.in_(sub)),
            batch=batch, max_batches=max_batches, dry_run=dry_run,
        )
    return total


async def sweep_once(session_factory: Callable[[], AsyncSession] = AsyncSessionLocal, *, now: datetime | None = None, settings: Any = default_settings, dry_run: bool | None = None) -> SweepResult:
    """One pass over every class. A class that fails is recorded and the rest still run."""
    now = now or datetime.now(UTC)
    dry = settings.RETENTION_DRY_RUN if dry_run is None else dry_run
    batch = max(1, int(settings.RETENTION_BATCH_SIZE))
    max_batches = max(1, int(settings.RETENTION_MAX_BATCHES_PER_SWEEP))
    result = SweepResult(dry_run=dry)
    jobs = {
        "copilot_conversations": lambda s: sweep_conversations(s, now=now, days=settings.RETENTION_COPILOT_CONVERSATIONS_DAYS, batch=batch, max_batches=max_batches, dry_run=dry),
        "detection_suggestions": lambda s: sweep_suggestions(s, now=now, days=settings.RETENTION_DETECTION_SUGGESTIONS_DAYS, batch=batch, max_batches=max_batches, dry_run=dry),
        "response_actions": lambda s: sweep_response_actions(s, now=now, default_days=settings.RETENTION_RESPONSE_ACTIONS_DEFAULT_DAYS, batch=batch, max_batches=max_batches, dry_run=dry),
    }
    for name, job in jobs.items():
        try:
            async with session_factory() as session:
                result.counts[name] = await job(session)
        except Exception as exc:  # noqa: BLE001
            result.errors[name] = type(exc).__name__
            logger.warning("retention.sweep_failed", data_class=name, error=str(exc), dry_run=dry)
    logger.info("retention.sweep_done", dry_run=dry, counts=result.counts, errors=result.errors)
    return result


async def run_retention_sweeper(*, sleep: Callable[[float], Any] = asyncio.sleep, settings: Any = default_settings, session_factory: Callable[[], AsyncSession] = AsyncSessionLocal) -> None:
    """The long-running loop (started under the scheduler lock from the API lifespan). The first sweep waits RETENTION_INITIAL_DELAY_SECONDS; a failure never ends the loop; cancellation does."""
    await sleep(max(0, settings.RETENTION_INITIAL_DELAY_SECONDS))
    while True:
        try:
            await sweep_once(session_factory, settings=settings)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("retention.sweeper_error", error=str(exc))
        await sleep(max(60, settings.RETENTION_SWEEP_INTERVAL_SECONDS))
