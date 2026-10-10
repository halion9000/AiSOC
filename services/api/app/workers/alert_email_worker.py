"""Emails new alerts to PLATFORM administrators (optional, off by default). Runs like the other in-process workers: one copy across replicas (scheduler_lock), switched on by ALERT_EMAIL_WORKER_ENABLED.

WHY IT POLLS. Alerts have two writers: the API's POST /alerts/submit and the fusion service, which writes fused alerts straight into Postgres. A hook in the API would miss the production path, so each cycle asks the database: which alerts are at or above the
severity, newer than the moment the feature was switched on, within the maximum age, and not yet in `alert_email_log`? Whoever wrote them, they are found.

ONE EMAIL PER CYCLE, up to ALERT_EMAIL_MAX_ALERTS_PER_EMAIL alerts, most severe first. An alert storm is therefore at most one message per interval (the rest wait and follow), which protects the mailbox from throttling and the recipients from a flood.

FAILURES ARE ABOUT THE WHOLE MESSAGE (credentials, permissions, throttling, network), so only SENT alerts are recorded. Anything unsent simply stays eligible: fixing a bad credential makes the backlog flow out (within the maximum age, so a long outage cannot dump a day-old pile on anyone). The error is
stored on the setting row where the platform administrator can see it, and the loop backs off while it keeps failing. If the process dies between Graph accepting the message and the log being written, the next cycle repeats it: at-least-once, deliberately (a duplicate email is better than a lost alert).

Alerts are read with a plain core table, not the ORM entity, so the worker needs only the handful of columns it uses.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import Uuid, and_, case, column, delete, exists, func, select, table
from sqlalchemy import DateTime as SADateTime
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.models.alert_email import AlertEmailLog
from app.models.tenant import Tenant
from app.services.alert_email.compose import SEVERITY_ORDER, AlertLine, build_message
from app.services.alert_email.graph import GraphMailer, MailError, scrub
from app.services.alert_email.settings_store import get_settings

logger = logging.getLogger(__name__)

alerts_t = table(
    "alerts",
    column("id", Uuid),
    column("tenant_id", Uuid),
    column("title"),
    column("severity"),
    column("created_at", SADateTime(timezone=True)),
    column("rule_name"),
    column("connector_type"),
)

NOT_CONFIGURED_MESSAGE = "Microsoft Graph credentials are not configured (ALERT_EMAIL_GRAPH_TENANT_ID, _CLIENT_ID, _CLIENT_SECRET and ALERT_EMAIL_SENDER)."
_MAX_BACKOFF_FACTOR = 16


@dataclass
class RunResult:
    sent: int = 0
    pending_after: int = 0
    skipped: str | None = None  # disabled | no_recipients | not_configured | nothing_to_send
    error: str | None = None


def _eligible_severities(minimum: str) -> list[str]:
    floor = SEVERITY_ORDER.get(minimum, SEVERITY_ORDER["high"])
    return [s for s, rank in SEVERITY_ORDER.items() if rank >= floor]


def _aware(moment: datetime | None) -> datetime | None:
    return moment if moment is None or moment.tzinfo is not None else moment.replace(tzinfo=UTC)


async def run_once(*, session_factory: Callable | None = None, mailer: GraphMailer | None = None, now: datetime | None = None) -> RunResult:
    """One cycle. Never raises for an expected problem: it returns what happened (and records a send failure on the setting row)."""
    factory = session_factory or AsyncSessionLocal
    mailer = mailer or GraphMailer.from_settings()
    now = now or datetime.now(UTC)
    async with factory() as db:
        cfg = await get_settings(db)
        await db.execute(delete(AlertEmailLog).where(AlertEmailLog.sent_at < now - timedelta(days=settings.ALERT_EMAIL_LOG_RETENTION_DAYS)))
        if not cfg.enabled:
            await db.commit()
            return RunResult(skipped="disabled")
        recipients = [str(r) for r in (cfg.recipients or [])]
        if not recipients:
            await db.commit()
            return RunResult(skipped="no_recipients")
        if not mailer.configured:
            if cfg.last_error != NOT_CONFIGURED_MESSAGE:
                cfg.last_error, cfg.last_error_at = NOT_CONFIGURED_MESSAGE, now
            await db.commit()
            return RunResult(skipped="not_configured", error=NOT_CONFIGURED_MESSAGE)

        since = max(filter(None, (_aware(cfg.enabled_since), now - timedelta(hours=settings.ALERT_EMAIL_MAX_ALERT_AGE_HOURS))))
        unsent = and_(alerts_t.c.created_at >= since, alerts_t.c.severity.in_(_eligible_severities(cfg.min_severity)), ~exists(select(1).where(AlertEmailLog.alert_id == alerts_t.c.id)))
        rank = case(*[(alerts_t.c.severity == s, r) for s, r in SEVERITY_ORDER.items()], else_=0)
        cap = settings.ALERT_EMAIL_MAX_ALERTS_PER_EMAIL
        rows = (
            await db.execute(
                select(alerts_t.c.id, alerts_t.c.tenant_id, alerts_t.c.title, alerts_t.c.severity, alerts_t.c.created_at, alerts_t.c.rule_name, alerts_t.c.connector_type)
                .where(unsent)
                .order_by(rank.desc(), alerts_t.c.created_at.asc())
                .limit(cap)
            )
        ).all()
        if not rows:
            await db.commit()
            return RunResult(skipped="nothing_to_send")
        total = (await db.execute(select(func.count()).select_from(alerts_t).where(unsent))).scalar_one()
        names = dict((await db.execute(select(Tenant.id, Tenant.name).where(Tenant.id.in_({r.tenant_id for r in rows})))).all())
        lines = [AlertLine(id=r.id, tenant_name=names.get(r.tenant_id, "unknown tenant"), title=r.title, severity=r.severity, rule_name=r.rule_name, connector_type=r.connector_type, created_at=_aware(r.created_at)) for r in rows]
        subject, body = build_message(lines, pending_more=max(0, total - len(rows)), min_severity=cfg.min_severity, console_base_url=settings.CONSOLE_PUBLIC_BASE_URL)

        try:
            await mailer.send(recipients, subject, body)
        except MailError as exc:
            cfg.last_error, cfg.last_error_at = scrub(str(exc), (mailer.client_secret,)), now
            cfg.consecutive_failures = (cfg.consecutive_failures or 0) + 1
            await db.commit()
            logger.warning("alert email send failed", extra={"permanent": exc.permanent, "consecutive_failures": cfg.consecutive_failures})
            return RunResult(error=cfg.last_error, pending_after=total)

        batch = uuid.uuid4()

        def record(settings_row, already_logged: set) -> None:
            for r in rows:
                if r.id not in already_logged:
                    db.add(AlertEmailLog(alert_id=r.id, alert_tenant_id=r.tenant_id, severity=r.severity, title=str(r.title)[:500], batch_id=batch, recipient_count=len(recipients), sent_at=now))
            settings_row.last_sent_at, settings_row.last_error, settings_row.last_error_at, settings_row.consecutive_failures = now, None, None, 0

        record(cfg, set())
        try:
            await db.commit()
        except IntegrityError:
            # Another copy logged some of these alerts while this message was going out. The message DID go out, so record the rest (skipping theirs) rather than leave them unlogged to be emailed again.
            await db.rollback()
            already = set((await db.execute(select(AlertEmailLog.alert_id).where(AlertEmailLog.alert_id.in_([r.id for r in rows])))).scalars())
            record(await get_settings(db), already)
            await db.commit()
            logger.warning("alert email log collided with another copy; the rest was recorded")
        return RunResult(sent=len(rows), pending_after=max(0, total - len(rows)))


async def run_forever(*, session_factory: Callable | None = None, mailer_factory: Callable[[], GraphMailer] | None = None, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:
    """The loop the API starts. A cycle that raised, or that failed to send, makes the next wait longer (up to 16 times the interval) until a cycle succeeds."""
    interval = settings.ALERT_EMAIL_POLL_INTERVAL_SECONDS
    failures = 0
    mailer = (mailer_factory or GraphMailer.from_settings)()
    while True:
        try:
            result = await run_once(session_factory=session_factory, mailer=mailer)
            failures = failures + 1 if result.error else 0
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001  # the loop must outlive a bad cycle
            logger.exception("alert email worker cycle failed")
            failures += 1
        await sleep(interval * min(2**failures, _MAX_BACKOFF_FACTOR))
