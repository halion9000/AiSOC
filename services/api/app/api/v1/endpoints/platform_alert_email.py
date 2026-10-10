"""Platform administrators' settings for emailing new alerts (optional; see app/workers/alert_email_worker.py and docs/security/alert-email.md).

PLATFORM ADMINISTRATORS ONLY. Every route requires `platform:cross_tenant_query` (written out on each route, where a reviewer and the route-authorization scanner can see it), which only the platform_admin role holds (a wildcard does not cover it): the emails carry OTHER tenants' alert titles, so the right to choose who receives them is the right to see all tenants. A tenant's own
administrators get 403, and nothing here is tenant data. The routes use the plain session (no tenant context): the setting belongs to the platform.

The Microsoft credentials are never accepted, stored or returned here: they are environment variables, and this API only reports WHICH are missing (by name). Changing the setting writes an audit event in the same transaction as the change.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.config import settings
from app.models.alert_email import AlertEmailLog
from app.models.tenant import Tenant
from app.services.alert_email.graph import GraphMailer, MailError, scrub
from app.services.alert_email.settings_store import InvalidSettings, get_settings, update_settings
from app.services.audit import emit_audit

router = APIRouter(prefix="/platform/alert-email", tags=["platform"])

Severity = Literal["info", "low", "medium", "high", "critical"]
TEST_EMAIL_MIN_INTERVAL_SECONDS = 10.0
_last_test_at: float | None = None

_CREDENTIAL_VARIABLES = (
    ("ALERT_EMAIL_GRAPH_TENANT_ID", "ALERT_EMAIL_GRAPH_TENANT_ID"),
    ("ALERT_EMAIL_GRAPH_CLIENT_ID", "ALERT_EMAIL_GRAPH_CLIENT_ID"),
    ("ALERT_EMAIL_GRAPH_CLIENT_SECRET", "ALERT_EMAIL_GRAPH_CLIENT_SECRET"),
    ("ALERT_EMAIL_SENDER", "ALERT_EMAIL_SENDER"),
)


class AlertEmailStatus(BaseModel):
    enabled: bool
    min_severity: Severity
    recipients: list[str]
    enabled_since: datetime | None = None
    updated_by: str | None = None
    updated_at: datetime | None = None
    last_sent_at: datetime | None = None
    last_error: str | None = None
    last_error_at: datetime | None = None
    consecutive_failures: int = 0
    worker_enabled: bool  # ALERT_EMAIL_WORKER_ENABLED: the process-level switch
    credentials_configured: bool
    missing_credentials: list[str]  # environment variable NAMES only, never values
    sender: str | None = None
    warnings: list[str] = Field(default_factory=list)


class AlertEmailUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    min_severity: Severity | None = None
    recipients: list[str] | None = Field(default=None, max_length=50)

    @model_validator(mode="after")
    def _something_to_change(self) -> AlertEmailUpdate:
        if self.enabled is None and self.min_severity is None and self.recipients is None:
            raise ValueError("send at least one of: enabled, min_severity, recipients")
        return self


class TestEmailResult(BaseModel):
    sent_to: list[str]


class SentAlert(BaseModel):
    alert_id: str
    tenant_id: str
    tenant_name: str | None
    severity: str
    title: str
    sent_at: datetime
    batch_id: str
    recipient_count: int


def _mailer() -> GraphMailer:
    return GraphMailer.from_settings()


def missing_credentials() -> list[str]:
    return [name for name, attr in _CREDENTIAL_VARIABLES if not getattr(settings, attr)]


def _status(row) -> AlertEmailStatus:
    missing = missing_credentials()
    warnings: list[str] = []
    if row.enabled and not settings.ALERT_EMAIL_WORKER_ENABLED:
        warnings.append("Alert email is on, but the background worker is switched off in this deployment (ALERT_EMAIL_WORKER_ENABLED), so nothing will be sent.")
    if row.enabled and missing:
        warnings.append("Alert email is on, but these environment variables are not set: " + ", ".join(missing) + ".")
    return AlertEmailStatus(
        enabled=row.enabled,
        min_severity=row.min_severity,
        recipients=[str(r) for r in (row.recipients or [])],
        enabled_since=row.enabled_since,
        updated_by=row.updated_by_label,
        updated_at=row.updated_at,
        last_sent_at=row.last_sent_at,
        last_error=row.last_error,
        last_error_at=row.last_error_at,
        consecutive_failures=row.consecutive_failures or 0,
        worker_enabled=bool(settings.ALERT_EMAIL_WORKER_ENABLED),
        credentials_configured=not missing,
        missing_credentials=missing,
        sender=settings.ALERT_EMAIL_SENDER or None,
        warnings=warnings,
    )


@router.get("", response_model=AlertEmailStatus)
async def get_alert_email(current_user: Annotated[AuthUser, Depends(require_permission("platform:cross_tenant_query"))], db: DBSession) -> AlertEmailStatus:
    """The setting, whether the deployment can actually send (which environment variables are missing, by name), and the last error."""
    return _status(await get_settings(db))


@router.put("", response_model=AlertEmailStatus)
async def update_alert_email(body: AlertEmailUpdate, current_user: Annotated[AuthUser, Depends(require_permission("platform:cross_tenant_query"))], db: DBSession) -> AlertEmailStatus:
    """Change who receives alert emails, from which severity, and whether it is on. Switching on needs a recipient and starts the clock: only alerts created afterwards are emailed. Audited in the same transaction."""
    before = await get_settings(db)
    was = {"enabled": before.enabled, "min_severity": before.min_severity, "recipients": list(before.recipients or [])}
    try:
        row = await update_settings(db, updated_by=current_user.email or str(current_user.user_id), enabled=body.enabled, min_severity=body.min_severity, recipients=body.recipients, commit=False)
    except InvalidSettings as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from None
    now = {"enabled": row.enabled, "min_severity": row.min_severity, "recipients": list(row.recipients or [])}
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="platform:alert_email_updated",
        resource="platform_alert_email",
        resource_id="settings",
        changes={"before": was, "after": now, "changed": sorted(k for k in now if now[k] != was[k])},
    )
    await db.commit()
    return _status(row)


@router.post("/test", response_model=TestEmailResult)
async def send_test_email(current_user: Annotated[AuthUser, Depends(require_permission("platform:cross_tenant_query"))], db: DBSession) -> TestEmailResult:
    """Send one test message to the configured recipients, now, through the real sender: the way to find out that the Microsoft setup works before an alert depends on it. At most one every 10 seconds."""
    global _last_test_at
    cfg = await get_settings(db)
    recipients = [str(r) for r in (cfg.recipients or [])]
    if not recipients:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Add at least one recipient first.")
    mailer = _mailer()
    if not mailer.configured:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="These environment variables are not set: " + ", ".join(missing_credentials()) + ".")
    clock = time.monotonic()
    if _last_test_at is not None and clock - _last_test_at < TEST_EMAIL_MIN_INTERVAL_SECONDS:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="A test email was just sent; wait a few seconds.", headers={"Retry-After": str(int(TEST_EMAIL_MIN_INTERVAL_SECONDS))})
    _last_test_at = clock
    who = (current_user.email or str(current_user.user_id)).replace("\r", " ").replace("\n", " ")[:120]
    try:
        await mailer.send(
            recipients,
            "[AiSOC] Test email: alert email is working",
            f"This is a test of AiSOC's alert email, requested by {who} at {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}.\n\nIf you can read this, the Microsoft Graph setup works. No action is needed.\n",
        )
    except MailError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=scrub(str(exc), (mailer.client_secret,))) from None
    await emit_audit(db=db, tenant_id=current_user.tenant_id, actor_id=current_user.user_id, actor_email=current_user.email, action="platform:alert_email_test_sent", resource="platform_alert_email", resource_id="settings", changes={"recipient_count": len(recipients)})
    await db.commit()
    return TestEmailResult(sent_to=recipients)


@router.get("/log", response_model=list[SentAlert])
async def recent_alert_emails(current_user: Annotated[AuthUser, Depends(require_permission("platform:cross_tenant_query"))], db: DBSession, limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[SentAlert]:
    """The alerts that have been emailed, newest first, with their tenant."""
    rows = (await db.execute(select(AlertEmailLog).order_by(AlertEmailLog.sent_at.desc()).limit(limit))).scalars().all()
    names = dict((await db.execute(select(Tenant.id, Tenant.name).where(Tenant.id.in_({r.alert_tenant_id for r in rows})))).all()) if rows else {}
    return [
        SentAlert(alert_id=str(r.alert_id), tenant_id=str(r.alert_tenant_id), tenant_name=names.get(r.alert_tenant_id), severity=r.severity, title=r.title, sent_at=r.sent_at, batch_id=str(r.batch_id), recipient_count=r.recipient_count)
        for r in rows
    ]
