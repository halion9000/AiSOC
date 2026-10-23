"""Hide an alert type: for one device, one client or everyone, for a number of days or without end.

``POST /alert-suppressions`` is made from an alert (the button on the alert page). ``GET`` lists the rules and how many alerts each hides. ``DELETE /{id}`` lifts a rule and puts its alerts back as they were.
Needs ``alerts:write``. Hiding is a view decision about noise; it never closes, deletes or changes an alert's data.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.alert import Alert
from app.models.alert_suppression import AlertSuppression
from app.models.tenant import Tenant
from app.services.alert_scope import alert_scope
from app.services.alert_suppression import (
    MAX_DAYS,
    SUPPRESSED,
    apply_rule,
    expiry_from_days,
    host_keys,
    is_active,
    release_rule,
    signature_of,
    source_of,
)
from app.services.device_identity import hostname_key

router = APIRouter(prefix="/alert-suppressions", tags=["alerts"])


class SuppressionIn(BaseModel):
    alert_id: uuid.UUID
    scope: Literal["device", "client", "all"]
    # Hide for this many days; leave out to hide without end.
    days: int | None = Field(default=None, description=f"1 to {MAX_DAYS} days, or leave out to hide without end")
    # For a device rule on an alert that names several machines: which one. Defaults to the alert's only machine.
    device: str | None = Field(default=None, max_length=255)


class SuppressionOut(BaseModel):
    id: uuid.UUID
    scope: str
    client_id: uuid.UUID | None = None
    client_name: str | None = None
    device: str | None = None
    source: str | None = None
    title: str
    expires_at: datetime | None = None
    indefinite: bool
    created_at: datetime
    active: bool
    hidden_alerts: int = 0


def _out(rule: AlertSuppression, now: datetime, names: dict[uuid.UUID, str], hidden: int) -> SuppressionOut:
    return SuppressionOut(
        id=rule.id,
        scope=rule.scope,
        client_id=rule.client_tenant_id,
        client_name=names.get(rule.client_tenant_id) if rule.client_tenant_id else None,
        device=rule.device_key,
        source=rule.source,
        title=rule.title,
        expires_at=rule.expires_at,
        indefinite=rule.expires_at is None,
        created_at=rule.created_at,
        active=is_active(rule, now),
        hidden_alerts=hidden,
    )


@router.post("", response_model=SuppressionOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("alerts:write"))])
async def hide_alert_type(body: SuppressionIn, user: AuthUser, db: DBSession) -> SuppressionOut:
    """Hide this alert's type for the device, its client, or all clients, and hide the open alerts of that type right away."""
    now = datetime.now(UTC)
    expires = expiry_from_days(body.days, now)
    async with alert_scope(db, user.tenant_id, body.alert_id) as tid:
        alert = (await db.execute(select(Alert).where(Alert.id == body.alert_id, Alert.tenant_id == tid))).scalar_one_or_none()
        if alert is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
        device_key = None
        if body.scope == "device":
            keys = host_keys(alert.affected_hosts)
            wanted = hostname_key(body.device) if body.device else ""
            if wanted:
                if wanted not in keys:
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="That device is not one this alert names")
                device_key = wanted
            elif len(keys) == 1:
                device_key = next(iter(keys))
            else:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="This alert names no device, or several: say which one" if keys else "This alert names no device to hide it for",
                )
        title = alert.title
        signature = signature_of(alert.rule_id, alert.title)
        source = source_of(alert.raw_event, alert.connector_type)
    rule = AlertSuppression(
        tenant_id=user.tenant_id,
        scope=body.scope,
        client_tenant_id=None if body.scope == "all" else tid,
        device_key=device_key,
        source=source,
        signature=signature,
        title=title[:500],
        expires_at=expires,
        created_by=user.user_id,
    )
    db.add(rule)
    await db.flush()
    hidden = await apply_rule(db, rule, user.tenant_id)
    await db.commit()
    names = {r.id: r.name for r in (await db.execute(select(Tenant.id, Tenant.name).where(Tenant.parent_tenant_id == user.tenant_id))).all()}
    return _out(rule, now, names, hidden)


@router.get("", response_model=list[SuppressionOut], dependencies=[Depends(require_permission("alerts:read"))])
async def list_suppressions(user: AuthUser, db: DBSession, include_ended: bool = False) -> list[SuppressionOut]:
    """The active rules (and, with ``include_ended``, those lifted or run out), with how many alerts each hides now."""
    now = datetime.now(UTC)
    q = select(AlertSuppression).where(AlertSuppression.tenant_id == user.tenant_id).order_by(AlertSuppression.created_at.desc()).limit(500)
    if not include_ended:
        q = q.where(AlertSuppression.revoked_at.is_(None))
    rules = list((await db.execute(q)).scalars().all())
    names = {r.id: r.name for r in (await db.execute(select(Tenant.id, Tenant.name).where(Tenant.parent_tenant_id == user.tenant_id))).all()}
    counts: dict[uuid.UUID, int] = {}
    for tid in {r.client_tenant_id or user.tenant_id for r in rules} | {user.tenant_id, *names}:
        try:
            rows = (
                await db.execute(select(Alert.suppression_id, func.count()).where(Alert.tenant_id == tid, Alert.status == SUPPRESSED).group_by(Alert.suppression_id))
            ).all()
        except Exception:  # noqa: BLE001 - a count that cannot be read is shown as zero, not an error
            rows = []
        for sid, n in rows:
            if sid is not None:
                counts[sid] = counts.get(sid, 0) + int(n)
    return [_out(r, now, names, counts.get(r.id, 0)) for r in rules]


@router.delete("/{suppression_id}", response_model=SuppressionOut, dependencies=[Depends(require_permission("alerts:write"))])
async def lift_suppression(suppression_id: uuid.UUID, user: AuthUser, db: DBSession) -> SuppressionOut:
    """Stop hiding this alert type: its hidden alerts come back with the status they had."""
    rule = (await db.execute(select(AlertSuppression).where(AlertSuppression.id == suppression_id, AlertSuppression.tenant_id == user.tenant_id))).scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such rule")
    restored = 0
    if rule.revoked_at is None:
        restored = await release_rule(db, rule, user.tenant_id)
        rule.revoked_at = datetime.now(UTC)
        rule.revoked_reason = "lifted"
        await db.commit()
    names = {r.id: r.name for r in (await db.execute(select(Tenant.id, Tenant.name).where(Tenant.parent_tenant_id == user.tenant_id))).all()}
    return _out(rule, datetime.now(UTC), names, restored)

