"""Hiding an alert type.

An alert type is "the same rule from the same tool": ``rule:<rule id>`` when the alert carries a rule id, otherwise ``title:<title>``, together with the tool that raised it (CORE puts it in
``raw_event.source``). A rule hides that type for one DEVICE of one client, for one CLIENT, or for ALL clients, until a date or without end.

A hidden alert is not deleted. Its status becomes ``suppressed`` (a finished status, so it falls out of every open count and list) and the status it had is kept, so lifting the rule, or the
rule running out, puts it back exactly as it was. The pure parts (signature, matching, dates) are separate from the database work so they can be tested without one.
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import and_, func, or_, select, update

from app.db.rls_scope import acting_as_tenant
from app.models.alert import Alert
from app.models.alert_suppression import AlertSuppression
from app.models.tenant import Tenant
from app.services.device_identity import hostname_key

SUPPRESSED = "suppressed"
SCOPES = ("device", "client", "all")
MAX_DAYS = 3650
_FINISHED = ("resolved", "closed", "false_positive", "fp", SUPPRESSED)
_CHUNK = 500


def signature_of(rule_id: str | None, title: str | None) -> str:
    """The alert type: its rule id when it has one, else its exact title."""
    rid = (rule_id or "").strip()
    return f"rule:{rid}" if rid else f"title:{(title or '').strip()}"


def source_of(raw_event: Any, connector_type: str | None = None) -> str | None:
    """The tool that raised the alert, as CORE names it, else the connector type; None when neither is known."""
    src = raw_event.get("source") if isinstance(raw_event, dict) else None
    text = str(src or connector_type or "").strip().lower()
    return text[:100] or None


def host_keys(hosts: Any) -> set[str]:
    return {k for k in (hostname_key(h) for h in (hosts if isinstance(hosts, list) else [])) if k}


def expiry_from_days(days: int | None, now: datetime) -> datetime | None:
    """When a rule made now for ``days`` days runs out. ``None`` days means without end. 1 to 3650 days; anything else is refused."""
    if days is None:
        return None
    if isinstance(days, bool) or not isinstance(days, int) or days < 1 or days > MAX_DAYS:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"days must be a whole number from 1 to {MAX_DAYS}, or leave it out to hide without end")
    return now + timedelta(days=days)


def is_active(rule: Any, now: datetime) -> bool:
    """A rule hides alerts while it is not lifted and has not run out."""
    if rule.revoked_at is not None:
        return False
    return rule.expires_at is None or rule.expires_at > now


def matches(rule: Any, *, tenant_id: uuid.UUID, rule_id: str | None, title: str | None, source: str | None, hosts: Any) -> bool:
    """Whether an alert (given by its tenant, rule id, title, tool and machine names) is of the type the rule hides, in the place the rule covers. The rule's own timing is checked by ``is_active``."""
    if signature_of(rule_id, title) != rule.signature or (rule.source or None) != (source or None):
        return False
    if rule.scope == "all":
        return True
    if rule.client_tenant_id != tenant_id:
        return False
    if rule.scope == "client":
        return True
    return bool(rule.device_key) and rule.device_key in host_keys(hosts)


async def _tenants_of(db: Any, rule: Any) -> list[uuid.UUID]:
    """The tenants whose alerts a rule can cover: the one client for a device or client rule, else the owner and all its clients."""
    if rule.scope in ("device", "client") and rule.client_tenant_id is not None:
        return [rule.client_tenant_id]
    kids = [r[0] for r in (await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == rule.tenant_id))).all()]
    return [rule.tenant_id, *kids]


def _type_filter(rule: Any) -> Any:
    kind, _, value = rule.signature.partition(":")
    return Alert.rule_id == value if kind == "rule" else and_(or_(Alert.rule_id.is_(None), Alert.rule_id == ""), Alert.title == value)


async def apply_rule(db: Any, rule: Any, owner_tenant: uuid.UUID) -> int:
    """Hide every open alert the rule covers that is not hidden yet. Returns how many were hidden. Safe to run again: only alerts not already hidden change."""
    hidden = 0
    for tid in await _tenants_of(db, rule):
        ctx = _acting(db, tid, owner_tenant)
        async with ctx:
            rows = (
                await db.execute(
                    select(Alert.id, Alert.status, Alert.raw_event, Alert.connector_type, Alert.affected_hosts, Alert.rule_id, Alert.title).where(
                        Alert.tenant_id == tid, Alert.status.notin_(_FINISHED), _type_filter(rule)
                    )
                )
            ).all()
            ids = [
                r.id
                for r in rows
                if matches(rule, tenant_id=tid, rule_id=r.rule_id, title=r.title, source=source_of(r.raw_event, r.connector_type), hosts=r.affected_hosts)
            ]
            for i in range(0, len(ids), _CHUNK):
                chunk = ids[i : i + _CHUNK]
                await db.execute(
                    update(Alert)
                    .where(Alert.id.in_(chunk), Alert.tenant_id == tid)
                    .values(status_before_suppression=Alert.status, status=SUPPRESSED, suppression_id=rule.id, updated_at=datetime.now(UTC))
                )
            hidden += len(ids)
    return hidden


async def release_rule(db: Any, rule: Any, owner_tenant: uuid.UUID) -> int:
    """Put back the alerts a rule hid, as they were. Returns how many."""
    restored = 0
    for tid in await _tenants_of(db, rule):
        async with _acting(db, tid, owner_tenant):
            result = await db.execute(
                update(Alert)
                .where(Alert.tenant_id == tid, Alert.suppression_id == rule.id)
                .values(status=func.coalesce(Alert.status_before_suppression, "new"), status_before_suppression=None, suppression_id=None, updated_at=datetime.now(UTC))
            )
            restored += result.rowcount or 0
    return restored


def _acting(db: Any, tid: uuid.UUID, owner_tenant: uuid.UUID) -> Any:
    return contextlib.nullcontext() if tid == owner_tenant else acting_as_tenant(db, tid)


async def sweep(db: Any, now: datetime | None = None) -> dict[str, int]:
    """One pass over every rule: lift the ones that have run out (their alerts come back), and hide any new alert an active rule covers. Run by the background worker; also safe to call from a request."""
    now = now or datetime.now(UTC)
    out = {"expired": 0, "hidden": 0, "restored": 0}
    rules = (await db.execute(select(AlertSuppression).where(AlertSuppression.revoked_at.is_(None)))).scalars().all()
    for rule in rules:
        if not is_active(rule, now):
            out["restored"] += await release_rule(db, rule, rule.tenant_id)
            rule.revoked_at = rule.expires_at or now
            rule.revoked_reason = "expired"
            out["expired"] += 1
        else:
            out["hidden"] += await apply_rule(db, rule, rule.tenant_id)
    await db.commit()
    return out
