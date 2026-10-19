"""A tenant's own auto-close confidence for AI triage: GET / PUT / DELETE /api/v1/tenant-settings/auto-close.

Triage closes an alert on its own when the verdict is benign or a false positive and the confidence is at or above a threshold. The platform has one value
(AISOC_AUTO_CLOSE_THRESHOLD, default 0.85); a tenant may raise or lower its own, between 0.5 and 1.0. The value is stored in ``tenants.settings.auto_close_threshold`` and the agents
service reads it when it triages that tenant's alerts (cached for a minute). Setting it merges one key: the rest of the tenant's settings are left alone (the generic
PATCH /tenants/me/settings replaces the whole object).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.tenant import Tenant

router = APIRouter(prefix="/tenant-settings", tags=["tenant-settings"])

KEY = "auto_close_threshold"
MIN_THRESHOLD = 0.5
MAX_THRESHOLD = 1.0


class AutoCloseSetting(BaseModel):
    """``threshold`` is this tenant's own value, or None when it follows the platform value."""

    threshold: float | None = None
    minimum: float = MIN_THRESHOLD
    maximum: float = MAX_THRESHOLD


class SetAutoClose(BaseModel):
    threshold: float = Field(
        ...,
        ge=MIN_THRESHOLD,
        le=MAX_THRESHOLD,
        description="Confidence from 0.5 to 1.0 at or above which benign and false-positive verdicts close on their own.",
    )


def stored_threshold(settings: object) -> float | None:
    """The tenant's own value from its settings object, or None when absent or not a usable number."""
    raw = (settings or {}).get(KEY) if isinstance(settings, dict) else None
    if raw is None or isinstance(raw, bool):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if MIN_THRESHOLD <= value <= MAX_THRESHOLD else None


async def _tenant(db: DBSession, tenant_id) -> Tenant:
    tenant = (await db.execute(select(Tenant).where(Tenant.id == tenant_id))).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return tenant


@router.get("/auto-close", response_model=AutoCloseSetting, summary="This tenant's own auto-close confidence (None = the platform value)")
async def get_auto_close(user: Annotated[AuthUser, Depends(require_permission("settings:read"))], db: DBSession) -> AutoCloseSetting:
    return AutoCloseSetting(threshold=stored_threshold((await _tenant(db, user.tenant_id)).settings))


@router.put("/auto-close", response_model=AutoCloseSetting, summary="Set this tenant's own auto-close confidence")
async def set_auto_close(
    body: SetAutoClose, user: Annotated[AuthUser, Depends(require_permission("settings:write"))], db: DBSession
) -> AutoCloseSetting:
    tenant = await _tenant(db, user.tenant_id)
    settings = dict(tenant.settings or {})
    settings[KEY] = round(body.threshold, 4)
    tenant.settings = settings
    tenant.updated_at = datetime.now(UTC)
    await db.commit()
    return AutoCloseSetting(threshold=settings[KEY])


@router.delete("/auto-close", response_model=AutoCloseSetting, summary="Go back to the platform's auto-close confidence")
async def clear_auto_close(user: Annotated[AuthUser, Depends(require_permission("settings:write"))], db: DBSession) -> AutoCloseSetting:
    tenant = await _tenant(db, user.tenant_id)
    settings = dict(tenant.settings or {})
    settings.pop(KEY, None)
    tenant.settings = settings
    tenant.updated_at = datetime.now(UTC)
    await db.commit()
    return AutoCloseSetting(threshold=None)
