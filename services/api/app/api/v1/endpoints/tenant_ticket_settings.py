"""Which HaloPSA ticket status a resolved incident moves its ticket to: GET / PUT / DELETE /api/v1/tenant-settings/tickets.

When an analyst resolves a security incident from AiSOC, CORE (which holds the HaloPSA credentials) leaves a note on the incident's ticket and moves the ticket to this status. The platform default
is "Tech Update"; an organization may choose another status by name (it must exist in its HaloPSA, which CORE checks when it makes the change). Stored in ``tenants.settings.ticket_close_status``;
setting it merges one key and leaves the rest of the tenant's settings alone.
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

KEY = "ticket_close_status"
DEFAULT_CLOSE_STATUS = "Tech Update"
MAX_LENGTH = 60


class TicketSettings(BaseModel):
    """``close_status`` is the status in force; ``is_default`` says it is the platform's, not this organization's own choice."""

    close_status: str = DEFAULT_CLOSE_STATUS
    is_default: bool = True
    default: str = DEFAULT_CLOSE_STATUS


class SetTicketSettings(BaseModel):
    close_status: str = Field(..., min_length=1, max_length=MAX_LENGTH, description="The exact name of a status in HaloPSA, for example Tech Update or Closed.")


def stored_close_status(settings: object) -> str | None:
    """The organization's own choice from its settings object, or None when absent or not usable text."""
    raw = (settings or {}).get(KEY) if isinstance(settings, dict) else None
    if not isinstance(raw, str):
        return None
    cleaned = " ".join(raw.split())
    return cleaned if 0 < len(cleaned) <= MAX_LENGTH else None


def close_status_of(settings: object) -> str:
    return stored_close_status(settings) or DEFAULT_CLOSE_STATUS


async def _tenant(db: DBSession, tenant_id) -> Tenant:
    tenant = (await db.execute(select(Tenant).where(Tenant.id == tenant_id))).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return tenant


def _view(settings: object) -> TicketSettings:
    own = stored_close_status(settings)
    return TicketSettings(close_status=own or DEFAULT_CLOSE_STATUS, is_default=own is None)


@router.get("/tickets", response_model=TicketSettings, summary="The HaloPSA status a resolved incident moves its ticket to")
async def get_ticket_settings(user: Annotated[AuthUser, Depends(require_permission("settings:read"))], db: DBSession) -> TicketSettings:
    return _view((await _tenant(db, user.tenant_id)).settings)


@router.put("/tickets", response_model=TicketSettings, summary="Choose the HaloPSA status a resolved incident moves its ticket to")
async def set_ticket_settings(body: SetTicketSettings, user: Annotated[AuthUser, Depends(require_permission("settings:write"))], db: DBSession) -> TicketSettings:
    cleaned = " ".join(body.close_status.split())
    if not cleaned:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="The status name is empty.")
    tenant = await _tenant(db, user.tenant_id)
    settings = dict(tenant.settings or {})
    settings[KEY] = cleaned
    tenant.settings = settings
    tenant.updated_at = datetime.now(UTC)
    await db.commit()
    return _view(settings)


@router.delete("/tickets", response_model=TicketSettings, summary="Go back to the default ticket status (Tech Update)")
async def clear_ticket_settings(user: Annotated[AuthUser, Depends(require_permission("settings:write"))], db: DBSession) -> TicketSettings:
    tenant = await _tenant(db, user.tenant_id)
    settings = dict(tenant.settings or {})
    settings.pop(KEY, None)
    tenant.settings = settings
    tenant.updated_at = datetime.now(UTC)
    await db.commit()
    return _view(settings)
