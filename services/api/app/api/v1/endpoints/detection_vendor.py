"""GET /detection/vendor-detections: what the connected tools' own detections have raised."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.services.vendor_detections import vendor_detections

router = APIRouter(prefix="/detection", tags=["detection_rules"])


class VendorDetection(BaseModel):
    source: str
    name: str
    count: int
    open: int
    severity: str
    clients: int
    last_seen: str | None = None


class VendorDetectionsResponse(BaseModel):
    window_days: int
    detections: list[VendorDetection]


@router.get("/vendor-detections", response_model=VendorDetectionsResponse)
async def list_vendor_detections(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
) -> VendorDetectionsResponse:
    """Detections the connected tools raised in the last 30 days, grouped by tool and detection name, across this workspace and its clients."""
    from app.services.vendor_detections import WINDOW

    rows = await vendor_detections(db, current_user.tenant_id)
    return VendorDetectionsResponse(window_days=WINDOW.days, detections=[VendorDetection(**r) for r in rows])
