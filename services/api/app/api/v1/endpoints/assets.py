"""Asset inventory and vulnerability management endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.asset import Asset, AssetVulnerability
from app.models.tenant import User
from app.api.v1.deps import require_permission

router = APIRouter(prefix="/assets", tags=["assets"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class AssetCreate(BaseModel):
    asset_type: str = "host"
    name: str
    fqdn: str | None = None
    ip_addresses: list[str] | None = None
    cloud_provider: str | None = None
    cloud_region: str | None = None
    cloud_account: str | None = None
    os: str | None = None
    os_version: str | None = None
    criticality: str = "medium"
    tags: list[str] | None = None
    owner_email: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetUpdate(AssetCreate):
    pass


class AssetOut(AssetCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    last_seen: datetime
    first_seen: datetime
    # The ORM attribute is `asset_metadata` (column "metadata"). A plain `metadata` field would be read from the ORM object's `metadata` attribute, which on a declarative class is the registry's MetaData(), not the column:
    # reading it made POST /assets fail response validation on every call. Read the real attribute; still serialise as `metadata`.
    metadata: dict[str, Any] = Field(default_factory=dict, validation_alias="asset_metadata")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    @field_validator("metadata", mode="before")
    @classmethod
    def _metadata_must_be_a_dict(cls, v: Any) -> Any:
        # A NULL column (legacy rows), or any attribute that is not a dict (e.g. the declarative registry's MetaData when the real column is absent), becomes {} instead of failing the whole response.
        return v if isinstance(v, dict) else {}


class VulnerabilityCreate(BaseModel):
    asset_id: uuid.UUID
    cve_id: str | None = None
    title: str
    description: str | None = None
    severity: str = "medium"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    is_exploited: bool = False
    source: str
    external_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityOut(VulnerabilityCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    first_found: datetime
    last_found: datetime
    remediated_at: datetime | None
    # Same collision as AssetOut: read the real column attribute, not the declarative registry's `metadata`.
    metadata: dict[str, Any] = Field(default_factory=dict, validation_alias="asset_metadata")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    @field_validator("metadata", mode="before")
    @classmethod
    def _metadata_must_be_a_dict(cls, v: Any) -> Any:
        # A NULL column (legacy rows), or any attribute that is not a dict (e.g. the declarative registry's MetaData when the real column is absent), becomes {} instead of failing the whole response.
        return v if isinstance(v, dict) else {}


# ---------------------------------------------------------------------------
# Asset CRUD
# ---------------------------------------------------------------------------


@router.get("", response_model=list[AssetOut], dependencies=[Depends(require_permission("alerts:read"))])
async def list_assets(
    asset_type: str | None = Query(None),
    criticality: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Asset]:
    q = select(Asset).where(Asset.tenant_id == current_user.tenant_id)
    if asset_type:
        q = q.where(Asset.asset_type == asset_type)
    if criticality:
        q = q.where(Asset.criticality == criticality)
    q = q.order_by(Asset.last_seen.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("alerts:write"))])
async def create_asset(
    body: AssetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Asset:
    data = body.model_dump()
    asset = Asset(
        **{k: v for k, v in data.items() if k != "metadata"},
        asset_metadata=data.get("metadata", {}),
        tenant_id=current_user.tenant_id,
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return asset


# Declared BEFORE the /{asset_id} routes: FastAPI matches in declaration order, and GET /{asset_id} would capture 'vulnerabilities' as an id (and answer 422), making this endpoint unreachable.
@router.get("/vulnerabilities", response_model=list[VulnerabilityOut], dependencies=[Depends(require_permission("alerts:read"))])
async def list_vulnerabilities(
    severity: str | None = Query(None),
    is_exploited: bool | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[AssetVulnerability]:
    q = select(AssetVulnerability).where(AssetVulnerability.tenant_id == current_user.tenant_id)
    if severity:
        q = q.where(AssetVulnerability.severity == severity)
    if is_exploited is not None:
        q = q.where(AssetVulnerability.is_exploited == is_exploited)
    q = q.order_by(AssetVulnerability.last_found.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.get("/{asset_id}", response_model=AssetOut, dependencies=[Depends(require_permission("alerts:read"))])
async def get_asset(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Asset:
    asset = await db.get(Asset, asset_id)
    if not asset or asset.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.patch("/{asset_id}", response_model=AssetOut, dependencies=[Depends(require_permission("alerts:write"))])
async def update_asset(
    asset_id: uuid.UUID,
    body: AssetUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Asset:
    asset = await db.get(Asset, asset_id)
    if not asset or asset.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    for k, v in body.model_dump(exclude_none=True).items():
        if k == "metadata":
            asset.asset_metadata = v
        else:
            setattr(asset, k, v)
    await db.commit()
    await db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None, dependencies=[Depends(require_permission("alerts:delete"))])
async def delete_asset(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    asset = await db.get(Asset, asset_id)
    if not asset or asset.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    await db.delete(asset)
    await db.commit()


# ---------------------------------------------------------------------------
# Vulnerability CRUD
# ---------------------------------------------------------------------------


@router.post("/vulnerabilities", response_model=VulnerabilityOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("alerts:write"))])
async def create_vulnerability(
    body: VulnerabilityCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AssetVulnerability:
    # ensure asset belongs to this tenant
    asset = await db.get(Asset, body.asset_id)
    if not asset or asset.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    data = body.model_dump()
    vuln = AssetVulnerability(
        **{k: v for k, v in data.items() if k != "metadata"},
        asset_metadata=data.get("metadata", {}),
        tenant_id=current_user.tenant_id,
    )
    db.add(vuln)
    await db.commit()
    await db.refresh(vuln)
    return vuln


@router.get("/{asset_id}/vulnerabilities", response_model=list[VulnerabilityOut], dependencies=[Depends(require_permission("alerts:read"))])
async def list_asset_vulnerabilities(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[AssetVulnerability]:
    asset = await db.get(Asset, asset_id)
    if not asset or asset.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    q = (
        select(AssetVulnerability)
        .where(AssetVulnerability.asset_id == asset_id)
        .order_by(AssetVulnerability.severity, AssetVulnerability.last_found.desc())
    )
    result = await db.execute(q)
    return list(result.scalars().all())
