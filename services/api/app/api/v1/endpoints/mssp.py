"""MSSP parent-tenant console endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.core.security import ROLE_PERMISSIONS
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.mssp import MSSPDelegation, MSSPTenantMetrics, MSSPTenantNote
from app.models.tenant import Tenant, User
from app.api.v1.deps import require_permission

router = APIRouter(prefix="/mssp", tags=["mssp"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ChildTenantOut(BaseModel):
    id: uuid.UUID
    name: str
    mssp_role: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class TenantNoteCreate(BaseModel):
    child_id: uuid.UUID
    body: str


class TenantNoteOut(TenantNoteCreate):
    id: uuid.UUID
    parent_id: uuid.UUID
    author_id: uuid.UUID | None
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class DelegationCreate(BaseModel):
    child_tenant_id: uuid.UUID
    granted_role: str = "soc_analyst"
    expires_at: datetime | None = None


class DelegationOut(DelegationCreate):
    id: uuid.UUID
    parent_tenant_id: uuid.UUID
    granted_by_user: uuid.UUID | None
    revoked_at: datetime | None
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class MetricsOut(BaseModel):
    tenant_id: uuid.UUID
    snapshot_at: str
    open_alerts: int
    critical_alerts: int
    open_cases: int
    mttr_minutes: float | None
    sla_breaches: int
    connector_count: int
    health_score: float | None

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Child-tenant management
# ---------------------------------------------------------------------------


@router.get("/children", response_model=list[ChildTenantOut], dependencies=[Depends(require_permission("mssp:read"))])
async def list_child_tenants(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Tenant]:
    """Return all child tenants of the current parent tenant."""
    result = await db.execute(select(Tenant).where(Tenant.parent_tenant_id == current_user.tenant_id))
    return list(result.scalars().all())


@router.post("/children/{child_id}/onboard", status_code=status.HTTP_200_OK, dependencies=[Depends(require_permission("mssp:onboard"))])
async def onboard_child_tenant(
    child_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Link an existing tenant as a child of the current MSSP tenant."""
    child = await db.get(Tenant, child_id)
    if not child:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if child.parent_tenant_id and child.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=409, detail="Tenant already has a parent")
    child.parent_tenant_id = current_user.tenant_id  # type: ignore[assignment]
    child.mssp_role = "child"  # type: ignore[assignment]
    parent = await db.get(Tenant, current_user.tenant_id)
    if parent:
        parent.mssp_role = "parent"  # type: ignore[assignment]
    await db.commit()
    return {"status": "ok", "child_id": str(child_id)}


# ---------------------------------------------------------------------------
# Cross-tenant notes
# ---------------------------------------------------------------------------


@router.get("/notes", response_model=list[TenantNoteOut], dependencies=[Depends(require_permission("mssp:read"))])
async def list_notes(
    child_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPTenantNote]:
    q = select(MSSPTenantNote).where(MSSPTenantNote.parent_id == current_user.tenant_id)
    if child_id:
        q = q.where(MSSPTenantNote.child_id == child_id)
    q = q.order_by(MSSPTenantNote.created_at.desc())
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/notes", response_model=TenantNoteOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("mssp:manage"))])
async def create_note(
    body: TenantNoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPTenantNote:
    await _require_owned_child(db, current_user, body.child_id)
    note = MSSPTenantNote(
        parent_id=current_user.tenant_id,
        child_id=body.child_id,
        body=body.body,
        author_id=current_user.id,
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return note


# ---------------------------------------------------------------------------
# Cross-tenant delegations
# ---------------------------------------------------------------------------


@router.get("/delegations", response_model=list[DelegationOut], dependencies=[Depends(require_permission("mssp:read"))])
async def list_delegations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPDelegation]:
    result = await db.execute(
        select(MSSPDelegation)
        .where(
            MSSPDelegation.parent_tenant_id == current_user.tenant_id,
            MSSPDelegation.revoked_at.is_(None),
        )
        .order_by(MSSPDelegation.created_at.desc())
    )
    return list(result.scalars().all())


@router.post("/delegations", response_model=DelegationOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("mssp:manage"))])
async def create_delegation(
    body: DelegationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPDelegation:
    await _require_owned_child(db, current_user, body.child_tenant_id)
    if body.granted_role not in _DELEGABLE_ROLES:
        raise HTTPException(status_code=422, detail=f"granted_role must be one of {sorted(_DELEGABLE_ROLES)}")
    delegation = MSSPDelegation(
        parent_tenant_id=current_user.tenant_id,
        child_tenant_id=body.child_tenant_id,
        granted_role=body.granted_role,
        granted_by_user=current_user.id,
        expires_at=body.expires_at,
    )
    db.add(delegation)
    await db.commit()
    await db.refresh(delegation)
    return delegation


@router.delete("/delegations/{delegation_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None, dependencies=[Depends(require_permission("mssp:manage"))])
async def revoke_delegation(
    delegation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    delegation = await db.get(MSSPDelegation, delegation_id)
    if not delegation or delegation.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Delegation not found")
    delegation.revoked_at = datetime.now(UTC)  # type: ignore[assignment]
    await db.commit()


# ---------------------------------------------------------------------------
# Tenant rollup metrics
# ---------------------------------------------------------------------------


@router.get("/metrics", response_model=list[MetricsOut], dependencies=[Depends(require_permission("mssp:read"))])
async def list_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPTenantMetrics]:
    """Return the latest metrics snapshot for every child tenant."""
    # Get child tenant ids
    children_result = await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == current_user.tenant_id))
    child_ids = list(children_result.scalars().all())
    if not child_ids:
        return []

    # Subquery: most recent snapshot per tenant
    subq = (
        select(
            MSSPTenantMetrics.tenant_id,
            MSSPTenantMetrics.snapshot_at,
        )
        .where(MSSPTenantMetrics.tenant_id.in_(child_ids))
        .order_by(MSSPTenantMetrics.tenant_id, MSSPTenantMetrics.snapshot_at.desc())
        .distinct(MSSPTenantMetrics.tenant_id)
        .subquery()
    )

    result = await db.execute(
        select(MSSPTenantMetrics).join(
            subq,
            (MSSPTenantMetrics.tenant_id == subq.c.tenant_id) & (MSSPTenantMetrics.snapshot_at == subq.c.snapshot_at),
        )
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# MSSP Rule Pack management (parent-only)
# ---------------------------------------------------------------------------

from app.models.detection_rule import DetectionRule  # noqa: E402
from app.models.mssp import (  # noqa: E402
    MSSPRuleOverride,
    MSSPRulePack,
    MSSPRulePackAssignment,
    MSSPRulePackRule,
)
from app.services.mssp_rule_resolver import count_effective_rules, resolve_effective_rules  # noqa: E402


class RulePackCreate(BaseModel):
    name: str
    description: str | None = None
    category: str | None = None
    is_default: bool = False


class RulePackUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    category: str | None = None
    is_default: bool | None = None


class RulePackOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    category: str | None
    is_default: bool
    created_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=True)


class RulePackRuleAdd(BaseModel):
    rule_id: uuid.UUID


class PackAssignmentCreate(BaseModel):
    child_tenant_id: uuid.UUID
    enabled: bool = True
    parameter_overrides: dict = {}


class PackAssignmentOut(BaseModel):
    id: uuid.UUID
    pack_id: uuid.UUID
    child_tenant_id: uuid.UUID
    enabled: bool
    parameter_overrides: dict
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class RuleOverrideCreate(BaseModel):
    child_tenant_id: uuid.UUID
    rule_id: uuid.UUID
    action: str  # "exclude" | "customize"
    note: str | None = None
    severity_override: str | None = None
    parameter_overrides: dict = {}


class RuleOverrideOut(BaseModel):
    id: uuid.UUID
    parent_tenant_id: uuid.UUID
    child_tenant_id: uuid.UUID
    rule_id: uuid.UUID
    action: str
    note: str | None
    severity_override: str | None
    parameter_overrides: dict
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class EffectiveRuleOut(BaseModel):
    id: uuid.UUID
    name: str
    rule_language: str
    severity: str
    category: str | None
    status: str
    is_builtin: bool
    source: str
    pack_ids: list[uuid.UUID]
    severity_overridden: bool
    original_severity: str | None
    override_note: str | None
    parameter_overrides: dict

    model_config = ConfigDict(from_attributes=True)


class EffectiveRuleCountOut(BaseModel):
    total: int
    tenant: int
    builtin: int
    pack: int
    excluded: int


async def _require_owned_child(db: AsyncSession, current_user: User, child_id: uuid.UUID) -> None:
    """404 unless `child_id` really is a child of the caller's tenant.

    Writes used to accept any tenant id in the body. A rule override naming someone
    else's tenant disabled that tenant's detections (the resolver now also ignores
    such rows; this stops them being written).
    """
    child = await db.get(Tenant, child_id)
    if not child or child.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Child tenant not found")


_DELEGABLE_ROLES = frozenset(r for r, perms in ROLE_PERMISSIONS.items() if "*" not in perms)


def _ensure_mssp_parent(current_user: User) -> None:
    """Lightweight guard — a parent tenant is one that has (or can have) children."""
    pass


@router.get("/rule-packs", response_model=list[RulePackOut], dependencies=[Depends(require_permission("mssp:read"))])
async def list_rule_packs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPRulePack]:
    """List all rule packs owned by the current parent tenant."""
    _ensure_mssp_parent(current_user)
    result = await db.execute(
        select(MSSPRulePack).where(MSSPRulePack.parent_tenant_id == current_user.tenant_id).order_by(MSSPRulePack.created_at.desc())
    )
    return list(result.scalars().all())


@router.post("/rule-packs", response_model=RulePackOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("mssp:manage"))])
async def create_rule_pack(
    body: RulePackCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPRulePack:
    """Create a new rule pack (parent tenant only)."""
    _ensure_mssp_parent(current_user)
    pack = MSSPRulePack(
        parent_tenant_id=current_user.tenant_id,
        name=body.name,
        description=body.description,
        category=body.category,
        is_default=body.is_default,
        created_by_user=current_user.id,
    )
    db.add(pack)
    await db.commit()
    await db.refresh(pack)
    return pack


@router.get("/rule-packs/{pack_id}", response_model=RulePackOut, dependencies=[Depends(require_permission("mssp:read"))])
async def get_rule_pack(
    pack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPRulePack:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")
    return pack


@router.put("/rule-packs/{pack_id}", response_model=RulePackOut, dependencies=[Depends(require_permission("mssp:manage"))])
async def update_rule_pack(
    pack_id: uuid.UUID,
    body: RulePackUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPRulePack:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")
    if body.name is not None:
        pack.name = body.name
    if body.description is not None:
        pack.description = body.description
    if body.category is not None:
        pack.category = body.category
    if body.is_default is not None:
        pack.is_default = body.is_default
    await db.commit()
    await db.refresh(pack)
    return pack


@router.delete("/rule-packs/{pack_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None, dependencies=[Depends(require_permission("mssp:manage"))])
async def delete_rule_pack(
    pack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")
    await db.delete(pack)
    await db.commit()


@router.post("/rule-packs/{pack_id}/rules", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("mssp:manage"))])
async def add_rule_to_pack(
    pack_id: uuid.UUID,
    body: RulePackRuleAdd,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")

    rule = await db.get(DetectionRule, body.rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")

    link = MSSPRulePackRule(pack_id=pack_id, rule_id=body.rule_id)
    db.add(link)
    await db.commit()
    return {"status": "ok", "pack_id": str(pack_id), "rule_id": str(body.rule_id)}


@router.delete("/rule-packs/{pack_id}/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None, dependencies=[Depends(require_permission("mssp:manage"))])
async def remove_rule_from_pack(
    pack_id: uuid.UUID,
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")
    link = await db.get(MSSPRulePackRule, (pack_id, rule_id))
    if link:
        await db.delete(link)
        await db.commit()


@router.post("/rule-packs/{pack_id}/assign", response_model=PackAssignmentOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("mssp:manage"))])
async def assign_pack_to_child(
    pack_id: uuid.UUID,
    body: PackAssignmentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPRulePackAssignment:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")

    assignment = MSSPRulePackAssignment(
        pack_id=pack_id,
        child_tenant_id=body.child_tenant_id,
        enabled=body.enabled,
        parameter_overrides=body.parameter_overrides,
    )
    db.add(assignment)
    await db.commit()
    await db.refresh(assignment)
    return assignment


@router.post("/overrides", response_model=RuleOverrideOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("mssp:manage"))])
async def create_rule_override(
    body: RuleOverrideCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPRuleOverride:
    _ensure_mssp_parent(current_user)
    if body.action not in ("exclude", "customize"):
        raise HTTPException(status_code=422, detail="action must be 'exclude' or 'customize'")
    await _require_owned_child(db, current_user, body.child_tenant_id)
    override = MSSPRuleOverride(
        parent_tenant_id=current_user.tenant_id,
        child_tenant_id=body.child_tenant_id,
        rule_id=body.rule_id,
        action=body.action,
        note=body.note,
        severity_override=body.severity_override,
        parameter_overrides=body.parameter_overrides,
        created_by_user=current_user.id,
    )
    db.add(override)
    await db.commit()
    await db.refresh(override)
    return override


@router.get("/overrides", response_model=list[RuleOverrideOut], dependencies=[Depends(require_permission("mssp:read"))])
async def list_overrides(
    child_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPRuleOverride]:
    q = select(MSSPRuleOverride).where(
        MSSPRuleOverride.child_tenant_id.in_(select(Tenant.id).where(Tenant.parent_tenant_id == current_user.tenant_id))
    )
    if child_id:
        q = q.where(MSSPRuleOverride.child_tenant_id == child_id)
    result = await db.execute(q.order_by(MSSPRuleOverride.created_at.desc()))
    return list(result.scalars().all())


@router.delete("/overrides/{override_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None, dependencies=[Depends(require_permission("mssp:manage"))])
async def delete_override(
    override_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    override = await db.get(MSSPRuleOverride, override_id)
    if not override:
        raise HTTPException(status_code=404, detail="Override not found")
    child = await db.get(Tenant, override.child_tenant_id)
    if not child or child.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Override not found")
    await db.delete(override)
    await db.commit()


# ---------------------------------------------------------------------------
# Effective rules preview (parent views what a child tenant gets)
# ---------------------------------------------------------------------------


@router.get("/children/{child_id}/effective-rules", response_model=list[EffectiveRuleOut], dependencies=[Depends(require_permission("mssp:read"))])
async def list_effective_rules_for_child(
    child_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    category: str | None = Query(None),
    rule_language: str | None = Query(None),
) -> list[EffectiveRuleOut]:
    """Preview the resolved rule set for a child tenant (parent-only)."""
    child = await db.get(Tenant, child_id)
    if not child or child.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Child tenant not found")

    resolved = await resolve_effective_rules(
        db,
        child_id,
        include_builtin=True,
        include_packs=True,
        rule_language=rule_language,
        category=category,
        only_active=False,
    )

    return [
        EffectiveRuleOut(
            id=r.id,
            name=r.name,
            rule_language=r.rule_language,
            severity=r.severity,
            category=r.category,
            status=r.status,
            is_builtin=r.is_builtin,
            source=r.source,
            pack_ids=r.pack_ids,
            severity_overridden=r.severity_overridden,
            original_severity=r.original_severity,
            override_note=r.override_note,
            parameter_overrides=r.parameter_overrides,
        )
        for r in resolved
    ]


@router.get("/children/{child_id}/effective-rules/count", response_model=EffectiveRuleCountOut, dependencies=[Depends(require_permission("mssp:read"))])
async def count_effective_rules_for_child(
    child_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EffectiveRuleCountOut:
    """Return source-breakdown counts for a child tenant's effective ruleset."""
    child = await db.get(Tenant, child_id)
    if not child or child.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Child tenant not found")

    counts = await count_effective_rules(db, child_id)
    return EffectiveRuleCountOut(**counts)


# ---------------------------------------------------------------------------
# Cross-tenant dashboard rollups (mock data for UI)
# ---------------------------------------------------------------------------


class MSSPKpiOverview(BaseModel):
    """Cross-tenant totals for the parent dashboard.

    Every figure comes from the latest metrics snapshot of the tenants that HAVE one. A figure no tenant has reported is ``None``, never a
    made-up number: this used to return hard-coded values (a fixed 23.4-minute MTTR, "3 connectors online") for tenants that did not exist.
    """

    total_tenants: int
    tenants_reporting: int
    total_open_alerts: int | None = None
    total_critical_alerts: int | None = None
    total_open_cases: int | None = None
    avg_health_score: float | None = None
    avg_mttr_minutes: float | None = None
    sla_breach_count: int | None = None

    model_config = ConfigDict(from_attributes=True)


class ManagedTenantRow(BaseModel):
    """One REAL child tenant of the caller, with its latest metrics snapshot if any (``has_metrics`` is False and every metric ``None`` otherwise)."""

    tenant_id: str
    name: str
    has_metrics: bool
    snapshot_at: str | None = None
    health_score: float | None = None
    open_alerts: int | None = None
    critical_alerts: int | None = None
    open_cases: int | None = None
    mttr_minutes: float | None = None
    sla_breaches: int | None = None
    connector_count: int | None = None

    model_config = ConfigDict(from_attributes=True)


class CrossTenantIncident(BaseModel):
    incident_id: str
    tenant_name: str
    title: str
    severity: str
    status: str
    created_at: str
    assignee: str | None = None

    model_config = ConfigDict(from_attributes=True)


async def _managed_children(db: AsyncSession, parent_id: uuid.UUID) -> list[Tenant]:
    """The REAL child tenants of ``parent_id`` (what /mssp/children returns), name-ordered."""
    result = await db.execute(select(Tenant).where(Tenant.parent_tenant_id == parent_id).order_by(Tenant.name))
    return list(result.scalars().all())


async def _latest_snapshots(db: AsyncSession, child_ids: list[uuid.UUID]) -> dict[uuid.UUID, MSSPTenantMetrics]:
    """The most recent metrics snapshot per tenant. Portable SQL (max + join), so it runs on SQLite as well as Postgres."""
    if not child_ids:
        return {}
    newest = (
        select(MSSPTenantMetrics.tenant_id, func.max(MSSPTenantMetrics.snapshot_at).label("newest"))
        .where(MSSPTenantMetrics.tenant_id.in_(child_ids))
        .group_by(MSSPTenantMetrics.tenant_id)
        .subquery()
    )
    rows = await db.execute(
        select(MSSPTenantMetrics).join(
            newest,
            and_(MSSPTenantMetrics.tenant_id == newest.c.tenant_id, MSSPTenantMetrics.snapshot_at == newest.c.newest),
        )
    )
    return {row.tenant_id: row for row in rows.scalars().all()}  # a tie on the same instant keeps one row per tenant


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 1) if values else None


@router.get("/overview", response_model=MSSPKpiOverview, dependencies=[Depends(require_permission("mssp:read"))])
async def mssp_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPKpiOverview:
    """Cross-tenant KPI summary for the MSSP parent dashboard: real children, latest snapshot each, ``None`` where nothing is reported."""
    children = await _managed_children(db, current_user.tenant_id)
    snaps = list((await _latest_snapshots(db, [c.id for c in children])).values())
    return MSSPKpiOverview(
        total_tenants=len(children),
        tenants_reporting=len(snaps),
        total_open_alerts=sum(s.open_alerts for s in snaps) if snaps else None,
        total_critical_alerts=sum(s.critical_alerts for s in snaps) if snaps else None,
        total_open_cases=sum(s.open_cases for s in snaps) if snaps else None,
        avg_health_score=_mean([s.health_score for s in snaps if s.health_score is not None]),
        avg_mttr_minutes=_mean([s.mttr_minutes for s in snaps if s.mttr_minutes is not None]),
        sla_breach_count=sum(s.sla_breaches for s in snaps) if snaps else None,
    )


@router.get("/tenants", response_model=list[ManagedTenantRow], dependencies=[Depends(require_permission("mssp:read"))])
async def list_managed_tenants(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ManagedTenantRow]:
    """The caller's real child tenants with their latest metrics snapshot. A tenant that is not an MSSP parent has no children: an empty list."""
    children = await _managed_children(db, current_user.tenant_id)
    snaps = await _latest_snapshots(db, [c.id for c in children])
    rows: list[ManagedTenantRow] = []
    for child in children:
        snap = snaps.get(child.id)
        rows.append(
            ManagedTenantRow(
                tenant_id=str(child.id),
                name=child.name,
                has_metrics=snap is not None,
                snapshot_at=snap.snapshot_at.isoformat() if snap is not None and snap.snapshot_at else None,
                health_score=snap.health_score if snap is not None else None,
                open_alerts=snap.open_alerts if snap is not None else None,
                critical_alerts=snap.critical_alerts if snap is not None else None,
                open_cases=snap.open_cases if snap is not None else None,
                mttr_minutes=snap.mttr_minutes if snap is not None else None,
                sla_breaches=snap.sla_breaches if snap is not None else None,
                connector_count=snap.connector_count if snap is not None else None,
            )
        )
    return rows


@router.get("/incidents", response_model=list[CrossTenantIncident], dependencies=[Depends(require_permission("mssp:read"))])
async def list_cross_tenant_incidents(
    severity: str | None = Query(None, description="Filter: high | medium | low"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[CrossTenantIncident]:
    """Critical incidents across managed tenants.

    There is no cross-tenant incident feed yet: reading a child's incidents needs a delegation-checked, tenant-scoped read (alerts and cases are
    row-level-security FORCED), which has not been built. This used to return five invented incidents for tenants that did not exist; it now
    returns an empty list rather than anything made up.
    """
    return []
