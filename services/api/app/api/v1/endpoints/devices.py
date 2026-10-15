"""Devices: one row per machine per client, with the tools that report it.

CORE posts each tool's devices to ``POST /api/v1/inbox/core-feed/{token}/devices`` (authenticated by the secret in the path, like the other core-feed endpoints). A device lands in
the client tenant its vendor client id is mapped to, and joins the device it already is by serial number (see ``services/device_upsert.py``).

An MSSP parent lists devices across its clients (``GET /devices``, each row carries ``client_name``; ``client_id`` narrows to one). The parent can name a MASTER tool (``PUT /devices/settings``,
for example NinjaOne): a device that no feed from that tool backs is flagged ``in_master: false``. That is a coverage gap (a machine Huntress sees that NinjaOne does not). The master only changes
what is flagged; every tool's devices are stored the same way, so changing it later needs no migration.
"""

from __future__ import annotations

import contextlib
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.inbox_core_feed import _verify_core_feed_token
from app.db.rls_scope import acting_as_tenant
from app.db.rls_sessions import adopt_tenant
from app.models.alert import Alert
from app.models.client_alias import ClientAlias
from app.models.device import Device, DeviceSource
from app.models.tenant import Tenant
from app.services.device_upsert import DeviceReport, upsert_device

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/devices", tags=["devices"])
ingest_router = APIRouter(prefix="/inbox", tags=["inbox-core-feed"])

_VENDOR = r"^[a-z0-9][a-z0-9_-]{0,39}$"


class DeviceSourceOut(BaseModel):
    vendor: str
    name: str | None = None
    last_seen: datetime
    details: dict[str, Any] = Field(default_factory=dict)


class DeviceAlertOut(BaseModel):
    id: uuid.UUID
    title: str
    severity: str | None = None
    status: str | None = None
    source: str | None = None
    created_at: datetime | None = None


class DeviceOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    client_name: str | None = None
    hostname: str
    serial_number: str | None = None
    os: str | None = None
    os_version: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    last_seen: datetime
    last_online: datetime | None = None
    first_seen: datetime
    sources: list[DeviceSourceOut] = Field(default_factory=list)
    in_master: bool = True
    # Open alerts whose record names this device (NinjaOne, ThreatMate, Addigy... send the device name). Counted by hostname within the client; the newest few are listed.
    open_alerts: int = 0
    alerts: list[DeviceAlertOut] = Field(default_factory=list)


class DeviceSummary(BaseModel):
    total: int
    not_in_master: int
    # Devices a tool should be covering but does not report (Addigy: Macs only, so Windows machines are never counted).
    not_in_addigy: int = 0
    not_in_threatmate: int = 0


class DeviceListOut(BaseModel):
    master_vendor: str | None = None
    summary: DeviceSummary
    items: list[DeviceOut]
    total: int
    page: int
    page_size: int
    pages: int


class DeviceSettings(BaseModel):
    master_vendor: str | None = Field(default=None, pattern=_VENDOR)


_APPLE_OS = re.compile(r"mac\s?os|os\s?x|darwin")
# iPhones and iPads are managed in Addigy only: they never run the RMM or security agents, so they are not "missing" from those tools.
_MOBILE = re.compile(r"\b(ios|ipados|iphone|ipad)\b")


def is_mobile(d: Any) -> bool:
    return bool(_MOBILE.search(f"{d.os or ''} {d.model or ''}".lower()))


def last_online_of(sources: list[Any]) -> datetime | None:
    """The newest time any tool says the device was actually online (Addigy ``last_online``, NinjaOne ``last_contact``). ``last_seen`` is only when CORE last synced it."""
    best: datetime | None = None
    for s in sources:
        det = s.details or {}
        raw = det.get("last_online") or det.get("last_contact")
        if not isinstance(raw, str):
            continue
        try:
            t = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        if t.tzinfo is None:
            t = t.replace(tzinfo=UTC)
        if best is None or t > best:
            best = t
    return best


def is_missing_from(d: DeviceOut, tool: str) -> bool:
    """True when ``tool`` should report this device but does not. Addigy manages Apple computers only, so a device is only missing from it when it is a Mac;
    ThreatMate covers every machine."""
    if any(s.vendor == tool for s in d.sources):
        return False
    if tool != "addigy" and is_mobile(d):
        return False
    if tool == "addigy":
        return bool(_APPLE_OS.search((d.os or "").lower()))
    return True


# ---- reading ---------------------------------------------------------------------------------------------------------------------------------------------


def _master_of(tenant: Tenant | None) -> str | None:
    value = ((tenant.settings or {}).get("devices") or {}).get("master_vendor") if tenant is not None else None
    return value if isinstance(value, str) and value else None


async def _scope(db: Any, owner: uuid.UUID, client_id: uuid.UUID | None) -> tuple[list[uuid.UUID], dict[uuid.UUID, str]]:
    clients = {r.id: r.name for r in (await db.execute(select(Tenant.id, Tenant.name).where(Tenant.parent_tenant_id == owner))).all()}
    if client_id is not None and client_id != owner and client_id not in clients:
        raise HTTPException(status_code=404, detail="Client not found")
    return ([client_id] if client_id is not None else [owner, *clients]), clients


def _as(db: Any, owner: uuid.UUID, tid: uuid.UUID) -> Any:
    return contextlib.nullcontext() if tid == owner else acting_as_tenant(db, tid)


_CLOSED = ("resolved", "false_positive", "fp", "closed")
_ALERTS_PER_DEVICE = 5
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def _alerts_by_host(db: Any, tid: uuid.UUID) -> dict[str, list[DeviceAlertOut]]:
    """This tenant's open alerts that name a device, grouped by lower-cased device name, worst severity then newest first. The caller has put ``db`` in the tenant's scope."""
    host = func.lower(Alert.raw_event["unmapped"]["context"]["device_name"].astext)
    rows = (
        await db.execute(
            select(
                Alert.id,
                Alert.title,
                Alert.severity,
                Alert.status,
                Alert.created_at,
                Alert.raw_event["source"].astext.label("source"),
                host.label("host"),
            ).where(Alert.tenant_id == tid, host.isnot(None), Alert.status.notin_(_CLOSED))
        )
    ).all()
    grouped: dict[str, list[DeviceAlertOut]] = {}
    for r in rows:
        grouped.setdefault(r.host, []).append(
            DeviceAlertOut(id=r.id, title=r.title, severity=r.severity, status=r.status, source=r.source, created_at=r.created_at)
        )
    for items in grouped.values():
        items.sort(key=lambda a: (_SEVERITY_RANK.get((a.severity or "").lower(), 5), -(a.created_at.timestamp() if a.created_at else 0)))
    return grouped


async def _load(db: Any, owner: uuid.UUID, tids: list[uuid.UUID], clients: dict[uuid.UUID, str], master: str | None) -> list[DeviceOut]:
    out: list[DeviceOut] = []
    for tid in tids:
        async with _as(db, owner, tid):
            devices = (await db.execute(select(Device).where(Device.tenant_id == tid))).scalars().all()
            sources = (await db.execute(select(DeviceSource).where(DeviceSource.tenant_id == tid))).scalars().all()
            alerts = await _alerts_by_host(db, tid)
        by_device: dict[uuid.UUID, list[DeviceSource]] = {}
        for s in sources:
            by_device.setdefault(s.device_id, []).append(s)
        for d in devices:
            srcs = sorted(by_device.get(d.id, []), key=lambda s: s.vendor)
            out.append(
                DeviceOut(
                    id=d.id,
                    tenant_id=d.tenant_id,
                    client_name=clients.get(d.tenant_id),
                    hostname=d.hostname,
                    serial_number=d.serial_number,
                    os=d.os,
                    os_version=d.os_version,
                    manufacturer=d.manufacturer,
                    model=d.model,
                    ip_addresses=list(d.ip_addresses or []),
                    last_seen=d.last_seen,
                    first_seen=d.first_seen,
                    sources=[DeviceSourceOut(vendor=s.vendor, name=s.name, last_seen=s.last_seen, details=s.details or {}) for s in srcs],
                    in_master=master is None or any(s.vendor == master for s in srcs) or is_mobile(d),
                    last_online=last_online_of(srcs),
                    open_alerts=len(alerts.get(d.hostname.lower(), [])),
                    alerts=alerts.get(d.hostname.lower(), [])[:_ALERTS_PER_DEVICE],
                )
            )
    return out


@router.get("/settings", response_model=DeviceSettings)
async def get_settings(current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))], db: DBSession) -> DeviceSettings:
    return DeviceSettings(master_vendor=_master_of(await db.get(Tenant, current_user.tenant_id)))


@router.put("/settings", response_model=DeviceSettings)
async def put_settings(
    body: DeviceSettings, current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))], db: DBSession
) -> DeviceSettings:
    tenant = await db.get(Tenant, current_user.tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    settings = dict(tenant.settings or {})
    devices = dict(settings.get("devices") or {})
    if body.master_vendor:
        devices["master_vendor"] = body.master_vendor
    else:
        devices.pop("master_vendor", None)
    settings["devices"] = devices
    tenant.settings = settings
    await db.commit()
    return DeviceSettings(master_vendor=body.master_vendor or None)


@router.get("", response_model=DeviceListOut)
async def list_devices(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    client_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    vendor: str | None = Query(default=None, pattern=_VENDOR, description="Only devices this tool reports."),
    not_in_master: bool = Query(default=False, description="Only devices the master tool does not report."),
    missing: str | None = Query(
        default=None, pattern="^(addigy|threatmate)$", description="Only devices this tool should report but does not."
    ),
) -> DeviceListOut:
    owner = current_user.tenant_id
    scope, clients = await _scope(db, owner, client_id)
    master = _master_of(await db.get(Tenant, owner))
    everything = await _load(db, owner, scope, clients, master)
    summary = DeviceSummary(
        total=len(everything),
        not_in_master=sum(1 for d in everything if not d.in_master),
        not_in_addigy=sum(1 for d in everything if is_missing_from(d, "addigy")),
        not_in_threatmate=sum(1 for d in everything if is_missing_from(d, "threatmate")),
    )

    rows = everything
    if search:
        needle = search.strip().lower()
        rows = [
            d
            for d in rows
            if needle in d.hostname.lower() or needle in (d.serial_number or "").lower() or needle in (d.client_name or "").lower()
        ]
    if vendor:
        rows = [d for d in rows if any(s.vendor == vendor for s in d.sources)]
    if not_in_master:
        rows = [d for d in rows if not d.in_master]
    if missing:
        rows = [d for d in rows if is_missing_from(d, missing)]
    rows.sort(key=lambda d: (d.client_name or "", d.hostname.lower()))
    total = len(rows)
    start = (page - 1) * page_size
    return DeviceListOut(
        master_vendor=master,
        summary=summary,
        items=rows[start : start + page_size],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/{device_id}", response_model=DeviceOut)
async def get_device(
    device_id: uuid.UUID, current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))], db: DBSession
) -> DeviceOut:
    owner = current_user.tenant_id
    scope, clients = await _scope(db, owner, None)
    master = _master_of(await db.get(Tenant, owner))
    for tid in scope:
        async with _as(db, owner, tid):
            found = (await db.execute(select(Device.id).where(Device.id == device_id, Device.tenant_id == tid))).first()
        if found is not None:
            return next(d for d in await _load(db, owner, [tid], clients, master) if d.id == device_id)
    raise HTTPException(status_code=404, detail="Device not found")


# ---- CORE posts devices ------------------------------------------------------------------------------------------------------------------------------------


class DeviceIn(BaseModel):
    vendor: str = Field(pattern=_VENDOR)
    vendor_client_id: str | None = Field(
        default=None, max_length=200, description="The tool's id for the device's client; mapped to a client tenant like alerts are."
    )
    external_id: str = Field(min_length=1, max_length=200)
    hostname: str = Field(min_length=1, max_length=255)
    serial: str | None = Field(default=None, max_length=200)
    os: str | None = Field(default=None, max_length=100)
    os_version: str | None = Field(default=None, max_length=100)
    manufacturer: str | None = Field(default=None, max_length=100)
    model: str | None = Field(default=None, max_length=100)
    ip_addresses: list[str] = Field(default_factory=list, max_length=20)
    details: dict[str, Any] = Field(default_factory=dict)


class DevicesReport(BaseModel):
    items: list[DeviceIn] = Field(max_length=1000)


class DevicesResponse(BaseModel):
    accepted: int
    unmapped: int


async def apply_devices(db: Any, owner: uuid.UUID, report: DevicesReport) -> DevicesResponse:
    """Store each device under the client its vendor client id is mapped to. The caller owns the transaction.

    A device whose client is not mapped yet (or ignored) is counted and skipped, not guessed at: it arrives again on the next run, after the mapping. A device with no client id at all belongs to
    the feed's own tenant (an organisation with no clients)."""
    aliases = {
        (a.vendor, a.vendor_client_id): a.child_tenant_id
        for a in (
            await db.execute(
                select(ClientAlias).where(
                    ClientAlias.tenant_id == owner, ClientAlias.ignored.is_(False), ClientAlias.child_tenant_id.is_not(None)
                )
            )
        )
        .scalars()
        .all()
    }
    children = set((await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == owner))).scalars().all())
    by_tenant: dict[uuid.UUID, list[DeviceIn]] = {}
    unmapped = 0
    for item in report.items:
        if item.vendor_client_id:
            target = aliases.get((item.vendor, item.vendor_client_id))
            if target is None or target not in children:
                unmapped += 1
                continue
        else:
            target = owner
        by_tenant.setdefault(target, []).append(item)
    accepted = 0
    for tid, items in by_tenant.items():
        async with acting_as_tenant(db, tid):
            for it in items:
                await upsert_device(
                    db,
                    tid,
                    DeviceReport(
                        vendor=it.vendor,
                        external_id=it.external_id,
                        hostname=it.hostname,
                        serial=it.serial,
                        os=it.os,
                        os_version=it.os_version,
                        manufacturer=it.manufacturer,
                        model=it.model,
                        ip_addresses=it.ip_addresses,
                        details=it.details,
                    ),
                )
                accepted += 1
    return DevicesResponse(accepted=accepted, unmapped=unmapped)


@ingest_router.post("/core-feed/{tenant_token}/devices", response_model=DevicesResponse)
async def report_core_feed_devices(tenant_token: str, body: DevicesReport, db: DBSession) -> DevicesResponse:
    """Record the devices a tool reports, under the client each belongs to."""
    owner = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, owner)
    result = await apply_devices(db, owner, body)
    await db.commit()
    return result
