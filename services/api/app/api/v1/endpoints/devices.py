"""Devices: one row per machine per client, with the tools that report it.

CORE posts each tool's devices to ``POST /api/v1/inbox/core-feed/{token}/devices`` (authenticated by the secret in the path, like the other core-feed endpoints). A device lands in
the client tenant its vendor client id is mapped to, and joins the device it already is by serial number (see ``services/device_upsert.py``).

An MSSP parent lists devices across its clients (``GET /devices``, each row carries ``client_name``; ``client_id`` narrows to one). The parent can name a MASTER tool (``PUT /devices/settings``,
for example NinjaOne): a device that no feed from that tool backs is flagged ``in_master: false``. That is a coverage gap (a machine Huntress sees that NinjaOne does not). The master only changes
what is flagged; every tool's devices are stored the same way, so changing it later needs no migration.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.inbox_core_feed import _verify_core_feed_token
from app.db.rls_scope import acting_as_tenant, cross_tenant_reads
from app.db.rls_sessions import adopt_tenant
from app.models.alert import Alert
from app.models.client_alias import ClientAlias
from app.models.device import Device, DeviceMergeLog, DeviceSnooze, DeviceSource
from app.models.tenant import Tenant
from app.services.client_mapping import record_device_hints, tenant_hidden
from app.services.device_merge import DeviceMergeError, can_undo, dismiss_pair, merge_devices, undo_merge
from app.services.device_upsert import DeviceReport, possible_duplicates, upsert_device

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
    # Whether the tools say it is online now (as of the last sync); None when no tool says.
    online: bool | None = None
    # Whole days since a tool last saw it online, when that is OFFLINE_AFTER_DAYS or more; None when it is recent or no tool says.
    offline_days: int | None = None
    first_seen: datetime
    sources: list[DeviceSourceOut] = Field(default_factory=list)
    in_master: bool = True
    # Open alerts whose record names this device (NinjaOne, ThreatMate, Addigy... send the device name). Counted by hostname within the client; the newest few are listed.
    open_alerts: int = 0
    alerts: list[DeviceAlertOut] = Field(default_factory=list)
    # When a person hid this device until it checks back in, and it has not been seen online since. None for a device that is shown.
    hidden_since: datetime | None = None


class DeviceSummary(BaseModel):
    total: int
    not_in_master: int
    # Devices a tool should be covering but does not report (Addigy: Macs only, so Windows machines are never counted).
    not_in_addigy: int = 0
    not_in_threatmate: int = 0
    not_in_huntress: int = 0
    # Devices a tool reports a problem with (Huntress: agent not checking in, Defender or firewall unhealthy, tamper protection not in force).
    needs_attention: int = 0
    # Devices whose protection agent has not checked in for STALE_AGENT_DAYS or more (Huntress), often a machine that was retired but still holds a licence.
    stale_agents: int = 0
    # Devices no tool has seen online for OFFLINE_AFTER_DAYS or more, and devices with at least one open alert.
    offline: int = 0
    with_alerts: int = 0
    # Devices a person hid until they check back in (not counted in any other number here).
    hidden: int = 0
    # Devices offline for LONG_OFFLINE_DAYS or more: still in the list and in `offline`, but left out of the attention, stale, not-in-tool and open-alert numbers.
    long_offline: int = 0


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
_MOBILE = re.compile(r"\b(ios|ipados|iphone|ipad)\d*\b")


def is_mobile(d: Any) -> bool:
    return bool(_MOBILE.search(f"{d.os or ''} {d.model or ''}".lower()))


OFFLINE_AFTER_DAYS = 7
# A device no tool has seen online for this long stops counting toward every number and filter except the offline count: a machine in a drawer is not a problem to chase. It stays in the list.
LONG_OFFLINE_DAYS = 10


def offline_days_of(last_online: datetime | None, now: datetime | None = None) -> int | None:
    """Days since the device was last online, once that reaches OFFLINE_AFTER_DAYS. A device with no online time from any tool is unknown, not offline."""
    if last_online is None:
        return None
    days = ((now or datetime.now(UTC)) - last_online).days
    return days if days >= OFFLINE_AFTER_DAYS else None


def last_online_of(sources: list[Any]) -> datetime | None:
    """The newest time any tool says the device was actually online (Addigy ``last_online``, NinjaOne ``last_contact``, Huntress ``last_callback_at``: when its agent last checked in, DNSFilter ``last_sync_at``: when its agent last synced). ``last_seen`` is only when CORE last synced it."""
    best: datetime | None = None
    for s in sources:
        det = s.details or {}
        raw = det.get("last_online") or det.get("last_contact") or det.get("last_callback_at") or det.get("last_sync_at")
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


def online_now_of(sources: list[Any]) -> bool | None:
    """Whether the tools say the device is online right now (as of the last sync): True if any says so, False if every tool that says anything says offline, None if none says.
    Addigy sends ``online``; NinjaOne sends ``offline``."""
    flags: list[bool] = []
    for s in sources:
        det = s.details or {}
        if isinstance(det.get("online"), bool):
            flags.append(det["online"])
        elif isinstance(det.get("offline"), bool):
            flags.append(not det["offline"])
    if not flags:
        return None
    return any(flags)


STALE_AGENT_DAYS = 14


def stale_days_of(d: DeviceOut) -> int | None:
    """The longest any of the device's protection agents has gone without checking in (``days_since_checkin`` a tool reports), when that is STALE_AGENT_DAYS or more; None otherwise."""
    worst: int | None = None
    for s in d.sources:
        days = s.details.get("days_since_checkin")
        if isinstance(days, int) and not isinstance(days, bool) and days >= STALE_AGENT_DAYS and (worst is None or days > worst):
            worst = days
    return worst


def attention_of(d: DeviceOut) -> list[str]:
    """What needs a person's attention on this device: what each tool reports (its ``needs_attention`` list), and a disagreement between tools that no single tool could see: another tool says the
    machine is online while its Huntress agent has gone quiet, so either the machine is in use unprotected or one of the two records is stale."""
    out: list[str] = []
    for s in d.sources:
        items = s.details.get("needs_attention")
        if isinstance(items, list):
            out.extend(str(i) for i in items if isinstance(i, str) and i)
    stale = stale_days_of(d)
    if stale is not None and d.online is True:
        out.append(f"Another tool says this machine is online, but its Huntress agent has not checked in for {stale} days")
    return out


class ClientRollup(BaseModel):
    client_id: uuid.UUID
    client_name: str | None
    devices: int
    needs_attention: int
    stale_agents: int
    not_in_huntress: int
    offline: int


def long_offline(d: DeviceOut) -> bool:
    """True when no tool has seen the device online for LONG_OFFLINE_DAYS or more. Such a device is left out of the problem counts (attention, stale agent, missing from a tool, open alerts)."""
    return d.offline_days is not None and d.offline_days >= LONG_OFFLINE_DAYS


def rollup_of(devices: list[DeviceOut]) -> list[ClientRollup]:
    """One row per client: how many devices, and how many of them need attention, have a stale agent, are not in Huntress or have been offline a week. Worst first, then by name."""
    rows: dict[uuid.UUID, ClientRollup] = {}
    for d in devices:
        r = rows.setdefault(
            d.tenant_id,
            ClientRollup(
                client_id=d.tenant_id, client_name=d.client_name, devices=0, needs_attention=0, stale_agents=0, not_in_huntress=0, offline=0
            ),
        )
        r.devices += 1
        counted = not long_offline(d)
        r.needs_attention += 1 if counted and attention_of(d) else 0
        r.stale_agents += 1 if counted and stale_days_of(d) is not None else 0
        r.not_in_huntress += 1 if counted and is_missing_from(d, "huntress") else 0
        r.offline += 1 if d.offline_days is not None else 0
    return sorted(rows.values(), key=lambda r: (-r.needs_attention, -r.stale_agents, (r.client_name or "").lower()))


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
    rows = (await db.execute(select(Tenant.id, Tenant.name, Tenant.settings).where(Tenant.parent_tenant_id == owner))).all()
    clients = {r.id: r.name for r in rows}
    # Archived and test clients (hidden) are left out of "all clients"; one can still be asked for by id.
    shown = [r.id for r in rows if not tenant_hidden(r)]
    if client_id is not None and client_id != owner and client_id not in clients:
        raise HTTPException(status_code=404, detail="Client not found")
    return ([client_id] if client_id is not None else [owner, *shown]), clients


def _as(db: Any, owner: uuid.UUID, tid: uuid.UUID) -> Any:
    return contextlib.nullcontext() if tid == owner else acting_as_tenant(db, tid)


_CLOSED = ("resolved", "false_positive", "fp", "closed")
_ALERTS_PER_DEVICE = 5
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


_IP_ADDRESS = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:.]*)$")


def host_key(name: str | None) -> str:
    """What a device name is compared by: lower case, without a domain suffix (``PC-1.acme.local`` and ``pc-1`` are one machine). An IP address is kept whole."""
    n = (name or "").strip().lower()
    return n if _IP_ADDRESS.match(n) else n.split(".")[0]


async def _alerts_by_host(db: Any, tid: uuid.UUID) -> dict[str, list[DeviceAlertOut]]:
    """This tenant's open alerts that name a device, grouped by lower-cased device name, worst severity then newest first. The caller has put ``db`` in the tenant's scope."""
    # The device a vendor named in its own context (RMM-style tools), else the host fusion recorded on the alert (SIEM/EDR alerts carry it only there).
    host = func.lower(func.coalesce(Alert.raw_event["unmapped"]["context"]["device_name"].astext, Alert.affected_hosts[0].astext))
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
        grouped.setdefault(host_key(r.host), []).append(
            DeviceAlertOut(id=r.id, title=r.title, severity=r.severity, status=r.status, source=r.source, created_at=r.created_at)
        )
    for items in grouped.values():
        items.sort(key=lambda a: (_SEVERITY_RANK.get((a.severity or "").lower(), 5), -(a.created_at.timestamp() if a.created_at else 0)))
    return grouped


# Building every device of a client (or of all of them) takes seconds and a database connection, and the page asks for the list AND the duplicates together, often twice. Left alone those
# requests queue up in one worker, each holding a connection, until the pool runs dry and the API answers 500. So concurrent loads of the same scope share one, and the result is kept for a few
# seconds. Anything that changes devices (a sync, a merge, a dismissal, the master setting) clears it, so a change is never hidden behind it.
LOAD_CACHE_SECONDS = 20.0
_loaded: dict[tuple, tuple[float, list[DeviceOut]]] = {}
_load_locks: dict[tuple, asyncio.Lock] = {}


def forget_loaded() -> None:
    _loaded.clear()


async def _load_cached(
    db: Any, owner: uuid.UUID, tids: list[uuid.UUID], clients: dict[uuid.UUID, str], master: str | None
) -> list[DeviceOut]:
    key = (owner, tuple(tids), master)
    lock = _load_locks.setdefault(key, asyncio.Lock())
    async with lock:
        hit = _loaded.get(key)
        if hit is not None and time.monotonic() - hit[0] < LOAD_CACHE_SECONDS:
            return hit[1]
        devices = await _load(db, owner, tids, clients, master)
        _loaded[key] = (time.monotonic(), devices)
        if len(_loaded) > 64:  # never grow without bound: drop whatever is oldest
            for old in sorted(_loaded, key=lambda k: _loaded[k][0])[:32]:
                _loaded.pop(old, None)
                _load_locks.pop(old, None)
        return devices


def hidden_since_of(snoozed_at: datetime | None, last_online: datetime | None) -> datetime | None:
    """When the device was hidden, while it still is: a device is hidden until a tool sees it online AFTER it was hidden. With no snooze, or a newer sighting, it is shown. A device no tool says
    anything about stays hidden until a person shows it again."""
    if snoozed_at is None:
        return None
    if snoozed_at.tzinfo is None:
        snoozed_at = snoozed_at.replace(tzinfo=UTC)
    if last_online is not None:
        seen = last_online if last_online.tzinfo else last_online.replace(tzinfo=UTC)
        if seen > snoozed_at:
            return None
    return snoozed_at


async def _load(db: Any, owner: uuid.UUID, tids: list[uuid.UUID], clients: dict[uuid.UUID, str], master: str | None) -> list[DeviceOut]:
    out: list[DeviceOut] = []
    for tid in tids:
        async with _as(db, owner, tid):
            devices = (await db.execute(select(Device).where(Device.tenant_id == tid))).scalars().all()
            sources = (await db.execute(select(DeviceSource).where(DeviceSource.tenant_id == tid))).scalars().all()
            alerts = await _alerts_by_host(db, tid)
            snoozes = {
                row.device_id: row.snoozed_at
                for row in (await db.execute(select(DeviceSnooze).where(DeviceSnooze.tenant_id == tid))).scalars().all()
            }
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
                    last_online=(online := last_online_of(srcs)),
                    online=online_now_of(srcs),
                    offline_days=offline_days_of(online),
                    open_alerts=len(alerts.get(host_key(d.hostname), [])),
                    alerts=alerts.get(host_key(d.hostname), [])[:_ALERTS_PER_DEVICE],
                    hidden_since=hidden_since_of(snoozes.get(d.id), online),
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
    forget_loaded()
    await db.commit()
    return DeviceSettings(master_vendor=body.master_vendor or None)


def filter_devices(
    everything: list[DeviceOut],
    *,
    search: str | None = None,
    vendor: str | None = None,
    not_in_master: bool = False,
    missing: str | None = None,
    offline: bool = False,
    has_alerts: bool = False,
    attention: bool = False,
    stale: bool = False,
    hidden: bool = False,
) -> list[DeviceOut]:
    """The devices a page (or an export) asked for: every filter given must hold. ``search`` matches the name, serial number, client name or any IP address, ignoring case. Sorted by client, then name."""
    rows = [d for d in everything if (d.hidden_since is not None) == hidden]
    # The problem filters agree with the problem counts: a device offline for a month is not in them (the Offline filter still shows it).
    if not_in_master or missing or has_alerts or attention or stale:
        rows = [d for d in rows if not long_offline(d)]
    if search:
        needle = search.strip().lower()
        rows = [
            d
            for d in rows
            if needle in d.hostname.lower()
            or needle in (d.serial_number or "").lower()
            or needle in (d.client_name or "").lower()
            or any(needle in ip.lower() for ip in d.ip_addresses)
        ]
    if vendor:
        rows = [d for d in rows if any(s.vendor == vendor for s in d.sources)]
    if not_in_master:
        rows = [d for d in rows if not d.in_master]
    if missing:
        rows = [d for d in rows if is_missing_from(d, missing)]
    if offline:
        rows = [d for d in rows if d.offline_days is not None]
    if has_alerts:
        rows = [d for d in rows if d.open_alerts > 0]
    if attention:
        rows = [d for d in rows if attention_of(d)]
    if stale:
        rows = [d for d in rows if stale_days_of(d) is not None]
    return sorted(rows, key=lambda d: (d.client_name or "", d.hostname.lower()))


_CSV_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: Any) -> str:
    """A cell that a spreadsheet will show as text: one that starts with =, +, - or @ would be run as a formula, so it is given a leading apostrophe."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_CSV_FORMULA_START) else text


def devices_csv(rows: list[DeviceOut]) -> str:
    """The devices as CSV: client, name, serial, OS, tools, last online, what needs attention, open alerts."""
    import csv
    import io

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Client", "Device", "Serial number", "OS", "Tools", "Last online", "Needs attention", "Open alerts"])
    for d in rows:
        writer.writerow(
            [
                csv_cell(d.client_name),
                csv_cell(d.hostname),
                csv_cell(d.serial_number),
                csv_cell(" ".join(x for x in (d.os, d.os_version) if x)),
                csv_cell(", ".join(sorted({s.vendor for s in d.sources}))),
                csv_cell(d.last_online.isoformat() if d.last_online else ""),
                csv_cell("; ".join(attention_of(d))),
                d.open_alerts,
            ]
        )
    return out.getvalue()


@router.get("", response_model=DeviceListOut)
async def list_devices(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
    page: int = Query(default=1, ge=1, le=100_000),
    page_size: int = Query(default=50, ge=1, le=200),
    client_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    vendor: str | None = Query(default=None, pattern=_VENDOR, description="Only devices this tool reports."),
    not_in_master: bool = Query(default=False, description="Only devices the master tool does not report."),
    missing: str | None = Query(
        default=None, pattern="^(addigy|threatmate|huntress)$", description="Only devices this tool should report but does not."
    ),
    offline: bool = Query(default=False, description="Only devices no tool has seen online for a week or more."),
    has_alerts: bool = Query(default=False, description="Only devices with at least one open alert."),
    attention: bool = Query(default=False, description="Only devices a tool reports a problem with."),
    stale: bool = Query(default=False, description="Only devices whose protection agent has not checked in for two weeks or more."),
    hidden: bool = Query(
        default=False,
        description="Only devices a person hid until they check back in. Without this they are left out of the list and every count.",
    ),
) -> DeviceListOut:
    owner = current_user.tenant_id
    scope, clients = await _scope(db, owner, client_id)
    master = _master_of(await db.get(Tenant, owner))
    loaded = await _load_cached(db, owner, scope, clients, master)
    everything = [d for d in loaded if d.hidden_since is None]
    counted = [d for d in everything if not long_offline(d)]
    summary = DeviceSummary(
        hidden=len(loaded) - len(everything),
        total=len(everything),
        long_offline=sum(1 for d in everything if long_offline(d)),
        not_in_master=sum(1 for d in counted if not d.in_master),
        not_in_addigy=sum(1 for d in counted if is_missing_from(d, "addigy")),
        not_in_threatmate=sum(1 for d in counted if is_missing_from(d, "threatmate")),
        not_in_huntress=sum(1 for d in counted if is_missing_from(d, "huntress")),
        needs_attention=sum(1 for d in counted if attention_of(d)),
        stale_agents=sum(1 for d in counted if stale_days_of(d) is not None),
        offline=sum(1 for d in everything if d.offline_days is not None),
        with_alerts=sum(1 for d in counted if d.open_alerts > 0),
    )

    rows = filter_devices(
        loaded,
        search=search,
        vendor=vendor,
        not_in_master=not_in_master,
        missing=missing,
        offline=offline,
        has_alerts=has_alerts,
        attention=attention,
        stale=stale,
        hidden=hidden,
    )
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


class DuplicatePairOut(BaseModel):
    a: DeviceOut
    b: DeviceOut


class DuplicatesOut(BaseModel):
    items: list[DuplicatePairOut]


class DismissIn(BaseModel):
    device_a: uuid.UUID
    device_b: uuid.UUID


class MergeIn(BaseModel):
    keep: uuid.UUID = Field(description="The device that stays; every tool that reported the other one now reports this one.")
    remove: uuid.UUID


@router.get("/export.csv", summary="The devices the page is showing, as a CSV file")
async def export_devices(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
    client_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    vendor: str | None = Query(default=None, pattern=_VENDOR),
    not_in_master: bool = Query(default=False),
    missing: str | None = Query(default=None, pattern="^(addigy|threatmate|huntress)$"),
    offline: bool = Query(default=False),
    has_alerts: bool = Query(default=False),
    attention: bool = Query(default=False),
    stale: bool = Query(default=False),
    hidden: bool = Query(default=False),
) -> Response:
    owner = current_user.tenant_id
    scope, clients = await _scope(db, owner, client_id)
    master = _master_of(await db.get(Tenant, owner))
    everything = await _load_cached(db, owner, scope, clients, master)
    rows = filter_devices(
        everything,
        search=search,
        vendor=vendor,
        not_in_master=not_in_master,
        missing=missing,
        offline=offline,
        has_alerts=has_alerts,
        attention=attention,
        stale=stale,
        hidden=hidden,
    )
    body = devices_csv(rows)
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="devices.csv"', "Cache-Control": "no-store"},
    )


@router.get(
    "/rollup",
    response_model=list[ClientRollup],
    summary="Per client: devices, how many need attention, have a stale agent, are not in Huntress or are offline",
)
async def devices_rollup(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))], db: DBSession
) -> list[ClientRollup]:
    owner = current_user.tenant_id
    scope, clients = await _scope(db, owner, None)
    master = _master_of(await db.get(Tenant, owner))
    return rollup_of([d for d in await _load_cached(db, owner, scope, clients, master) if d.hidden_since is None])


@router.get("/duplicates", response_model=DuplicatesOut)
async def list_duplicates(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
    client_id: uuid.UUID | None = Query(default=None),
) -> DuplicatesOut:
    """Pairs of a client's devices that share a hostname but have no serial number proving they differ. Pairs a person dismissed are not listed."""
    owner = current_user.tenant_id
    scope, clients = await _scope(db, owner, client_id)
    master = _master_of(await db.get(Tenant, owner))
    items: list[DuplicatePairOut] = []
    for tid in scope:
        async with _as(db, owner, tid):
            pairs = await possible_duplicates(db, tid)
        if not pairs:
            continue
        by_id = {d.id: d for d in await _load_cached(db, owner, [tid], clients, master)}
        items.extend(DuplicatePairOut(a=by_id[a], b=by_id[b]) for a, b in pairs if a in by_id and b in by_id)
    items.sort(key=lambda p: ((p.a.client_name or ""), p.a.hostname.lower()))
    return DuplicatesOut(items=items)


async def _client_of(db: Any, owner: uuid.UUID, device_id: uuid.UUID) -> uuid.UUID:
    scope, _ = await _scope(db, owner, None)
    for tid in scope:
        async with _as(db, owner, tid):
            if (await db.execute(select(Device.id).where(Device.id == device_id, Device.tenant_id == tid))).first() is not None:
                return tid
    raise HTTPException(status_code=404, detail="Device not found")


class HideOut(BaseModel):
    device_id: uuid.UUID
    hidden_since: datetime | None


@router.post("/{device_id}/hide", response_model=HideOut, summary="Hide a device until a tool sees it online again")
async def hide_device(
    device_id: uuid.UUID, current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))], db: DBSession
) -> HideOut:
    """For an offline machine that is cluttering the list: it is left out of the list and the counts until any tool reports it online after now. Hiding it again later starts over."""
    owner = current_user.tenant_id
    tid = await _client_of(db, owner, device_id)
    now = datetime.now(UTC)
    async with _as(db, owner, tid):
        row = (
            await db.execute(select(DeviceSnooze).where(DeviceSnooze.device_id == device_id, DeviceSnooze.tenant_id == tid))
        ).scalar_one_or_none()
        if row is None:
            db.add(DeviceSnooze(device_id=device_id, tenant_id=tid, snoozed_at=now, created_by=current_user.user_id))
        else:
            row.snoozed_at = now
            row.created_by = current_user.user_id
    forget_loaded()
    await db.commit()
    return HideOut(device_id=device_id, hidden_since=now)


@router.delete("/{device_id}/hide", response_model=HideOut, summary="Show a hidden device again")
async def unhide_device(
    device_id: uuid.UUID, current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))], db: DBSession
) -> HideOut:
    owner = current_user.tenant_id
    tid = await _client_of(db, owner, device_id)
    async with _as(db, owner, tid):
        row = (
            await db.execute(select(DeviceSnooze).where(DeviceSnooze.device_id == device_id, DeviceSnooze.tenant_id == tid))
        ).scalar_one_or_none()
        if row is not None:
            await db.delete(row)
    forget_loaded()
    await db.commit()
    return HideOut(device_id=device_id, hidden_since=None)


@router.post("/duplicates/dismiss", status_code=204)
async def dismiss_duplicate(
    body: DismissIn, current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))], db: DBSession
) -> None:
    """These two are different machines: stop suggesting them. Remembered for the whole organization."""
    owner = current_user.tenant_id
    tid = await _client_of(db, owner, body.device_a)
    try:
        async with _as(db, owner, tid):
            await dismiss_pair(db, tid, body.device_a, body.device_b)
    except DeviceMergeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    forget_loaded()
    await db.commit()


@router.post("/duplicates/merge", response_model=DeviceOut)
async def merge_duplicate(
    body: MergeIn, current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))], db: DBSession
) -> DeviceOut:
    """These two are the same machine: fold the second into the first."""
    owner = current_user.tenant_id
    tid = await _client_of(db, owner, body.keep)
    try:
        async with _as(db, owner, tid):
            kept = await merge_devices(db, tid, body.keep, body.remove, current_user.user_id)
    except DeviceMergeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    forget_loaded()
    await db.commit()
    scope, clients = await _scope(db, owner, tid if tid != owner else None)
    master = _master_of(await db.get(Tenant, owner))
    return next(d for d in await _load(db, owner, [tid], clients, master) if d.id == kept)


class MergeOut(BaseModel):
    id: uuid.UUID
    client_name: str | None = None
    removed_hostname: str
    kept_device_id: uuid.UUID
    created_at: datetime


@router.get("/duplicates/merges", response_model=list[MergeOut], summary="Recent merges that can still be undone")
async def list_merges(current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))], db: DBSession) -> list[MergeOut]:
    owner = current_user.tenant_id
    scope, clients = await _scope(db, owner, None)
    async with cross_tenant_reads(db):
        rows = (
            (
                await db.execute(
                    select(DeviceMergeLog)
                    .where(DeviceMergeLog.tenant_id.in_(scope), DeviceMergeLog.undone_at.is_(None))
                    .order_by(DeviceMergeLog.created_at.desc())
                    .limit(50)
                )
            )
            .scalars()
            .all()
        )
    return [
        MergeOut(
            id=r.id,
            client_name=clients.get(r.tenant_id),
            removed_hostname=str((r.removed or {}).get("hostname") or ""),
            kept_device_id=r.kept_device_id,
            created_at=r.created_at,
        )
        for r in rows
        if can_undo(r)
    ][:20]


@router.post("/duplicates/merges/{merge_id}/undo", response_model=MergeOut, summary="Undo a recent merge")
async def undo_merge_route(
    merge_id: uuid.UUID, current_user: Annotated[AuthUser, Depends(require_permission("mssp:manage"))], db: DBSession
) -> MergeOut:
    owner = current_user.tenant_id
    scope, clients = await _scope(db, owner, None)
    async with cross_tenant_reads(db):
        entry = (
            await db.execute(select(DeviceMergeLog).where(DeviceMergeLog.id == merge_id, DeviceMergeLog.tenant_id.in_(scope)))
        ).scalar_one_or_none()
    if entry is None:
        raise HTTPException(status_code=404, detail="That merge was not found.")
    try:
        async with _as(db, owner, entry.tenant_id):
            await undo_merge(db, entry.tenant_id, merge_id)
    except DeviceMergeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    forget_loaded()
    await db.commit()
    return MergeOut(
        id=entry.id,
        client_name=clients.get(entry.tenant_id),
        removed_hostname=str((entry.removed or {}).get("hostname") or ""),
        kept_device_id=entry.kept_device_id,
        created_at=entry.created_at,
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


class UnmappedClient(BaseModel):
    """A tool's client that devices belong to but that is not mapped to a client here (``name`` is None when the tool's client list has not reached AiSOC yet)."""

    vendor_client_id: str
    name: str | None = None
    devices: int


class DevicesResponse(BaseModel):
    accepted: int
    unmapped: int
    # Devices of clients someone chose to ignore: skipped on purpose, so they are not "unmapped" and need no attention.
    ignored: int = 0
    # The unmapped clients with the most devices, so the feed's card can name them.
    unmapped_clients: list[UnmappedClient] = Field(default_factory=list)


async def apply_devices(db: Any, owner: uuid.UUID, report: DevicesReport) -> DevicesResponse:
    """Store each device under the client its vendor client id is mapped to. The caller owns the transaction.

    A device whose client is not mapped yet (or ignored) is counted and skipped, not guessed at: it arrives again on the next run, after the mapping. A device with no client id at all belongs to
    the feed's own tenant (an organisation with no clients)."""
    rows = (await db.execute(select(ClientAlias).where(ClientAlias.tenant_id == owner))).scalars().all()
    known = {(a.vendor, a.vendor_client_id): a for a in rows}
    children = set((await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == owner))).scalars().all())
    by_tenant: dict[uuid.UUID, list[DeviceIn]] = {}
    waiting: dict[tuple[str, str], int] = {}
    waiting_names: dict[tuple[str, str], list[str]] = {}
    unmapped = 0
    ignored = 0
    for item in report.items:
        if item.vendor_client_id:
            alias = known.get((item.vendor, item.vendor_client_id))
            if alias is not None and alias.ignored:
                ignored += 1
                continue
            target = alias.child_tenant_id if alias is not None else None
            if target is None or target not in children:
                unmapped += 1
                key = (item.vendor, item.vendor_client_id)
                waiting[key] = waiting.get(key, 0) + 1
                waiting_names.setdefault(key, []).append(item.hostname)
                continue
        else:
            target = owner
        by_tenant.setdefault(target, []).append(item)
    # The machine names of clients that are not mapped yet are kept, to suggest which client they belong to (see client_mapping.device_overlaps).
    for (vendor, vid), hostnames in waiting_names.items():
        await record_device_hints(db, owner, vendor, vid, hostnames)
    unmapped_clients = [
        UnmappedClient(vendor_client_id=vid, name=known[(vendor, vid)].vendor_client_name if (vendor, vid) in known else None, devices=n)
        for (vendor, vid), n in sorted(waiting.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    ]
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
    return DevicesResponse(accepted=accepted, unmapped=unmapped, ignored=ignored, unmapped_clients=unmapped_clients)


@ingest_router.post("/core-feed/{tenant_token}/devices", response_model=DevicesResponse)
async def report_core_feed_devices(tenant_token: str, body: DevicesReport, db: DBSession) -> DevicesResponse:
    """Record the devices a tool reports, under the client each belongs to."""
    owner = await _verify_core_feed_token(db, tenant_token)
    await adopt_tenant(db, owner)
    result = await apply_devices(db, owner, body)
    forget_loaded()
    await db.commit()
    return result
