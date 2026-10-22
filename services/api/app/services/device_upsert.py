"""Record that a tool reported a device, joining it to the device it already is, if any.

Rules, in order:
  * The tool's own id for the device is looked up first (``device_sources``). A tool reporting the same id again updates the same device.
  * Otherwise a usable serial number finds the client's device with that serial (created if none). Serial is the only automatic match across tools.
  * With no usable serial the report becomes its own new device. It is not merged by hostname at this point; afterwards ``device_merge.auto_merge_same_name`` merges a pair that is plainly one machine
    (a unique, non-stock name; different tools; no conflicting serial or OS), and ``possible_duplicates`` offers every other same-name pair for a person to confirm.
If a known source now reports a serial that belongs to a different device in the client, the source moves to that device, and a device left with no sources is removed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select

from app.models.device import Device, DeviceSource
from app.services.device_identity import hostname_key, normalize_serial


@dataclass
class DeviceReport:
    vendor: str
    external_id: str
    hostname: str
    serial: str | None = None
    os: str | None = None
    os_version: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    ip_addresses: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


def _fill(device: Device, report: DeviceReport) -> None:
    """A tool's value fills a field only when the device has none yet; the first tool to say something is not overwritten by a later one."""
    for name in ("os", "os_version", "manufacturer", "model"):
        if getattr(device, name) is None and getattr(report, name):
            setattr(device, name, getattr(report, name)[:100])
    if not device.ip_addresses and report.ip_addresses:
        device.ip_addresses = list(report.ip_addresses)[:20]
    device.last_seen = datetime.now(UTC)


async def upsert_device(db: Any, tenant_id: uuid.UUID, report: DeviceReport) -> uuid.UUID:
    """Apply one report inside ``tenant_id``'s scope. The caller owns the transaction. Returns the device id."""
    serial = normalize_serial(report.serial)
    source = (
        await db.execute(
            select(DeviceSource).where(
                DeviceSource.tenant_id == tenant_id, DeviceSource.vendor == report.vendor, DeviceSource.external_id == report.external_id
            )
        )
    ).scalar_one_or_none()

    device: Device | None = None
    if source is not None:
        device = await db.get(Device, source.device_id)
    previous_id = device.id if device is not None else None

    if serial is not None:
        owner = (await db.execute(select(Device).where(Device.tenant_id == tenant_id, Device.serial_number == serial))).scalar_one_or_none()
        if owner is not None:
            device = owner
        elif device is not None and device.serial_number is None:
            device.serial_number = serial
        elif device is not None and device.serial_number != serial:
            device = None  # the tool now reports a different machine's serial under the same id: it gets a device of its own

    if device is None:
        device = Device(
            tenant_id=tenant_id,
            serial_number=serial,
            hostname=(report.hostname or report.external_id)[:255],
            os=(report.os or None),
            os_version=(report.os_version or None),
            manufacturer=(report.manufacturer or None),
            model=(report.model or None),
            ip_addresses=list(report.ip_addresses)[:20] or None,
        )
        db.add(device)
        await db.flush()
    else:
        _fill(device, report)

    if source is None:
        db.add(
            DeviceSource(
                tenant_id=tenant_id,
                device_id=device.id,
                vendor=report.vendor,
                external_id=report.external_id,
                name=(report.hostname or None),
                details=report.details,
            )
        )
    else:
        source.device_id = device.id
        source.name = report.hostname or source.name
        source.details = report.details
        source.last_seen = datetime.now(UTC)
    await db.flush()
    if previous_id is not None and previous_id != device.id:
        remaining = (
            await db.execute(select(func.count()).select_from(DeviceSource).where(DeviceSource.device_id == previous_id))
        ).scalar_one()
        if remaining == 0:
            await db.execute(delete(Device).where(Device.id == previous_id))
    return device.id


async def possible_duplicates(db: Any, tenant_id: uuid.UUID) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """Pairs of the client's devices a person might want to merge: the same hostname, and not provably different (two different serials mean two machines). Dismissed pairs are left out, and so is any machine only ScreenConnect lists and that has no serial number."""
    from app.models.device import DeviceMergeDismissal

    rows = (await db.execute(select(Device).where(Device.tenant_id == tenant_id))).scalars().all()
    dismissed = {
        (d.device_a, d.device_b)
        for d in (await db.execute(select(DeviceMergeDismissal).where(DeviceMergeDismissal.tenant_id == tenant_id))).scalars().all()
    }
    # ScreenConnect lists some machines with no serial number (a stock BIOS, a reinstall): with nothing to tell one from another they are not offered as duplicates of anything.
    only_screenconnect = {
        device_id
        for (device_id,) in (
            await db.execute(
                select(DeviceSource.device_id)
                .where(DeviceSource.tenant_id == tenant_id)
                .group_by(DeviceSource.device_id)
                .having(func.count().filter(DeviceSource.vendor != "screenconnect") == 0)
            )
        ).all()
    }
    by_name: dict[str, list[Device]] = {}
    for d in rows:
        key = hostname_key(d.hostname)
        if key and not (d.id in only_screenconnect and not d.serial_number):
            by_name.setdefault(key, []).append(d)
    pairs: list[tuple[uuid.UUID, uuid.UUID]] = []
    for group in by_name.values():
        for i, a in enumerate(group):
            for b in group[i + 1 :]:
                if a.serial_number and b.serial_number:  # two different serials: not the same machine
                    continue
                lo, hi = sorted((a.id, b.id), key=str)
                if (lo, hi) in dismissed:
                    continue
                pairs.append((lo, hi))
    return pairs
