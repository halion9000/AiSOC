"""A person's decisions about "possible duplicate" devices (see ``possible_duplicates``): say two are NOT the same machine, or merge them into one.

Both are stored on the client tenant, so every person in the organization sees the same decision. The caller owns the transaction and has put ``db`` in the client's scope.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.models.device import Device, DeviceMergeDismissal, DeviceMergeLog, DeviceSource


class DeviceMergeError(ValueError):
    """The request cannot be done; the message is safe to show."""


def _ordered(a: uuid.UUID, b: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
    lo, hi = sorted((a, b), key=str)
    return lo, hi


async def _both(db: Any, tenant_id: uuid.UUID, a: uuid.UUID, b: uuid.UUID) -> tuple[Device, Device]:
    if a == b:
        raise DeviceMergeError("Pick two different devices.")
    found = {
        d.id: d for d in (await db.execute(select(Device).where(Device.tenant_id == tenant_id, Device.id.in_([a, b])))).scalars().all()
    }
    if a not in found or b not in found:
        raise DeviceMergeError("Both devices must belong to the same client.")
    return found[a], found[b]


async def dismiss_pair(db: Any, tenant_id: uuid.UUID, a: uuid.UUID, b: uuid.UUID) -> None:
    """Remember that these two devices are different machines, so they are not suggested again. Saying it twice is fine."""
    await _both(db, tenant_id, a, b)
    lo, hi = _ordered(a, b)
    await db.execute(pg_insert(DeviceMergeDismissal).values(tenant_id=tenant_id, device_a=lo, device_b=hi).on_conflict_do_nothing())


UNDO_WINDOW = timedelta(days=14)
_COPIED = ("os", "os_version", "manufacturer", "model")


def snapshot_of(device: Any) -> dict[str, Any]:
    """The removed device as it was: enough to recreate it."""
    return {
        "id": str(device.id),
        "hostname": device.hostname,
        "serial_number": device.serial_number,
        "os": device.os,
        "os_version": device.os_version,
        "manufacturer": device.manufacturer,
        "model": device.model,
        "ip_addresses": list(device.ip_addresses or []),
        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
    }


def can_undo(entry: Any, now: datetime | None = None) -> bool:
    """A merge can be undone while it is recent and has not been undone already."""
    moment = now or datetime.now(UTC)
    created = entry.created_at if entry.created_at.tzinfo else entry.created_at.replace(tzinfo=UTC)
    return entry.undone_at is None and moment - created <= UNDO_WINDOW


async def merge_devices(
    db: Any, tenant_id: uuid.UUID, keep_id: uuid.UUID, remove_id: uuid.UUID, actor_id: uuid.UUID | None = None
) -> uuid.UUID:
    """Fold ``remove_id`` into ``keep_id``: every tool that reported the removed device now reports the kept one, blanks on the kept device are filled from the removed one,
    and the removed device is deleted. Two devices with different serial numbers are different machines and are refused."""
    keep, remove = await _both(db, tenant_id, keep_id, remove_id)
    if keep.serial_number and remove.serial_number and keep.serial_number != remove.serial_number:
        raise DeviceMergeError("These have different serial numbers, so they are different machines.")

    removed_snapshot = snapshot_of(remove)
    moved = (await db.execute(select(DeviceSource).where(DeviceSource.device_id == remove.id))).scalars().all()
    moved_ids = [str(s.id) for s in moved]
    for source in moved:
        source.device_id = keep.id
    filled: dict[str, Any] = {"fields": [], "ip_addresses": False, "first_seen_was": None, "carried_serial": None}
    for name in _COPIED:
        if getattr(keep, name) is None and getattr(remove, name) is not None:
            setattr(keep, name, getattr(remove, name))
            filled["fields"].append(name)
    if not keep.ip_addresses and remove.ip_addresses:
        keep.ip_addresses = list(remove.ip_addresses)
        filled["ip_addresses"] = True
    if remove.first_seen < keep.first_seen:
        filled["first_seen_was"] = keep.first_seen.isoformat()
        keep.first_seen = remove.first_seen
    carried_serial = remove.serial_number if keep.serial_number is None else None
    filled["carried_serial"] = carried_serial
    await db.flush()

    # The serial is unique per client, so the removed device has to be gone before the kept one can take its serial. Its dismissals go with it (they cascade).
    await db.execute(delete(Device).where(Device.id == remove.id))
    db.expunge(remove)
    if carried_serial:
        keep.serial_number = carried_serial
    db.add(
        DeviceMergeLog(
            tenant_id=tenant_id,
            kept_device_id=keep.id,
            removed=removed_snapshot,
            moved_source_ids=moved_ids,
            filled=filled,
            created_by=actor_id,
        )
    )
    await db.flush()
    return keep.id


async def undo_merge(db: Any, tenant_id: uuid.UUID, merge_id: uuid.UUID, now: datetime | None = None) -> uuid.UUID:
    """Reverse a merge: recreate the removed device with its own id and serial, move its feed rows back, and put back what was filled in on the kept device. Returns the recreated device's id.

    Refused (with a message safe to show) when the merge is too old, was already undone, or the kept device is gone. Dismissals the removed device had are not restored.
    """
    entry = (
        await db.execute(select(DeviceMergeLog).where(DeviceMergeLog.id == merge_id, DeviceMergeLog.tenant_id == tenant_id))
    ).scalar_one_or_none()
    if entry is None:
        raise DeviceMergeError("That merge was not found.")
    if entry.undone_at is not None:
        raise DeviceMergeError("That merge was already undone.")
    if not can_undo(entry, now):
        raise DeviceMergeError("That merge is too old to undo.")
    keep = (await db.execute(select(Device).where(Device.id == entry.kept_device_id, Device.tenant_id == tenant_id))).scalar_one_or_none()
    if keep is None:
        raise DeviceMergeError("The device it was merged into no longer exists, so this cannot be undone.")
    removed = entry.removed
    filled = entry.filled or {}
    restored_id = uuid.UUID(removed["id"])
    if (await db.execute(select(Device.id).where(Device.id == restored_id))).first() is not None:
        raise DeviceMergeError("A device with the removed device's id already exists, so this cannot be undone.")

    # The serial is unique per client: if the kept device took the removed one's serial, give it back before the removed device is recreated.
    carried = filled.get("carried_serial")
    if carried and keep.serial_number == carried:
        keep.serial_number = None
        await db.flush()
    db.add(
        Device(
            id=restored_id,
            tenant_id=tenant_id,
            hostname=removed["hostname"],
            serial_number=removed.get("serial_number"),
            os=removed.get("os"),
            os_version=removed.get("os_version"),
            manufacturer=removed.get("manufacturer"),
            model=removed.get("model"),
            ip_addresses=list(removed.get("ip_addresses") or []),
            first_seen=datetime.fromisoformat(removed["first_seen"]) if removed.get("first_seen") else datetime.now(UTC),
            last_seen=datetime.fromisoformat(removed["last_seen"]) if removed.get("last_seen") else datetime.now(UTC),
        )
    )
    await db.flush()
    moved_ids = [uuid.UUID(x) for x in entry.moved_source_ids or []]
    if moved_ids:
        for source in (
            (await db.execute(select(DeviceSource).where(DeviceSource.id.in_(moved_ids), DeviceSource.device_id == keep.id)))
            .scalars()
            .all()
        ):
            source.device_id = restored_id
    for name in filled.get("fields", []):
        if getattr(keep, name) == removed.get(name):
            setattr(keep, name, None)
    if filled.get("ip_addresses") and list(keep.ip_addresses or []) == list(removed.get("ip_addresses") or []):
        keep.ip_addresses = []
    if filled.get("first_seen_was"):
        keep.first_seen = datetime.fromisoformat(filled["first_seen_was"])
    entry.undone_at = now or datetime.now(UTC)
    await db.flush()
    return restored_id
