"""A person's decisions about "possible duplicate" devices (see ``possible_duplicates``): say two are NOT the same machine, or merge them into one.

Both are stored on the client tenant, so every person in the organization sees the same decision. The caller owns the transaction and has put ``db`` in the client's scope.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.models.device import Device, DeviceMergeDismissal, DeviceSource


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


async def merge_devices(db: Any, tenant_id: uuid.UUID, keep_id: uuid.UUID, remove_id: uuid.UUID) -> uuid.UUID:
    """Fold ``remove_id`` into ``keep_id``: every tool that reported the removed device now reports the kept one, blanks on the kept device are filled from the removed one,
    and the removed device is deleted. Two devices with different serial numbers are different machines and are refused."""
    keep, remove = await _both(db, tenant_id, keep_id, remove_id)
    if keep.serial_number and remove.serial_number and keep.serial_number != remove.serial_number:
        raise DeviceMergeError("These have different serial numbers, so they are different machines.")

    for source in (await db.execute(select(DeviceSource).where(DeviceSource.device_id == remove.id))).scalars().all():
        source.device_id = keep.id
    for name in ("os", "os_version", "manufacturer", "model"):
        if getattr(keep, name) is None and getattr(remove, name) is not None:
            setattr(keep, name, getattr(remove, name))
    if not keep.ip_addresses and remove.ip_addresses:
        keep.ip_addresses = list(remove.ip_addresses)
    if remove.first_seen < keep.first_seen:
        keep.first_seen = remove.first_seen
    carried_serial = remove.serial_number if keep.serial_number is None else None
    await db.flush()

    # The serial is unique per client, so the removed device has to be gone before the kept one can take its serial. Its dismissals go with it (they cascade).
    await db.execute(delete(Device).where(Device.id == remove.id))
    db.expunge(remove)
    if carried_serial:
        keep.serial_number = carried_serial
    await db.flush()
    return keep.id
