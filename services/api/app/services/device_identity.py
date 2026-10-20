"""How a device is recognised across tools: the serial number is the key, the hostname only suggests.

A serial number is trusted to be the same machine in every tool, so devices from different tools merge on it automatically. Tools often report junk instead of a real serial
("To Be Filled By O.E.M.", "0", "Default string"), and two unrelated machines would then merge, so those values count as no serial. A hostname alone is NOT trusted: the same name can be two
machines (or one machine renamed). A pair is merged on its name only when it is unambiguous (``device_merge.auto_merge_same_name``); every other name match is a "possible duplicate" for a person to confirm.
"""

from __future__ import annotations

import re

_PLACEHOLDERS = frozenset(
    {
        "TOBEFILLEDBYOEM",
        "TOBEFILLEDBYO.E.M.",
        "DEFAULTSTRING",
        "SYSTEMSERIALNUMBER",
        "SERIALNUMBER",
        "NONE",
        "NA",
        "N/A",
        "NULL",
        "UNKNOWN",
        "NOTSPECIFIED",
        "NOTAPPLICABLE",
        "OEM",
        "O.E.M.",
        "TOBEFILLEDBYO.E.M",
        "INVALID",
        "NOSERIAL",
        "NOSERIALNUMBER",
        "XXXXXXXX",
        "123456789",
        "1234567890",
        "0123456789",
    }
)
_MIN_SERIAL_LEN = 4


def normalize_serial(raw: object) -> str | None:
    """The comparable form of a serial number, or None when the value is empty or a known placeholder."""
    if raw is None:
        return None
    text = re.sub(r"\s+", "", str(raw)).upper()
    if len(text) < _MIN_SERIAL_LEN or text in _PLACEHOLDERS:
        return None
    if len(set(text)) == 1:  # 0000000, XXXXXXX, 1111111
        return None
    return text[:100]


def hostname_key(raw: object) -> str:
    """A hostname reduced for comparison: lower-case, first label only (``PC-01.corp.local`` and ``pc-01`` are one name)."""
    text = str(raw or "").strip().lower()
    return text.split(".", 1)[0].strip()
