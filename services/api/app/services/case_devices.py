"""The devices a case is about, each with a link to it in the tool that knows it.

A case holds alerts; each alert names the machines it is about. For every machine the case lists where to open it: the alert's own link into the tool that raised it (Huntress), and the link the
device's record holds from each tool that reports it (NinjaOne). Only plain https addresses are passed on. Pure functions here, so they can be tested without a database; the route loads the rows.
"""

from __future__ import annotations

import re
from typing import Any

_HTTPS = re.compile(r"^https://[^\s]+$", re.IGNORECASE)
_MAX_URL = 1000

VENDOR_LABELS = {"huntress": "Huntress", "ninjaone": "NinjaOne", "addigy": "Addigy", "blumira": "Blumira", "threatmate": "ThreatMate", "dnsfilter": "DNSFilter", "screenconnect": "ScreenConnect", "fieldeffect": "Field Effect"}
# Which key of a device record's details holds the tool's own page for the device. Add a tool here once its record carries one.
SOURCE_URL_KEYS = {"ninjaone": "url", "screenconnect": "url"}


def _https(value: Any) -> str | None:
    return value if isinstance(value, str) and len(value) <= _MAX_URL and _HTTPS.match(value) else None


def _hosts(alert: Any) -> list[str]:
    hosts = alert.affected_hosts if isinstance(getattr(alert, "affected_hosts", None), list) else []
    return [h.strip() for h in hosts if isinstance(h, str) and h.strip()]


def _alert_device_link(alert: Any) -> tuple[str, str] | None:
    raw = alert.raw_event if isinstance(getattr(alert, "raw_event", None), dict) else {}
    links = raw.get("links") if isinstance(raw.get("links"), dict) else {}
    url = _https(links.get("device_url"))
    source = raw.get("source")
    return (str(source), url) if url and isinstance(source, str) else None


def build_case_devices(alerts: list[Any], devices: list[Any], sources: list[Any]) -> list[dict[str, Any]]:
    """One entry per machine the case's alerts name, A to Z, with every link to it. ``devices`` are this client's device records, ``sources`` their per-tool rows."""
    by_host = {str(d.hostname).lower(): d for d in devices}
    sources_of: dict[Any, list[Any]] = {}
    for s in sources:
        sources_of.setdefault(s.device_id, []).append(s)

    found: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        link = _alert_device_link(alert)
        for host in _hosts(alert):
            entry = found.setdefault(host.lower(), {"hostname": host, "alerts": 0, "links": {}})
            entry["alerts"] += 1
            if link:
                entry["links"].setdefault(link[0], link[1])

    out: list[dict[str, Any]] = []
    for key, entry in found.items():
        device = by_host.get(key)
        if device is not None:
            for s in sources_of.get(device.id, []):
                url_key = SOURCE_URL_KEYS.get(s.vendor)
                url = _https((s.details or {}).get(url_key)) if url_key else None
                if url:
                    entry["links"].setdefault(s.vendor, url)
        out.append(
            {
                "hostname": entry["hostname"],
                "device_id": str(device.id) if device is not None else None,
                "os": getattr(device, "os", None) if device is not None else None,
                "alerts": entry["alerts"],
                "links": [{"vendor": v, "label": VENDOR_LABELS.get(v, v), "url": u} for v, u in sorted(entry["links"].items())],
            }
        )
    return sorted(out, key=lambda d: d["hostname"].lower())
