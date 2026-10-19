"""EASM active-scan targets are public IP addresses, few, and probed with bounded concurrency.

``ip_targets`` was an unvalidated ``list[str]`` and ``_active_scan`` gathered one TCP connect per (target, port) with no bound: a tenant admin could point the API host at 169.254.169.254, a loopback or an internal service name,
read the open ports back from /easm/assets, or open thousands of sockets at once.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from app.api.v1.endpoints.easm import ScanRequest
from app.services import easm_discovery
from pydantic import ValidationError

T = uuid.uuid4()


def test_public_ip_targets_are_accepted():
    assert ScanRequest(tenant_id=T, ip_targets=["8.8.8.8", "2001:4860:4860::8888"]).ip_targets == ["8.8.8.8", "2001:4860:4860::8888"]


@pytest.mark.parametrize(
    "bad",
    [
        "169.254.169.254",
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.9",
        "0.0.0.0",
        "::1",
        "redis",
        "aisoc-postgres",
        "evil.example.test",
        "8.8.8.0/24",
        "8.8.8.8:80",
        "",
    ],
)
def test_non_public_or_non_ip_targets_are_refused(bad):
    with pytest.raises(ValidationError):
        ScanRequest(tenant_id=T, ip_targets=[bad])


def test_the_number_of_targets_is_capped():
    ScanRequest(tenant_id=T, ip_targets=[f"8.8.{i // 250}.{i % 250 + 1}" for i in range(64)])
    with pytest.raises(ValidationError):
        ScanRequest(tenant_id=T, ip_targets=[f"8.8.{i // 250}.{i % 250 + 1}" for i in range(65)])


@pytest.mark.asyncio
async def test_probes_run_with_bounded_concurrency(monkeypatch):
    live = {"now": 0, "max": 0}

    async def probe(host, port, timeout=3.0):
        live["now"] += 1
        live["max"] = max(live["max"], live["now"])
        await asyncio.sleep(0.01)
        live["now"] -= 1
        return False

    monkeypatch.setattr(easm_discovery, "_probe_port", probe)
    await easm_discovery._active_scan([f"8.8.8.{i}" for i in range(1, 41)], [22, 80, 443, 3389])  # 160 probes
    assert live["max"] <= easm_discovery._MAX_CONCURRENT_PROBES
    assert easm_discovery._MAX_CONCURRENT_PROBES <= 64


def test_the_tenant_is_optional_so_the_console_can_scan_its_own_tenant():
    assert ScanRequest().tenant_id is None
    assert ScanRequest(ip_targets=["8.8.8.8"]).ip_targets == ["8.8.8.8"]
