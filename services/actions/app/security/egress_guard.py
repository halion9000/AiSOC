"""Outbound-request guard for the actions service (SSRF). The same guard the connectors service uses (services/connectors/app/security/egress_guard.py).

Response actions call hosts that come from the REQUEST (`webhook_url`, `splunk_url`, `*_base_url`, `panos_host`, ...). Without a guard a caller holding the service token could point an action at the cloud metadata address (169.254.169.254), this host's loopback services or another internal service, and vendor executors would send their credentials to whatever host was named. The policy is enforced on the HTTP layer: every httpx client created after install() carries a request hook, and httpx runs it for every hop of a redirect.

POLICY: deliberately narrow, because on-prem integrations legitimately live on private addresses (a customer's Splunk or firewall on 10.x is the normal case), so RFC1918 / unique-local ranges are ALLOWED. Refused: a non-http(s) scheme; loopback; link-local (which contains the AWS/Azure/GCP metadata address); the unspecified address; multicast; reserved ranges; and the
metadata addresses that are not link-local (fd00:ec2::254, 100.100.100.200). A hostname is resolved and refused if ANY address it resolves to is refused. A name that does not resolve is let through (the request fails on its own).
ESCAPE HATCHES: ACTIONS_EGRESS_ALLOW_HOSTS (comma-separated hostnames or IPs that are always allowed) and ACTIONS_EGRESS_ALLOW_LOOPBACK=1 (local development, where the platform's own services are on localhost). ACTIONS_EGRESS_GUARD=0 turns the guard off.
LIMIT: resolve-then-connect leaves a DNS-rebinding window (a name that resolves differently at connect time). This narrows the SSRF surface a great deal; it is not a network egress firewall, and a network policy that denies the metadata address from this service remains the stronger control.
"""

from __future__ import annotations

import asyncio
import collections
import ipaddress
import logging
import os
import socket
import time
from datetime import UTC, datetime

import httpx

logger = logging.getLogger(__name__)

_EXTRA_BLOCKED = (ipaddress.ip_address("fd00:ec2::254"), ipaddress.ip_address("100.100.100.200"))
_INSTALLED_FLAG = "_aisoc_egress_guard_installed"


class EgressBlocked(httpx.RequestError):
    """The request was refused by the egress guard (reported like any other network failure, so the executors' existing error handling applies)."""


def _enabled() -> bool:
    return os.getenv("ACTIONS_EGRESS_GUARD", "1").strip().lower() not in {"0", "false", "no", "off"}


def _allow_loopback() -> bool:
    return os.getenv("ACTIONS_EGRESS_ALLOW_LOOPBACK", "").strip().lower() in {"1", "true", "yes", "on"}


def _allowed_hosts() -> set[str]:
    hosts = {h.strip().lower() for h in os.getenv("ACTIONS_EGRESS_ALLOW_HOSTS", "").split(",") if h.strip()}
    return hosts


def _unwrap(ip: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    """An IPv4-mapped IPv6 address (::ffff:169.254.169.254) is judged as the IPv4 address it carries."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def address_is_blocked(ip: ipaddress._BaseAddress) -> bool:
    ip = _unwrap(ip)
    if ip in _EXTRA_BLOCKED:
        return True
    if ip.is_loopback:
        return not _allow_loopback()
    return ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved


def _literal_ip(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


_RESOLVE_TTL_SECONDS = 60.0
_resolve_cache: dict[str, tuple[float, list[ipaddress._BaseAddress]]] = {}


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    """Every address `host` resolves to ([] if it does not resolve), remembered for a minute: failures included, because a name that does not resolve costs a full resolver timeout each
    time it is tried. A seam for tests (they replace this function)."""
    now = time.monotonic()
    hit = _resolve_cache.get(host)
    if hit is not None and now - hit[0] < _RESOLVE_TTL_SECONDS:
        return list(hit[1])
    addrs = _lookup(host)
    if len(_resolve_cache) > 1024:
        _resolve_cache.clear()
    _resolve_cache[host] = (now, addrs)
    return list(addrs)


def _lookup(host: str) -> list[ipaddress._BaseAddress]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0].split("%")[0]))
        except ValueError:
            continue
    return out


def _refusal(url: httpx.URL, addresses: list[ipaddress._BaseAddress] | None = None) -> str | None:
    """Why `url` may not be requested, or None if it may."""
    if url.scheme not in ("http", "https"):
        return f"scheme {url.scheme!r} is not allowed"
    host = (url.host or "").lower()
    if not host:
        return "the URL has no host"
    if host in _allowed_hosts():
        return None
    if host == "localhost" or host.endswith(".localhost"):
        return None if _allow_loopback() else "loopback addresses are not allowed"
    literal = _literal_ip(host)
    if literal is not None:
        addrs = [literal]
    elif "." not in host:
        addrs = []  # a single-label name is not resolved (see check_request_async)
    else:
        addrs = addresses if addresses is not None else _resolve(host)
    for ip in addrs:
        if address_is_blocked(ip):
            return f"{host} resolves to {_unwrap(ip)}, which is not a permitted destination"
    return None


# The last refusals, for an operator asking "what did the guard stop?": host and reason only (never a path, query or header, which can carry secrets). In memory, per process.
_RECENT_LIMIT = 100
_recent: collections.deque[dict[str, object]] = collections.deque(maxlen=_RECENT_LIMIT)


def _record_block(request: httpx.Request, reason: str) -> None:
    _recent.append({"at": datetime.now(UTC).isoformat(), "host": (request.url.host or "").lower(), "reason": reason})


def recent_blocked() -> list[dict[str, object]]:
    """The most recent refusals, newest first."""
    return list(reversed(_recent))


def check_request_sync(request: httpx.Request) -> None:
    reason = _refusal(request.url) if _enabled() else None
    if reason:
        logger.warning("actions.egress_blocked reason=%s", reason)
        _record_block(request, reason)
        raise EgressBlocked(f"Request blocked by the egress guard: {reason}", request=request)


async def check_request_async(request: httpx.Request) -> None:
    if not _enabled():
        return
    host = (request.url.host or "").lower()
    addresses = None
    # A name with no dot ("test", "testserver", a compose service name) cannot be attacker-registered public DNS (that is how a public name is pointed at 169.254.169.254), so it is not
    # resolved: the lookup of a name that does not exist ran for the whole resolver timeout, which delayed in-process transports and made timing-sensitive tests fail. "localhost" is still
    # refused by name in _refusal.
    if host and "." in host and _literal_ip(host) is None and host not in _allowed_hosts():
        loop = asyncio.get_running_loop()
        addresses = await loop.run_in_executor(None, _resolve, host)  # never block the event loop on DNS
    reason = _refusal(request.url, addresses)
    if reason:
        logger.warning("actions.egress_blocked reason=%s", reason)
        _record_block(request, reason)
        raise EgressBlocked(f"Request blocked by the egress guard: {reason}", request=request)


def install_egress_guard() -> None:
    """Make every httpx client created from now on carry the guard (idempotent). Hooks a caller supplies are kept and run after it."""
    if getattr(httpx.AsyncClient, _INSTALLED_FLAG, False):
        return
    original_async, original_sync = httpx.AsyncClient.__init__, httpx.Client.__init__

    def async_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        hooks = dict(kwargs.get("event_hooks") or {})
        hooks["request"] = [check_request_async, *list(hooks.get("request", []))]
        kwargs["event_hooks"] = hooks
        original_async(self, *args, **kwargs)

    def sync_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        hooks = dict(kwargs.get("event_hooks") or {})
        hooks["request"] = [check_request_sync, *list(hooks.get("request", []))]
        kwargs["event_hooks"] = hooks
        original_sync(self, *args, **kwargs)

    httpx.AsyncClient.__init__ = async_init  # type: ignore[method-assign]
    httpx.Client.__init__ = sync_init  # type: ignore[method-assign]
    setattr(httpx.AsyncClient, _INSTALLED_FLAG, True)
    setattr(httpx.Client, _INSTALLED_FLAG, True)
