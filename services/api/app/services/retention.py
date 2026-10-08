"""Configurable data-retention policies (Wave 5, W5.1).

Per-tenant retention windows for each data class, plus the bounded, tenant-
scoped purge SQL that enforces them. Pure functions — the scheduler/worker that
runs the purge composes these; the API exposes get/set. Bounds keep a
misconfiguration (0 days / 100 years) from nuking or never-purging data.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass

MIN_DAYS = 1
MAX_DAYS = 3650  # 10 years

# Data classes we retain, with sane defaults (days).
DEFAULT_RETENTION: dict[str, int] = {
    "raw_events": 90,  # ClickHouse lake
    "alerts": 365,  # Postgres alerts
    "audit": 730,  # audit/ledger — longer for compliance
}


@dataclass(frozen=True)
class RetentionPolicy:
    raw_events_days: int = DEFAULT_RETENTION["raw_events"]
    alerts_days: int = DEFAULT_RETENTION["alerts"]
    audit_days: int = DEFAULT_RETENTION["audit"]

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


def _clamp(value: int) -> int:
    return max(MIN_DAYS, min(MAX_DAYS, int(value)))


def resolve_policy(config: dict[str, int] | None) -> RetentionPolicy:
    """Merge a tenant's stored config over defaults, clamped to safe bounds."""
    cfg = dict(config or {})
    return RetentionPolicy(
        raw_events_days=_clamp(cfg.get("raw_events_days", DEFAULT_RETENTION["raw_events"])),
        alerts_days=_clamp(cfg.get("alerts_days", DEFAULT_RETENTION["alerts"])),
        audit_days=_clamp(cfg.get("audit_days", DEFAULT_RETENTION["audit"])),
    )


def build_lake_purge_sql(tenant_id: uuid.UUID, days: int) -> str:
    """Tenant-scoped ClickHouse purge of lake events older than ``days``.

    Uses a lightweight ``ALTER TABLE … DELETE`` (ClickHouse mutation). The
    tenant predicate is mandatory so a purge can never cross tenants; the day
    count is clamped and interpolated as an integer literal (never string)."""
    days = _clamp(days)
    tid = str(tenant_id)
    # tenant_id is a UUID (validated by type); days is an int literal.
    return "ALTER TABLE aisoc.raw_events DELETE " f"WHERE tenant_id = '{tid}' AND event_time < now() - INTERVAL {days} DAY"


def build_alert_purge_sql(tenant_id: uuid.UUID, days: int) -> tuple[str, dict[str, object]]:
    """Postgres purge of ONE tenant's alerts older than ``days``. NOT WIRED to anything (nothing enforces alert retention yet).

    The tenant predicate is EXPLICIT. This used to say "RLS scopes the tenant" and filter on nothing else: but the services connect as the Postgres superuser by default, which bypasses RLS, so running it for one
    tenant's window would have deleted EVERY tenant's old alerts. A purge must never depend on RLS for tenant scoping. Parameterised: never string-interpolate the cutoff or the tenant."""
    days = _clamp(days)
    sql = "DELETE FROM alerts WHERE tenant_id = :tenant_id AND created_at < now() - make_interval(days => :days)"
    return sql, {"tenant_id": tenant_id, "days": days}


# Response actions in these states are finished: only these may ever be swept. An action that is pending, awaiting approval, approved or RUNNING is live (or may have executed without an outcome being recorded)
# and must never be deleted by age.
TERMINAL_ACTION_STATUSES = ("completed", "failed", "rejected", "rolled_back")


def clamp_days(value: int) -> int:
    """The same bounds as every retention window: 1 day to 10 years, so a misconfiguration can neither delete everything now nor keep everything forever."""
    return _clamp(value)
