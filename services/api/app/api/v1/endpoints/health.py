"""Pipeline health endpoint — operator-facing snapshot of the SOC pipeline.

Backs ``GET /api/v1/health/pipeline`` (v1.5 SOC Console parity).

Returns a 5-row strip describing the health of each stage of the
pipeline ``ingest → normalize → fuse → correlate → alert``. The shape
matches the ``PipelineHealth`` Pydantic model declared alongside the
funnel response in ``endpoints/metrics.py`` so the funnel and pipeline-
health views can share the same schema package.

Honest-measurement principles
-----------------------------

The plan calls for ``{backlog, p95_latency_ms, error_rate, status}`` per
stage. We compute each cell from data we *actually have* — no synthetic
fillers, no fake percentiles. When a column is genuinely unknowable
without deeper instrumentation (e.g. fusion-engine job timings), the
response is ``0`` (numeric) or ``unknown`` (status). The SOC Console UI
renders zeros as "n/a" pills rather than zero-bars so operators don't
read absence as "all good".

Per-stage definitions
---------------------

* **ingest** — events arriving from connectors. ``status`` aggregates
  ``app.services.connector_freshness`` across all enabled connectors
  (worst-of). ``backlog`` is the number of enabled connectors that
  haven't fired an event within 2× their per-category cadence (the
  ``red`` band in ``connector_freshness``). ``error_rate`` is
  ``unhealthy / enabled`` from ``Connector.health_status``.
  ``p95_latency_ms`` is left at 0 — we don't carry a source-side
  timestamp on the wire to compute true ingest lag.

* **normalize** — raw event JSON → structured ``Alert`` fields
  (event_time, src/dst, MITRE, severity). ``p95_latency_ms`` is
  ``percentile_cont(0.95) WITHIN GROUP (created_at - event_time)`` for
  alerts in the last hour where ``event_time`` was set. ``backlog``
  is 0 (no queue at this layer in the current pipeline). ``error_rate``
  is 0 — parse errors are not yet surfaced to Postgres.

* **fuse** — events grouped into alerts. ``p95_latency_ms`` is
  ``percentile_cont(0.95) WITHIN GROUP (last_seen - first_seen)`` for
  alerts in the window. ``backlog`` is 0 (the fusion engine doesn't
  queue alerts — it emits or drops). ``error_rate`` is 0.

* **correlate** — multi-event correlation. ``backlog`` is the count of
  recent *single-event* alerts (``jsonb_array_length(source_event_ids)
  = 1``) in the window — alerts that haven't yet been merged into a
  richer incident. ``p95_latency_ms`` is left at 0 (the fusion service
  doesn't emit per-correlation-job timing yet).

* **alert** — alert visible to analyst. ``backlog`` is the open queue
  depth (``status in ('new','triaging','in_progress')`` AND
  ``first_seen_at IS NULL``). ``p95_latency_ms`` is
  ``percentile_cont(0.95) WITHIN GROUP (first_seen_at - created_at)``
  — i.e. MTTD p95. ``error_rate`` is 0.

Status ladder
-------------

Each stage's status follows the same ladder used by
``connector_freshness``: ``unknown | green | yellow | red``. The
thresholds for latency-driven stages are read from two configurable
knobs in ``app.core.config``:

* ``AISOC_PIPELINE_STALE_WARN_SECONDS`` (default 600) — green ceiling
* ``AISOC_PIPELINE_STALE_DOWN_SECONDS`` (default 1800) — yellow ceiling

Any stage with no data in the window collapses to ``unknown`` rather
than ``green``, mirroring the "never paint green on absence of data"
rule in ``connector_freshness``.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import and_, func, select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.metrics import PipelineHealth, PipelineStage
from app.core.config import settings
from app.models.alert import Alert
from app.models.connector import Connector
from app.services.connector_freshness import compute_freshness

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", summary="Reachability probe for the web UI (no auth, no DB)")
async def api_reachability() -> dict:
    """Cheap probe the web UI uses to show whether the API is reachable.

    The Copilot dock calls GET /api/v1/health for its connected/disconnected
    badge. It must live under /api/v1 because the Next.js rewrite only proxies
    /api/v1/*; the root /health is not reachable from the browser. Before this
    route existed the probe always 404'd, so the dock always said
    "disconnected". Deliberately no auth and no database work.
    """
    return {"status": "healthy", "service": "aisoc-api"}


# ───────────────────────────── Status helpers ────────────────────────────────


# Order from best to worst. ``unknown`` is slightly worse than ``green`` so a
# tenant with one brand-new (never-seen-an-event) connector still reports
# ``unknown`` overall rather than ``green`` — we never paint green on absence
# of data. Matches the convention enforced by ``connector_freshness``.
_STATUS_RANK: dict[str, int] = {"green": 0, "unknown": 1, "yellow": 2, "red": 3}


def _status_from_latency(
    *,
    p95_seconds: float | None,
    warn_seconds: int,
    down_seconds: int,
) -> str:
    """Map a p95 latency to ``unknown|green|yellow|red``.

    ``None`` (no data in the window) → ``unknown``; we deliberately do
    not return ``green`` for absence of data.
    """
    if p95_seconds is None:
        return "unknown"
    if p95_seconds <= warn_seconds:
        return "green"
    if p95_seconds <= down_seconds:
        return "yellow"
    return "red"


def _worst_status(statuses: list[str]) -> str:
    """Aggregate a list of statuses to the worst entry on ``_STATUS_RANK``."""
    if not statuses:
        return "unknown"
    return max(statuses, key=lambda s: _STATUS_RANK.get(s, 1))


# Postgres ``percentile_cont(p)`` returns ``double precision``. SQLAlchemy
# exposes it via the ``func`` namespace; we wrap the (admittedly verbose)
# ``WITHIN GROUP (ORDER BY ...)`` expression here so the per-stage helpers
# below stay readable.
def _p95_seconds_expr(expr: Any) -> Any:
    """Build a SQLA expression for ``percentile_cont(0.95) WITHIN GROUP``.

    ``expr`` is the per-row scalar to take the percentile of (already in
    seconds — callers pass ``func.extract('epoch', ...)``).
    """
    return func.percentile_cont(0.95).within_group(expr)


# ─────────────────────────────── ingest stage ────────────────────────────────


async def _ingest_stage(db, tenant_id, *, now: datetime) -> PipelineStage:
    """Build the ``ingest`` row from connector freshness aggregates.

    Reads every Connector for the tenant, runs ``compute_freshness``
    per row (which honours per-instance cadence overrides via
    ``connector_config.expected_cadence_seconds``), then rolls the
    per-connector statuses up to a single worst-of verdict.
    """
    rows = (
        await db.execute(
            select(
                Connector.category,
                Connector.connector_type,
                Connector.last_sync,
                Connector.last_event_at,
                Connector.health_status,
                Connector.is_enabled,
                Connector.connector_config,
            ).where(Connector.tenant_id == tenant_id)
        )
    ).all()

    enabled = [r for r in rows if r.is_enabled]
    if not enabled:
        # No enabled connectors → nothing is flowing on purpose. Status
        # ``unknown`` rather than red so a fresh tenant doesn't see a
        # paged alert before they've onboarded anything.
        return PipelineStage(
            stage="ingest",
            backlog=0,
            p95_latency_ms=0.0,
            error_rate=0.0,
            status="unknown",
        )

    statuses: list[str] = []
    backlog = 0
    unhealthy = 0
    for r in enabled:
        override: int | None = None
        if isinstance(r.connector_config, dict):
            raw_override = r.connector_config.get("expected_cadence_seconds")
            if isinstance(raw_override, int | float) and raw_override > 0:
                override = int(raw_override)
        # A connector CORE feeds is fresh when CORE last synced it OK, even if that sync found nothing new: "no alerts" is not "stale".
        seen = r.last_event_at
        last_sync = getattr(r, "last_sync", None)
        if getattr(r, "connector_type", None) == "core_feed" and last_sync is not None and (seen is None or last_sync > seen):
            seen = last_sync
        verdict = compute_freshness(
            category=r.category,
            last_event_at=seen,
            now=now,
            override_seconds=override,
        )
        statuses.append(verdict.status)
        if verdict.status == "red":
            backlog += 1
        if r.health_status == "unhealthy":
            unhealthy += 1

    error_rate = round(unhealthy / len(enabled), 4) if enabled else 0.0
    return PipelineStage(
        stage="ingest",
        backlog=backlog,
        p95_latency_ms=0.0,
        error_rate=error_rate,
        status=_worst_status(statuses),
    )


# ───────────────────────────── normalize stage ───────────────────────────────


async def _normalize_stage(
    db,
    tenant_id,
    *,
    warn_seconds: int,
    down_seconds: int,
    window_start: datetime,
    window_end: datetime,
) -> PipelineStage:
    """Build the ``normalize`` row from event_time → created_at lag.

    The "normalize" step in the AiSOC pipeline is the transition from
    raw event JSON (carrying a vendor-side ``event_time``) to a fully
    structured ``Alert`` row in Postgres. The p95 lag between the two
    is the most honest single-number proxy for normalization latency.
    """
    p95_seconds = await db.scalar(
        select(_p95_seconds_expr(func.extract("epoch", Alert.created_at - Alert.event_time))).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= window_start,
                Alert.created_at < window_end,
                Alert.event_time.isnot(None),
            )
        )
    )
    if p95_seconds is None:
        return PipelineStage(
            stage="normalize",
            backlog=0,
            p95_latency_ms=0.0,
            error_rate=0.0,
            status="unknown",
        )

    p95_seconds = max(0.0, float(p95_seconds))
    return PipelineStage(
        stage="normalize",
        backlog=0,
        p95_latency_ms=round(p95_seconds * 1000.0, 2),
        error_rate=0.0,
        status=_status_from_latency(
            p95_seconds=p95_seconds,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
        ),
    )


# ─────────────────────────────── fuse stage ──────────────────────────────────


async def _fuse_stage(
    db,
    tenant_id,
    *,
    warn_seconds: int,
    down_seconds: int,
    window_start: datetime,
    window_end: datetime,
) -> PipelineStage:
    """Build the ``fuse`` row from first_seen → last_seen spread.

    A single Alert can absorb many raw events. The spread between the
    earliest and latest contributing event (first_seen → last_seen)
    is the closest single-number proxy for fusion latency we can
    compute without instrumenting the fusion service itself.
    """
    p95_seconds = await db.scalar(
        select(_p95_seconds_expr(func.extract("epoch", Alert.last_seen - Alert.first_seen))).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= window_start,
                Alert.created_at < window_end,
                Alert.first_seen.isnot(None),
                Alert.last_seen.isnot(None),
            )
        )
    )
    if p95_seconds is None:
        return PipelineStage(
            stage="fuse",
            backlog=0,
            p95_latency_ms=0.0,
            error_rate=0.0,
            status="unknown",
        )

    p95_seconds = max(0.0, float(p95_seconds))
    return PipelineStage(
        stage="fuse",
        backlog=0,
        p95_latency_ms=round(p95_seconds * 1000.0, 2),
        error_rate=0.0,
        status=_status_from_latency(
            p95_seconds=p95_seconds,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
        ),
    )


# ───────────────────────────── correlate stage ───────────────────────────────


async def _correlate_stage(
    db,
    tenant_id,
    *,
    window_start: datetime,
    window_end: datetime,
) -> PipelineStage:
    """Build the ``correlate`` row from single-event-alert backlog.

    Backlog = alerts in the window with exactly one source event (i.e.
    not yet correlated). Status is ``green`` if at least one alert in
    the window has multiple source events (correlation engine is
    working), ``yellow`` if alerts exist but none are multi-event
    (correlation engine is idle), and ``unknown`` if there are no
    alerts at all in the window.
    """
    single_event = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= window_start,
                    Alert.created_at < window_end,
                    func.jsonb_array_length(Alert.source_event_ids) == 1,
                )
            )
        )
        or 0
    )
    multi_event = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= window_start,
                    Alert.created_at < window_end,
                    func.jsonb_array_length(Alert.source_event_ids) >= 2,
                )
            )
        )
        or 0
    )

    total = int(single_event) + int(multi_event)
    if total == 0:
        status = "unknown"
    elif multi_event > 0:
        status = "green"
    else:
        status = "yellow"

    return PipelineStage(
        stage="correlate",
        backlog=int(single_event),
        p95_latency_ms=0.0,
        error_rate=0.0,
        status=status,
    )


# ─────────────────────────────── alert stage ─────────────────────────────────


async def _alert_stage(
    db,
    tenant_id,
    *,
    warn_seconds: int,
    down_seconds: int,
    window_start: datetime,
    window_end: datetime,
) -> PipelineStage:
    """Build the ``alert`` row from MTTD p95 + open-queue depth.

    Backlog is the open-queue depth (alerts visible to an analyst that
    haven't been viewed yet). ``p95_latency_ms`` is MTTD p95 — the
    p95 wall-clock gap between ``created_at`` (the alert appeared in
    Postgres) and ``first_seen_at`` (the analyst opened it).
    """
    unacked = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.status.in_(("new", "triaging", "in_progress")),
                    Alert.first_seen_at.is_(None),
                )
            )
        )
        or 0
    )

    p95_seconds = await db.scalar(
        select(_p95_seconds_expr(func.extract("epoch", Alert.first_seen_at - Alert.created_at))).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= window_start,
                Alert.created_at < window_end,
                Alert.first_seen_at.isnot(None),
            )
        )
    )

    if p95_seconds is None:
        # No alerts have been seen by an analyst in the window. If
        # there are unacked alerts in the queue we report ``yellow``
        # (the analyst is behind); otherwise ``unknown`` (no data).
        status = "yellow" if unacked > 0 else "unknown"
        latency_ms = 0.0
    else:
        p95_seconds = max(0.0, float(p95_seconds))
        latency_ms = round(p95_seconds * 1000.0, 2)
        status = _status_from_latency(
            p95_seconds=p95_seconds,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
        )

    return PipelineStage(
        stage="alert",
        backlog=int(unacked),
        p95_latency_ms=latency_ms,
        error_rate=0.0,
        status=status,
    )


# ─────────────────────────────── endpoint ────────────────────────────────────


@router.get("/pipeline", response_model=PipelineHealth)
async def get_pipeline_health(
    user: AuthUser,
    db: DBSession,
) -> PipelineHealth:
    """Return a 5-stage health snapshot of the SOC pipeline for the tenant.

    Stages: ``ingest → normalize → fuse → correlate → alert``. See the
    module docstring for what each cell measures and why some columns
    are intentionally ``0`` until deeper instrumentation lands.

    The window for latency / backlog computations is the last hour.
    The ``status`` ladder is ``unknown | green | yellow | red`` and
    follows the same convention as
    ``app.services.connector_freshness``.
    """
    now = datetime.now(UTC)
    window_start = now - timedelta(hours=1)
    window_end = now

    warn_seconds = int(getattr(settings, "AISOC_PIPELINE_STALE_WARN_SECONDS", 600) or 600)
    down_seconds = int(getattr(settings, "AISOC_PIPELINE_STALE_DOWN_SECONDS", 1800) or 1800)

    stages = [
        await _ingest_stage(db, user.tenant_id, now=now),
        await _normalize_stage(
            db,
            user.tenant_id,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
            window_start=window_start,
            window_end=window_end,
        ),
        await _fuse_stage(
            db,
            user.tenant_id,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
            window_start=window_start,
            window_end=window_end,
        ),
        await _correlate_stage(
            db,
            user.tenant_id,
            window_start=window_start,
            window_end=window_end,
        ),
        await _alert_stage(
            db,
            user.tenant_id,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
            window_start=window_start,
            window_end=window_end,
        ),
    ]

    return PipelineHealth(
        overall_status=_worst_status([s.status for s in stages]),
        stages=stages,
        generated_at=now,
    )


# ───────────────────────────── platform services ─────────────────────────────

# Where each internal service answers its own health probe (compose hostnames; ``AISOC_SERVICE_HEALTH_<NAME>`` overrides a URL, empty omits the service).
_SERVICE_PROBES: dict[str, str] = {
    "fusion": "http://fusion:8003/readyz",
    "enrichment": "http://enrichment:8082/health",
    "agents": "http://agents:8084/readyz",
    "actions": "http://actions:8085/readyz",
    "connectors": "http://connectors:8087/readyz",
    "threatintel": "http://threatintel:8005/readyz",
    "ueba": "http://ueba:8004/health",
    "ingest": "http://ingest-worker:8080/health",
    "realtime": "http://realtime:4000/health",
    "honeytokens": "http://honeytokens:8005/livez",
    "purple-team": "http://purple-team:8006/livez",
}


def _service_probes() -> dict[str, str]:
    import os

    probes = {}
    for name, url in _SERVICE_PROBES.items():
        url = os.environ.get(f"AISOC_SERVICE_HEALTH_{name.upper()}", url)
        if url:
            probes[name] = url
    return probes


def _idle_detail(resp: Any) -> str:
    """A service that answers but reports it has consumed no events (UEBA) is up, and says so: ready is not the same as learning."""
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001 - a probe body that is not JSON just has no extra detail
        return ""
    if isinstance(body, dict) and body.get("events_consumed") == 0:
        return "up, but has consumed no events yet"
    return ""


async def _probe(client: Any, name: str, url: str) -> dict[str, Any]:
    import time

    started = time.monotonic()
    try:
        resp = await client.get(url)
        ok = resp.status_code == 200
        detail = "" if ok else f"HTTP {resp.status_code}"
        if ok:
            detail = _idle_detail(resp)
    except Exception as exc:  # noqa: BLE001 - any failure to answer is the finding
        ok, detail = False, type(exc).__name__
    return {"service": name, "status": "up" if ok else "down", "latency_ms": round((time.monotonic() - started) * 1000), "detail": detail}


def pool_usage(pool: Any) -> dict[str, Any]:
    """How full the database connection pool is. ``in_use`` counts connections checked out (including overflow); ``limit`` is the pool size plus its overflow allowance. A pool that is
    nearly full is the early warning for the API starting to answer 500: requests queue for a connection and time out."""
    try:
        size = int(pool.size())
        overflow_allowed = int(getattr(pool, "_max_overflow", 0))
        in_use = int(pool.checkedout())
    except Exception:  # noqa: BLE001 - a pool type that cannot say is "unknown", not a failed health check
        return {"known": False}
    limit = size + max(overflow_allowed, 0)
    percent = round(100 * in_use / limit) if limit > 0 else 0
    return {"known": True, "in_use": in_use, "limit": limit, "percent": percent, "near_limit": percent >= 80}


# How full the database pool has been, remembered in memory (it starts over when the API restarts): a sample is taken from the request path at most every POOL_SAMPLE_EVERY seconds, so a busy
# spell, which is exactly when the pool fills, is captured without a background task. "How full is it NOW" says little after the moment has passed; this says how close it came.
POOL_SAMPLE_EVERY = 15.0
POOL_HISTORY_HOURS = 6
_pool_samples: deque[tuple[float, int, int]] = deque(maxlen=int(POOL_HISTORY_HOURS * 3600 / POOL_SAMPLE_EVERY) + 8)


def note_pool_usage(now: float, in_use: int, limit: int) -> bool:
    """Remember a sample unless one was taken in the last POOL_SAMPLE_EVERY seconds. Returns whether it was kept. Ignores a pool that cannot say how big it is."""
    if limit <= 0:
        return False
    if _pool_samples and now - _pool_samples[-1][0] < POOL_SAMPLE_EVERY:
        return False
    _pool_samples.append((now, in_use, limit))
    return True


def pool_peak(now: float, window_minutes: int = 60) -> dict[str, Any]:
    """The fullest the pool has been in the last ``window_minutes``: how many connections, what share of the limit, and how many minutes ago. ``samples`` is how many readings that rests on."""
    cutoff = now - window_minutes * 60
    recent = [s for s in _pool_samples if s[0] >= cutoff]
    if not recent:
        return {"window_minutes": window_minutes, "samples": 0}
    at, in_use, limit = max(recent, key=lambda s: (s[1] / s[2], s[0]))
    return {
        "window_minutes": window_minutes,
        "samples": len(recent),
        "peak_in_use": in_use,
        "peak_limit": limit,
        "peak_percent": round(100 * in_use / limit),
        "peak_minutes_ago": max(0, int((now - at) // 60)),
    }


def reset_pool_history() -> None:
    _pool_samples.clear()


CORE_FEED_SILENT_AFTER = timedelta(minutes=15)


def core_feed_row(last_report: datetime | None, sources: int, now: datetime) -> dict[str, Any]:
    """Is CORE still reporting to AiSOC? CORE reports every run, including runs that found nothing new, so a long silence means CORE is closed, asleep or cannot reach AiSOC, and nothing from
    Huntress, Petra, NinjaOne and the rest is arriving. ``silent`` is true after fifteen minutes (or when it has never reported)."""
    if last_report is None:
        return {"sources": sources, "last_report": None, "minutes_ago": None, "silent": True}
    if last_report.tzinfo is None:
        last_report = last_report.replace(tzinfo=UTC)
    return {
        "sources": sources,
        "last_report": last_report,
        "minutes_ago": max(0, int((now - last_report).total_seconds() // 60)),
        "silent": (now - last_report) > CORE_FEED_SILENT_AFTER,
    }


async def core_feed_status(db: Any, owner: Any, now: datetime | None = None) -> dict[str, Any] | None:
    """CORE's last report about its sources, or None when CORE has never been connected to this organization (so there is nothing to warn about)."""
    from app.models.connector import Connector

    row = (
        await db.execute(
            select(func.max(Connector.last_health_check), func.count()).where(
                Connector.tenant_id == owner, Connector.connector_type == "core_feed"
            )
        )
    ).first()
    if row is None or not row[1]:
        return None
    return core_feed_row(row[0], int(row[1]), now or datetime.now(UTC))


async def _signins_or_none(db: Any, user: Any) -> dict[str, Any] | None:
    """Sign-ins collected through CORE in the last 24 hours and how many were scored, or None when none has ever been collected (or this cannot be read)."""
    try:
        from app.api.v1.endpoints.signins import signin_summary

        s = await signin_summary(user, db)
        if s.last_24h == 0 and s.unscored == 0 and s.newest_received is None:
            return None
        return {
            "last_24h": s.last_24h,
            "scored_last_24h": s.scored_last_24h,
            "unscored": s.unscored,
            "users_last_24h": s.users_last_24h,
            "newest_received": s.newest_received,
        }
    except Exception:  # noqa: BLE001 - extra detail on a health page must not take it down
        return None


async def _core_feed_or_none(db: Any, user: Any) -> dict[str, Any] | None:
    try:
        return await core_feed_status(db, user.tenant_id)
    except Exception:  # noqa: BLE001 - extra detail on a health page must not take it down
        return None


DEVICE_SYNC_STALLED_AFTER = timedelta(hours=3)


def device_feed_row(vendor: str, devices: int, newest: datetime | None, now: datetime) -> dict[str, Any]:
    """One tool's device feed: how many devices it holds in AiSOC, when it last synced, and whether it looks stalled (nothing for three hours, when CORE syncs hourly)."""
    if newest is None:
        return {"vendor": vendor, "devices": devices, "last_synced": None, "minutes_ago": None, "stalled": True}
    if newest.tzinfo is None:
        newest = newest.replace(tzinfo=UTC)
    minutes = max(0, int((now - newest).total_seconds() // 60))
    return {
        "vendor": vendor,
        "devices": devices,
        "last_synced": newest,
        "minutes_ago": minutes,
        "stalled": (now - newest) > DEVICE_SYNC_STALLED_AFTER,
    }


async def device_feeds(db: Any, owner: Any, now: datetime | None = None) -> list[dict[str, Any]]:
    """Per tool: devices held and last sync, across this organization and its clients. A tool that has never sent a device is not listed (it may simply not be connected)."""
    from app.db.rls_scope import cross_tenant_reads
    from app.models.device import DeviceSource
    from app.models.tenant import Tenant

    scope = [owner, *[r[0] for r in (await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == owner))).all()]]
    async with cross_tenant_reads(db):
        rows = (
            await db.execute(
                select(DeviceSource.vendor, func.count(), func.max(DeviceSource.last_seen))
                .where(DeviceSource.tenant_id.in_(scope))
                .group_by(DeviceSource.vendor)
            )
        ).all()
    moment = now or datetime.now(UTC)
    return sorted((device_feed_row(v, int(n), newest, moment) for v, n, newest in rows), key=lambda r: (not r["stalled"], r["vendor"]))


async def _device_feeds_or_none(db: Any, user: Any) -> list[dict[str, Any]]:
    """The device feeds, or an empty list when they cannot be read: this is extra detail on a health page, and failing to read it must not take the rest of the page down."""
    try:
        return await device_feeds(db, user.tenant_id)
    except Exception:  # noqa: BLE001
        return []


def _pool_now() -> dict[str, Any]:
    from app.db.database import engine

    usage = pool_usage(engine.pool)
    if usage.get("known"):
        note_pool_usage(time.time(), usage["in_use"], usage["limit"])
        usage["peak_last_hour"] = pool_peak(time.time())
    return usage


def sample_pool_now() -> None:
    """Called from the request path: one cheap reading of the pool, kept if it is time for another. Never raises."""
    try:
        from app.db.database import engine

        usage = pool_usage(engine.pool)
        if usage.get("known"):
            note_pool_usage(time.time(), usage["in_use"], usage["limit"])
    except Exception:  # noqa: BLE001 - a health sample must never fail a request
        pass


async def database_row_security(db: Any) -> dict[str, Any]:
    """Whether the database role this API connects as can bypass row-level security. A superuser (or a role with BYPASSRLS) ignores every tenant-isolation policy, so the
    policies exist but protect nothing from this API's own queries. ``enforced`` is None when the role could not be read."""
    from sqlalchemy import text

    try:
        row = (await db.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"))).fetchone()
    except Exception:  # noqa: BLE001 - the answer is "unknown", not an error page
        return {"enforced": None, "reason": "the database role could not be read"}
    if row is None:
        return {"enforced": None, "reason": "the database role could not be read"}
    superuser, bypass = bool(row[0]), bool(row[1])
    if superuser or bypass:
        return {
            "enforced": False,
            "reason": "the API connects as a database superuser" if superuser else "the API connects as a role with BYPASSRLS",
            "fix": "connect the API as a role without SUPERUSER and BYPASSRLS (tenant isolation then rests on the database, not only on the application's own filters)",
        }
    return {"enforced": True, "reason": "the API's database role cannot bypass row-level security"}


DISK_WARN_PERCENT = 85
SCORING_BACKLOG_WARN = 1000


def disk_row(path: str = "/") -> dict[str, Any] | None:
    """Used space on the disk the API runs on, or None when it cannot be read."""
    import shutil

    try:
        u = shutil.disk_usage(path)
    except OSError:
        return None
    return {"used_percent": round(u.used * 100 / u.total, 1) if u.total else 0.0, "free_gb": round(u.free / 1024**3, 1)}


async def pending_migrations(db: Any) -> list[str] | None:
    """Migration files shipped with this API that the database has not recorded as applied (a rebuilt API on an old database), or None when this cannot be read."""
    from sqlalchemy import text

    try:
        from app.scripts.run_migrations import MIGRATIONS_DIR

        files = {p.name for p in MIGRATIONS_DIR.iterdir() if p.suffix == ".sql"}
        applied = {r[0] for r in (await db.execute(text("SELECT name FROM aisoc_schema_migrations"))).all()}
    except Exception:  # noqa: BLE001 - extra detail on a health page must not take it down
        return None
    return sorted(files - applied)


def platform_warnings(
    *,
    down: list[str],
    disk: dict[str, Any] | None,
    pending: list[str] | None,
    core_feed: dict[str, Any] | None,
    device_feeds: list[dict[str, Any]],
    signins: dict[str, Any] | None,
) -> list[dict[str, str]]:
    """Plain-language problems worth a person's attention, worst first, built only from what the page already knows (pure; unit-tested)."""
    out: list[dict[str, str]] = []
    if down:
        out.append({"key": "services", "level": "error", "text": f"Not answering: {', '.join(down)}"})
    if pending:
        out.append(
            {
                "key": "migrations",
                "level": "error",
                "text": f"{len(pending)} database migration(s) not applied ({pending[0]}...): rebuild or restart the API",
            }
        )
    if core_feed and core_feed.get("silent"):
        out.append(
            {
                "key": "core",
                "level": "error",
                "text": "CORE has not reported for over 15 minutes: no alerts, devices or links arrive while it is silent",
            }
        )
    if disk and disk["used_percent"] >= DISK_WARN_PERCENT:
        out.append({"key": "disk", "level": "warn", "text": f"Disk is {disk['used_percent']}% full ({disk['free_gb']} GB free)"})
    stalled = [f["vendor"] for f in device_feeds if f.get("stalled")]
    if stalled:
        out.append({"key": "feeds", "level": "warn", "text": f"Device feed stalled (nothing for 3+ hours): {', '.join(stalled)}"})
    if signins and signins.get("unscored", 0) > 0 and signins.get("scored_last_24h", 0) == 0:
        out.append(
            {
                "key": "signins",
                "level": "warn",
                "text": "Sign-ins are being stored but none are scored: check the behaviour service token in the API's environment",
            }
        )
    elif signins and signins.get("unscored", 0) >= SCORING_BACKLOG_WARN:
        out.append(
            {
                "key": "backlog",
                "level": "warn",
                "text": f"{signins['unscored']:,} sign-ins are waiting to be scored. They are scored a hundred at a time as new ones arrive; "
                "if the number is not falling, look at the behaviour service's log for errors",
            }
        )
    return out


@router.get(
    "/services",
    summary="Is each internal platform service answering its own health probe?",
    dependencies=[Depends(require_permission("alerts:read"))],
)
async def platform_services(user: AuthUser, db: DBSession) -> dict[str, Any]:
    """One row per internal service (fusion, connectors, agents, ...), probed live from the API. A service that does not answer in 3 s is ``down``.

    Needs alerts:read (it reveals the platform's internals); it never returns a URL, only the service name and what the probe saw.
    """
    import asyncio

    import httpx

    async with httpx.AsyncClient(timeout=3.0) as client:
        rows = await asyncio.gather(*(_probe(client, name, url) for name, url in _service_probes().items()))
    rows = sorted(rows, key=lambda r: (r["status"] == "up", r["service"]))
    down = [r["service"] for r in rows if r["status"] != "up"]
    feeds = await _device_feeds_or_none(db, user)
    core_feed = await _core_feed_or_none(db, user)
    signins = await _signins_or_none(db, user)
    disk = disk_row()
    pending = await pending_migrations(db)
    return {
        "overall": "degraded" if down else "ok",
        "down": down,
        "services": rows,
        "database": {**await database_row_security(db), "pool": _pool_now()},
        "device_feeds": feeds,
        "core_feed": core_feed,
        "signins": signins,
        "disk": disk,
        "pending_migrations": pending or [],
        "warnings": platform_warnings(down=down, disk=disk, pending=pending, core_feed=core_feed, device_feeds=feeds, signins=signins),
        "generated_at": datetime.now(UTC),
    }
