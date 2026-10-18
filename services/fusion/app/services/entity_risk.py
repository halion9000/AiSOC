"""
Risk-Based Alerting (RBA) — entity rollup with time-decayed risk scores.

The Splunk-pioneered RBA pattern: alerts contribute *points* to the entities
they touch (user, host, src_ip, domain). Points decay exponentially with a
half-life so stale signal naturally drops out. Once an entity's score crosses
``rba_promotion_threshold`` AiSOC promotes the entity to an incident with the
contributing alerts attached — and the entity-centric queue surfaces the
top-N highest-risk entities to the analyst, not raw alerts.

Why entity-first
----------------
The 2026 buyer-side scoring bar mandates ``alert-to-incident ratio ≥ 50:1``
(SANS 2025 + AI-SOC 30-item checklist). Per-alert correlation alone caps
collapse at the entity boundary; entity-rollup compounds across detections
so one user with five medium signals lands above one with a single
high-severity false positive.

Storage
-------
Redis hashes per entity, namespaced by tenant. Cheap, atomic, and TTLs match
``rba_window_seconds`` so cold entities self-evict. Two ZSETs keep top-N
entities sorted (by score, by last_seen) for O(log N) queue reads. All
keys are RLS-safe because the tenant_id is part of the key prefix and the
API service re-checks tenant on read.
"""

from __future__ import annotations

import asyncio
import json
import math
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

import redis.asyncio as aioredis
import structlog

from app.core.config import settings
from app.models.alert import AlertSeverity, RawAlert

logger = structlog.get_logger()

# Key layout (all prefixed by tenant for RLS at the cache layer):
#   aisoc:fusion:rba:entity:{tenant}:{entity_type}:{entity_value}  →  hash
#   aisoc:fusion:rba:topn:{tenant}                                  →  zset (score)
#   aisoc:fusion:rba:promoted:{tenant}                              →  zset (last seen)
_ENTITY_PREFIX = "aisoc:fusion:rba:entity:"
_TOPN_KEY = "aisoc:fusion:rba:topn:"
_PROMOTED_KEY = "aisoc:fusion:rba:promoted:"
# When each queued entity's record expires (score = the time). The queue's sorted set cannot expire members on its own, so without this a member outlived its record forever: the count said 656
# active entities while the list could show only the handful whose record still existed.
_EXPIRY_KEY = "aisoc:fusion:rba:expiry:"

ENTITY_TYPES: tuple[str, ...] = ("user", "host", "src_ip", "domain")


def _utc_z(moment: datetime) -> str:
    """A UTC ISO-8601 timestamp ending in Z. A timezone-aware value is converted to UTC first: appending 'Z' to its isoformat gave '...+00:00Z', which a browser reads as an Invalid Date."""
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC).replace(tzinfo=None)
    return moment.isoformat() + "Z"


@dataclass(frozen=True)
class EntitySignal:
    """A single alert's contribution to one entity."""

    entity_type: str
    entity_value: str
    points: float
    alert_id: str
    severity: str
    detection: str
    occurred_at: datetime


@dataclass
class EntityRiskRecord:
    """The current decayed risk picture for one entity."""

    tenant_id: str
    entity_type: str
    entity_value: str
    score: float
    alert_count: int
    last_seen: datetime
    contributing_alerts: list[str]
    severities: dict[str, int]
    promoted_at: datetime | None
    contributors: list[dict] | None = None

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "score": round(self.score, 2),
            "alert_count": self.alert_count,
            "last_seen": _utc_z(self.last_seen),
            "contributing_alerts": self.contributing_alerts,
            "severities": self.severities,
            "promoted_at": _utc_z(self.promoted_at) if self.promoted_at else None,
            "contributors": self.contributors or [],
        }


class EntityRiskEngine:
    """Time-decaying entity risk accumulator + entity-centric queue."""

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client
        self._enabled = settings.rba_enabled
        self._threshold = settings.rba_promotion_threshold
        self._window = settings.rba_window_seconds
        self._half_life = max(60, settings.rba_decay_half_life_seconds)
        self._max_top = max(10, settings.rba_max_top_entities)
        self._legacy_checked: set[str] = set()
        self._weights: dict[AlertSeverity, float] = {
            AlertSeverity.CRITICAL: settings.rba_severity_weights_critical,
            AlertSeverity.HIGH: settings.rba_severity_weights_high,
            AlertSeverity.MEDIUM: settings.rba_severity_weights_medium,
            AlertSeverity.LOW: settings.rba_severity_weights_low,
            AlertSeverity.INFO: settings.rba_severity_weights_info,
        }

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def threshold(self) -> float:
        return self._threshold

    # ------------------------------------------------------------------
    # Ingest path
    # ------------------------------------------------------------------
    async def observe(self, alert: RawAlert) -> list[EntityRiskRecord]:
        """
        Apply ``alert`` against every entity it touches.

        Returns the list of entity records that crossed the promotion
        threshold *as a result of this alert*. The fusion engine uses the
        return value to log promotions and emit downstream signals.
        """
        if not self._enabled:
            return []

        signals = self._build_signals(alert)
        if not signals:
            return []

        promoted: list[EntityRiskRecord] = []
        for sig in signals:
            record = await self._apply_signal(alert.tenant_id, sig)
            if record.score >= self._threshold and record.promoted_at is None:
                record = await self._promote(alert.tenant_id, record)
                promoted.append(record)

        return promoted

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------
    @staticmethod
    def _text(value: Any) -> str:
        return value.decode() if isinstance(value, bytes | bytearray) else str(value)

    async def _prune(self, tenant_id: str) -> int:
        """Remove queue members whose record has expired, so the list and the count agree. Returns how many were removed.

        Members written since the expiry index existed are removed when their time passes. Members written before it (the first read of each tenant after an upgrade) are checked once
        against their record's remaining life: a record that is gone is dropped, one that has life left is given its expiry.
        """
        topn, promoted, expiry = _TOPN_KEY + tenant_id, _PROMOTED_KEY + tenant_id, _EXPIRY_KEY + tenant_id
        now = time.time()
        stale = [self._text(m) for m in await self._redis.zrangebyscore(expiry, "-inf", now)]
        if tenant_id not in self._legacy_checked:
            self._legacy_checked.add(tenant_id)
            known = {self._text(m) for m in await self._redis.zrevrange(expiry, 0, -1)}
            for raw in await self._redis.zrevrange(topn, 0, -1):
                member = self._text(raw)
                if member in known:
                    continue
                entity_type, _, entity_value = member.partition("::")
                ttl = await self._redis.ttl(_ENTITY_PREFIX + f"{tenant_id}:{entity_type}:{entity_value}")
                if ttl is None or ttl == -2 or ttl == 0:
                    stale.append(member)
                elif ttl > 0:
                    await self._redis.zadd(expiry, {member: now + ttl})
        if stale:
            stale = list(dict.fromkeys(stale))
            await self._redis.zrem(topn, *stale)
            await self._redis.zrem(promoted, *stale)
            await self._redis.zrem(expiry, *stale)
        return len(stale)

    async def top_entities(
        self,
        tenant_id: UUID | str,
        *,
        limit: int = 25,
        promoted_only: bool = False,
    ) -> list[EntityRiskRecord]:
        """Return the top-N entities by current decayed score."""
        await self._prune(str(tenant_id))
        key = _TOPN_KEY + str(tenant_id)
        raw = await self._redis.zrevrange(key, 0, max(0, limit - 1), withscores=True)
        records: list[EntityRiskRecord] = []
        for member, _zscore in raw:
            entity = member.decode() if isinstance(member, bytes | bytearray) else member
            entity_type, _, entity_value = entity.partition("::")
            rec = await self._load(str(tenant_id), entity_type, entity_value)
            if rec is None:
                continue
            if promoted_only and rec.promoted_at is None:
                continue
            records.append(rec)
        return records

    async def top_entities_many(
        self,
        tenant_ids: list[UUID | str],
        *,
        limit: int = 25,
        promoted_only: bool = False,
    ) -> list[EntityRiskRecord]:
        """The top-N entities by score across several tenants at once (an MSSP parent and its clients).

        One ranked list: each tenant's own top-N is read from its sorted set, merged by score, and only the winners are loaded."""
        tenants = [str(t) for t in dict.fromkeys(tenant_ids)]
        await asyncio.gather(*(self._prune(t) for t in tenants))
        if promoted_only:
            per_tenant = await asyncio.gather(*(self.top_entities(t, limit=limit, promoted_only=True) for t in tenants))
            merged = [r for records in per_tenant for r in records]
            merged.sort(key=lambda r: r.score, reverse=True)
            return merged[:limit]
        ranges = await asyncio.gather(*(self._redis.zrevrange(_TOPN_KEY + t, 0, max(0, limit - 1), withscores=True) for t in tenants))
        ranked = sorted(
            ((score, t, member) for t, raw in zip(tenants, ranges, strict=True) for member, score in raw),
            key=lambda row: row[0],
            reverse=True,
        )[:limit]
        records: list[EntityRiskRecord] = []
        for _score, t, member in ranked:
            entity = member.decode() if isinstance(member, bytes | bytearray) else member
            entity_type, _, entity_value = entity.partition("::")
            rec = await self._load(t, entity_type, entity_value)
            if rec is not None:
                records.append(rec)
        return records

    async def stats_many(self, tenant_ids: list[UUID | str]) -> dict:
        """``stats`` summed over several tenants."""
        parts = await asyncio.gather(*(self.stats(t) for t in dict.fromkeys(tenant_ids)))
        bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for part in parts:
            for band, count in part["score_bands"].items():
                bands[band] = bands.get(band, 0) + count
        tracked = sum(p["tracked_entities"] for p in parts)
        promoted = sum(p["promoted_entities"] for p in parts)
        return {
            "tracked_entities": tracked,
            "promoted_entities": promoted,
            "score_bands": bands,
            "threshold": self._threshold,
            "total": tracked,
            "promoted": promoted,
            "bands": bands,
        }

    async def get(self, tenant_id: UUID | str, entity_type: str, entity_value: str) -> EntityRiskRecord | None:
        return await self._load(str(tenant_id), entity_type, entity_value)

    async def stats(self, tenant_id: UUID | str) -> dict:
        """Return queue-level metrics for the dashboard."""
        await self._prune(str(tenant_id))
        topn_key = _TOPN_KEY + str(tenant_id)
        promoted_key = _PROMOTED_KEY + str(tenant_id)
        total = await self._redis.zcard(topn_key)
        promoted = await self._redis.zcard(promoted_key)
        # Score histogram (≥80, 50–80, 20–50, <20).
        bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        members = await self._redis.zrevrange(topn_key, 0, self._max_top - 1, withscores=True)
        for _m, score in members:
            if score >= 80:
                bands["critical"] += 1
            elif score >= 50:
                bands["high"] += 1
            elif score >= 20:
                bands["medium"] += 1
            else:
                bands["low"] += 1
        return {
            "tracked_entities": total,
            "promoted_entities": promoted,
            "score_bands": bands,
            # The console's EntityRiskStats (apps/web/src/lib/api.ts) and the API's offline stub read these names.
            "total": total,
            "promoted": promoted,
            "bands": bands,
            "threshold": self._threshold,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _build_signals(self, alert: RawAlert) -> list[EntitySignal]:
        weight = self._weights.get(alert.severity, self._weights[AlertSeverity.MEDIUM])
        # Detection-confidence boost: higher upstream risk_score amplifies points.
        confidence_factor = 1.0 + min(max(alert.risk_score, 0.0), 1.0)
        points = round(weight * confidence_factor, 2)
        detection = alert.title or alert.source
        occurred = alert.event_time or alert.created_at

        candidates: list[tuple[str, str | None]] = [
            ("user", alert.username),
            ("host", alert.hostname),
            ("src_ip", alert.src_ip),
            ("domain", alert.domain),
        ]
        signals: list[EntitySignal] = []
        for entity_type, value in candidates:
            if not value:
                continue
            signals.append(
                EntitySignal(
                    entity_type=entity_type,
                    entity_value=str(value),
                    points=points,
                    alert_id=str(alert.id),
                    severity=alert.severity.value,
                    detection=detection,
                    occurred_at=occurred,
                )
            )
        return signals

    async def _apply_signal(self, tenant_id: UUID, sig: EntitySignal) -> EntityRiskRecord:
        record = await self._load(str(tenant_id), sig.entity_type, sig.entity_value)
        now = datetime.utcnow()

        if record is None:
            record = EntityRiskRecord(
                tenant_id=str(tenant_id),
                entity_type=sig.entity_type,
                entity_value=sig.entity_value,
                score=0.0,
                alert_count=0,
                last_seen=now,
                contributing_alerts=[],
                severities={},
                promoted_at=None,
                contributors=[],
            )

        if sig.alert_id in record.contributing_alerts:
            # This alert already counted toward this entity: a redelivery or a retry (the consumer retries a failed message) must not add its points again.
            return record

        record.score = self._decay(record.score, record.last_seen, now) + sig.points
        record.alert_count += 1
        record.last_seen = now
        if sig.alert_id not in record.contributing_alerts:
            record.contributing_alerts.append(sig.alert_id)
            # Cap contributing list to keep payload small in the queue UI.
            if len(record.contributing_alerts) > 50:
                record.contributing_alerts = record.contributing_alerts[-50:]
        record.severities[sig.severity] = record.severities.get(sig.severity, 0) + 1
        contributors = record.contributors or []
        contributors.append(
            {
                "alert_id": sig.alert_id,
                "severity": sig.severity,
                "detection": sig.detection,
                "points": sig.points,
                "at": _utc_z(sig.occurred_at),
            }
        )
        if len(contributors) > 25:
            contributors = contributors[-25:]
        record.contributors = contributors

        await self._save(record)
        return record

    def _decay(self, prior: float, prior_seen: datetime, now: datetime) -> float:
        if prior <= 0:
            return 0.0
        elapsed = max(0.0, (now - prior_seen).total_seconds())
        if elapsed <= 0:
            return prior
        decay = math.pow(0.5, elapsed / float(self._half_life))
        decayed = prior * decay
        return decayed if decayed > 0.05 else 0.0

    async def _promote(self, tenant_id: UUID, record: EntityRiskRecord) -> EntityRiskRecord:
        record.promoted_at = datetime.utcnow()
        await self._save(record)
        promoted_key = _PROMOTED_KEY + str(tenant_id)
        await self._redis.zadd(promoted_key, {self._member(record): time.time()})
        await self._redis.expire(promoted_key, self._window)
        logger.info(
            "rba_entity_promoted",
            tenant_id=str(tenant_id),
            entity_type=record.entity_type,
            entity_value=record.entity_value,
            score=round(record.score, 2),
            alert_count=record.alert_count,
            contributing_alerts=record.contributing_alerts[-10:],
        )
        return record

    @staticmethod
    def _member(record: EntityRiskRecord) -> str:
        return f"{record.entity_type}::{record.entity_value}"

    async def _save(self, record: EntityRiskRecord) -> None:
        key = _ENTITY_PREFIX + f"{record.tenant_id}:{record.entity_type}:{record.entity_value}"
        payload = {
            "score": str(record.score),
            "alert_count": str(record.alert_count),
            "last_seen": record.last_seen.isoformat(),
            "contributing_alerts": json.dumps(record.contributing_alerts),
            "severities": json.dumps(record.severities),
            "promoted_at": record.promoted_at.isoformat() if record.promoted_at else "",
            "contributors": json.dumps(record.contributors or []),
        }
        await self._redis.hset(key, mapping=payload)
        await self._redis.expire(key, self._window)
        expiry_key = _EXPIRY_KEY + record.tenant_id
        await self._redis.zadd(expiry_key, {self._member(record): time.time() + self._window})
        await self._redis.expire(expiry_key, self._window)
        topn_key = _TOPN_KEY + record.tenant_id
        await self._redis.zadd(topn_key, {self._member(record): record.score})
        await self._redis.zremrangebyrank(topn_key, 0, -(self._max_top + 1))
        await self._redis.expire(topn_key, self._window)

    async def _load(self, tenant_id: str, entity_type: str, entity_value: str) -> EntityRiskRecord | None:
        key = _ENTITY_PREFIX + f"{tenant_id}:{entity_type}:{entity_value}"
        data = await self._redis.hgetall(key)
        if not data:
            return None
        decoded = {
            (k.decode() if isinstance(k, bytes | bytearray) else k): (v.decode() if isinstance(v, bytes | bytearray) else v)
            for k, v in data.items()
        }
        promoted_at = None
        if decoded.get("promoted_at"):
            try:
                promoted_at = datetime.fromisoformat(decoded["promoted_at"])
            except ValueError:
                promoted_at = None
        try:
            last_seen = datetime.fromisoformat(decoded["last_seen"])
        except (KeyError, ValueError):
            last_seen = datetime.utcnow()
        return EntityRiskRecord(
            tenant_id=tenant_id,
            entity_type=entity_type,
            entity_value=entity_value,
            score=float(decoded.get("score", "0")),
            alert_count=int(decoded.get("alert_count", "0")),
            last_seen=last_seen,
            contributing_alerts=json.loads(decoded.get("contributing_alerts", "[]")),
            severities=json.loads(decoded.get("severities", "{}")),
            promoted_at=promoted_at,
            contributors=json.loads(decoded.get("contributors", "[]")),
        )
