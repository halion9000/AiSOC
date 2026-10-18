"""Persist fused alerts into the Postgres ``alerts`` table.

Phase 3.1 (world-class program) closed the second spine gap the reality audit
exposed: fusion published fused alerts to ``aisoc.alerts.fused`` and — before
this module — **nothing wrote them to the alert store**. The only writers were
the API's manual ``POST /alerts/submit`` endpoint and the demo seeder, so a
raw event could never become an alert row without a human in the loop.

Design constraints:

* **Fail-soft.** Fusion ran for months without a database; a Postgres outage
  must degrade to "fused alerts still stream over Kafka/WS, persistence
  resumes when the DB returns" — never crash the consumer.
* **Idempotent.** The insert is guarded by the alert's dedup fingerprint per
  tenant, so replaying a Kafka batch (consumer-group rebalance, restart
  mid-batch) cannot produce duplicate rows.
* **Duplicates are not persisted.** Fusion publishes DUPLICATE decisions
  downstream for observability, but they must not become new alert rows.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from enum import Enum

import asyncpg
import structlog

from app.core.config import settings
from app.models.alert import FusedAlert, FusionDecision, RawAlert

logger = structlog.get_logger()


class PersistOutcome(str, Enum):
    """Distinguishable outcomes of a persist attempt (issue #568).

    The old sink collapsed "inserted", "already-existed", "DB down", and
    "insert errored" all into ``None``, so the caller could not tell a real
    duplicate from an outage it should retry. Each state is now explicit.
    """

    INSERTED = "inserted"  # a new row was written; alert_id is the row id
    DUPLICATE = "duplicate"  # already existed (dedup hit or id conflict)
    UNAVAILABLE = "unavailable"  # DB unreachable — retryable, NOT a duplicate
    FAILED = "failed"  # insert errored (bad tenant, SQL error) — observable


@dataclass(frozen=True)
class PersistResult:
    """Outcome of :meth:`AlertSink.persist` plus the canonical alert id."""

    outcome: PersistOutcome
    alert_id: str | None = None

    @property
    def persisted(self) -> bool:
        return self.outcome is PersistOutcome.INSERTED

    @property
    def durable(self) -> bool:
        """True when the alert is known to exist in the store (new or dup)."""
        return self.outcome in (PersistOutcome.INSERTED, PersistOutcome.DUPLICATE)


_INSERT_SQL = """
INSERT INTO alerts (
    id, tenant_id, title, description, severity, status,
    mitre_tactics, mitre_techniques, iocs, entities, raw_event,
    dedup_hash, confidence, confidence_label, confidence_rationale,
    narrative, anomaly_score, event_time,
    connector_id, connector_type, source_event_ids, ocsf_class_uid,
    rule_id, rule_name,
    affected_ips, affected_hosts, affected_users,
    enrichment_data
)
SELECT
    $1, $2, $3, $4, $5, 'new',
    $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb,
    $11::text, $12, $13, $14::jsonb,
    $15, $16, COALESCE($17, NOW()),
    $18, $19, $20::jsonb, $21,
    $22, $23,
    $24::jsonb, $25::jsonb, $26::jsonb,
    $28::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM alerts WHERE tenant_id = $2 AND dedup_hash = $11::text
)
-- The vendor's own incident id (CORE puts it at raw_event.finding.uid) is the alert's identity: the fingerprint changes whenever the entity extraction or the fingerprint itself
-- does, and each change stored every re-forwarded incident a second time. The expression matches idx_alerts_tenant_finding_uid.
AND ($27::text IS NULL OR NOT EXISTS (
    SELECT 1 FROM alerts WHERE tenant_id = $2 AND ((raw_event -> 'finding') ->> 'uid') = $27::text
))
ON CONFLICT (id) DO NOTHING
RETURNING id
"""
# Two idempotency guards, complementary (issue #568):
#   * WHERE NOT EXISTS (tenant_id, dedup_hash) — content dedup; also protects
#     legacy rows written before ids were deterministic (random id, same hash).
#   * ON CONFLICT (id) DO NOTHING — exact-replay idempotency on the canonical
#     deterministic UUID (RawAlert.deterministic_id()).
# NB: $11 (dedup_hash) is cast ::text in BOTH the INSERT target and the WHERE.
# `dedup_hash` is VARCHAR(64); a varchar/text mismatch makes asyncpg's prepare
# fail to unify parameter $11 ("inconsistent types deduced"), silently dropping
# every write. Pinning both uses to ::text makes the deduction unambiguous.


# A recurrence of an alert that is already stored: the row is kept (one alert, not one per repeat) but shows it happened again.
_TOUCH_SQL = """
UPDATE alerts
SET last_seen = GREATEST(last_seen, COALESCE($3, NOW())), updated_at = NOW()
WHERE tenant_id = $1 AND (dedup_hash = $2::text OR ($4::text IS NOT NULL AND ((raw_event -> 'finding') ->> 'uid') = $4::text))
"""


# The mapping is only honoured when the chosen tenant really is a child of the tenant that owns the feed (a mapping row alone is not enough to move an alert into someone else's tenant).
_CLIENT_TENANT_SQL = """
SELECT a.child_tenant_id
FROM client_aliases a
JOIN tenants t ON t.id = a.child_tenant_id AND t.parent_tenant_id = a.tenant_id
WHERE a.tenant_id = $1 AND a.vendor = $2 AND a.vendor_client_id = $3
  AND a.ignored = FALSE AND a.child_tenant_id IS NOT NULL
"""


def _finding_uid(alert: RawAlert) -> str | None:
    """The vendor incident id CORE forwarded (``raw_event.finding.uid``, e.g. ``huntress:123``), or None for an alert that carries none."""
    raw = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    finding = raw.get("finding")
    uid = finding.get("uid") if isinstance(finding, dict) else None
    return uid if isinstance(uid, str) and 0 < len(uid) <= 200 else None


def _asyncpg_dsn(url: str) -> str:
    """Strip the SQLAlchemy driver suffix — asyncpg wants plain postgresql://."""
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


def _iocs(fused: FusedAlert) -> list[dict[str, str]]:
    alert = fused.alert
    out: list[dict[str, str]] = []
    for ioc_type, value in (
        ("ip", alert.src_ip),
        ("ip", alert.dst_ip),
        ("hash", alert.file_hash),
        ("domain", alert.domain),
        ("url", alert.url),
    ):
        if value:
            out.append({"type": ioc_type, "value": value})
    return out


def _entities(fused: FusedAlert) -> list[dict[str, str]]:
    alert = fused.alert
    out: list[dict[str, str]] = []
    if alert.hostname:
        out.append({"type": "host", "value": alert.hostname})
    if alert.username:
        out.append({"type": "user", "value": alert.username})
    return out


def _affected(*values: str | None) -> list[str]:
    """The distinct, non-empty values in order (the alerts.affected_* columns are plain string lists)."""
    out: list[str] = []
    for v in values:
        if v and v not in out:
            out.append(v)
    return out



# A newly promoted entity (its risk score crossed the threshold) can open a case, so the work reaches the queue analysts actually use. One open case per entity: a second promotion while the
# first case is still open (not resolved or closed) opens nothing. Off unless AISOC_RBA_OPEN_CASE is set.
_PROMOTION_CASE_SQL = """
INSERT INTO aisoc_cases (tenant_id, title, description, severity, alert_ids, created_by, tags)
SELECT $1, $2, $3, $4, $5::uuid[], 'aisoc-rba', $6::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM aisoc_cases
    WHERE tenant_id = $1 AND status NOT IN ('resolved', 'closed') AND tags ->> 'rba_entity' = $7::text
)
RETURNING id
"""
_LINK_ALERTS_SQL = "UPDATE alerts SET case_id = $1 WHERE tenant_id = $2 AND id = ANY($3::uuid[]) AND case_id IS NULL"


def case_for_promotion(promotion: dict, alert_title: str, threshold: float) -> dict | None:
    """The case to open for one promotion record (as ``EntityRiskRecord.to_dict`` writes it), or None when it names no entity. Pure."""
    kind, value = str(promotion.get("entity_type") or "").strip(), str(promotion.get("entity_value") or "").strip()
    if not kind or not value:
        return None
    score = float(promotion.get("score") or 0.0)
    ids: list[str] = []
    for raw in promotion.get("contributing_alerts") or []:
        try:
            ids.append(str(uuid.UUID(str(raw))))
        except ValueError:
            continue
    severities = ", ".join(f"{n} {name}" for name, n in sorted((promotion.get("severities") or {}).items(), key=lambda kv: -kv[1]) if n)
    description = (
        f"Risk-based alerting promoted {kind} {value}: its risk score reached {score:.0f} (promotion threshold {threshold:.0f}) from {promotion.get('alert_count', len(ids))} recent alert(s)"
        + (f" ({severities})" if severities else "")
        + f". Latest alert: {alert_title[:300]}."
    )
    return {
        "title": f"Risk-based alert: {kind} {value}"[:500],
        "description": description,
        "severity": "critical" if score >= 2 * threshold else "high",
        "alert_ids": ids,
        "tags": {"rba_entity": f"{kind}:{value}", "source": "rba"},
        "entity_key": f"{kind}:{value}",
    }


class AlertSink:
    """asyncpg-backed writer from the fusion pipeline into the alert store."""

    def __init__(self, database_url: str, pool_size: int = 2) -> None:
        self._dsn = _asyncpg_dsn(database_url)
        self._pool_size = pool_size
        self._pool: asyncpg.Pool | None = None
        self._connect_failed_logged = False

    async def start(self) -> None:
        """Open the pool (once: a second call keeps the open one). Failure is logged, not raised (fail-soft)."""
        if self._pool is not None:
            return
        try:
            self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=self._pool_size, timeout=10)
            logger.info("alert_sink.started")
        except Exception as exc:  # noqa: BLE001 — degrade, never crash the worker
            self._pool = None
            logger.error("alert_sink.connect_failed", error=str(exc))

    async def stop(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def _ensure_pool(self) -> asyncpg.Pool | None:
        if self._pool is None:
            # One reconnect attempt per persist call — cheap when the DB is
            # down (fast connect error) and self-healing when it returns.
            await self.start()
        return self._pool

    async def child_tenant_for_client(self, tenant_id: uuid.UUID, vendor: str, vendor_client_id: str) -> uuid.UUID | None:
        """The client tenant a vendor client is mapped to, or None (unmapped, ignored, not a real child of ``tenant_id``, or the DB is unreachable)."""
        pool = await self._ensure_pool()
        if pool is None:
            return None
        async with pool.acquire() as conn:
            row = await conn.fetchrow(_CLIENT_TENANT_SQL, tenant_id, vendor, vendor_client_id)
        return row["child_tenant_id"] if row else None

    async def _touch_existing(self, pool: asyncpg.Pool, alert: RawAlert) -> None:
        """Move the stored alert's last_seen forward. Best effort: the alert is already safe, so a failure here is only logged."""
        try:
            async with pool.acquire() as conn:
                await conn.execute(_TOUCH_SQL, alert.tenant_id, alert.fingerprint(), alert.event_time, _finding_uid(alert))
        except Exception as exc:  # noqa: BLE001
            logger.warning("alert_sink.touch_failed", error=str(exc))

    async def open_cases_for_promotions(self, fused: FusedAlert) -> int:
        """Open a case for each entity this alert newly promoted (when AISOC_RBA_OPEN_CASE is on). Returns how many were opened; never raises."""
        promotions = fused.enrichments.get("rba_promotions") if isinstance(fused.enrichments, dict) else None
        if not settings.rba_open_case or not promotions:
            return 0
        pool = await self._ensure_pool()
        if pool is None:
            return 0
        opened = 0
        try:
            async with pool.acquire() as conn:
                for promotion in promotions:
                    case = case_for_promotion(promotion, fused.alert.title, settings.rba_promotion_threshold)
                    if case is None:
                        continue
                    row = await conn.fetchrow(
                        _PROMOTION_CASE_SQL,
                        fused.alert.tenant_id,
                        case["title"],
                        case["description"],
                        case["severity"],
                        case["alert_ids"],
                        json.dumps(case["tags"]),
                        case["entity_key"],
                    )
                    if row is None:
                        continue  # an open case for this entity already exists
                    opened += 1
                    if case["alert_ids"]:
                        await conn.execute(_LINK_ALERTS_SQL, row["id"], fused.alert.tenant_id, case["alert_ids"])
                    logger.info("alert_sink.rba_case_opened", entity=case["entity_key"], case_id=str(row["id"]))
        except Exception as exc:  # noqa: BLE001 - a case that could not be opened must not lose the alert
            logger.warning("alert_sink.rba_case_failed", error=str(exc))
        return opened

    async def persist(self, fused: FusedAlert) -> PersistResult:
        """Insert one fused alert, returning a structured :class:`PersistResult`.

        The canonical alert id is ``fused.id`` (deterministic — issue #568), so
        even a duplicate / outage carries the id the row resolves to once the
        DB is reachable.
        """
        canonical_id = str(fused.id)
        if fused.fusion_decision == FusionDecision.DUPLICATE:
            return PersistResult(PersistOutcome.DUPLICATE, canonical_id)

        pool = await self._ensure_pool()
        if pool is None:
            if not self._connect_failed_logged:
                logger.error("alert_sink.unavailable_dropping_persistence")
                self._connect_failed_logged = True
            return PersistResult(PersistOutcome.UNAVAILABLE, canonical_id)
        self._connect_failed_logged = False

        alert = fused.alert
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    _INSERT_SQL,
                    fused.id,
                    alert.tenant_id,
                    alert.title[:500],
                    alert.description or None,
                    alert.severity.value,
                    json.dumps(alert.mitre_tactics),
                    json.dumps(alert.mitre_techniques),
                    json.dumps(_iocs(fused)),
                    json.dumps(_entities(fused)),
                    json.dumps(alert.raw_event, default=str),
                    alert.fingerprint(),
                    int(round(fused.confidence_score * 100)),
                    fused.confidence_label.value,
                    json.dumps([f.model_dump() for f in fused.confidence_rationale]),
                    fused.narrative,
                    fused.anomaly_score,
                    alert.event_time,
                    alert.connector_id,
                    alert.connector_type,
                    json.dumps(alert.source_event_ids),
                    alert.ocsf_class_uid,
                    alert.rule_id,
                    alert.rule_name,
                    json.dumps(_affected(alert.src_ip, alert.dst_ip)),
                    json.dumps(_affected(alert.hostname)),
                    json.dumps(_affected(alert.username)),
                    _finding_uid(alert),
                    json.dumps({"fusion_incident_id": str(fused.incident_id)} if fused.incident_id else {}),
                )
            if row is None:
                logger.debug("alert_sink.dedup_skip", fingerprint=alert.fingerprint())
                await self._touch_existing(pool, alert)
                await self.open_cases_for_promotions(fused)
                return PersistResult(PersistOutcome.DUPLICATE, canonical_id)
            await self.open_cases_for_promotions(fused)
            return PersistResult(PersistOutcome.INSERTED, str(row["id"]))
        except asyncpg.ForeignKeyViolationError:
            # Unknown tenant — a mis-provisioned connector, not a pipeline bug.
            # Distinct from a duplicate so it is observable, not silently masked.
            logger.warning("alert_sink.unknown_tenant", tenant_id=str(alert.tenant_id))
            return PersistResult(PersistOutcome.FAILED, None)
        except Exception as exc:  # noqa: BLE001 — one bad row must not wedge the consumer
            logger.error("alert_sink.persist_failed", error=str(exc))
            return PersistResult(PersistOutcome.FAILED, None)
