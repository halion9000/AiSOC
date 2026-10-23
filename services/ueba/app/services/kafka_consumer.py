"""Kafka consumer — reads security events, scores them, emits anomalies.

Message schema (JSON, ``security.events`` topic):
  {
    "event_id":       "uuid-string",
    "tenant_id":      "uuid-string",
    "entity_type":    "user" | "device" | "ip",
    "entity_id":      "alice@example.com",
    "event_type":     "login" | "file_access" | "network" | ...,
    "peer_group_id":  "dept:engineering",   // optional
    "features": {
      "hour_of_day":   14,
      "login_count":   3,
      "bytes_sent":    1024000,
      ...
    },
    "ts": "2026-05-03T12:00:00Z"
  }

Anomalies are published to ``ueba.anomalies``:
  {
    "anomaly_id":     "uuid",
    "tenant_id":      "uuid",
    "entity_type":    "user",
    "entity_id":      "alice@example.com",
    "event_type":     "login",
    "anomaly_score":  4.7,
    "risk_level":     "high",
    "features":       {...},
    "detected_at":    "2026-05-03T12:00:01Z"
  }
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import settings
from app.services.peer_group import PeerGroupService
from app.services.scoring import ScoringService

LOG = logging.getLogger(__name__)


def clean_features(features_raw: Any) -> dict[str, float]:
    """The numeric, finite feature values of a message. ``float()`` happily takes "nan" and "inf", and one of those in a baseline's running mean poisons it for good."""
    out: dict[str, float] = {}
    if not isinstance(features_raw, dict):
        return out
    for k, v in features_raw.items():
        try:
            number = float(v)
        except (TypeError, ValueError):
            continue  # non-numeric feature value; skip
        if math.isfinite(number):
            out[k] = number
    return out


# What the service reports on /health, so "ready" is not mistaken for "learning": a consumer that has seen no event has nothing to learn from.
STATS: dict[str, object] = {"consumed": 0, "last_message_at": None}


def record_event() -> None:
    """Count one event that reached the service, from the Kafka topic or from a direct ``/score`` call (the API scores sign-ins that way): either way the service is being fed."""
    STATS["consumed"] += 1  # type: ignore[operator]
    STATS["last_message_at"] = datetime.now(UTC).isoformat()


class UEBAKafkaConsumer:
    def __init__(self) -> None:
        self._engine = create_async_engine(settings.database_url, pool_size=5)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
        self._running = False

    async def _process_message(self, raw: bytes, producer: Any) -> None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            LOG.warning("Invalid JSON message; skipping.")
            return

        tenant_id_raw = msg.get("tenant_id")
        entity_type = msg.get("entity_type", "user")
        entity_id = msg.get("entity_id", "")
        event_type = msg.get("event_type", "unknown")
        peer_group_id = msg.get("peer_group_id")
        features_raw = msg.get("features", {})
        source_event_id = msg.get("event_id")

        if not tenant_id_raw or not entity_id:
            LOG.debug("Skipping message: missing tenant_id or entity_id")
            return

        try:
            tenant_id = uuid.UUID(tenant_id_raw)
        except ValueError:
            LOG.warning("Invalid tenant_id: %s", tenant_id_raw)
            return

        features = clean_features(features_raw)

        if not features:
            return

        async with self._session_factory() as session:
            async with session.begin():
                # Update peer group if provided
                if peer_group_id:
                    peer_svc = PeerGroupService(session)
                    await peer_svc.update(tenant_id, peer_group_id, entity_type, features)

                scorer = ScoringService(session)
                anomaly = await scorer.score_event(
                    tenant_id=tenant_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    event_type=event_type,
                    features=features,
                    source_event_id=source_event_id,
                    peer_group_id=peer_group_id,
                )

        if anomaly and producer:
            payload = {
                "anomaly_id": str(anomaly.id),
                "tenant_id": str(anomaly.tenant_id),
                "entity_type": anomaly.entity_type,
                "entity_id": anomaly.entity_id,
                "event_type": anomaly.event_type,
                "anomaly_score": anomaly.anomaly_score,
                "risk_level": anomaly.risk_level,
                "features": anomaly.features,
                "peer_group_id": anomaly.peer_group_id,
                "peer_deviation_score": anomaly.peer_deviation_score,
                "detected_at": anomaly.detected_at.isoformat() if anomaly.detected_at else None,
            }
            await producer.send_and_wait(
                settings.kafka_output_topic,
                json.dumps(payload).encode(),
            )
            LOG.info(
                "Anomaly emitted: entity=%s/%s score=%.2f risk=%s",
                entity_type,
                entity_id,
                anomaly.anomaly_score,
                anomaly.risk_level,
            )

    async def run(self) -> None:
        try:
            from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
        except ImportError:
            LOG.error("aiokafka not installed; Kafka consumer disabled.")
            return

        consumer = AIOKafkaConsumer(
            settings.kafka_input_topic,
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id=settings.kafka_consumer_group,
            auto_offset_reset="latest",
            enable_auto_commit=True,
        )
        producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
        )

        await consumer.start()
        await producer.start()
        self._running = True
        LOG.info("UEBA Kafka consumer started (topic=%s)", settings.kafka_input_topic)

        try:
            await self._consume(consumer, producer)
        finally:
            await consumer.stop()
            await producer.stop()
            LOG.info("UEBA Kafka consumer stopped.")

    async def _consume(self, messages: Any, producer: Any) -> None:
        """Process messages until stopped. A message that fails is logged and skipped: one bad row (a DB error, a schema mismatch) must not end the consumer."""
        async for msg in messages:
            if not self._running:
                break
            record_event()
            try:
                await self._process_message(msg.value, producer)
            except Exception:  # noqa: BLE001
                LOG.exception("UEBA failed to process a message; continuing")

    def stop(self) -> None:
        self._running = False
