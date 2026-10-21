"""Baseline computation service.

Maintains a rolling Welford online-statistics baseline per entity.
On each call to ``update_baseline`` the running mean and variance are
updated without having to re-read the full window of historical events.
"""

from __future__ import annotations

import copy
import math
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import settings
from app.models.ueba import EntityBaseline

# ---------------------------------------------------------------------------
# Welford online statistics helpers
# ---------------------------------------------------------------------------


def _welford_update(
    stats: dict[str, dict[str, float]],
    feature: str,
    value: float,
) -> dict[str, dict[str, float]]:
    """Update incremental mean/variance for *feature* with new *value*.

    Uses Welford's online algorithm:
      n  ← n + 1
      δ  ← x - mean
      mean ← mean + δ/n
      δ2 ← x - mean
      M2 ← M2 + δ·δ2
      variance = M2 / (n−1) for n > 1
    """
    if feature not in stats:
        stats[feature] = {"mean": 0.0, "M2": 0.0, "count": 0}

    s = stats[feature]
    s["count"] += 1
    n = s["count"]
    delta = value - s["mean"]
    s["mean"] += delta / n
    delta2 = value - s["mean"]
    s["M2"] += delta * delta2

    # Compute std from M2
    variance = s["M2"] / (n - 1) if n > 1 else 0.0
    s["std"] = math.sqrt(variance)

    return stats


# Features where only an INCREASE is a warning sign: more failed sign-ins, a sign-in without multi-factor, a higher risk level, a new country or address. A person who usually has these and
# has fewer of them today is not suspicious, so a value below their usual scores zero instead of the same distance upward. Everything else (the hour of day) is judged both ways.
UPWARD_ONLY_FEATURES = frozenset({"failed", "no_mfa", "non_interactive", "risk", "new_country", "new_ip"})


def compute_z_score(
    stats: dict[str, dict[str, float]],
    feature: str,
    value: float,
    *,
    min_samples: int | None = None,
    upward_only: bool | None = None,
) -> float | None:
    """Return the z-score of *value* given the baseline stats for *feature*.

    Returns ``None`` when the baseline cannot produce a meaningful score: the
    feature has never been observed, fewer than *min_samples* events have been
    recorded, or the observed variance is degenerate. The degenerate case is
    not an edge case in practice — service accounts, batch jobs and automation
    users converge on a constant stream, so their standard deviation collapses
    to zero and every subsequent value, however extreme, sits zero deviations
    from the mean.

    ``None`` means "unknown", not "normal". Returning ``0.0`` for these cases
    made an unscoreable entity indistinguishable from one sitting exactly on
    its own mean, and the RSS composite reads that as all-clear. Callers must
    skip ``None`` rather than coerce it to a number.
    ``peer_group.deviation_score`` already draws this distinction — this brings
    the personal-baseline path in line with it.
    """
    threshold = settings.min_baseline_samples if min_samples is None else min_samples

    # 1. No baseline recorded for this feature at all.
    if feature not in stats:
        return None

    s = stats[feature]

    # 2. Too few observations for the sample variance to carry information.
    if s.get("count", 0) < threshold:
        return None

    # 3. Degenerate distribution — every observation identical.
    std = s.get("std", 0.0)
    if std < 1e-9:
        return None

    one_sided = (feature in UPWARD_ONLY_FEATURES) if upward_only is None else upward_only
    deviation = value - s["mean"]
    return max(0.0, deviation) / std if one_sided else abs(deviation) / std


# ---------------------------------------------------------------------------
# DB-backed baseline service
# ---------------------------------------------------------------------------


class BaselineService:
    def __init__(self, session: AsyncSession) -> None:
        self._db = session

    async def get_or_create(
        self,
        tenant_id: uuid.UUID,
        entity_type: str,
        entity_id: str,
    ) -> EntityBaseline:
        now = datetime.now(UTC)
        # Create it if absent in ONE statement: the unique index (migration 0003) makes a request that loses the race do nothing, instead of leaving a second row that
        # broke every later read of this entity.
        await self._db.execute(
            pg_insert(EntityBaseline)
            .values(
                tenant_id=tenant_id,
                entity_type=entity_type,
                entity_id=entity_id,
                feature_stats={},
                window_start=now - timedelta(days=settings.baseline_window_days),
                window_end=now,
            )
            .on_conflict_do_nothing(index_elements=["tenant_id", "entity_type", "entity_id"])
        )
        result = await self._db.execute(
            select(EntityBaseline)
            .where(
                EntityBaseline.tenant_id == tenant_id,
                EntityBaseline.entity_type == entity_type,
                EntityBaseline.entity_id == entity_id,
            )
            .order_by(EntityBaseline.updated_at.desc())
            .limit(1)
        )
        return result.scalars().one()

    async def update(
        self,
        tenant_id: uuid.UUID,
        entity_type: str,
        entity_id: str,
        features: dict[str, float],
    ) -> EntityBaseline:
        """Incrementally update the baseline with new feature observations."""
        baseline = await self.get_or_create(tenant_id, entity_type, entity_id)
        # A DEEP copy: the update below edits each feature's numbers in place. With a shallow copy the stored value was edited too, so the new and old values compared equal, SQLAlchemy saw no
        # change and wrote nothing: every baseline stayed at its first observation (count 1) and nothing was ever flagged.
        stats = copy.deepcopy(baseline.feature_stats)

        for feature, value in features.items():
            stats = _welford_update(stats, feature, value)

        baseline.feature_stats = stats
        flag_modified(baseline, "feature_stats")  # belt and braces: always write it
        baseline.window_end = datetime.now(UTC)
        await self._db.flush()
        return baseline

    async def score_features(
        self,
        tenant_id: uuid.UUID,
        entity_type: str,
        entity_id: str,
        features: dict[str, float],
    ) -> dict[str, dict[str, float | None]]:
        """Return per-feature z-scores (does not mutate the baseline).

        ``z_score`` is ``None`` for features whose baseline cannot be scored;
        ``value``/``mean``/``std`` are still populated so the UI can show what
        little is known about the entity.
        """
        baseline = await self.get_or_create(tenant_id, entity_type, entity_id)
        stats = baseline.feature_stats

        scored: dict[str, dict[str, float | None]] = {}
        for feature, value in features.items():
            z = compute_z_score(stats, feature, value)
            feat_stats = stats.get(feature, {})
            scored[feature] = {
                "value": value,
                "mean": feat_stats.get("mean", 0.0),
                "std": feat_stats.get("std", 0.0),
                "z_score": z,
            }
        return scored
