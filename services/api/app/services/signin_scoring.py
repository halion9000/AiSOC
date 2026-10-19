"""Turn sign-ins into the numbers the UEBA service scores, and ask it to score them.

The UEBA service keeps, for each person, a running baseline of every numeric feature it is sent, and says how far a new event is from that baseline. So what matters is choosing
features whose ordinary value is near zero and whose unusual value is a clear signal:

- ``hour_of_day`` (UTC): a person who always signs in 14:00-22:00 UTC is unusual at 04:00.
- ``failed``: 1 when Microsoft refused the sign-in (a run of them is a guessing attack).
- ``no_mfa``: 1 when a sign-in succeeded without multi-factor.
- ``non_interactive``: 1 for a token refresh or a background sign-in rather than a person.
- ``risk``: Microsoft's own risk level for the sign-in (none 0, low 1, medium 2, high 3); only tenants with the right licence report it.
- ``new_country`` and ``new_ip``: 1 when this person has not signed in from that country or address in the last 45 days. These are only judged for a person already seen at least once,
  so the first sign-ins collected for anyone never count as "new".

This module only builds features and makes the call; it raises nothing itself.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

RISK_LEVEL = {"none": 0.0, "low": 1.0, "medium": 2.0, "high": 3.0}
HISTORY_DAYS = 45
DEFAULT_UEBA_URL = "http://ueba:8004"
SCORE_CONCURRENCY = 8
SCORE_TIMEOUT_SECONDS = 10.0


@dataclass
class History:
    """What is already known about one person: the countries and addresses they signed in from, and whether any record exists."""

    countries: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    seen: bool = False

    def remember(self, country: str | None, ip: str | None) -> None:
        self.seen = True
        if country:
            self.countries.add(country)
        if ip:
            self.ips.add(ip)


def signin_features(
    *,
    occurred_at: datetime,
    success: bool,
    mfa: bool | None,
    interactive: bool,
    risk: str | None,
    country: str | None,
    ip: str | None,
    history: History,
) -> dict[str, float]:
    """The features of one sign-in, judged against what is already known about the person (see the module comment)."""
    return {
        "hour_of_day": float(occurred_at.hour),
        "failed": 0.0 if success else 1.0,
        "no_mfa": 1.0 if success and mfa is False else 0.0,
        "non_interactive": 0.0 if interactive else 1.0,
        "risk": RISK_LEVEL.get((risk or "none").lower(), 0.0),
        "new_country": 1.0 if history.seen and country and country not in history.countries else 0.0,
        "new_ip": 1.0 if history.seen and ip and ip not in history.ips else 0.0,
    }


def ueba_settings() -> tuple[str, str]:
    """(URL, bearer token) for the UEBA service; the token is empty when none is configured."""
    return (os.getenv("AISOC_UEBA_URL") or DEFAULT_UEBA_URL).rstrip("/"), (os.getenv("AISOC_UEBA_SERVICE_TOKEN") or "").strip()


@dataclass
class ScoreOutcome:
    """How scoring went for a batch: ``status`` is ok (all asked), unavailable (the service could not be reached or refused), or not_configured (no token set)."""

    status: str
    scored: dict[Any, float | None] = field(default_factory=dict)
    anomalies: int = 0


async def score_events(events: list[dict[str, Any]], *, client: httpx.AsyncClient | None = None) -> ScoreOutcome:
    """Send each event to the UEBA service's ``/score``. ``events`` items: ``key`` (anything hashable, returned in ``scored``), ``tenant_id``, ``entity_id``, ``event_type``,
    ``features``, ``source_event_id``. A score of None means the event was scored and was not anomalous. A failure on one event stops asking (the service is down), and the rest stay unscored."""
    base, token = ueba_settings()
    if not token:
        return ScoreOutcome(status="not_configured")
    if not events:
        return ScoreOutcome(status="ok")
    out = ScoreOutcome(status="ok")
    own = client is None
    http = client or httpx.AsyncClient(timeout=SCORE_TIMEOUT_SECONDS)
    sem = asyncio.Semaphore(SCORE_CONCURRENCY)
    stop = False

    async def one(e: dict[str, Any]) -> None:
        nonlocal stop
        if stop:
            return
        async with sem:
            if stop:
                return
            try:
                res = await http.post(
                    f"{base}/api/v1/ueba/score",
                    headers={"Authorization": f"Bearer {token}"},
                    json={
                        "tenant_id": str(e["tenant_id"]),
                        "entity_type": "user",
                        "entity_id": e["entity_id"],
                        "event_type": e["event_type"],
                        "features": e["features"],
                        "source_event_id": e.get("source_event_id"),
                    },
                )
            except httpx.HTTPError:
                stop = True
                return
            if res.status_code != 200:
                stop = True
                return
            try:
                body = res.json()
            except ValueError:
                body = None
            if body:
                out.anomalies += 1
                out.scored[e["key"]] = float(body.get("anomaly_score", 0.0))
            else:
                out.scored[e["key"]] = None

    try:
        await asyncio.gather(*(one(e) for e in events))
    finally:
        if own:
            await http.aclose()
    if stop:
        out.status = "unavailable"
    return out
