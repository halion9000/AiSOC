"""What AiSOC suggests adding to a client's vCIO Toolbox, worked out from the same checks the client review shows.

A check that is "not met" or "partly" becomes a suggested recommendation (a title, a plain description with the evidence, a priority). A person approves or rejects each one; CORE creates an approved one at
vCIO Toolbox. This module only decides what to suggest and keeps the rows in step with the checks; it never contacts vCIO Toolbox.

Row states: ``suggested`` (waiting for a person), ``approved`` (CORE will send it), ``sent`` / ``failed`` (CORE's result), ``rejected`` (a person said no; it stays rejected, so it is not suggested again),
``cleared`` (nobody acted and the condition went away).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.models.signin import ClientVcioProposal
from app.services.client_review import Readiness

SOURCE = "vciotoolbox"
ACTIONABLE = ("not_met", "partly")


@dataclass(frozen=True, slots=True)
class Draft:
    key: str
    name: str
    description: str
    priority: str
    evidence: str


# The recommendation to suggest for each check that can fail: its title in the words a client reads.
TITLES = {
    "mfa_everyone": "Require Multi-Factor Authentication for every person",
    "mfa_admins": "Require Multi-Factor Authentication for every administrator",
    "edr": "Put endpoint detection and response on every computer",
    "management": "Manage and patch every computer through the management tool",
    "dns": "Put DNS or web filtering on every computer",
    "privilege": "Control administrator access with privilege elevation",
    "agents_reporting": "Repair the protection agents that have stopped checking in",
    "patching": "Fix the known-exploited vulnerabilities on the client's computers",
    "backups": "Put every server and computer on the backup service and confirm restores are tested",
    "saas_backup": "Back up Microsoft 365 and Google Workspace data and fix the services that are not being backed up",
    "network_online": "Bring the offline network equipment back online",
    "secure_score": "Raise the Microsoft 365 Secure Score by applying Microsoft's recommendations",
}


def drafts_from_readiness(readiness: Readiness, now: datetime | None = None) -> list[Draft]:
    """One draft for each check that is not met or partly met and has a recommendation to suggest. Unknown checks are never suggested: AiSOC cannot say they are failing."""
    stamp = (now or datetime.now(UTC)).date().isoformat()
    out: list[Draft] = []
    for item in readiness.items:
        title = TITLES.get(item.key)
        if title is None or item.status not in ACTIONABLE:
            continue
        out.append(
            Draft(
                key=item.key,
                name=title,
                description=f"{item.question} {item.evidence} Suggested by AiSOC from the connected tools on {stamp}.",
                priority="High" if item.status == "not_met" else "Medium",
                evidence=item.evidence,
            )
        )
    return out


async def sync_suggestions(db: Any, tenant_id: uuid.UUID, drafts: list[Draft], now: datetime | None = None) -> dict[str, int]:
    """Bring this client's rows in step with ``drafts``. The caller owns the transaction and the tenant scope. Returns counts of what changed."""
    now = now or datetime.now(UTC)
    rows = (
        (await db.execute(select(ClientVcioProposal).where(ClientVcioProposal.tenant_id == tenant_id, ClientVcioProposal.source == SOURCE)))
        .scalars()
        .all()
    )
    by_key = {r.key: r for r in rows}
    wanted = {d.key for d in drafts}
    added = refreshed = cleared = 0
    for d in drafts:
        row = by_key.get(d.key)
        if row is None:
            db.add(
                ClientVcioProposal(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    source=SOURCE,
                    key=d.key,
                    kind="recommendation",
                    name=d.name,
                    description=d.description,
                    priority=d.priority,
                    evidence=d.evidence,
                    status="suggested",
                    created_at=now,
                    updated_at=now,
                )
            )
            added += 1
        elif row.status in ("suggested", "cleared"):
            # Nobody has acted on it: keep the words current, and bring it back if the condition is true again.
            row.name, row.description, row.priority, row.evidence = d.name, d.description, d.priority, d.evidence
            row.status = "suggested"
            row.updated_at = now
            refreshed += 1
        # approved / sent / failed / rejected are a person's or CORE's outcome: left as they are.
    for key, row in by_key.items():
        if key not in wanted and row.status == "suggested":
            row.status = "cleared"
            row.updated_at = now
            cleared += 1
    await db.flush()
    return {"added": added, "refreshed": refreshed, "cleared": cleared}
