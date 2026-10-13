"""Load AiSOC's shipped first-party detection rules (``detections/**/*.yaml``) into the ``detection_rules`` table as built-in rules.

Why this exists: the repository ships ~870 curated detection rules as YAML, and the live detection engine (services/fusion) runs them from its own bundled
ruleset, but nothing ever put them in the database, so ``GET /api/v1/rules``, the console and anything built on them (Cipher's ``aisoc_list_rules``) saw an
empty list on every install. This loads them. They are CATALOGUE rows: the engine does not read this table, so loading changes what people can SEE, not
what fires.

    python -m app.scripts.load_builtin_detections            # prints one JSON line: {"ok": true, "created": N, "updated": N, "unchanged": N, "skipped": N}

Each TENANT gets its own copy (``is_builtin`` true, ``tenant_id`` = that tenant), not one shared row: ``detection_rules.tenant_id`` is NOT NULL in the real schema
(the model's "NULL = platform-wide" comment is not what the database allows), and a copy per tenant is also what row-level security can serve to a tenant
session without any shared-row rule. A tenant can tune or disable its own copy:
a rule is refreshed from its file ONLY when the shipped file's content changed (``provenance.sha256``), and even then the tenant's ``status`` is kept, so a rule
someone disabled stays disabled across launches and upgrades. Tenants created later are picked up the next time the loader runs.

Idempotent: a rule is identified within a tenant by (provenance.source == "aisoc-builtin", provenance.source_id == the rule's own ``id``), so running it again
updates rules in place and never duplicates. Only first-party tiers are read: ``*-imports/`` trees,
``fixtures/`` and ``_quarantine/`` are skipped, and so is any YAML that is not a rule (the playbook files in the same tree have no ``detection`` block).

Where the rules come from: ``AISOC_DETECTIONS_DIR``, else ``/app/detections`` (the compose file mounts the repository's folder there, read-only), else the
repository's own ``detections/`` folder when run from a checkout.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SOURCE = "aisoc-builtin"
RULE_LANGUAGE = "aisoc"
_SKIP_PARTS = ("-imports", "fixtures", "_quarantine")
_TECHNIQUE_TAG = re.compile(r"^mitre\.attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TACTIC_TAG = re.compile(r"^mitre\.attack\.([a-z][a-z-]*)$", re.IGNORECASE)
_SEVERITIES = {"low", "medium", "high", "critical"}


def detections_dir() -> Path | None:
    for candidate in (os.environ.get("AISOC_DETECTIONS_DIR"), "/app/detections", str(Path(__file__).resolve().parents[4] / "detections")):
        if candidate and Path(candidate).is_dir():
            return Path(candidate)
    return None


@dataclass
class LoadReport:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped: int = 0
    skipped_files: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"ok": True, "created": self.created, "updated": self.updated, "unchanged": self.unchanged, "skipped": self.skipped}


def _is_first_party(path: Path, root: Path) -> bool:
    rel = path.relative_to(root).parts
    return not any(part.endswith("-imports") or part in ("fixtures", "_quarantine") for part in rel[:-1])


def _techniques_and_tactics(tags: Any) -> tuple[list[str], list[str]]:
    techniques: list[str] = []
    tactics: list[str] = []
    for tag in tags if isinstance(tags, list) else []:
        text = str(tag).strip()
        m = _TECHNIQUE_TAG.match(text)
        if m:
            value = m.group(1).upper()
            if value not in techniques:
                techniques.append(value)
            continue
        m = _TACTIC_TAG.match(text)
        if m and m.group(1).lower() != "attack":
            value = m.group(1).lower()
            if value not in tactics:
                tactics.append(value)
    return techniques, tactics


def normalise(raw_text: str, rel_path: str) -> dict[str, Any] | None:
    """The column values for one rule file, or None when the file is not a first-party rule."""
    try:
        doc = yaml.safe_load(raw_text)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("detection"), dict):
        return None
    rule_id, name = doc.get("id"), doc.get("name")
    if not isinstance(rule_id, str) or not rule_id.strip() or not isinstance(name, str) or not name.strip():
        return None
    severity = str(doc.get("severity", "medium")).lower()
    if severity not in _SEVERITIES:
        severity = "medium"
    techniques, tactics = _techniques_and_tactics(doc.get("tags"))
    major = re.match(r"\s*(\d+)", str(doc.get("version", "1")))
    return {
        "source_id": rule_id.strip(),
        "name": name.strip()[:255],
        "description": (str(doc["description"]).strip() or None) if doc.get("description") else None,
        "rule_body": raw_text,
        "category": str(doc.get("category") or "uncategorized")[:100],
        "severity": severity,
        "status": "active" if doc.get("enabled", True) is not False else "disabled",
        "mitre_techniques": techniques,
        "mitre_tactics": tactics,
        "tags": [str(t) for t in doc["tags"]] if isinstance(doc.get("tags"), list) else [],
        "version": int(major.group(1)) if major else 1,
        "provenance": {
            "source": SOURCE,
            "source_id": rule_id.strip(),
            "file": rel_path,
            "sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
        },
    }


def read_rules(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rules: list[dict[str, Any]] = []
    skipped: list[str] = []
    seen: set[str] = set()
    for path in sorted(root.rglob("*.yaml")):
        if not _is_first_party(path, root):
            continue
        rel = path.relative_to(root).as_posix()
        row = normalise(path.read_text(encoding="utf-8"), rel)
        if row is None or row["source_id"] in seen:
            skipped.append(rel)
            continue
        seen.add(row["source_id"])
        rules.append(row)
    return rules, skipped


_COLUMNS = (
    "name",
    "description",
    "rule_body",
    "category",
    "severity",
    "status",
    "mitre_techniques",
    "mitre_tactics",
    "tags",
    "version",
    "provenance",
)


async def load(session: Any, rules: list[dict[str, Any]], tenant_id: Any, skipped: list[str] | None = None) -> LoadReport:
    """Upsert ``rules`` (as produced by :func:`read_rules`) into ONE tenant. The caller owns the transaction and commits.

    The transaction is scoped to the tenant (``app.current_tenant_id``, local to the transaction) so it works the way a tenant request does, including with the
    fail-closed row-level-security switch on, rather than relying on a platform session that can write anywhere.
    """
    from sqlalchemy import select, text  # noqa: PLC0415

    from app.models.detection_rule import DetectionRule  # noqa: PLC0415

    await session.execute(text("select set_config('app.current_tenant_id', :t, true)"), {"t": str(tenant_id)})
    report = LoadReport(skipped=len(skipped or []), skipped_files=list(skipped or []))
    existing = {
        (r.provenance or {}).get("source_id"): r
        for r in (
            await session.execute(select(DetectionRule).where(DetectionRule.tenant_id == tenant_id, DetectionRule.is_builtin.is_(True)))
        ).scalars()
        if (r.provenance or {}).get("source") == SOURCE
    }
    for row in rules:
        current = existing.get(row["source_id"])
        values = {c: row[c] for c in _COLUMNS}
        if current is None:
            session.add(DetectionRule(tenant_id=tenant_id, is_builtin=True, rule_language=RULE_LANGUAGE, **values))
            report.created += 1
            continue
        if (current.provenance or {}).get("sha256") == row["provenance"]["sha256"]:
            report.unchanged += 1  # the file is as it was: leave the row exactly as the tenant has it
            continue
        for column, value in values.items():
            if column != "status":  # status belongs to the tenant once the row exists
                setattr(current, column, value)
        report.updated += 1
    return report


async def list_tenant_ids(session: Any) -> list[Any]:
    from sqlalchemy import text  # noqa: PLC0415

    return [row[0] for row in (await session.execute(text("select id from tenants order by created_at, id"))).all()]


async def main() -> None:
    root = detections_dir()
    if root is None:
        print(json.dumps({"ok": False, "error": "no detections folder found (set AISOC_DETECTIONS_DIR)"}))
        sys.exit(1)
    rules, skipped = read_rules(root)
    if not rules:
        print(json.dumps({"ok": False, "error": f"no rules found under {root}"}))
        sys.exit(1)

    from app.db.database import AsyncSessionLocal  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        tenants = await list_tenant_ids(session)
    if not tenants:
        print(json.dumps({"ok": False, "error": "no tenants exist yet (run AiSOC's setup step first)"}))
        sys.exit(1)

    total = LoadReport(skipped=len(skipped), skipped_files=skipped)
    for tenant_id in tenants:
        async with AsyncSessionLocal() as session:  # one transaction per tenant, each scoped to that tenant
            report = await load(session, rules, tenant_id, skipped)
            await session.commit()
        total.created += report.created
        total.updated += report.updated
        total.unchanged += report.unchanged
    print(json.dumps({**total.as_dict(), "tenants": len(tenants)}))


if __name__ == "__main__":
    asyncio.run(main())
