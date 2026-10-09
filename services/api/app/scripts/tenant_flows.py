"""Two-tenant, multi-step flows against the REAL API: does tenant B ever see or change tenant A's data?

It boots the real app (real lifespan, real database), logs in as an admin of each of two tenants, and runs flows in which A creates and modifies things through sub-resources (cases and their comments, saved views, API keys, saved hunts, shifts,
approvals, alerts) while B probes them: B must get 404 reading, changing or deleting A's objects, and B's lists must exclude A's. Finally A creates a FRESH object of every kind that B has never mentioned, and B calls every parameterless GET endpoint:
any response containing one of those ids is a leak. (B must not have mentioned the ids: the audit log and cost dashboard faithfully record B's OWN requests, so ids B sent show up there. An earlier version of this test reported those as leaks.)

WHY IT EXISTS. Row-level security only protects a connection that is NOT a superuser, and the default deployment connects as the Postgres bootstrap superuser, so any endpoint that relies on RLS alone leaks there. The shifts module did ("every query is
automatically filtered by row-level security"): as the superuser any tenant could list, close and overwrite every other tenant's shifts and read their open alerts. A read-only sweep and a row-count comparison could not see it; this found it. It also found
that attaching alerts to a case never checked the alerts belonged to the caller (wrong under BOTH roles).

USAGE (against a SCRATCH database only: it creates data, and it refuses to run in production):
    # 1. two tenants with an admin each (any password hash from app.core.security.get_password_hash); clone this database once per role you want to compare
    # 2. run once per role, each on its own clone, e.g. as the superuser and as aisoc_app (with MIGRATION_DATABASE_URL = the owner):
    TENANT_FLOWS_PASSWORD=... DATABASE_URL=...  python -m app.scripts.tenant_flows run --label superuser --yes-write-test-data
    TENANT_FLOWS_PASSWORD=... DATABASE_URL=...  python -m app.scripts.tenant_flows run --label app_role  --yes-write-test-data
    # 3. compare:
    python -m app.scripts.tenant_flows compare tenant_flows_superuser.json tenant_flows_app_role.json
`run` exits 1 if any step was not as expected; `compare` exits 1 if the two runs differ in any step's status or outcome or in the leaks found.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

ISO = (404, 403)  # what "not yours" may look like


def _ref(spec: dict, schema: dict) -> dict:
    comps = spec.get("components", {}).get("schemas", {})
    while "$ref" in schema:
        schema = comps[schema["$ref"].split("/")[-1]]
    return schema


def gen(spec: dict, schema: dict, seed: str, depth: int = 0) -> Any:
    """A minimal valid value for `schema`, deterministic in `seed` (so two runs send byte-identical requests)."""
    if depth > 5:
        return None
    s = _ref(spec, schema)
    if "allOf" in s:
        out: dict = {}
        for part in s["allOf"]:
            v = gen(spec, part, seed, depth + 1)
            if isinstance(v, dict):
                out.update(v)
        return out
    for k in ("anyOf", "oneOf"):
        if k in s:
            opts = [o for o in s[k] if _ref(spec, o).get("type") != "null"]
            return gen(spec, opts[0], seed, depth + 1) if opts else None
    if "enum" in s:
        return s["enum"][0]
    t, f = s.get("type"), s.get("format", "")
    if t == "string":
        if f == "email":
            return "user@example.com"
        if f == "uuid":
            return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
        if f == "date-time":
            return "2026-01-01T00:00:00Z"
        if f == "date":
            return "2026-01-01"
        return ("flow-" + re.sub(r"\W", "", seed)[-14:]).ljust(s.get("minLength", 0), "x")[: s.get("maxLength", 200)]
    if t == "integer":
        return max(int(s.get("minimum", 1)), 1)
    if t == "number":
        return 1.0
    if t == "boolean":
        return False
    if t == "array":
        item = gen(spec, s.get("items", {}), seed + "[]", depth + 1)
        return [item] if s.get("minItems", 0) >= 1 and item is not None else []
    if t == "object" or "properties" in s:
        return {n: gen(spec, s.get("properties", {}).get(n, {}), seed + "." + n, depth + 1) for n in s.get("required", [])}
    return None


def find_spec(spec: dict, tpl: str) -> str:
    """My templates name path parameters their own way ({case}); the spec's differ ({case_id}). Match by shape."""
    shape = re.sub(r"\{[^}]+\}", "{}", tpl)
    for path in spec["paths"]:
        if re.sub(r"\{[^}]+\}", "{}", path) == shape:
            return path
    raise KeyError(tpl)


def body_for(spec: dict, tpl: str, method: str, **over: Any) -> Any:
    op = spec["paths"][find_spec(spec, tpl)][method]
    sch = op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema")
    body = gen(spec, sch, tpl + method) if sch is not None else {}
    if isinstance(body, dict):
        body.update(over)
    return body


@dataclass
class Step:
    name: str
    user: str  # "A" or "B"
    method: str
    tpl: str
    over: dict = field(default_factory=dict)
    capture: tuple[str, str] | None = None
    expect: tuple[int, ...] = (200, 201, 202, 204)
    check: Callable[[Any, dict], bool] | None = None
    nobody: bool = False
    params: dict | None = None


def _has(resp: Any, needle: str) -> bool:
    return needle in resp.text


def S(name: str, user: str, method: str, tpl: str, **kw: Any) -> Step:
    return Step(name, user, method, tpl, **kw)


def build_flows() -> dict[str, list[Step]]:
    flows = {
        "cases": [
            S("A creates a case", "A", "post", "/api/v1/cases", capture=("case", "id")),
            S("A's shift handoff includes the case", "A", "get", "/api/v1/shifts/handoff-items", expect=(200,), check=lambda r, c: _has(r, c["case"])),
            S("B's shift handoff does not", "B", "get", "/api/v1/shifts/handoff-items", expect=(200,), check=lambda r, c: not _has(r, c["case"])),
            S("A reads it", "A", "get", "/api/v1/cases/{case}", expect=(200,)),
            S("A renames it", "A", "patch", "/api/v1/cases/{case}", over={"title": "Renamed by A"}, expect=(200,)),
            S("A comments", "A", "post", "/api/v1/cases/{case}/comments", capture=("comment", "id")),
            S("A lists comments (has it)", "A", "get", "/api/v1/cases/{case}/comments", expect=(200,), check=lambda r, c: _has(r, c["comment"])),
            S("A lists cases (has it)", "A", "get", "/api/v1/cases", expect=(200,), check=lambda r, c: _has(r, c["case"])),
            S("B cannot read A's case", "B", "get", "/api/v1/cases/{case}", expect=ISO),
            S("B cannot rename A's case", "B", "patch", "/api/v1/cases/{case}", over={"title": "pwned"}, expect=ISO),
            S("B cannot comment on A's case", "B", "post", "/api/v1/cases/{case}/comments", expect=ISO),
            S("B cannot list A's comments", "B", "get", "/api/v1/cases/{case}/comments", expect=(404, 403, 200), check=lambda r, c: r.status_code != 200 or not _has(r, c["comment"])),
            S("B's case list excludes it", "B", "get", "/api/v1/cases", expect=(200,), check=lambda r, c: not _has(r, c["case"])),
            S("A's case is still intact", "A", "get", "/api/v1/cases/{case}", expect=(200,), check=lambda r, c: _has(r, "Renamed by A")),
            S("B's shift handoff items exclude A's case", "B", "get", "/api/v1/shifts/handoff-items", expect=(200,), check=lambda r, c: not _has(r, c["case"])),
        ],
        "saved_views": [
            S("A creates a view", "A", "post", "/api/v1/saved-views", over={"view_type": "alerts"}, capture=("view", "id")),
            S("A renames it", "A", "patch", "/api/v1/saved-views/{view}", over={"name": "A renamed"}, expect=(200,)),
            S("A lists (has it)", "A", "get", "/api/v1/saved-views", params={"view_type": "alerts"}, expect=(200,), check=lambda r, c: _has(r, c["view"])),
            S("B's list excludes it", "B", "get", "/api/v1/saved-views", params={"view_type": "alerts"}, expect=(200,), check=lambda r, c: not _has(r, c["view"])),
            S("B cannot change it", "B", "patch", "/api/v1/saved-views/{view}", over={"name": "pwned"}, expect=ISO),
            S("B cannot delete it", "B", "delete", "/api/v1/saved-views/{view}", expect=ISO, nobody=True),
            S("A deletes it", "A", "delete", "/api/v1/saved-views/{view}", expect=(200, 204), nobody=True),
            S("A's list no longer has it", "A", "get", "/api/v1/saved-views", params={"view_type": "alerts"}, expect=(200,), check=lambda r, c: not _has(r, c["view"])),
        ],
        "api_keys": [
            S("A creates a key", "A", "post", "/api/v1/api-keys", capture=("key", "id")),
            S("A reads it", "A", "get", "/api/v1/api-keys/{key}", expect=(200,)),
            S("A renames it", "A", "patch", "/api/v1/api-keys/{key}", over={"name": "A-key-renamed"}, expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/api-keys/{key}", expect=ISO),
            S("B cannot change it", "B", "patch", "/api/v1/api-keys/{key}", over={"name": "pwned"}, expect=ISO),
            S("B cannot delete it", "B", "delete", "/api/v1/api-keys/{key}", expect=ISO, nobody=True),
            S("B's list excludes it", "B", "get", "/api/v1/api-keys", expect=(200,), check=lambda r, c: not _has(r, c["key"])),
            S("A deletes it", "A", "delete", "/api/v1/api-keys/{key}", expect=(200, 204), nobody=True),
        ],
        "saved_hunts": [
            S("A saves a hunt", "A", "post", "/api/v1/saved-hunts", capture=("hunt", "id")),
            S("A reads it", "A", "get", "/api/v1/saved-hunts/{hunt}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/saved-hunts/{hunt}", expect=ISO),
            S("B cannot delete it", "B", "delete", "/api/v1/saved-hunts/{hunt}", expect=ISO, nobody=True),
            S("B's list excludes it", "B", "get", "/api/v1/saved-hunts", expect=(200,), check=lambda r, c: not _has(r, c["hunt"])),
            S("A deletes it", "A", "delete", "/api/v1/saved-hunts/{hunt}", expect=(200, 204), nobody=True),
        ],
        "shifts": [
            S("A starts a shift", "A", "post", "/api/v1/shifts", capture=("shift", "id")),
            S("B starts ITS OWN shift", "B", "post", "/api/v1/shifts", capture=("shift_b", "id")),
            S("A's shift is still active (B starting one must not close it)", "A", "get", "/api/v1/shifts", expect=(200,), check=lambda r, c: any(x["id"] == c["shift"] and x["status"] == "active" for x in r.json())),
            S("A writes the handoff", "A", "put", "/api/v1/shifts/{shift}/handoff", expect=(200,)),
            S("A lists (has it)", "A", "get", "/api/v1/shifts", expect=(200,), check=lambda r, c: _has(r, c["shift"])),
            S("B cannot write A's handoff", "B", "put", "/api/v1/shifts/{shift}/handoff", expect=ISO),
            S("B's shift list excludes A's shift", "B", "get", "/api/v1/shifts", expect=(200,), check=lambda r, c: not _has(r, c["shift"])),
            S("B's own shift is still active (A's actions must not touch it)", "B", "get", "/api/v1/shifts", expect=(200,), check=lambda r, c: any(x["id"] == c["shift_b"] and x["status"] == "active" for x in r.json())),
        ],
        "approvals": [
            S("A requests an approval", "A", "post", "/api/v1/approvals", capture=("appr", "id")),
            S("A reads it", "A", "get", "/api/v1/approvals/{appr}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/approvals/{appr}", expect=ISO),
            S("B cannot decide it", "B", "post", "/api/v1/approvals/{appr}/decide", expect=ISO),
            S("B's list excludes it", "B", "get", "/api/v1/approvals", expect=(200,), check=lambda r, c: not _has(r, c["appr"])),
            S("A decides it", "A", "post", "/api/v1/approvals/{appr}/decide", expect=(200, 201, 202)),
        ],
        "alerts": [
            S("A submits an alert", "A", "post", "/api/v1/alerts/submit", over={"title": "flow alert", "severity": "high", "events": [{"message": "flow event", "host": "h1", "user": "u1"}]}, capture=("alert", "id")),
            S("A reads it", "A", "get", "/api/v1/alerts/{alert}", expect=(200,)),
            S("A claims it", "A", "post", "/api/v1/alerts/{alert}/claim", expect=(200, 201, 202), nobody=True),
            S("B cannot read it", "B", "get", "/api/v1/alerts/{alert}", expect=ISO),
            S("B cannot claim it", "B", "post", "/api/v1/alerts/{alert}/claim", expect=ISO, nobody=True),
            S("B's alert list excludes it", "B", "get", "/api/v1/alerts", expect=(200,), check=lambda r, c: not _has(r, c["alert"])),
            S("A attaches it to a case", "A", "post", "/api/v1/cases", capture=("case2", "id")),
            S("A links the alert", "A", "post", "/api/v1/cases/{case2}/alerts", expect=(200, 201, 202)),
            S("B makes its own case", "B", "post", "/api/v1/cases", capture=("case_b", "id")),
            S("B cannot attach A's alert", "B", "post", "/api/v1/cases/{case_b}/alerts", expect=(404, 403, 400, 422)),
            S("B's case does not expose A's alert content", "B", "get", "/api/v1/cases/{case_b}", expect=(200,), check=lambda r, c: "flow alert" not in r.text),
            S("B's shift handoff items exclude A's alert", "B", "get", "/api/v1/shifts/handoff-items", expect=(200,), check=lambda r, c: not _has(r, c["alert"])),
        ],
        # A creates objects B has NEVER mentioned: the only ids the final sweep may look for.
        "fresh": [
            S("A creates a fresh case", "A", "post", "/api/v1/cases", capture=("f_case", "id")),
            S("A creates a fresh view", "A", "post", "/api/v1/saved-views", over={"view_type": "alerts"}, capture=("f_view", "id")),
            S("A creates a fresh key", "A", "post", "/api/v1/api-keys", capture=("f_key", "id")),
            S("A saves a fresh hunt", "A", "post", "/api/v1/saved-hunts", capture=("f_hunt", "id")),
            S("A starts a fresh shift", "A", "post", "/api/v1/shifts", capture=("f_shift", "id")),
            S("A requests a fresh approval", "A", "post", "/api/v1/approvals", capture=("f_appr", "id")),
            S("A submits a fresh alert", "A", "post", "/api/v1/alerts/submit", over={"title": "fresh alert", "severity": "high", "events": [{"message": "fresh event", "host": "h2", "user": "u2"}]}, capture=("f_alert", "id")),
        ],
    }
    fresh = flows.pop("fresh")
    flows.update(_more_flows())
    flows["fresh"] = fresh + _more_fresh()  # still last: A creating objects B has never mentioned
    return flows


NOT_YOURS = (404, 403, 400, 422)  # for cross-tenant WRITES that name another tenant's object in the body: any refusal will do, success is the bug


def _more_flows() -> dict[str, list[Step]]:
    nothave = lambda key: (lambda r, c: not _has(r, c[key]))  # noqa: E731
    return {
        "assets": [
            S("A creates an asset", "A", "post", "/api/v1/assets", capture=("asset", "id")),
            S("A reads it", "A", "get", "/api/v1/assets/{asset}", expect=(200,)),
            S("A renames it", "A", "patch", "/api/v1/assets/{asset}", over={"name": "asset-renamed-by-A"}, expect=(200,)),
            S("A adds a vulnerability to it", "A", "post", "/api/v1/assets/vulnerabilities", capture=("vuln", "id")),
            S("A lists its vulnerabilities (has it)", "A", "get", "/api/v1/assets/{asset}/vulnerabilities", expect=(200,), check=lambda r, c: _has(r, c["vuln"])),
            S("B cannot read it", "B", "get", "/api/v1/assets/{asset}", expect=ISO),
            S("B cannot rename it", "B", "patch", "/api/v1/assets/{asset}", over={"name": "pwned"}, expect=ISO),
            S("B cannot delete it", "B", "delete", "/api/v1/assets/{asset}", expect=ISO, nobody=True),
            S("B cannot list its vulnerabilities", "B", "get", "/api/v1/assets/{asset}/vulnerabilities", expect=(404, 403, 200), check=lambda r, c: r.status_code != 200 or not _has(r, c["vuln"])),
            S("B's asset list excludes it", "B", "get", "/api/v1/assets", expect=(200,), check=nothave("asset")),
            S("B's vulnerability list excludes it", "B", "get", "/api/v1/assets/vulnerabilities", expect=(200,), check=nothave("vuln")),
            S("A's asset is still intact", "A", "get", "/api/v1/assets/{asset}", expect=(200,), check=lambda r, c: _has(r, "asset-renamed-by-A")),
            S("A deletes it", "A", "delete", "/api/v1/assets/{asset}", expect=(200, 204), nobody=True),
        ],
        "threat_intel": [
            S("A adds an IOC", "A", "post", "/api/v1/threat-intel/iocs", over={"ioc_type": "ip", "value": "203.0.113.9"}, capture=("ioc", "id")),
            S("A adds a feed", "A", "post", "/api/v1/threat-intel/feeds", over={"feed_type": "taxii"}, capture=("feed", "id")),
            S("A reads the IOC", "A", "get", "/api/v1/threat-intel/iocs/{ioc}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/threat-intel/iocs/{ioc}", expect=ISO),
            S("B cannot delete it", "B", "delete", "/api/v1/threat-intel/iocs/{ioc}", expect=ISO, nobody=True),
            S("B cannot delete A's feed", "B", "delete", "/api/v1/threat-intel/feeds/{feed}", expect=ISO, nobody=True),
            S("B's IOC list excludes it", "B", "get", "/api/v1/threat-intel/iocs", expect=(200,), check=nothave("ioc")),
            S("B's feed list excludes it", "B", "get", "/api/v1/threat-intel/feeds", expect=(200,), check=nothave("feed")),
            S("A's IOC is still there", "A", "get", "/api/v1/threat-intel/iocs/{ioc}", expect=(200,)),
            S("A deletes the IOC", "A", "delete", "/api/v1/threat-intel/iocs/{ioc}", expect=(200, 204), nobody=True),
            S("A deletes the feed", "A", "delete", "/api/v1/threat-intel/feeds/{feed}", expect=(200, 204), nobody=True),
        ],
        "reports": [
            S("A creates a report template", "A", "post", "/api/v1/reports/templates", over={"report_type": "soc_weekly"}, capture=("tmpl", "id")),
            S("A reads it", "A", "get", "/api/v1/reports/templates/{tmpl}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/reports/templates/{tmpl}", expect=ISO),
            S("B cannot delete it", "B", "delete", "/api/v1/reports/templates/{tmpl}", expect=ISO, nobody=True),
            S("B's template list excludes it", "B", "get", "/api/v1/reports/templates", expect=(200,), check=nothave("tmpl")),
            S("A deletes it", "A", "delete", "/api/v1/reports/templates/{tmpl}", expect=(200, 204), nobody=True),
        ],
        "remediation": [
            S("A whitelists an action", "A", "post", "/api/v1/remediation/whitelist", over={"action_type": "isolate_host", "blast_radius": "low"}, capture=("wl", "id")),
            S("B cannot remove it", "B", "delete", "/api/v1/remediation/whitelist/{wl}", expect=ISO, nobody=True),
            S("B's whitelist excludes it", "B", "get", "/api/v1/remediation/whitelist", expect=(200,), check=nothave("wl")),
            S("A removes it", "A", "delete", "/api/v1/remediation/whitelist/{wl}", expect=(200, 204), nobody=True),
        ],
        "identity_graph": [
            S("A creates a node", "A", "post", "/api/v1/identity-graph/nodes", over={"node_type": "human_user", "external_id": "ext-a-1", "source_system": "okta"}, capture=("n1", "id")),
            S("A creates a second node", "A", "post", "/api/v1/identity-graph/nodes", over={"node_type": "human_user", "external_id": "ext-a-2", "source_system": "okta"}, capture=("n2", "id")),
            S("A links them", "A", "post", "/api/v1/identity-graph/edges", over={"edge_type": "member_of"}, capture=("edge", "id")),
            S("A reads the node", "A", "get", "/api/v1/identity-graph/nodes/{n1}", expect=(200,)),
            S("B cannot read A's node", "B", "get", "/api/v1/identity-graph/nodes/{n1}", expect=ISO),
            S("B cannot read A's node edges", "B", "get", "/api/v1/identity-graph/nodes/{n1}/edges", expect=(404, 403, 200), check=lambda r, c: r.status_code != 200 or not _has(r, c["edge"])),
            S("B's node list excludes it", "B", "get", "/api/v1/identity-graph/nodes", expect=(200,), check=nothave("n1")),
            S("B's edge list excludes it", "B", "get", "/api/v1/identity-graph/edges", expect=(200,), check=nothave("edge")),
            S("B makes its own node", "B", "post", "/api/v1/identity-graph/nodes", over={"node_type": "human_user", "external_id": "ext-b-1", "source_system": "okta"}, capture=("nb", "id")),
            S("B cannot link its node to A's node", "B", "post", "/api/v1/identity-graph/edges", over={"edge_type": "member_of"}, expect=NOT_YOURS),
        ],
        "posture": [
            S("A records a finding", "A", "post", "/api/v1/posture/findings", over={"cloud_provider": "aws", "resource_type": "s3_bucket", "resource_id": "bucket-a", "rule_id": "S3-001"}, capture=("finding", "id")),
            S("A reads it", "A", "get", "/api/v1/posture/findings/{finding}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/posture/findings/{finding}", expect=ISO),
            S("B cannot resolve it", "B", "post", "/api/v1/posture/findings/{finding}/resolve", expect=ISO, nobody=True),
            S("B cannot suppress it", "B", "post", "/api/v1/posture/findings/{finding}/suppress", expect=ISO),
            S("B's finding list excludes it", "B", "get", "/api/v1/posture/findings", expect=(200,), check=nothave("finding")),
            S("A's finding is still open", "A", "get", "/api/v1/posture/findings/{finding}", expect=(200,), check=lambda r, c: "suppressed" not in r.text.lower() or "resolved" not in r.text.lower()),
        ],
        "detection_rules": [
            S("A creates a rule", "A", "post", "/api/v1/detection/rules", over={"language": "sigma"}, capture=("rule", "id")),
            S("A reads it", "A", "get", "/api/v1/detection/rules/{rule}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/detection/rules/{rule}", expect=ISO),
            S("B cannot change it", "B", "patch", "/api/v1/detection/rules/{rule}", expect=ISO),
            S("B cannot delete it", "B", "delete", "/api/v1/detection/rules/{rule}", expect=ISO, nobody=True),
            S("B's rule list excludes it", "B", "get", "/api/v1/detection/rules", expect=(200,), check=nothave("rule")),
            S("B cannot tune it", "B", "post", "/api/v1/detection/tuning/{rule}/dismiss", over={"reason": "x"}, expect=ISO),
            S("A's rule is still there", "A", "get", "/api/v1/detection/rules/{rule}", expect=(200,)),
            S("A deletes it", "A", "delete", "/api/v1/detection/rules/{rule}", expect=(200, 204), nobody=True),
        ],
    }


def _more_fresh() -> list[Step]:
    return [
        S("A creates a fresh asset", "A", "post", "/api/v1/assets", capture=("f_asset", "id")),
        S("A adds a fresh IOC", "A", "post", "/api/v1/threat-intel/iocs", over={"ioc_type": "ip", "value": "198.51.100.7"}, capture=("f_ioc", "id")),
        S("A adds a fresh feed", "A", "post", "/api/v1/threat-intel/feeds", over={"feed_type": "taxii"}, capture=("f_feed", "id")),
        S("A creates a fresh template", "A", "post", "/api/v1/reports/templates", over={"report_type": "soc_weekly"}, capture=("f_tmpl", "id")),
        S("A whitelists a fresh action", "A", "post", "/api/v1/remediation/whitelist", over={"action_type": "isolate_host", "blast_radius": "low"}, capture=("f_wl", "id")),
        S("A creates a fresh node", "A", "post", "/api/v1/identity-graph/nodes", over={"node_type": "human_user", "external_id": "ext-fresh", "source_system": "okta"}, capture=("f_node", "id")),
        S("A records a fresh finding", "A", "post", "/api/v1/posture/findings", over={"cloud_provider": "aws", "resource_type": "s3_bucket", "resource_id": "bucket-fresh", "rule_id": "S3-002"}, capture=("f_finding", "id")),
        S("A creates a fresh rule", "A", "post", "/api/v1/detection/rules", over={"language": "sigma"}, capture=("f_rule", "id")),
    ]


def compare_runs(a: list[list], b: list[list]) -> dict[str, list]:
    """Differences between two runs: a step whose status or outcome changed, and the endpoints on which the leak sweep found something in only one."""
    key = lambda o: (o[0], o[1], o[2])  # noqa: E731
    A, B = {key(o): o for o in a}, {key(o): o for o in b}
    status = sorted((k[1], A[k][3], B[k][3]) for k in A if k in B and A[k][3] != B[k][3])
    outcome = sorted((k[1], A[k][4], B[k][4]) for k in A if k in B and A[k][4] != B[k][4] and k[0] != "SWEEP")
    only_a, only_b = sorted(k[1] for k in A if k not in B), sorted(k[1] for k in B if k not in A)
    leaks = lambda run: sorted({m for o in run if o[0] == "SWEEP" for m in re.findall(r"'(/api/v1[^']*)'", o[5])})  # noqa: E731
    la, lb = leaks(a), leaks(b)
    return {"status": status, "outcome": outcome, "only_in_first": only_a, "only_in_second": only_b, "leaks_only_in_first": sorted(set(la) - set(lb)), "leaks_only_in_second": sorted(set(lb) - set(la))}


async def run_flows(emails: tuple[str, str], password: str) -> list[list]:
    """Run every flow against the real app. Each result row: [flow, step, user, status, as_expected, detail]."""
    import httpx  # noqa: PLC0415

    from app.main import app  # noqa: PLC0415

    spec = app.openapi()
    out: list[list] = []
    fresh_ids: dict[str, str] = {}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", timeout=15) as c:
            tok: dict[str, dict] = {}
            for user, email in zip("AB", emails, strict=True):
                r = await c.post("/api/v1/auth/login", json={"email": email, "password": password})
                if r.status_code != 200:
                    raise SystemExit(f"login failed for tenant {user} ({email}): HTTP {r.status_code}")
                tok[user] = {"Authorization": "Bearer " + r.json()["access_token"]}
            for flow, steps in build_flows().items():
                ctx: dict[str, str] = {}
                for st in steps:
                    try:
                        path = st.tpl.format(**ctx) if "{" in st.tpl else st.tpl
                    except KeyError as e:
                        out.append([flow, st.name, st.user, "SKIP", False, f"needs {e}, which an earlier step did not produce"])
                        continue
                    over = dict(st.over)
                    if flow == "alerts" and st.name in ("A links the alert", "B cannot attach A's alert"):
                        over = {"alert_ids": [ctx.get("alert")]}
                    if flow == "assets" and st.name == "A adds a vulnerability to it":
                        over = {"asset_id": ctx.get("asset"), "title": "CVE-2026-0001", "source": "scanner"}
                    if flow == "identity_graph" and st.name == "A links them":
                        over = {**over, "source_id": ctx.get("n1"), "target_id": ctx.get("n2")}
                    if flow == "identity_graph" and st.name == "B cannot link its node to A's node":
                        over = {**over, "source_id": ctx.get("nb"), "target_id": ctx.get("n1")}
                    kw: dict[str, Any] = {}
                    if st.params:
                        kw["params"] = st.params
                    if st.method in ("post", "put", "patch") and not st.nobody:
                        try:
                            kw["json"] = body_for(spec, st.tpl, st.method, **over)
                        except KeyError:
                            kw["json"] = over
                    try:
                        r = await asyncio.wait_for(c.request(st.method.upper(), path, headers=tok[st.user], **kw), 15)
                    except Exception as e:  # noqa: BLE001
                        out.append([flow, st.name, st.user, "EXC", False, type(e).__name__])
                        continue
                    if st.capture and r.status_code < 300:
                        try:
                            ctx[st.capture[0]] = str(r.json()[st.capture[1]])
                            if st.user == "A" and flow == "fresh":
                                fresh_ids[ctx[st.capture[0]]] = st.capture[0]
                        except Exception:  # noqa: BLE001, S110
                            pass
                    ok = r.status_code in st.expect
                    if ok and st.check:
                        try:
                            ok = bool(st.check(r, ctx))
                        except Exception:  # noqa: BLE001
                            ok = False
                    out.append([flow, st.name, st.user, r.status_code, ok, "" if ok else r.text[:140]])
            gets = sorted(p for p, ops in spec["paths"].items() if "get" in ops and "{" not in p and p.startswith("/api/v1"))
            sem, leaks = asyncio.Semaphore(6), []

            async def sweep(p: str) -> None:
                async with sem:
                    try:
                        x = await asyncio.wait_for(c.get(p, headers=tok["B"]), 12)
                        leaks.extend([p, kind, x.status_code] for i, kind in fresh_ids.items() if i in x.text)
                    except Exception:  # noqa: BLE001, S110
                        pass

            await asyncio.gather(*[sweep(p) for p in gets])
            leaks.sort()
            out.append(["SWEEP", f"B called {len(gets)} GET endpoints; A created {len(fresh_ids)} FRESH ids that B never mentioned", "B", 200, not leaks, f"LEAKS: {leaks}" if leaks else ""])
    return out


def summarize(label: str, rows: list[list]) -> str:
    bad = [o for o in rows if not o[4]]
    lines = [f"[{label}] {len(rows)} steps; as expected: {len(rows) - len(bad)}; NOT as expected: {len(bad)}"]
    lines += [f"   {o[0]:12} {o[1][:60]:60} user {o[2]} -> {o[3]}  {o[5][:150]}" for o in bad]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Two-tenant multi-step flows against the real API (see the module docstring).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the flows against the database DATABASE_URL points at")
    run.add_argument("--label", required=True)
    run.add_argument("--out", help="default: tenant_flows_<label>.json")
    run.add_argument("--email-a", default="admin-a@example.com")
    run.add_argument("--email-b", default="admin-b@example.com")
    run.add_argument("--password-env", default="TENANT_FLOWS_PASSWORD")
    run.add_argument("--yes-write-test-data", action="store_true", help="required: the flows create (and some delete) data")
    cmp_ = sub.add_parser("compare", help="compare two result files")
    cmp_.add_argument("first")
    cmp_.add_argument("second")
    args = ap.parse_args(argv)
    if args.cmd == "compare":
        with open(args.first, encoding="utf-8") as f1, open(args.second, encoding="utf-8") as f2:
            diff = compare_runs(json.load(f1), json.load(f2))
        for name, items in diff.items():
            print(f"{name}: {items or 'none'}")
        return 1 if any(diff.values()) else 0
    if not args.yes_write_test_data:
        print("refusing to run: the flows CREATE data. Run against a scratch database and pass --yes-write-test-data.", file=sys.stderr)
        return 2
    from app.core.config import settings  # noqa: PLC0415

    if (settings.ENVIRONMENT or "").strip().lower() == "production":
        print("refusing to run with ENVIRONMENT=production.", file=sys.stderr)
        return 2
    password = os.environ.get(args.password_env, "")
    if not password:
        print(f"set {args.password_env} to the admins' password.", file=sys.stderr)
        return 2
    rows = asyncio.run(run_flows((args.email_a, args.email_b), password))
    out = args.out or f"tenant_flows_{args.label}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rows, f)
    print(summarize(args.label, rows))
    return 1 if any(not o[4] for o in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
