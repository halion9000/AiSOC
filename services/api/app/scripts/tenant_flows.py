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
    # `absent="key"`: the object captured under ctx[key] must NOT be visible to this user. The runner first makes the SAME request as the other tenant (the owner) and requires it to FIND the object (a "control" row), so an exclusion can never pass vacuously
    # (a list that is empty for an unrelated reason, a pagination default, an error that returns []). Use this, never a bare `not _has(...)`, for an exclusion check.
    absent: str | None = None


def _dig(obj: Any, path: str) -> Any:
    """Follow a dotted path through JSON: a digit indexes a list ("0.id" is the id of the first element), anything else is a key."""
    for part in path.split("."):
        obj = obj[int(part)] if part.isdigit() else obj[part]
    return obj


def _has(resp: Any, needle: str) -> bool:
    return needle in resp.text


def _lacks(resp: Any, needle: str) -> bool:
    """The response does not contain `needle`. Only ever combine this with a `_has` on the SAME response (see the rbac flow): on its own it passes for an empty or failing answer, which is why bare exclusion checks are guarded against."""
    return needle not in resp.text


def _top_field_is(resp: Any, key: str, want: str) -> bool:
    """True if the response's TOP-LEVEL JSON object has `key` equal to `want`. Not a search: the same id can appear elsewhere in a response (the alert detail repeats its case_id inside a rail event's payload), and a step that matches that
    passes whether or not the field under test is right (a recursive version of this helper did exactly that and failed to notice the link being removed)."""
    try:
        body = resp.json()
    except ValueError:
        return False
    return isinstance(body, dict) and str(body.get(key)) == str(want)


def control_found(owner_resp: Any, want: str) -> bool:
    """The control: the OWNER's request succeeded and the object is in it."""
    return owner_resp.status_code == 200 and want in owner_resp.text


def exclusion_holds(resp: Any, want: str, expect: tuple[int, ...]) -> bool:
    """The exclusion: an expected status, and if the request was served at all (200) the object is not in the body. A 404/403 is the endpoint refusing, which is also a pass."""
    return resp.status_code in expect and (resp.status_code != 200 or want not in resp.text)


def S(name: str, user: str, method: str, tpl: str, **kw: Any) -> Step:
    return Step(name, user, method, tpl, **kw)


def build_flows() -> dict[str, list[Step]]:
    flows = {
        "cases": [
            S("A creates a case", "A", "post", "/api/v1/cases", capture=("case", "id")),
            S("A's shift handoff includes the case", "A", "get", "/api/v1/shifts/handoff-items", expect=(200,), check=lambda r, c: _has(r, c["case"])),
            S("B's shift handoff does not", "B", "get", "/api/v1/shifts/handoff-items", expect=(200,), absent="case"),
            S("A reads it", "A", "get", "/api/v1/cases/{case}", expect=(200,)),
            S("A renames it", "A", "patch", "/api/v1/cases/{case}", over={"title": "Renamed by A"}, expect=(200,)),
            S("A comments", "A", "post", "/api/v1/cases/{case}/comments", capture=("comment", "id")),
            S("A lists comments (has it)", "A", "get", "/api/v1/cases/{case}/comments", expect=(200,), check=lambda r, c: _has(r, c["comment"])),
            S("A lists cases (has it)", "A", "get", "/api/v1/cases", expect=(200,), check=lambda r, c: _has(r, c["case"])),
            S("B cannot read A's case", "B", "get", "/api/v1/cases/{case}", expect=ISO),
            S("B cannot rename A's case", "B", "patch", "/api/v1/cases/{case}", over={"title": "pwned"}, expect=ISO),
            S("B cannot comment on A's case", "B", "post", "/api/v1/cases/{case}/comments", expect=ISO),
            S("B cannot list A's comments", "B", "get", "/api/v1/cases/{case}/comments", expect=(404, 403, 200), absent="comment"),
            S("B's case list excludes it", "B", "get", "/api/v1/cases", expect=(200,), absent="case"),
            S("A's case is still intact", "A", "get", "/api/v1/cases/{case}", expect=(200,), check=lambda r, c: _has(r, "Renamed by A")),
            S("B's shift handoff items exclude A's case", "B", "get", "/api/v1/shifts/handoff-items", expect=(200,), absent="case"),
        ],
        "saved_views": [
            S("A creates a view", "A", "post", "/api/v1/saved-views", over={"view_type": "alerts"}, capture=("view", "id")),
            S("A renames it", "A", "patch", "/api/v1/saved-views/{view}", over={"name": "A renamed"}, expect=(200,)),
            S("A lists (has it)", "A", "get", "/api/v1/saved-views", params={"view_type": "alerts"}, expect=(200,), check=lambda r, c: _has(r, c["view"])),
            S("B's list excludes it", "B", "get", "/api/v1/saved-views", params={"view_type": "alerts"}, expect=(200,), absent="view"),
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
            S("B's list excludes it", "B", "get", "/api/v1/api-keys", expect=(200,), absent="key"),
            S("A deletes it", "A", "delete", "/api/v1/api-keys/{key}", expect=(200, 204), nobody=True),
        ],
        "saved_hunts": [
            S("A saves a hunt", "A", "post", "/api/v1/saved-hunts", capture=("hunt", "id")),
            S("A reads it", "A", "get", "/api/v1/saved-hunts/{hunt}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/saved-hunts/{hunt}", expect=ISO),
            S("B cannot delete it", "B", "delete", "/api/v1/saved-hunts/{hunt}", expect=ISO, nobody=True),
            S("B's list excludes it", "B", "get", "/api/v1/saved-hunts", expect=(200,), absent="hunt"),
            S("A deletes it", "A", "delete", "/api/v1/saved-hunts/{hunt}", expect=(200, 204), nobody=True),
        ],
        "shifts": [
            S("A starts a shift", "A", "post", "/api/v1/shifts", capture=("shift", "id")),
            S("B starts ITS OWN shift", "B", "post", "/api/v1/shifts", capture=("shift_b", "id")),
            S("A's shift is still active (B starting one must not close it)", "A", "get", "/api/v1/shifts", expect=(200,), check=lambda r, c: any(x["id"] == c["shift"] and x["status"] == "active" for x in r.json())),
            S("A writes the handoff", "A", "put", "/api/v1/shifts/{shift}/handoff", expect=(200,)),
            S("A lists (has it)", "A", "get", "/api/v1/shifts", expect=(200,), check=lambda r, c: _has(r, c["shift"])),
            S("B cannot write A's handoff", "B", "put", "/api/v1/shifts/{shift}/handoff", expect=ISO),
            S("B's shift list excludes A's shift", "B", "get", "/api/v1/shifts", expect=(200,), absent="shift"),
            S("B's own shift is still active (A's actions must not touch it)", "B", "get", "/api/v1/shifts", expect=(200,), check=lambda r, c: any(x["id"] == c["shift_b"] and x["status"] == "active" for x in r.json())),
        ],
        "approvals": [
            S("A requests an approval", "A", "post", "/api/v1/approvals", capture=("appr", "id")),
            S("A reads it", "A", "get", "/api/v1/approvals/{appr}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/approvals/{appr}", expect=ISO),
            S("B cannot decide it", "B", "post", "/api/v1/approvals/{appr}/decide", expect=ISO),
            S("B's list excludes it", "B", "get", "/api/v1/approvals", expect=(200,), absent="appr"),
            S("A decides it", "A", "post", "/api/v1/approvals/{appr}/decide", expect=(200, 201, 202)),
        ],
        "alerts": [
            S("A submits an alert", "A", "post", "/api/v1/alerts/submit", over={"title": "flow alert", "severity": "high", "events": [{"message": "flow event", "host": "h1", "user": "u1"}]}, capture=("alert", "id")),
            S("A reads it", "A", "get", "/api/v1/alerts/{alert}", expect=(200,)),
            S("A claims it", "A", "post", "/api/v1/alerts/{alert}/claim", expect=(200, 201, 202), nobody=True),
            S("B cannot read it", "B", "get", "/api/v1/alerts/{alert}", expect=ISO),
            S("B cannot claim it", "B", "post", "/api/v1/alerts/{alert}/claim", expect=ISO, nobody=True),
            S("B's alert list excludes it", "B", "get", "/api/v1/alerts", expect=(200,), absent="alert"),
            S("A attaches it to a case", "A", "post", "/api/v1/cases", capture=("case2", "id")),
            S("A links the alert", "A", "post", "/api/v1/cases/{case2}/alerts", expect=(200, 201, 202)),
            S("the alert now shows the case it was linked to", "A", "get", "/api/v1/alerts/{alert}", expect=(200,), check=lambda r, c: _top_field_is(r, "case_id", c["case2"])),
            S("B makes its own case", "B", "post", "/api/v1/cases", capture=("case_b", "id")),
            S("B cannot attach A's alert", "B", "post", "/api/v1/cases/{case_b}/alerts", expect=(404, 403, 400, 422)),
            S("B cannot create a case citing A's alert", "B", "post", "/api/v1/cases", expect=(404, 403, 400, 422)),
            S("A can create a case citing its OWN alert", "A", "post", "/api/v1/cases", expect=(201,)),
            S("B's case does not expose A's alert content", "B", "get", "/api/v1/cases/{case_b}", expect=(200,), check=lambda r, c: "flow alert" not in r.text),
            S("B's shift handoff items exclude A's alert", "B", "get", "/api/v1/shifts/handoff-items", expect=(200,), absent="alert"),
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
    flows.update(_third_batch())
    flows.update(_fourth_batch())
    flows.update(_fifth_batch())
    flows.update(_sixth_batch())
    flows.update(_seventh_batch())
    flows.update(_eighth_batch())
    flows.update(_ninth_batch())
    flows.update(_tenth_batch())
    flows.update(_eleventh_batch())
    flows["fresh"] = fresh + _more_fresh()  # still last: A creating objects B has never mentioned
    return flows


NOT_YOURS = (404, 403, 400, 422)  # for cross-tenant WRITES that name another tenant's object in the body: any refusal will do, success is the bug


def _more_flows() -> dict[str, list[Step]]:
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
            S("B cannot list its vulnerabilities", "B", "get", "/api/v1/assets/{asset}/vulnerabilities", expect=(404, 403, 200), absent="vuln"),
            S("B's asset list excludes it", "B", "get", "/api/v1/assets", expect=(200,), absent="asset"),
            S("B's vulnerability list excludes it", "B", "get", "/api/v1/assets/vulnerabilities", expect=(200,), absent="vuln"),
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
            S("B's IOC list excludes it", "B", "get", "/api/v1/threat-intel/iocs", expect=(200,), absent="ioc"),
            S("B's feed list excludes it", "B", "get", "/api/v1/threat-intel/feeds", expect=(200,), absent="feed"),
            S("A's IOC is still there", "A", "get", "/api/v1/threat-intel/iocs/{ioc}", expect=(200,)),
            S("A deletes the IOC", "A", "delete", "/api/v1/threat-intel/iocs/{ioc}", expect=(200, 204), nobody=True),
            S("A deletes the feed", "A", "delete", "/api/v1/threat-intel/feeds/{feed}", expect=(200, 204), nobody=True),
        ],
        "reports": [
            S("A creates a report template", "A", "post", "/api/v1/reports/templates", over={"report_type": "soc_weekly"}, capture=("tmpl", "id")),
            S("A reads it", "A", "get", "/api/v1/reports/templates/{tmpl}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/reports/templates/{tmpl}", expect=ISO),
            S("B cannot delete it", "B", "delete", "/api/v1/reports/templates/{tmpl}", expect=ISO, nobody=True),
            S("B's template list excludes it", "B", "get", "/api/v1/reports/templates", expect=(200,), absent="tmpl"),
            S("A deletes it", "A", "delete", "/api/v1/reports/templates/{tmpl}", expect=(200, 204), nobody=True),
        ],
        "remediation": [
            S("A whitelists an action", "A", "post", "/api/v1/remediation/whitelist", over={"action_type": "isolate_host", "blast_radius": "low"}, capture=("wl", "id")),
            S("B cannot remove it", "B", "delete", "/api/v1/remediation/whitelist/{wl}", expect=ISO, nobody=True),
            S("B's whitelist excludes it", "B", "get", "/api/v1/remediation/whitelist", expect=(200,), absent="wl"),
            S("A removes it", "A", "delete", "/api/v1/remediation/whitelist/{wl}", expect=(200, 204), nobody=True),
        ],
        "identity_graph": [
            S("A creates a node", "A", "post", "/api/v1/identity-graph/nodes", over={"node_type": "human_user", "external_id": "ext-a-1", "source_system": "okta"}, capture=("n1", "id")),
            S("A creates a second node", "A", "post", "/api/v1/identity-graph/nodes", over={"node_type": "human_user", "external_id": "ext-a-2", "source_system": "okta"}, capture=("n2", "id")),
            S("A links them", "A", "post", "/api/v1/identity-graph/edges", over={"edge_type": "member_of"}, capture=("edge", "id")),
            S("A reads the node", "A", "get", "/api/v1/identity-graph/nodes/{n1}", expect=(200,)),
            S("B cannot read A's node", "B", "get", "/api/v1/identity-graph/nodes/{n1}", expect=ISO),
            S("B cannot read A's node edges", "B", "get", "/api/v1/identity-graph/nodes/{n1}/edges", expect=(404, 403, 200), absent="edge"),
            S("B's node list excludes it", "B", "get", "/api/v1/identity-graph/nodes", expect=(200,), absent="n1"),
            S("B's edge list excludes it", "B", "get", "/api/v1/identity-graph/edges", expect=(200,), absent="edge"),
            S("B makes its own node", "B", "post", "/api/v1/identity-graph/nodes", over={"node_type": "human_user", "external_id": "ext-b-1", "source_system": "okta"}, capture=("nb", "id")),
            S("B cannot link its node to A's node", "B", "post", "/api/v1/identity-graph/edges", over={"edge_type": "member_of"}, expect=NOT_YOURS),
        ],
        "posture": [
            S("A records a finding", "A", "post", "/api/v1/posture/findings", over={"cloud_provider": "aws", "resource_type": "s3_bucket", "resource_id": "bucket-a", "rule_id": "S3-001"}, capture=("finding", "id")),
            S("A reads it", "A", "get", "/api/v1/posture/findings/{finding}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/posture/findings/{finding}", expect=ISO),
            S("B cannot resolve it", "B", "post", "/api/v1/posture/findings/{finding}/resolve", expect=ISO, nobody=True),
            S("B cannot suppress it", "B", "post", "/api/v1/posture/findings/{finding}/suppress", expect=ISO),
            S("B's finding list excludes it", "B", "get", "/api/v1/posture/findings", expect=(200,), absent="finding"),
            S("A's finding is still open", "A", "get", "/api/v1/posture/findings/{finding}", expect=(200,), check=lambda r, c: "suppressed" not in r.text.lower() or "resolved" not in r.text.lower()),
        ],
        "detection_rules": [
            S("A creates a rule", "A", "post", "/api/v1/detection/rules", over={"language": "sigma"}, capture=("rule", "id")),
            S("A reads it", "A", "get", "/api/v1/detection/rules/{rule}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/detection/rules/{rule}", expect=ISO),
            S("B cannot change it", "B", "patch", "/api/v1/detection/rules/{rule}", expect=ISO),
            S("B cannot delete it", "B", "delete", "/api/v1/detection/rules/{rule}", expect=ISO, nobody=True),
            S("B's rule list excludes it", "B", "get", "/api/v1/detection/rules", expect=(200,), absent="rule"),
            S("B cannot tune it", "B", "post", "/api/v1/detection/tuning/{rule}/dismiss", over={"reason": "x"}, expect=ISO),
            S("A's rule is still there", "A", "get", "/api/v1/detection/rules/{rule}", expect=(200,)),
            S("A deletes it", "A", "delete", "/api/v1/detection/rules/{rule}", expect=(200, 204), nobody=True),
        ],
    }


def _third_batch() -> dict[str, list[Step]]:
    """Case children, rules, hunts and detection proposals. Exclusions use absent= (which adds the owner's positive control); cross-tenant WRITES expect any refusal."""
    child = lambda tail: f"/api/v1/cases/{{cc}}/{tail}"  # noqa: E731
    return {
        "case_children": [
            S("A creates a case", "A", "post", "/api/v1/cases", capture=("cc", "id")),
            S("B makes its own case", "B", "post", "/api/v1/cases", capture=("cc_b", "id")),
            S("A adds a note", "A", "post", child("notes"), capture=("note", "id")),
            S("B cannot list A's notes", "B", "get", child("notes"), expect=(404, 403, 200), absent="note"),
            S("B cannot add a note to A's case", "B", "post", child("notes"), expect=ISO),
            S("A adds a task", "A", "post", child("tasks"), capture=("task", "id")),
            S("B cannot list A's tasks", "B", "get", child("tasks"), expect=(404, 403, 200), absent="task"),
            S("B cannot add a task to A's case", "B", "post", child("tasks"), expect=ISO),
            S("B cannot patch A's task through A's case", "B", "patch", "/api/v1/cases/{cc}/tasks/{task}", over={"title": "pwned"}, expect=ISO),
            S("B cannot patch A's task through ITS OWN case", "B", "patch", "/api/v1/cases/{cc_b}/tasks/{task}", over={"title": "pwned"}, expect=ISO),
            S("B cannot update A's observables", "B", "post", child("observables"), expect=ISO),
            S("A's task is intact", "A", "get", child("tasks"), expect=(200,), check=lambda r, c: "pwned" not in r.text),
            S("A reads the evidence", "A", "get", child("evidence"), expect=(200,)),
            S("B cannot read A's evidence", "B", "get", child("evidence"), expect=ISO),
            S("A reads the related cases", "A", "get", child("related"), expect=(200,)),
            S("B cannot read A's related cases", "B", "get", child("related"), expect=ISO),
            S("A reads the timeline", "A", "get", child("timeline"), expect=(200,)),
            S("B cannot read A's timeline", "B", "get", child("timeline"), expect=ISO),
            S("A reads the attack chain", "A", "get", child("attack-chain"), expect=(200,)),
            S("B cannot read A's attack chain", "B", "get", child("attack-chain"), expect=ISO),
            S("A reads the summary", "A", "get", child("summary"), expect=(200,), check=lambda r, c: _top_field_is(r, "headline", r.json().get("headline")) and "case" in r.json()),
            S("A reads the graph attack path", "A", "get", "/api/v1/graph/attack-path/{cc}", expect=(200,), check=lambda r, c: _has(r, c["cc"])),
            S("B cannot read A's graph attack path", "B", "get", "/api/v1/graph/attack-path/{cc}", expect=ISO),
            S("B cannot read A's summary", "B", "get", child("summary"), expect=ISO),
            S("B cannot read A's summary as HTML", "B", "get", child("summary"), params={"format": "html"}, expect=ISO),
            S("A reads the postmortem", "A", "get", child("postmortem"), expect=(200,)),
            S("B cannot read A's postmortem", "B", "get", child("postmortem"), expect=ISO),
            S("B cannot read A's postmortem as HTML", "B", "get", child("postmortem"), params={"format": "html"}, expect=ISO),
            S("A lists its investigations", "A", "get", child("investigations"), expect=(200,)),
            S("B cannot read A's investigations", "B", "get", child("investigations"), expect=ISO),
        ],
        "rules": [
            S("A creates a rule", "A", "post", "/api/v1/rules", over={"rule_language": "sigma", "rule_body": "title: flow\nlogsource:\n  product: windows\ndetection:\n  selection:\n    x: 1\n  condition: selection\n", "category": "custom"}, capture=("rl", "id")),
            S("A reads it", "A", "get", "/api/v1/rules/{rl}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/rules/{rl}", expect=ISO),
            S("B cannot change it", "B", "patch", "/api/v1/rules/{rl}", expect=ISO),
            S("B cannot back-test it", "B", "post", "/api/v1/rules/{rl}/backtest", expect=ISO),
            S("B cannot run it", "B", "post", "/api/v1/rules/{rl}/execute", over={"events": []}, expect=ISO),
            S("B's rule list excludes it", "B", "get", "/api/v1/rules", expect=(200,), absent="rl"),
            S("B cannot delete it", "B", "delete", "/api/v1/rules/{rl}", expect=ISO, nobody=True),
            S("A's rule is still there", "A", "get", "/api/v1/rules/{rl}", expect=(200,)),
            S("A deletes it", "A", "delete", "/api/v1/rules/{rl}", expect=(200, 204), nobody=True),
        ],
        "explain_lineage": [
            # An alert's explanation looks up "the rule that produced it" by an id the SUBMITTING tenant puts in the alert's tags. The control (A naming its own rule) proves the explanation does show a matched rule, so B's clean result is not vacuous.
            S("A creates a rule", "A", "post", "/api/v1/rules", over={"name": "flow-secret-rule-name", "description": "flow-secret-rule-description", "rule_language": "sigma", "category": "custom", "rule_body": "title: flow\nlogsource:\n  product: windows\ndetection:\n  selection:\n    x: 1\n  condition: selection\n"}, capture=("rl2", "id")),
            S("A submits an alert naming its own rule", "A", "post", "/api/v1/alerts/submit", over={"title": "flow alert", "severity": "high", "events": [{"message": "flow event", "host": "h1", "user": "u1"}]}, capture=("a_al", "id")),
            S("A's explanation shows the rule (control)", "A", "post", "/api/v1/alerts/{a_al}/explain", nobody=True, expect=(200,), check=lambda r, c: _has(r, "flow-secret-rule-name")),
            S("B submits an alert naming A's rule", "B", "post", "/api/v1/alerts/submit", over={"title": "flow alert", "severity": "high", "events": [{"message": "flow event", "host": "h1", "user": "u1"}]}, capture=("b_al", "id")),
            S("B's explanation does not show A's rule", "B", "post", "/api/v1/alerts/{b_al}/explain", nobody=True, expect=(200,), check=lambda r, c: "flow-secret-rule-name" not in r.text and "flow-secret-rule-description" not in r.text),
        ],
        "hunts": [
            S("A opens a hunt", "A", "post", "/api/v1/hunts", capture=("ht", "id")),
            S("A reads it", "A", "get", "/api/v1/hunts/{ht}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/hunts/{ht}", expect=ISO),
            S("B cannot change it", "B", "patch", "/api/v1/hunts/{ht}", expect=ISO),
            S("B cannot add findings to it", "B", "post", "/api/v1/hunts/{ht}/findings", over={"findings": [{"title": "pwned"}]}, expect=ISO),
            S("B cannot run it", "B", "post", "/api/v1/hunts/{ht}/run", expect=ISO),
            S("B cannot read its runs", "B", "get", "/api/v1/hunts/{ht}/runs", expect=ISO),
            S("B's hunt list excludes it", "B", "get", "/api/v1/hunts", expect=(200,), absent="ht"),
        ],
        "detection_proposals": [
            S("A opens a proposal", "A", "post", "/api/v1/detection-proposals", over={"rule_language": "sigma", "category": "custom", "rule_body": "title: flow\n"}, capture=("prop", "id")),
            S("A reads it", "A", "get", "/api/v1/detection-proposals/{prop}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/detection-proposals/{prop}", expect=ISO),
            S("B cannot comment on it", "B", "post", "/api/v1/detection-proposals/{prop}/comment", over={"comment": "pwned"}, expect=ISO),
            S("B cannot decide it", "B", "post", "/api/v1/detection-proposals/{prop}/decide", over={"decision": "reject"}, expect=ISO),
            S("B cannot attach an eval to it", "B", "post", "/api/v1/detection-proposals/{prop}/eval", over={"eval_report": {}}, expect=ISO),
            S("B cannot evaluate its rule", "B", "post", "/api/v1/detection-proposals/{prop}/evaluate-rule", over={"positive_fixtures": [{"x": 1}]}, expect=ISO),
            S("B cannot back-test it", "B", "post", "/api/v1/detection-proposals/{prop}/backtest", expect=ISO),
            S("B cannot promote it", "B", "post", "/api/v1/detection-proposals/{prop}/promote", expect=ISO, nobody=True),
            S("B's proposal list excludes it", "B", "get", "/api/v1/detection-proposals", expect=(200,), absent="prop"),
            S("A's proposal is untouched", "A", "get", "/api/v1/detection-proposals/{prop}", expect=(200,), check=lambda r, c: "pwned" not in r.text and '"status":"proposed"' in r.text.replace(" ", "")),
        ],
    }


def _fourth_batch() -> dict[str, list[Step]]:
    """Connectors, compliance evidence and knowledge-base documents. LEFT OUT because they need services this environment does not run: playbook CRUD, honeytokens and tabletop sessions (each is proxied to another service and answers 503 here), and the operations needing external infrastructure (connector test / push refresh, atomics, caldera)."""
    return {
        "connectors": [
            S("A creates a connector", "A", "post", "/api/v1/connectors", over={"connector_type": "okta"}, capture=("cn", "id")),
            S("A reads it", "A", "get", "/api/v1/connectors/{cn}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/connectors/{cn}", expect=ISO),
            S("B cannot change it", "B", "patch", "/api/v1/connectors/{cn}", over={"name": "pwned"}, expect=ISO),
            S("B cannot set its capabilities", "B", "put", "/api/v1/connectors/{cn}/capabilities", expect=ISO),
            S("B cannot read its last event time", "B", "get", "/api/v1/connectors/{cn}/last_event_at", expect=ISO),
            S("B cannot refresh its ingest token", "B", "post", "/api/v1/connectors/{cn}/push/refresh", expect=ISO, nobody=True),
            S("B cannot test it", "B", "post", "/api/v1/connectors/{cn}/test", expect=ISO, nobody=True),
            S("B's connector list excludes it", "B", "get", "/api/v1/connectors", expect=(200,), absent="cn"),
            S("B cannot delete it", "B", "delete", "/api/v1/connectors/{cn}", expect=ISO, nobody=True),
            S("A's connector is intact", "A", "get", "/api/v1/connectors/{cn}", expect=(200,), check=lambda r, c: "pwned" not in r.text),
        ],
        "compliance_evidence": [
            S("A adds evidence", "A", "post", "/api/v1/compliance/evidence", over={"framework": "soc2", "control_id": "CC6.1", "summary": "flow-evidence-secret"}, capture=("ev", "id")),
            S("A reads it", "A", "get", "/api/v1/compliance/evidence/{ev}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/compliance/evidence/{ev}", expect=ISO),
            S("B cannot review it", "B", "post", "/api/v1/compliance/evidence/{ev}/review", over={"decision": "accepted"}, expect=ISO),
            S("B's evidence list excludes it", "B", "get", "/api/v1/compliance/evidence", expect=(200,), absent="ev"),
            S("A's evidence is still pending", "A", "get", "/api/v1/compliance/evidence/{ev}", expect=(200,), check=lambda r, c: "accepted" not in r.text),
        ],
        "kb_documents": [
            S("A ingests a document", "A", "post", "/api/v1/kb/ingest", over={"title": "flow-kb-secret-title", "content": "flow-kb-secret-content about phishing playbooks"}, capture=("kb", "0.id")),
            S("A reads it", "A", "get", "/api/v1/kb/documents/{kb}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/kb/documents/{kb}", expect=ISO),
            S("B's document list excludes it", "B", "get", "/api/v1/kb/documents", expect=(200,), absent="kb"),
            S("B cannot delete it", "B", "delete", "/api/v1/kb/documents/{kb}", expect=ISO, nobody=True),
            S("A's document is intact", "A", "get", "/api/v1/kb/documents/{kb}", expect=(200,)),
        ],
    }


def _fifth_batch() -> dict[str, list[Step]]:
    """RBAC roles and role assignments, phishing submissions and data-lifecycle parsers."""
    return {
        "rbac": [
            S("A creates a role", "A", "post", "/api/v1/rbac/roles", over={"name": "flow-role-a"}, capture=("ra", "id")),
            S("B creates a role", "B", "post", "/api/v1/rbac/roles", over={"name": "flow-role-b"}, capture=("rb", "id")),
            S("A learns its own user id", "A", "get", "/api/v1/auth/me", expect=(200,), capture=("ua", "id")),
            S("B learns its own user id", "B", "get", "/api/v1/auth/me", expect=(200,), capture=("ub", "id")),
            S("A reads its role", "A", "get", "/api/v1/rbac/roles/{ra}", expect=(200,)),
            S("B cannot read A's role", "B", "get", "/api/v1/rbac/roles/{ra}", expect=ISO),
            S("B cannot change A's role", "B", "patch", "/api/v1/rbac/roles/{ra}", over={"name": "pwned"}, expect=ISO),
            S("B's role list excludes A's role", "B", "get", "/api/v1/rbac/roles", expect=(200,), absent="ra"),
            S("A gives its own user A's role", "A", "post", "/api/v1/rbac/users/{ua}/roles", expect=(200, 201, 204)),
            S("A reads its user's roles", "A", "get", "/api/v1/rbac/users/{ua}/roles", expect=(200,), check=lambda r, c: _has(r, c["ra"])),
            S("B cannot read A's user's roles", "B", "get", "/api/v1/rbac/users/{ua}/roles", expect=(404, 403, 200), absent="ra"),
            S("B cannot give A's user B's role", "B", "post", "/api/v1/rbac/users/{ua}/roles", expect=NOT_YOURS),
            S("B cannot give its own user A's role", "B", "post", "/api/v1/rbac/users/{ub}/roles", expect=NOT_YOURS),
            S("B cannot remove A's role from A's user", "B", "delete", "/api/v1/rbac/users/{ua}/roles/{ra}", expect=ISO, nobody=True),
            S("B gives its own user B's role", "B", "post", "/api/v1/rbac/users/{ub}/roles", expect=(200, 201, 204)),
            # Positive and negative in ONE response: B's own role must be there (so an empty or failing answer cannot pass) and A's must not.
            S("B's own user has B's role and not A's", "B", "get", "/api/v1/rbac/users/{ub}/roles", expect=(200,), check=lambda r, c: _has(r, c["rb"]) and _lacks(r, c["ra"])),
            S("A's assignment is intact", "A", "get", "/api/v1/rbac/users/{ua}/roles", expect=(200,), check=lambda r, c: _has(r, c["ra"])),
            S("B cannot delete A's role", "B", "delete", "/api/v1/rbac/roles/{ra}", expect=ISO, nobody=True),
            S("A's role is intact", "A", "get", "/api/v1/rbac/roles/{ra}", expect=(200,)),
        ],
        "phishing_submissions": [
            S("A submits a phishing artifact", "A", "post", "/api/v1/phishing/submit", capture=("ps", "id")),
            S("A reads it", "A", "get", "/api/v1/phishing/{ps}", expect=(200,)),
            S("B cannot read it", "B", "get", "/api/v1/phishing/{ps}", expect=ISO),
            S("B cannot re-triage it", "B", "post", "/api/v1/phishing/{ps}/retriage", expect=ISO, nobody=True),
        ],
        "parsers": [
            S("A creates a parser", "A", "post", "/api/v1/data-lifecycle/parsers", over={"name": "flow-parser-a"}, capture=("pa", "id")),
            S("B's parser list excludes it", "B", "get", "/api/v1/data-lifecycle/parsers", expect=(200,), absent="pa"),
            S("B cannot delete it", "B", "delete", "/api/v1/data-lifecycle/parsers/{pa}", expect=ISO, nobody=True),
            S("A's parser is intact", "A", "get", "/api/v1/data-lifecycle/parsers", expect=(200,), check=lambda r, c: _has(r, c["pa"])),
        ],
    }


def _sixth_batch() -> dict[str, list[Step]]:
    """Natural-language queries: the caller picks the index pattern of a query that runs with the SERVER's Elasticsearch credentials, so it must only be able to name ordinary indices."""
    q = {"question": "Show failed logins per user in the last day", "time_range_hours": 24}
    return {
        "nl_query": [
            S("a normal index pattern translates", "B", "post", "/api/v1/nl-query/translate", over={**q, "index_pattern": "logs-*,aisoc-events-*"}, expect=(200,), check=lambda r, c: "FROM logs-*,aisoc-events-*" in r.text),
            S("every index is refused", "B", "post", "/api/v1/nl-query/translate", over={**q, "index_pattern": "*"}, expect=(422,)),
            S("system indices are refused", "B", "post", "/api/v1/nl-query/translate", over={**q, "index_pattern": ".security-*,.kibana*"}, expect=(422,)),
            S("an injected pipeline is refused", "B", "post", "/api/v1/nl-query/translate", over={**q, "index_pattern": "logs-* | EVAL pwned = 1 | DROP message | LIMIT 5 //"}, expect=(422,)),
            S("a newline-separated command is refused", "B", "post", "/api/v1/nl-query/translate", over={**q, "index_pattern": "logs-*\n| KEEP user.password"}, expect=(422,)),
            S("execute refuses a hostile pattern too", "B", "post", "/api/v1/nl-query/execute", over={**q, "index_pattern": "*"}, expect=(422,)),
            # Tenant selection: B is a plain tenant admin (no platform:cross_tenant_query). The two tenants of the flow database have these fixed ids.
            S("B searching its OWN tenant is allowed", "B", "post", "/api/v1/nl-query/translate", over={**q, "tenant_ids": ["bbbbbbbb-0000-0000-0000-000000000002"]}, expect=(200,)),
            S("B cannot search tenant A", "B", "post", "/api/v1/nl-query/translate", over={**q, "tenant_ids": ["aaaaaaaa-0000-0000-0000-000000000001"]}, expect=(403,)),
            S("B cannot search A and B together", "B", "post", "/api/v1/nl-query/translate", over={**q, "tenant_ids": ["aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002"]}, expect=(403,)),
            S("B cannot search all tenants", "B", "post", "/api/v1/nl-query/translate", over={**q, "all_tenants": True}, expect=(403,)),
            S("execute refuses another tenant too", "B", "post", "/api/v1/nl-query/execute", over={**q, "tenant_ids": ["aaaaaaaa-0000-0000-0000-000000000001"]}, expect=(403,)),
            S("B's selector lists only its own tenant", "B", "get", "/api/v1/nl-query/tenants", expect=(200,), check=lambda r, c: len(r.json()["tenants"]) == 1 and r.json()["tenants"][0]["id"] == "bbbbbbbb-0000-0000-0000-000000000002" and r.json()["cross_tenant_enabled"] is False and "tenant-a" not in r.text),
        ],
    }


def _seventh_batch() -> dict[str, list[Step]]:
    """Business-context rules. Rule ids are user-chosen slugs (not UUIDs), so the isolation question is a COLLISION: two tenants using the same slug must each see, change and delete only their own."""
    rule = lambda marker, sev: f"id: flow-rule-a\ndescription: {marker}\nwhen:\n  field: alert.severity\n  op: eq\n  value: high\nthen:\n  set_severity: {sev}\n"  # noqa: E731
    mine = lambda yes, no: (lambda r, c: _has(r, yes) and _lacks(r, no))  # noqa: E731  (the positive control and the exclusion are in the SAME response)
    return {
        "business_context_rules": [
            # {rule_id} is captured from A's response: it is the slug both tenants will use.
            S("A sets its rules (slug flow-rule-a)", "A", "post", "/api/v1/business-context/rules", over={"yaml": rule("marker-alpha", "critical")}, expect=(200,), capture=("rule_id", "rules.0.id")),
            S("B sets ITS rules with the SAME slug", "B", "post", "/api/v1/business-context/rules", over={"yaml": rule("marker-bravo", "low")}, expect=(200,)),
            S("A still sees only its own rule", "A", "get", "/api/v1/business-context/rules", expect=(200,), check=mine("marker-alpha", "marker-bravo")),
            S("B sees only its own rule", "B", "get", "/api/v1/business-context/rules", expect=(200,), check=mine("marker-bravo", "marker-alpha")),
            S("B updates ITS flow-rule-a", "B", "put", "/api/v1/business-context/rules/{rule_id}", over={"yaml": rule("marker-bravo-2", "medium")}, expect=(200,)),
            S("A is unaffected by B's update", "A", "get", "/api/v1/business-context/rules", expect=(200,), check=mine("marker-alpha", "marker-bravo")),
            S("B deletes ITS flow-rule-a", "B", "delete", "/api/v1/business-context/rules/{rule_id}", expect=(200, 204), nobody=True),
            S("A's rule survives B's delete", "A", "get", "/api/v1/business-context/rules", expect=(200,), check=mine("marker-alpha", "marker-bravo")),
            # B no longer has that slug: deleting it again finds nothing of B's (it must NOT find A's), so 404.
            S("B deleting a slug it no longer has finds nothing", "B", "delete", "/api/v1/business-context/rules/{rule_id}", expect=(404,), nobody=True),
            S("A's rule survives that too", "A", "get", "/api/v1/business-context/rules", expect=(200,), check=mine("marker-alpha", "marker-bravo")),
            # PUT is documented as an upsert: for B it CREATES B's own rule, and only B's.
            S("B's PUT of that slug creates B's OWN rule (upsert)", "B", "put", "/api/v1/business-context/rules/{rule_id}", over={"yaml": rule("marker-bravo-3", "low")}, expect=(200,), check=mine("marker-bravo-3", "marker-alpha")),
            S("A is still untouched by B's upsert", "A", "get", "/api/v1/business-context/rules", expect=(200,), check=mine("marker-alpha", "marker-bravo")),
            S("B cleans up its own rule", "B", "delete", "/api/v1/business-context/rules/{rule_id}", expect=(200, 204), nobody=True),
            S("A removes its own rule", "A", "delete", "/api/v1/business-context/rules/{rule_id}", expect=(200, 204), nobody=True),
        ],
    }


def _eighth_batch() -> dict[str, list[Step]]:
    """Inbox tokens: a credential identified by a fingerprint (its last 8 characters). Rotating or revoking one is acting on a credential, so another tenant must get nothing, and must not even learn that the fingerprint exists."""
    live = lambda c, r: [t for t in r.json() if t["fingerprint"] == c["fp"] and t["revoked_at"] is None]  # noqa: E731
    return {
        "inbox_tokens": [
            S("A mints an inbox token", "A", "post", "/api/v1/inbox/tokens", over={"template_id": "generic-json"}, expect=(201,)),
            S("A lists it (and we capture its fingerprint)", "A", "get", "/api/v1/inbox/tokens", expect=(200,), capture=("fp", "0.fingerprint")),
            S("B's list does not contain A's fingerprint", "B", "get", "/api/v1/inbox/tokens", expect=(200,), check=lambda r, c: _lacks(r, c["fp"])),
            S("B cannot rotate A's token", "B", "post", "/api/v1/inbox/tokens/{fp}/rotate", expect=(404,), nobody=True),
            S("B cannot revoke A's token", "B", "delete", "/api/v1/inbox/tokens/{fp}", expect=(404,), nobody=True),
            S("A's token is intact: present, not revoked, and still the only one", "A", "get", "/api/v1/inbox/tokens", expect=(200,), check=lambda r, c: len(r.json()) == 1 and len(live(c, r)) == 1),
            # B proves the same routes work on B's OWN token, so the 404s above are about ownership and not about the routes being broken.
            S("B mints its own token", "B", "post", "/api/v1/inbox/tokens", over={"template_id": "generic-json"}, expect=(201,)),
            S("B lists only its own (capturing it)", "B", "get", "/api/v1/inbox/tokens", expect=(200,), capture=("fpb", "0.fingerprint"), check=lambda r, c: len(r.json()) == 1 and _lacks(r, c["fp"])),
            S("B rotates its OWN token", "B", "post", "/api/v1/inbox/tokens/{fpb}/rotate", expect=(200,), nobody=True),
            S("A's token is still untouched by B's rotation", "A", "get", "/api/v1/inbox/tokens", expect=(200,), check=lambda r, c: len(r.json()) == 1 and len(live(c, r)) == 1),
            S("A revokes its own token", "A", "delete", "/api/v1/inbox/tokens/{fp}", expect=(204,), nobody=True),
            S("A's revoked token no longer appears in its list (the list hides revoked tokens)", "A", "get", "/api/v1/inbox/tokens", expect=(200,), check=lambda r, c: r.json() == [] and _lacks(r, c["fp"])),
        ],
    }


# Values a flow starts with, for a path parameter that is chosen by the caller rather than returned by the API (a connector type, a slug): {name} in a step's path is filled from here until a step captures it.
FLOW_SEEDS: dict[str, dict[str, str]] = {"oauth_apps": {"ct": "github"}, "tenant_selection": {"etype": "user", "evalue": "alice"}}


def _eleventh_batch() -> dict[str, list[Step]]:
    """Endpoints that let the caller NAME a tenant (fusion entity risk, osquery file integrity). Neither flow user holds platform:cross_tenant_query, so naming the other tenant must be a 403, decided BEFORE any upstream call; naming one's own must not be. (The upstream services are not running here, so "own" answers 200 / 404 / 503: anything but 403 shows the check let it through.)"""
    A, B = "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002"
    routes = (("fusion queue", "/api/v1/fusion/entity-risk/queue", (200,)), ("fusion stats", "/api/v1/fusion/entity-risk/stats", (200,)), ("fusion entity", "/api/v1/fusion/entity-risk/{etype}/{evalue}", (200, 404)),
              ("osquery events", "/api/v1/osquery/fim/events", (200, 503)), ("osquery summary", "/api/v1/osquery/fim/summary", (200, 503)))
    steps: list[Step] = []
    for label, path, own_ok in routes:
        steps += [
            S(f"B names its OWN tenant on {label} (not refused)", "B", "get", path, params={"tenant_id": B}, expect=own_ok),
            S(f"B cannot name A's tenant on {label}", "B", "get", path, params={"tenant_id": A}, expect=(403,)),
            S(f"A names its OWN tenant on {label} (not refused)", "A", "get", path, params={"tenant_id": A}, expect=own_ok),
            S(f"A cannot name B's tenant on {label}", "A", "get", path, params={"tenant_id": B}, expect=(403,)),
        ]
    # The picker's list: a caller without the permission is offered exactly their own tenant, and is never shown the other tenant's name.
    steps += [
        S("B's picker offers only B's own tenant", "B", "get", "/api/v1/tenants/selectable", expect=(200,), check=lambda r, c: [t["id"] for t in r.json()["tenants"]] == [B] and r.json()["can_select_other_tenants"] is False and _lacks(r, "tenant-a")),
        S("A's picker offers only A's own tenant", "A", "get", "/api/v1/tenants/selectable", expect=(200,), check=lambda r, c: [t["id"] for t in r.json()["tenants"]] == [A] and r.json()["can_select_other_tenants"] is False and _lacks(r, "tenant-b")),
    ]
    return {"tenant_selection": steps}


def _tenth_batch() -> dict[str, list[Step]]:
    """OAuth app credentials: a tenant's client id and client SECRET for a connector type. The secret is encrypted at rest and must never be returned; each tenant must see, replace and delete only its own."""
    secret_a, secret_b = "alpha-secret-VALUE-1234", "bravo-secret-VALUE-5678"
    none_of = lambda r: _lacks(r, secret_a) and _lacks(r, secret_b)  # noqa: E731  (neither tenant's secret appears in ANY response)
    return {
        "oauth_apps": [
            S("A registers its OAuth app", "A", "put", "/api/v1/oauth/app/{ct}", over={"client_id": "alpha-client-id", "client_secret": secret_a}, expect=(200,), check=lambda r, c: none_of(r) and r.json()["has_secret"] is True and r.json()["client_id"] == "alpha-client-id"),
            S("A reads it back (and the secret is not returned)", "A", "get", "/api/v1/oauth/app/{ct}", expect=(200,), check=lambda r, c: none_of(r) and _has(r, "alpha-client-id")),
            S("B has no app for that connector", "B", "get", "/api/v1/oauth/app/{ct}", expect=(404,)),
            S("B registers ITS OWN app for the same connector", "B", "put", "/api/v1/oauth/app/{ct}", over={"client_id": "bravo-client-id", "client_secret": secret_b}, expect=(200,), check=lambda r, c: none_of(r) and _has(r, "bravo-client-id") and _lacks(r, "alpha-client-id")),
            S("A still has only its own", "A", "get", "/api/v1/oauth/app/{ct}", expect=(200,), check=lambda r, c: none_of(r) and _has(r, "alpha-client-id") and _lacks(r, "bravo-client-id")),
            S("B has only its own", "B", "get", "/api/v1/oauth/app/{ct}", expect=(200,), check=lambda r, c: none_of(r) and _has(r, "bravo-client-id") and _lacks(r, "alpha-client-id")),
            S("B deletes ITS app", "B", "delete", "/api/v1/oauth/app/{ct}", expect=(204,), nobody=True),
            S("B's app is gone", "B", "get", "/api/v1/oauth/app/{ct}", expect=(404,)),
            S("A's app survives B's delete", "A", "get", "/api/v1/oauth/app/{ct}", expect=(200,), check=lambda r, c: _has(r, "alpha-client-id") and r.json()["has_secret"] is True),
            S("B deleting again finds nothing of B's and changes nothing of A's", "B", "delete", "/api/v1/oauth/app/{ct}", expect=(204,), nobody=True),
            S("A's app still survives", "A", "get", "/api/v1/oauth/app/{ct}", expect=(200,), check=lambda r, c: _has(r, "alpha-client-id")),
            S("A deletes its own", "A", "delete", "/api/v1/oauth/app/{ct}", expect=(204,), nobody=True),
            S("A's app is gone", "A", "get", "/api/v1/oauth/app/{ct}", expect=(404,)),
        ],
    }


def _ninth_batch() -> dict[str, list[Step]]:
    """Tenant user management and settings. B is a plain `admin` here: it holds every tenant-level permission but no platform permission, so it must be refused a platform_admin and allowed lower roles."""
    user_of = lambda r, uid: next((u for u in r.json() if u["id"] == uid), None)  # noqa: E731
    return {
        "tenant_users": [
            S("A creates a user", "A", "post", "/api/v1/tenants/me/users", over={"email": "flow-user-a@example.com", "username": "flowusera", "password": "Trial-Passw0rd!x", "role": "viewer"}, expect=(201,), capture=("fuser", "id")),
            S("A's user list has it", "A", "get", "/api/v1/tenants/me/users", expect=(200,), check=lambda r, c: _has(r, "flow-user-a@example.com")),
            S("B's user list does not", "B", "get", "/api/v1/tenants/me/users", expect=(200,), check=lambda r, c: _lacks(r, "flow-user-a@example.com") and _has(r, "admin-b@example.com")),
            S("B cannot change A's user's role", "B", "patch", "/api/v1/tenants/me/users/{fuser}", over={"role": "soc_analyst"}, expect=(404,)),
            S("B cannot deactivate A's user", "B", "patch", "/api/v1/tenants/me/users/{fuser}", over={"is_active": False}, expect=(404,)),
            S("A's user is unchanged (still a viewer, still active)", "A", "get", "/api/v1/tenants/me/users", expect=(200,), check=lambda r, c: (user_of(r, c["fuser"]) or {}).get("role") == "viewer" and (user_of(r, c["fuser"]) or {}).get("is_active") is True),
            # The role rules, over HTTP (unit-tested as well): nobody grants more power than they hold.
            S("B (admin) cannot create a platform_admin", "B", "post", "/api/v1/tenants/me/users", over={"email": "flow-pa-b@example.com", "username": "flowpab", "password": "Trial-Passw0rd!x", "role": "platform_admin"}, expect=(403,)),
            S("B cannot create a user with an unknown role", "B", "post", "/api/v1/tenants/me/users", over={"email": "flow-xx-b@example.com", "username": "flowxxb", "password": "Trial-Passw0rd!x", "role": "overlord"}, expect=(422,)),
            S("B CAN create a tenant_admin (a role within its own permissions)", "B", "post", "/api/v1/tenants/me/users", over={"email": "flow-ta-b@example.com", "username": "flowtab", "password": "Trial-Passw0rd!x", "role": "tenant_admin"}, expect=(201,), capture=("btadm", "id")),
            S("B cannot promote that user to platform_admin", "B", "patch", "/api/v1/tenants/me/users/{btadm}", over={"role": "platform_admin"}, expect=(403,)),
            S("B CAN change that user to a lower role", "B", "patch", "/api/v1/tenants/me/users/{btadm}", over={"role": "viewer"}, expect=(200,), check=lambda r, c: r.json()["role"] == "viewer"),
            S("neither platform_admin nor the refused users exist anywhere in B's list", "B", "get", "/api/v1/tenants/me/users", expect=(200,), check=lambda r, c: _has(r, "flow-ta-b@example.com") and _lacks(r, "flow-pa-b@example.com") and _lacks(r, "flow-xx-b@example.com") and all(u["role"] != "platform_admin" for u in r.json())),
            S("A's list never shows B's users", "A", "get", "/api/v1/tenants/me/users", expect=(200,), check=lambda r, c: _has(r, "flow-user-a@example.com") and _lacks(r, "flow-ta-b@example.com")),
        ],
        "tenant_settings": [
            S("A sets its settings", "A", "patch", "/api/v1/tenants/me/settings", over={"settings": {"flow_marker": "alpha-marker"}}, expect=(200,), check=lambda r, c: _has(r, "alpha-marker")),
            S("B sets ITS settings", "B", "patch", "/api/v1/tenants/me/settings", over={"settings": {"flow_marker": "bravo-marker"}}, expect=(200,), check=lambda r, c: _has(r, "bravo-marker") and _lacks(r, "alpha-marker")),
            S("A still has only its own", "A", "get", "/api/v1/tenants/me", expect=(200,), check=lambda r, c: _has(r, "alpha-marker") and _lacks(r, "bravo-marker")),
            S("B has only its own", "B", "get", "/api/v1/tenants/me", expect=(200,), check=lambda r, c: _has(r, "bravo-marker") and _lacks(r, "alpha-marker")),
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
                ctx: dict[str, str] = dict(FLOW_SEEDS.get(flow, {}))
                for st in steps:
                    try:
                        path = st.tpl.format(**ctx) if "{" in st.tpl else st.tpl
                    except KeyError as e:
                        out.append([flow, st.name, st.user, "SKIP", False, f"needs {e}, which an earlier step did not produce"])
                        continue
                    over = dict(st.over)
                    if flow == "alerts" and st.name in ("A links the alert", "B cannot attach A's alert", "B cannot create a case citing A's alert", "A can create a case citing its OWN alert"):
                        over = {"alert_ids": [ctx.get("alert")]}
                    if flow == "rbac" and st.name == "B cannot give A's user B's role":
                        over = {"user_id": ctx.get("ua"), "role_id": ctx.get("rb")}
                    if flow == "rbac" and st.name == "B cannot give its own user A's role":
                        over = {"user_id": ctx.get("ub"), "role_id": ctx.get("ra")}
                    if flow == "rbac" and st.name == "B gives its own user B's role":
                        over = {"user_id": ctx.get("ub"), "role_id": ctx.get("rb")}
                    if flow == "rbac" and st.name == "A gives its own user A's role":
                        over = {"user_id": ctx.get("ua"), "role_id": ctx.get("ra")}
                    if flow == "explain_lineage" and st.name in ("A submits an alert naming its own rule", "B submits an alert naming A's rule"):
                        over = {**over, "tags": [f"rule:{ctx.get('rl2')}"]}
                    if flow == "assets" and st.name == "A adds a vulnerability to it":
                        over = {"asset_id": ctx.get("asset"), "title": "CVE-2026-0001", "source": "scanner"}
                    if flow == "identity_graph" and st.name == "A links them":
                        over = {**over, "source_id": ctx.get("n1"), "target_id": ctx.get("n2")}
                    if flow == "identity_graph" and st.name == "B cannot link its node to A's node":
                        over = {**over, "source_id": ctx.get("nb"), "target_id": ctx.get("n1")}
                    kw: dict[str, Any] = {}
                    if st.params:
                        kw["params"] = st.params
                    if st.absent:
                        want = ctx.get(st.absent)
                        if want is None:
                            out.append([flow, st.name, st.user, "SKIP", False, f"needs '{st.absent}', which an earlier step did not produce"])
                            continue
                        owner = "A" if st.user == "B" else "B"
                        try:
                            ctrl = await asyncio.wait_for(c.get(path, headers=tok[owner], **kw), 15)
                            found = control_found(ctrl, want)
                            out.append([flow, st.name + " [control: the owner finds it]", owner, ctrl.status_code, found, "" if found else "the owner cannot see it either, so this exclusion proves nothing: " + ctrl.text[:90]])
                        except Exception as e:  # noqa: BLE001
                            out.append([flow, st.name + " [control: the owner finds it]", owner, "EXC", False, type(e).__name__])
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
                            ctx[st.capture[0]] = str(_dig(r.json(), st.capture[1]))
                            if st.user == "A" and flow == "fresh":
                                fresh_ids[ctx[st.capture[0]]] = st.capture[0]
                        except Exception:  # noqa: BLE001, S110
                            pass
                    ok = r.status_code in st.expect
                    if ok and st.absent:
                        ok = exclusion_holds(r, ctx[st.absent], st.expect)
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
