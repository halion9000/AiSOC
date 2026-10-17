"""Autonomy policy: defaults must match the agents service, and the admin endpoints must behave.

The endpoint module says it duplicates the agents' default thresholds and that "a small CI test catches drift between the two copies".
No such test existed. test_defaults_match_agents_service is that test: it loads the agents' real table and compares every action.

NOT VERIFIED LIVE: SQL runs against a fake session here, so the INSERT ... ON CONFLICT and the legacy-schema retry were exercised for
control flow, not against Postgres.
"""

import asyncio
import importlib.util
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.api.v1.endpoints import autonomy_policy as ap
from fastapi import HTTPException
from pydantic import ValidationError

GUARDRAILS = Path(__file__).resolve().parents[2] / "agents" / "app" / "policy" / "guardrails.py"


def run(coro):
    return asyncio.run(coro)


class FakeUser:
    def __init__(self, allowed=("settings:read", "settings:write")):
        self.tenant_id = uuid.uuid4()
        self.email = "admin@example.test"
        self.allowed = set(allowed)
        self.checked: list[str] = []

    async def require_permission_db(self, permission, db):
        self.checked.append(permission)
        if permission not in self.allowed:
            raise HTTPException(status_code=403, detail="forbidden")


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows


class FakeDB:
    """Records statements; `fail_first` makes the first N executes raise (to drive the legacy-schema fallbacks)."""

    def __init__(self, rows=None, fail_first=0, fail_always=False):
        self.rows = rows or []
        self.fail_first = fail_first
        self.fail_always = fail_always
        self.calls: list[tuple[str, dict]] = []
        self.commits = 0
        self.rollbacks = 0

    async def execute(self, statement, params=None):
        self.calls.append((str(statement), params or {}))
        if self.fail_always or len(self.calls) <= self.fail_first:
            raise RuntimeError("boom")
        return _Rows(self.rows)

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


def row(action, auto, review=None, escalation=None, **extra):
    return {
        "action_name": action,
        "min_confidence": auto,
        "review_confidence": review,
        "escalation_confidence": escalation,
        "updated_by": "someone@example.test",
        "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
        "source": None,
        "reason": "because",
        **extra,
    }


# --- drift ---------------------------------------------------------------------------------------------------------------------


def test_defaults_match_agents_service():
    spec = importlib.util.spec_from_file_location("agents_guardrails_for_drift_test", GUARDRAILS)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their own module through sys.modules
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    agents = {name: (t.auto, t.review, t.escalation) for name, t in module._DEFAULT_THRESHOLDS.items()}
    assert set(agents) == set(ap._DEFAULTS), "the two services list different actions"
    for name, triple in ap._DEFAULTS.items():
        assert agents[name] == pytest.approx(triple), f"{name} differs between agents and API"


def test_every_default_action_has_a_blast_radius_and_every_default_is_ordered():
    assert set(ap._BLAST_RADIUS) == set(ap._DEFAULTS)
    for name, (auto, review, escalation) in ap._DEFAULTS.items():
        assert 0.0 <= escalation <= review <= auto <= 1.0, name


def test_blast_radius_labels_follow_the_risk_of_the_action():
    assert {a for a, r in ap._BLAST_RADIUS.items() if r == "read"} == {
        "lookup_ip",
        "lookup_domain",
        "search_logs",
        "enrich_alert",
        "mitre_lookup",
        "get_alert_context",
    }
    assert ap._BLAST_RADIUS["delete_object"] == "critical"
    assert ap._BLAST_RADIUS["revoke_session"] == "medium"
    for action in ("isolate_host", "block_ip", "quarantine_file", "disable_user_account", "firewall_rule_add", "firewall_rule_remove"):
        assert ap._BLAST_RADIUS[action] == "high", action


def test_unknown_actions_default_to_always_asking_an_analyst():
    triple = ap._default_triple("brand_new_action")
    assert (triple.auto, triple.review, triple.escalation) == (1.0, 1.0, 1.0)


# --- validation ----------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("auto,review,escalation", [(0.5, 0.6, 0.1), (0.5, 0.4, 0.45), (1.1, 0.5, 0.1), (0.5, -0.1, -0.2)])
def test_bad_thresholds_are_rejected(auto, review, escalation):
    with pytest.raises(ValidationError):
        ap.ThresholdTriple(auto=auto, review=review, escalation=escalation)
    with pytest.raises(ValidationError):
        ap.ThresholdUpdateRequest(auto=auto, review=review, escalation=escalation)


def test_equal_thresholds_are_allowed_and_reason_is_length_capped():
    assert ap.ThresholdUpdateRequest(auto=0.5, review=0.5, escalation=0.5).reason is None
    with pytest.raises(ValidationError):
        ap.ThresholdUpdateRequest(auto=0.5, review=0.4, escalation=0.3, reason="x" * 501)


def test_row_to_triple_derives_missing_tiers_and_clamps_legacy_rows():
    derived = ap._row_to_triple(row("a", 0.9))
    assert (derived.auto, round(derived.review, 6), round(derived.escalation, 6)) == (0.9, 0.8, 0.6)
    low = ap._row_to_triple(row("a", 0.05))
    assert (low.auto, low.review, low.escalation) == (0.05, 0.0, 0.0)
    clamped = ap._row_to_triple(row("a", 0.5, review=0.9, escalation=0.95))
    assert (clamped.auto, clamped.review, clamped.escalation) == (0.5, 0.5, 0.5)


# --- GET -----------------------------------------------------------------------------------------------------------------------


def test_get_requires_settings_read():
    user = FakeUser(allowed=())
    with pytest.raises(HTTPException) as exc:
        run(ap.get_autonomy_policy(user, FakeDB()))
    assert exc.value.status_code == 403
    assert user.checked == ["settings:read"]


def test_get_without_overrides_returns_defaults_not_overridden_sorted_by_blast_radius():
    user = FakeUser()
    out = run(ap.get_autonomy_policy(user, FakeDB()))
    assert out.tenant_id == str(user.tenant_id)
    assert len(out.actions) == len(ap._DEFAULTS)
    assert not any(a.overridden for a in out.actions)
    keys = [(a.blast_radius, a.action) for a in out.actions]
    assert keys == sorted(keys)


def test_get_merges_overrides_and_surfaces_custom_actions():
    db = FakeDB(rows=[row("block_ip", 0.99, 0.8, 0.5), row("tenant_special", 0.7, 0.6, 0.2)])
    out = run(ap.get_autonomy_policy(FakeUser(), db))
    by = {a.action: a for a in out.actions}
    block = by["block_ip"]
    assert block.overridden and block.thresholds.auto == 0.99 and block.default_thresholds.auto == 0.90
    assert block.override_source == "admin_ui" and block.last_updated_by == "someone@example.test"
    assert block.last_updated_at.startswith("2026-01-02") and block.last_reason == "because"
    assert by["isolate_host"].overridden is False
    custom = by["tenant_special"]
    assert custom.blast_radius == "custom" and custom.overridden
    assert (custom.default_thresholds.auto,) == (1.0,)


def test_get_scopes_the_query_to_the_callers_tenant():
    user, db = FakeUser(), FakeDB()
    run(ap.get_autonomy_policy(user, db))
    assert db.calls[0][1] == {"tenant_id": str(user.tenant_id)}


def test_get_falls_back_to_the_legacy_shape_then_to_plain_defaults():
    legacy = FakeDB(rows=[{"action_name": "block_ip", "min_confidence": 0.99, "updated_by": "u", "updated_at": None}], fail_first=1)
    out = run(ap.get_autonomy_policy(FakeUser(), legacy))
    assert len(legacy.calls) == 2 and {a.action: a for a in out.actions}["block_ip"].thresholds.auto == 0.99
    dead = run(ap.get_autonomy_policy(FakeUser(), FakeDB(fail_always=True)))
    assert not any(a.overridden for a in dead.actions)


# --- PUT -----------------------------------------------------------------------------------------------------------------------


def update(**kw):
    return ap.ThresholdUpdateRequest(**{"auto": 0.9, "review": 0.7, "escalation": 0.4, **kw})


def test_put_requires_settings_write_and_writes_nothing_without_it():
    user, db = FakeUser(allowed=("settings:read",)), FakeDB()
    with pytest.raises(HTTPException) as exc:
        run(ap.upsert_action_threshold("block_ip", update(), user, db))
    assert exc.value.status_code == 403
    assert db.calls == [] and db.commits == 0


@pytest.mark.parametrize("name", ["", "block-ip", "block ip", "a;drop", "x" * 101, "ü"])
def test_put_rejects_odd_action_names(name):
    db = FakeDB()
    with pytest.raises(HTTPException) as exc:
        run(ap.upsert_action_threshold(name, update(), FakeUser(), db))
    assert exc.value.status_code == 422
    assert db.calls == []


def test_put_persists_for_the_callers_tenant_and_returns_what_was_stored():
    user, db = FakeUser(), FakeDB()
    out = run(ap.upsert_action_threshold("block_ip", update(reason="tightened"), user, db))
    assert out.action == "block_ip" and out.updated_by == user.email
    assert (out.thresholds.auto, out.thresholds.review, out.thresholds.escalation) == (0.9, 0.7, 0.4)
    sql, params = db.calls[0]
    assert "ON CONFLICT (tenant_id, action_name)" in sql
    assert params["tenant_id"] == str(user.tenant_id) and params["action"] == "block_ip"
    assert (params["auto"], params["review"], params["escalation"], params["reason"]) == (0.9, 0.7, 0.4, "tightened")
    assert db.commits == 1 and db.rollbacks == 0


def test_put_retries_against_the_legacy_schema_and_keeps_only_the_auto_tier():
    db = FakeDB(fail_first=1)
    out = run(ap.upsert_action_threshold("block_ip", update(), FakeUser(), db))
    assert out.thresholds.auto == 0.9
    assert db.rollbacks == 1 and db.commits == 1 and len(db.calls) == 2
    assert "review_confidence" not in db.calls[1][0] and "review" not in db.calls[1][1]


def test_put_gives_a_generic_500_when_both_attempts_fail():
    db = FakeDB(fail_always=True)
    with pytest.raises(HTTPException) as exc:
        run(ap.upsert_action_threshold("block_ip", update(), FakeUser(), db))
    assert exc.value.status_code == 500
    assert exc.value.detail == "Failed to persist autonomy threshold"
    assert "boom" not in exc.value.detail
    assert db.commits == 0 and db.rollbacks == 2


# --- DELETE --------------------------------------------------------------------------------------------------------------------


def test_delete_requires_settings_write():
    db = FakeDB()
    with pytest.raises(HTTPException) as exc:
        run(ap.reset_action_threshold("block_ip", FakeUser(allowed=("settings:read",)), db))
    assert exc.value.status_code == 403 and db.calls == []


def test_delete_is_scoped_to_tenant_and_action():
    user, db = FakeUser(), FakeDB()
    assert run(ap.reset_action_threshold("block_ip", user, db)) is None
    sql, params = db.calls[0]
    assert "DELETE FROM aisoc_autonomy_thresholds" in sql and "tenant_id = :tenant_id" in sql
    assert params == {"tenant_id": str(user.tenant_id), "action": "block_ip"}
    assert db.commits == 1


def test_delete_failure_is_a_generic_500():
    db = FakeDB(fail_always=True)
    with pytest.raises(HTTPException) as exc:
        run(ap.reset_action_threshold("block_ip", FakeUser(), db))
    assert exc.value.status_code == 500 and exc.value.detail == "Failed to reset autonomy threshold"
    assert db.rollbacks == 1
