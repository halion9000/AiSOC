"""Wave 5 (W5.1) - configurable retention policies + purge SQL."""

from __future__ import annotations

import uuid

from app.services.retention import (
    MAX_DAYS,
    MIN_DAYS,
    build_alert_purge_sql,
    build_lake_purge_sql,
    resolve_policy,
)


def test_defaults_when_no_config():
    policy = resolve_policy(None)
    assert policy.raw_events_days == 90
    assert policy.alerts_days == 365
    assert policy.audit_days == 730


def test_tenant_override_merges():
    policy = resolve_policy({"raw_events_days": 30})
    assert policy.raw_events_days == 30
    assert policy.alerts_days == 365  # default preserved


def test_bounds_are_clamped():
    assert resolve_policy({"raw_events_days": 0}).raw_events_days == MIN_DAYS
    assert resolve_policy({"alerts_days": 99999}).alerts_days == MAX_DAYS


def test_lake_purge_sql_is_tenant_scoped():
    tid = uuid.uuid4()
    sql = build_lake_purge_sql(tid, 30)
    assert str(tid) in sql
    assert "tenant_id" in sql
    assert "INTERVAL 30 DAY" in sql


def test_lake_purge_clamps_days():
    sql = build_lake_purge_sql(uuid.uuid4(), 0)
    assert f"INTERVAL {MIN_DAYS} DAY" in sql


def test_alert_purge_sql_is_parameterised():
    tid = uuid.uuid4()
    sql, params = build_alert_purge_sql(tid, 45)
    assert ":days" in sql and ":tenant_id" in sql
    assert params == {"tenant_id": tid, "days": 45}
    # never string-interpolate the cutoff or the tenant
    assert "45" not in sql and str(tid) not in sql


def test_alert_purge_names_the_tenant_explicitly_and_never_relies_on_rls():
    """It used to say "RLS scopes the tenant" and filter on nothing else. The services connect as the Postgres superuser by default, which bypasses RLS, so one tenant's window would have deleted EVERY tenant's old alerts."""
    sql, _ = build_alert_purge_sql(uuid.uuid4(), 30)
    assert "WHERE tenant_id = :tenant_id" in sql
    assert sql.index("tenant_id") < sql.index("created_at")


def test_alert_purge_is_still_clamped():
    assert build_alert_purge_sql(uuid.uuid4(), 0)[1]["days"] == MIN_DAYS
    assert build_alert_purge_sql(uuid.uuid4(), 10**6)[1]["days"] == MAX_DAYS
