"""Detection rule CRUD, execute, hunt and backtest endpoints: tenant/builtin visibility, which fields an update may touch, hit-stat updates, lake error mapping.

NOT VERIFIED LIVE: the session is a fake (SQL compiled, never executed); the rule engine, resolver and lake are stubbed.
"""

import asyncio
import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import detection_rules as dr
from fastapi import HTTPException
from pydantic import ValidationError

TENANT = uuid.uuid4()
OTHER = uuid.uuid4()
RULE_ID = uuid.uuid4()


def run(coro):
    return asyncio.run(coro)


def user(tenant=TENANT):
    return SimpleNamespace(tenant_id=tenant, user_id=uuid.uuid4())


def sql(statement) -> str:
    return str(statement.compile(compile_kwargs={"literal_binds": True})).replace("-", "")


def where(statement) -> str:
    return sql(statement).split("WHERE", 1)[1]


def dashless(value) -> str:
    return str(value).replace("-", "")


class FakeDB:
    def __init__(self, found=None, rows=()):
        self.found = found
        self.rows = list(rows)
        self.executed = []
        self.added = []
        self.deleted = []
        self.commits = 0

    async def execute(self, statement):
        self.executed.append(statement)
        found, rows = self.found, self.rows
        return SimpleNamespace(scalar_one_or_none=lambda: found, scalars=lambda: SimpleNamespace(all=lambda: rows))

    def add(self, obj):
        self.added.append(obj)

    async def delete(self, obj):
        self.deleted.append(obj)

    async def commit(self):
        self.commits += 1

    async def refresh(self, obj):
        now = __import__("datetime").datetime(2026, 10, 1, tzinfo=__import__("datetime").UTC)
        for key, value in {
            "id": RULE_ID,
            "status": "active",
            "fp_rate": 0.0,
            "total_hits": 0,
            "is_builtin": False,
            "version": 1,
            "created_at": now,
            "updated_at": now,
        }.items():
            if getattr(obj, key, None) is None:
                setattr(obj, key, value)


def rule_row(tenant=TENANT, **over):
    now = __import__("datetime").datetime(2026, 10, 1, tzinfo=__import__("datetime").UTC)
    base = {
        "id": RULE_ID,
        "tenant_id": tenant,
        "name": "r",
        "description": None,
        "rule_language": "sigma",
        "rule_body": "title: x",
        "category": "auth",
        "status": "active",
        "severity": "high",
        "confidence": 60,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "fp_rate": 0.0,
        "total_hits": 0,
        "last_triggered": None,
        "tags": [],
        "is_builtin": False,
        "version": 3,
        "created_at": now,
        "updated_at": now,
    }
    base.update(over)
    return SimpleNamespace(**base)


def list_call(db, **kw):
    args = {"category": None, "rule_language": None, "include_builtin": True, "include_packs": True}
    args.update(kw)
    return run(dr.list_rules(user(), db, **args))


def test_list_scopes_to_tenant_plus_builtins_packs_and_drops_excluded():
    db = FakeDB(rows=[rule_row()])
    out = list_call(db)
    assert [r.name for r in out] == ["r"]
    text = where(db.executed[0])
    assert dashless(TENANT) in text and dashless(OTHER) not in text
    assert "is_builtin" in text
    assert "mssp_rule_pack_assignments" in text and "enabled IS true" in text
    assert "NOT IN" in text and "'exclude'" in text
    assert "ORDER BY" in text


def test_list_without_builtins_or_packs_is_tenant_only():
    db = FakeDB()
    list_call(db, include_builtin=False, include_packs=False)
    text = where(db.executed[0])
    assert "is_builtin" not in text
    assert "pack" not in text.lower()
    assert dashless(TENANT) in text


def test_list_filters_by_category_and_language():
    db = FakeDB()
    list_call(db, category="auth", rule_language="kql")
    text = sql(db.executed[0])
    assert "category = 'auth'" in text and "rule_language = 'kql'" in text
    plain = FakeDB()
    list_call(plain)
    assert "category =" not in sql(plain.executed[0])


def test_create_belongs_to_the_caller_and_defaults_are_sane():
    body = dr.CreateRuleRequest(name="n", rule_language="sigma", rule_body="b", category="c")
    caller = user()
    db = FakeDB()
    out = run(dr.create_rule(body, caller, db))
    row = db.added[0]
    assert row.tenant_id == TENANT and row.created_by_id == caller.user_id
    assert (row.severity, row.confidence) == ("medium", 50)
    assert db.commits == 1
    assert out.name == "n"


def test_create_requires_language_body_and_category():
    with pytest.raises(ValidationError):
        dr.CreateRuleRequest(name="n")  # type: ignore[call-arg]


def test_get_can_see_own_and_platform_rules_but_not_another_tenants():
    db = FakeDB(found=rule_row())
    run(dr.get_rule(RULE_ID, user(), db))
    text = sql(db.executed[0])
    assert dashless(TENANT) in text and "tenant_id IS NULL" in text
    assert dashless(OTHER) not in text
    with pytest.raises(HTTPException) as exc:
        run(dr.get_rule(RULE_ID, user(), FakeDB(found=None)))
    assert exc.value.status_code == 404


def test_update_and_delete_only_find_tenant_owned_rules():
    for call in (
        lambda db: dr.update_rule(RULE_ID, dr.UpdateRuleRequest(name="x"), user(), db),
        lambda db: dr.delete_rule(RULE_ID, user(), db),
    ):
        db = FakeDB(found=None)
        with pytest.raises(HTTPException) as exc:
            run(call(db))
        assert exc.value.status_code == 404
        text = sql(db.executed[0])
        assert dashless(TENANT) in text
        assert "tenant_id IS NULL" not in text
        assert db.commits == 0 and db.deleted == []


def test_delete_removes_the_found_rule():
    row = rule_row()
    db = FakeDB(found=row)
    assert run(dr.delete_rule(RULE_ID, user(), db)) is None
    assert db.deleted == [row] and db.commits == 1


def test_update_writes_only_the_fields_sent_and_bumps_the_version():
    row = rule_row(version=3)
    db = FakeDB(found=row)
    run(dr.update_rule(RULE_ID, dr.UpdateRuleRequest(severity="low", tags=["a"]), user(), db))
    stmt = db.executed[1]
    params = stmt.compile().params
    assert params["severity"] == "low" and params["tags"] == ["a"]
    assert params["version"] == 4
    assert "updated_at" in params
    assert "name" not in params and "rule_body" not in params
    assert db.commits == 1


def test_an_update_with_nothing_in_it_does_not_touch_the_rule():
    row = rule_row()
    db = FakeDB(found=row)
    out = run(dr.update_rule(RULE_ID, dr.UpdateRuleRequest(), user(), db))
    assert len(db.executed) == 1 and db.commits == 0
    assert out.version == 3


def test_an_update_may_set_a_falsy_value():
    db = FakeDB(found=rule_row())
    run(dr.update_rule(RULE_ID, dr.UpdateRuleRequest(confidence=0, tags=[]), user(), db))
    params = db.executed[1].compile().params
    assert params["confidence"] == 0 and params["tags"] == []


def test_the_update_request_cannot_change_ownership_or_category():
    fields = set(dr.UpdateRuleRequest.model_fields)
    assert not fields & {"tenant_id", "is_builtin", "category", "rule_language", "version"}


@pytest.fixture
def engine(monkeypatch):
    calls = {}

    def execute_rule(**kw):
        calls["kw"] = kw
        return SimpleNamespace(
            matched=calls.get("matched", True),
            match_details={"matched_events": calls.get("events", [{"a": 1}, {"a": 2}])},
            score=0.5,
            error=None,
            execution_time_ms=1.0,
        )

    monkeypatch.setattr(dr, "execute_rule", execute_rule)
    return calls


def test_execute_runs_the_rule_on_the_given_events_and_records_hits(engine):
    db = FakeDB(found=rule_row())
    out = run(dr.execute_detection_rule(RULE_ID, dr.ExecuteRuleRequest(events=[{"x": 1}]), user(), db))
    assert engine["kw"]["events"] == [{"x": 1}]
    assert engine["kw"]["rule_body"] == "title: x" and engine["kw"]["rule_language"] == "sigma"
    assert out.matched and out.match_count == 2
    stmt = db.executed[1]
    assert "total_hits" in sql(stmt) and "last_triggered" in stmt.compile().params
    assert db.commits == 1


def test_execute_with_no_match_leaves_the_stats_alone(engine):
    engine["matched"], engine["events"] = False, []
    db = FakeDB(found=rule_row())
    out = run(dr.execute_detection_rule(RULE_ID, dr.ExecuteRuleRequest(events=[]), user(), db))
    assert not out.matched and out.match_count == 0
    assert len(db.executed) == 1 and db.commits == 0


def test_execute_of_a_rule_the_caller_cannot_see_is_404(engine):
    with pytest.raises(HTTPException) as exc:
        run(dr.execute_detection_rule(RULE_ID, dr.ExecuteRuleRequest(events=[]), user(), FakeDB(found=None)))
    assert exc.value.status_code == 404
    assert "kw" not in engine


def test_execute_and_hunt_cap_the_number_of_events():
    with pytest.raises(ValidationError):
        dr.ExecuteRuleRequest(events=[{}] * 1001)
    with pytest.raises(ValidationError):
        dr.HuntRequest(events=[{}] * 5001)


def test_hunt_uses_the_resolved_active_rules_for_the_callers_tenant(monkeypatch):
    seen = {}

    async def resolve(db, tenant_id, **kw):
        seen.update(tenant=tenant_id, **kw)
        return [SimpleNamespace(to_engine_dict=lambda: {"id": "r1"})]

    async def run_hunt(**kw):
        seen["hunt"] = kw
        return SimpleNamespace(
            hunt_id="h",
            rules_evaluated=1,
            rules_matched=0,
            total_events_scanned=2,
            matched_events=[],
            match_summary=[],
            execution_time_ms=1.0,
            errors=[],
        )

    monkeypatch.setattr(dr, "resolve_effective_rules", resolve)
    monkeypatch.setattr(dr, "run_hunt", run_hunt)
    out = run(dr.hunt(dr.HuntRequest(events=[{}, {}], rule_language="sigma"), user(), FakeDB()))
    assert seen["tenant"] == TENANT and seen["only_active"] is True and seen["rule_language"] == "sigma"
    assert seen["hunt"]["tenant_id"] == str(TENANT) and seen["hunt"]["rules"] == [{"id": "r1"}]
    assert out.hunt_id == "h" and out.total_events_scanned == 2


def test_hunt_with_no_matching_rules_is_404_and_runs_nothing(monkeypatch):
    async def resolve(db, tenant_id, **kw):
        return []

    async def run_hunt(**kw):
        raise AssertionError("must not run")

    monkeypatch.setattr(dr, "resolve_effective_rules", resolve)
    monkeypatch.setattr(dr, "run_hunt", run_hunt)
    with pytest.raises(HTTPException) as exc:
        run(dr.hunt(dr.HuntRequest(events=[]), user(), FakeDB()))
    assert exc.value.status_code == 404


def backtest(db, fetch=None, summary=None, monkeypatch=None, **body):
    async def default_fetch(tenant_id, **kw):
        default_fetch.kw = (tenant_id, kw)
        return [{"e": 1}]

    monkeypatch.setattr(dr, "_fetch_lake_events", fetch or default_fetch)
    monkeypatch.setattr(
        dr,
        "backtest_rule",
        lambda **kw: summary or {"events_scanned": 1, "would_fire": 1, "hit_rate": 1.0, "sample_matches": [], "error": None},
    )
    return run(dr.backtest_detection_rule(RULE_ID, dr.BacktestRequest(**body), user(), db)), default_fetch


def test_backtest_scans_the_callers_tenant_and_reports_the_window(monkeypatch):
    out, fetch = backtest(FakeDB(found=rule_row()), monkeypatch=monkeypatch, window_days=7, limit=50, source="okta")
    assert fetch.kw == (TENANT, {"window_days": 7, "limit": 50, "source": "okta"})
    assert out.window_days == 7 and out.would_fire == 1 and out.rule_id == RULE_ID


def test_backtest_of_an_invisible_rule_is_404_before_any_lake_query(monkeypatch):
    async def fetch(*a, **k):
        raise AssertionError("must not query")

    with pytest.raises(HTTPException) as exc:
        backtest(FakeDB(found=None), fetch=fetch, monkeypatch=monkeypatch)
    assert exc.value.status_code == 404


def test_backtest_maps_lake_failures_to_503_and_502(monkeypatch):
    from app.db.clickhouse import LakeQueryNotConfiguredError

    async def not_configured(*a, **k):
        raise LakeQueryNotConfiguredError("x")

    async def broken(*a, **k):
        raise RuntimeError("boom")

    with pytest.raises(HTTPException) as exc:
        backtest(FakeDB(found=rule_row()), fetch=not_configured, monkeypatch=monkeypatch)
    assert exc.value.status_code == 503
    with pytest.raises(HTTPException) as exc2:
        backtest(FakeDB(found=rule_row()), fetch=broken, monkeypatch=monkeypatch)
    assert exc2.value.status_code == 502 and "boom" in exc2.value.detail


def test_backtest_window_and_limit_are_bounded():
    for bad in ({"window_days": 0}, {"window_days": 366}, {"limit": 0}, {"limit": 100_001}):
        with pytest.raises(ValidationError):
            dr.BacktestRequest(**bad)
