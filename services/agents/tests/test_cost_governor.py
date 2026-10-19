"""Tests for the per-tenant CostGovernor (Phase 1.5 cost-DoS enforcement).

Hermetic: injectable clock, in-memory store, no DB/LLM. The headline test is
the 10k-identical-alert flood asserting bounded spend.
"""

from __future__ import annotations

from app.core.cost_governor import (
    BudgetConfig,
    CostGovernor,
    Decision,
    get_governor,
)


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _cfg(**kw) -> BudgetConfig:
    base = {
        "soft_usd": 5.0,
        "hard_usd": 10.0,
        "max_tokens_per_alert": 20_000,
        "window_seconds": 3600,
        "cache_ttl_seconds": 3600,
    }
    base.update(kw)
    return BudgetConfig(**base)


# ── The DoS bound: 10k identical alerts cost one investigation ────────────────


def test_flood_of_identical_alerts_is_deduplicated_to_one_spend():
    clock = FakeClock()
    gov = CostGovernor(config=_cfg(), now=clock)
    tenant = "t1"
    alert = {"category": "malware", "host": "web-1", "signature": "sig-abc"}
    fp = gov.evidence_fingerprint(tenant, alert)

    per_run_cost = 0.05
    allowed = 0
    deduped = 0
    for _ in range(10_000):
        d = gov.check(tenant, fp)
        if d.decision is Decision.ALLOW:
            allowed += 1
            # simulate the investigation running and caching its verdict
            gov.record_verdict(tenant, fp, {"verdict": "malicious"}, usd=per_run_cost, tokens=1500)
        elif d.decision is Decision.DEDUPLICATED:
            deduped += 1
            assert d.cached_verdict == {"verdict": "malicious"}

    assert allowed == 1, "identical alerts must only run once"
    assert deduped == 9_999
    # Total spend is exactly one run, not 10k runs.
    assert abs(gov.spent_usd(tenant) - per_run_cost) < 1e-9


# ── Circuit breaker bounds spend on distinct alerts ───────────────────────────


def test_distinct_alert_flood_trips_circuit_breaker_and_bounds_spend():
    clock = FakeClock()
    gov = CostGovernor(config=_cfg(hard_usd=10.0), now=clock)
    tenant = "t2"

    per_run_cost = 1.0
    llm_runs = 0
    deterministic_runs = 0
    for i in range(10_000):
        alert = {"category": "malware", "host": f"host-{i}", "signature": f"sig-{i}"}
        fp = gov.evidence_fingerprint(tenant, alert)
        d = gov.check(tenant, fp)
        if d.decision is Decision.ALLOW:
            llm_runs += 1
            gov.record_verdict(tenant, fp, {"verdict": "benign"}, usd=per_run_cost, tokens=1000)
        elif d.decision is Decision.CIRCUIT_OPEN:
            deterministic_runs += 1
            assert d.use_llm is False

    # Spend is capped near the hard budget, not 10k * per_run_cost.
    assert gov.spent_usd(tenant) <= 10.0 + per_run_cost
    assert llm_runs <= 10
    assert deterministic_runs >= 9_000
    assert gov.state(tenant)["hard_breached"] is True


def test_circuit_reopens_after_window_expires():
    clock = FakeClock()
    gov = CostGovernor(config=_cfg(hard_usd=10.0, window_seconds=3600), now=clock)
    tenant = "t3"
    gov.record_spend(tenant, usd=10.0, tokens=5000)
    assert gov.check(tenant, "fp").decision is Decision.CIRCUIT_OPEN
    # advance past the window; old spend ages out
    clock.advance(3601)
    assert gov.check(tenant, "fp").decision is Decision.ALLOW
    assert gov.spent_usd(tenant) == 0.0


# ── Per-alert token ceiling ───────────────────────────────────────────────────


def test_per_alert_token_ceiling():
    gov = CostGovernor(config=_cfg(max_tokens_per_alert=20_000))
    assert gov.cap_tokens(1_000_000) == 20_000
    assert gov.cap_tokens(5_000) == 5_000
    assert gov.cap_tokens(-3) == 0


# ── Soft cap precedes hard cap ────────────────────────────────────────────────


def test_soft_breach_flagged_before_hard():
    clock = FakeClock()
    gov = CostGovernor(config=_cfg(soft_usd=5.0, hard_usd=10.0), now=clock)
    tenant = "t4"
    gov.record_spend(tenant, usd=6.0, tokens=1000)  # over soft, under hard
    d = gov.check(tenant, "fp")
    assert d.decision is Decision.ALLOW
    assert d.soft_breached is True
    assert gov.state(tenant)["hard_breached"] is False


# ── Dedup wins even when circuit is open ──────────────────────────────────────


def test_cached_verdict_served_even_when_circuit_open():
    clock = FakeClock()
    gov = CostGovernor(config=_cfg(hard_usd=10.0), now=clock)
    tenant = "t5"
    fp = gov.evidence_fingerprint(tenant, {"a": 1})
    gov.record_verdict(tenant, fp, {"verdict": "malicious"}, usd=10.0, tokens=1000)  # trips hard cap + caches
    d = gov.check(tenant, fp)
    assert d.decision is Decision.DEDUPLICATED
    assert d.cached_verdict == {"verdict": "malicious"}


def test_cache_expiry_falls_back_to_circuit_or_allow():
    clock = FakeClock()
    gov = CostGovernor(config=_cfg(hard_usd=100.0, cache_ttl_seconds=60), now=clock)
    tenant = "t6"
    fp = gov.evidence_fingerprint(tenant, {"a": 1})
    gov.record_verdict(tenant, fp, {"v": 1}, usd=0.01, tokens=10)
    assert gov.check(tenant, fp).decision is Decision.DEDUPLICATED
    clock.advance(61)
    assert gov.check(tenant, fp).decision is Decision.ALLOW  # cache expired, budget fine


# ── fingerprint + config + singleton ──────────────────────────────────────────


def test_fingerprint_is_stable_and_tenant_scoped():
    gov = CostGovernor(config=_cfg())
    a = {"category": "malware", "host": "h1"}
    assert gov.evidence_fingerprint("t1", a) == gov.evidence_fingerprint("t1", dict(reversed(list(a.items()))))
    assert gov.evidence_fingerprint("t1", a) != gov.evidence_fingerprint("t2", a)


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("AISOC_BUDGET_HARD_USD", "250")
    monkeypatch.setenv("AISOC_MAX_TOKENS_PER_ALERT", "9000")
    cfg = BudgetConfig.from_env()
    assert cfg.hard_usd == 250.0
    assert cfg.max_tokens_per_alert == 9000


def test_get_governor_is_singleton():
    assert get_governor() is get_governor()


# ── a count limit on LLM runs: dollars are 0 on a flat-rate plan, so they cannot bound a flood ───────────────────────────


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _gov(limit, clock=None):
    from app.core.cost_governor import BudgetConfig, CostGovernor

    return CostGovernor(config=BudgetConfig(max_llm_runs=limit, window_seconds=3600), now=clock or _Clock())


def test_with_no_limit_set_a_flood_of_zero_cost_runs_is_never_stopped():
    g = _gov(0)
    for i in range(50):
        g.record_verdict("t", f"f{i}", {"verdict": "x"}, usd=0.0, tokens=700)
    assert g.check("t", "new").use_llm


def test_past_the_limit_a_tenant_goes_deterministic_instead_of_dropping_alerts():
    from app.core.cost_governor import Decision

    g = _gov(3)
    for i in range(3):
        assert g.check("t", f"f{i}").use_llm
        g.record_verdict("t", f"f{i}", {"verdict": "x"}, usd=0.0, tokens=700)
    d = g.check("t", "another")
    assert d.decision is Decision.CIRCUIT_OPEN and not d.use_llm and "3 LLM investigations" in d.reason


def test_one_tenants_flood_does_not_stop_another_tenant():
    g = _gov(1)
    g.record_verdict("noisy", "f", {"verdict": "x"}, usd=0.0, tokens=700)
    assert not g.check("noisy", "g").use_llm
    assert g.check("quiet", "g").use_llm


def test_deterministic_runs_do_not_count_toward_the_limit():
    g = _gov(2)
    for i in range(10):
        g.record_verdict("t", f"d{i}", {"verdict": "x"}, usd=0.0, tokens=0)
    assert g.check("t", "n").use_llm and g.llm_runs("t") == 0


def test_the_limit_is_per_window_so_it_frees_up():
    clock = _Clock()
    g = _gov(1, clock)
    g.record_verdict("t", "f", {"verdict": "x"}, usd=0.0, tokens=700)
    assert not g.check("t", "g").use_llm
    clock.t += 3601
    assert g.check("t", "g").use_llm


def test_a_cached_identical_alert_is_still_served_when_the_limit_is_reached():
    from app.core.cost_governor import Decision

    g = _gov(1)
    g.record_verdict("t", "same", {"verdict": "benign", "confidence": 0.9}, usd=0.0, tokens=700)
    assert g.check("t", "same").decision is Decision.DEDUPLICATED


def test_the_limit_comes_from_the_environment(monkeypatch):
    from app.core.cost_governor import BudgetConfig

    monkeypatch.setenv("AISOC_BUDGET_MAX_LLM_RUNS", "7")
    assert BudgetConfig.from_env().max_llm_runs == 7
    monkeypatch.setenv("AISOC_BUDGET_MAX_LLM_RUNS", "-4")
    assert BudgetConfig.from_env().max_llm_runs == 0
    monkeypatch.setenv("AISOC_BUDGET_MAX_LLM_RUNS", "junk")
    assert BudgetConfig.from_env().max_llm_runs == 0
