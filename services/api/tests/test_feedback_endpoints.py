"""Analyst override feedback: verdict validation, tenant scoping, the redisposition blast-radius controls, and the summary counts.

NOT VERIFIED LIVE: the session is a fake (SQL not executed) and the override-learning service is stubbed; its own tests cover it.
"""

import asyncio
import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import feedback as fb
from app.services.override_learning import RedispositionCandidate
from fastapi import HTTPException

TENANT = uuid.uuid4()


def run(coro):
    return asyncio.run(coro)


def user(tenant=TENANT):
    return SimpleNamespace(tenant_id=tenant, user_id=uuid.uuid4())


def sql(statement) -> str:
    return str(statement.compile(compile_kwargs={"literal_binds": True})).replace("-", "")


def has(statement, value) -> bool:
    return str(value).replace("-", "") in sql(statement)


class FakeDB:
    def __init__(self, alert=object(), summary_rows=()):
        self.alert = alert
        self.summary_rows = list(summary_rows)
        self.scalar_statements = []
        self.executed = []
        self.commits = 0

    async def scalar(self, statement):
        self.scalar_statements.append(statement)
        return self.alert

    async def execute(self, statement):
        self.executed.append(statement)
        return SimpleNamespace(all=lambda: self.summary_rows)

    async def commit(self):
        self.commits += 1


class Signature:
    def memory_key(self):
        return "sig-key"


@pytest.fixture
def stub_learning(monkeypatch):
    calls = {}

    async def record_override(db, **kw):
        calls["record"] = kw
        return calls.get("signature", Signature())

    async def find_candidates(db, **kw):
        calls["find"] = kw
        return calls.get("candidates", [])

    monkeypatch.setattr(fb, "record_override", record_override)
    monkeypatch.setattr(fb, "find_redisposition_candidates", find_candidates)
    return calls


def request(**over):
    return fb.AlertOverrideRequest(
        **{"alert_id": str(uuid.uuid4()), "original_verdict": "true_positive", "corrected_verdict": "false_positive", **over}
    )


def candidate(i):
    return RedispositionCandidate(
        alert_id=str(uuid.UUID(int=i + 1)),
        title=f"t{i}",
        severity="low",
        current_disposition=None,
        proposed_disposition="false_positive",
        event_time="2026-01-01T00:00:00Z",
    )


# --- POST /alert-override --------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("verdict", ["", "malicious", "FALSE_POSITIVE", "false positive"])
def test_unknown_verdicts_are_rejected_before_any_lookup(verdict, stub_learning):
    db = FakeDB()
    with pytest.raises(HTTPException) as exc:
        run(fb.submit_alert_override(request(corrected_verdict=verdict), user(), db))
    assert exc.value.status_code == 422 and db.scalar_statements == [] and db.commits == 0


def test_every_documented_verdict_is_accepted(stub_learning):
    for verdict in sorted(fb._VALID_VERDICTS):
        out = run(fb.submit_alert_override(request(corrected_verdict=verdict), user(), FakeDB()))
        assert out.corrected_verdict == verdict
    assert {"true_positive", "benign_true_positive", "false_positive", "benign", "escalate"} == fb._VALID_VERDICTS


def test_bad_alert_id_is_a_422_and_unknown_alert_a_404_and_nothing_is_written(stub_learning):
    db = FakeDB()
    with pytest.raises(HTTPException) as exc:
        run(fb.submit_alert_override(request(alert_id="not-a-uuid"), user(), db))
    assert exc.value.status_code == 422 and "alert_id" in exc.value.detail
    db = FakeDB(alert=None)
    with pytest.raises(HTTPException) as exc:
        run(fb.submit_alert_override(request(), user(), db))
    assert exc.value.status_code == 404
    assert db.executed == [] and db.commits == 0 and "record" not in stub_learning


def test_lookup_and_update_are_both_scoped_to_the_callers_tenant(stub_learning):
    u, db = user(), FakeDB()
    req = request()
    run(fb.submit_alert_override(req, u, db))
    assert has(db.scalar_statements[0], u.tenant_id) and has(db.scalar_statements[0], req.alert_id)
    (update,) = db.executed
    assert has(update, u.tenant_id) and has(update, req.alert_id) and "false_positive" in sql(update)
    assert db.commits == 1


def test_override_is_recorded_with_who_why_and_what(stub_learning):
    u = user()
    run(fb.submit_alert_override(request(reason="known scanner"), u, FakeDB()))
    rec = stub_learning["record"]
    assert rec["tenant_id"] == u.tenant_id and rec["analyst_id"] == u.user_id
    assert (rec["original_verdict"], rec["corrected_verdict"], rec["reason"]) == ("true_positive", "false_positive", "known scanner")


def test_candidates_come_back_with_a_confirmation_token_the_apply_step_can_check(stub_learning):
    stub_learning["candidates"] = [candidate(i) for i in range(3)]
    out = run(fb.submit_alert_override(request(), user(), FakeDB()))
    assert out.memory_key == "sig-key" and len(out.redisposition_candidates) == 3
    assert out.redisposition_total_matched == 3 and out.redisposition_confirmation_token
    assert out.redisposition_capped is False and out.redisposition_quarantined is False
    from app.services.memory_poisoning import compute_confirmation_token

    assert out.redisposition_confirmation_token == compute_confirmation_token(
        [c.alert_id for c in stub_learning["candidates"]], "false_positive"
    )


def test_the_alert_itself_is_excluded_from_its_own_candidates(stub_learning):
    req = request()
    run(fb.submit_alert_override(req, user(), FakeDB()))
    assert str(stub_learning["find"]["exclude_alert_id"]) == req.alert_id
    assert stub_learning["find"]["corrected_verdict"] == "false_positive"


def test_no_signature_means_no_memory_key_no_candidates_and_no_token(stub_learning):
    stub_learning["signature"] = None
    out = run(fb.submit_alert_override(request(), user(), FakeDB()))
    assert out.memory_key is None and out.redisposition_candidates == []
    assert out.redisposition_confirmation_token is None and out.redisposition_total_matched == 0
    assert "find" not in stub_learning


def test_an_over_cap_match_is_capped_reports_the_true_total_and_the_token_covers_only_the_capped_batch(stub_learning):
    """The preview lists every match but the token binds only the first `max_batch`; applying any other set is refused (409) rather than flipping history.

    Not asserted: `redisposition_quarantined`. The field's comment says an over-cap match is quarantined, but plan_redisposition only sets it for a poisoning-flagged
    signature, and nothing passes `flagged=` from this endpoint, so it is always False today (see docs/findings in the session notes).
    """
    from app.services.memory_poisoning import compute_confirmation_token

    cap = fb.plan_redisposition.__kwdefaults__["max_batch"]
    stub_learning["candidates"] = [candidate(i) for i in range(cap + 3)]
    out = run(fb.submit_alert_override(request(), user(), FakeDB()))
    assert out.redisposition_capped is True and out.redisposition_total_matched == cap + 3
    assert len(out.redisposition_candidates) == cap + 3
    ids = [c.alert_id for c in stub_learning["candidates"]]
    assert out.redisposition_confirmation_token == compute_confirmation_token(ids[:cap], "false_positive")
    assert out.redisposition_confirmation_token != compute_confirmation_token(ids, "false_positive")


# --- POST /redisposition/apply ---------------------------------------------------------------------------------------------------


def test_apply_rejects_unknown_dispositions_and_does_nothing_for_an_empty_list(monkeypatch):
    called = []

    async def fake_apply(db, **kw):
        called.append(kw)
        return 0

    monkeypatch.setattr(fb, "apply_redisposition", fake_apply)
    with pytest.raises(HTTPException) as exc:
        run(
            fb.apply_redisposition_endpoint(
                fb.RedispositionApplyRequest(alert_ids=[str(uuid.uuid4())], new_disposition="nope", confirmation_token="t"),
                user(),
                FakeDB(),
            )
        )
    assert exc.value.status_code == 422
    out = run(
        fb.apply_redisposition_endpoint(
            fb.RedispositionApplyRequest(alert_ids=[], new_disposition="benign", confirmation_token="t"), user(), FakeDB()
        )
    )
    assert out.updated == 0 and out.new_disposition == "benign" and called == []


def test_apply_passes_tenant_analyst_ids_and_token_through_and_returns_the_rowcount(monkeypatch):
    seen = {}

    async def fake_apply(db, **kw):
        seen.update(kw)
        return 2

    monkeypatch.setattr(fb, "apply_redisposition", fake_apply)
    u, ids = user(), [uuid.uuid4(), uuid.uuid4()]
    out = run(
        fb.apply_redisposition_endpoint(
            fb.RedispositionApplyRequest(alert_ids=[str(i) for i in ids], new_disposition="benign", confirmation_token="tok"), u, FakeDB()
        )
    )
    assert out.updated == 2
    assert (
        seen["tenant_id"] == u.tenant_id
        and seen["analyst_id"] == u.user_id
        and seen["alert_ids"] == ids
        and seen["confirmation_token"] == "tok"
    )


def test_apply_turns_a_stale_or_tampered_token_into_a_409(monkeypatch):
    async def refuse(db, **kw):
        raise ValueError("confirmation token does not match")

    monkeypatch.setattr(fb, "apply_redisposition", refuse)
    with pytest.raises(HTTPException) as exc:
        run(
            fb.apply_redisposition_endpoint(
                fb.RedispositionApplyRequest(alert_ids=[str(uuid.uuid4())], new_disposition="benign", confirmation_token="bad"),
                user(),
                FakeDB(),
            )
        )
    assert exc.value.status_code == 409 and "does not match" in exc.value.detail


def test_apply_rejects_a_malformed_alert_id_without_calling_the_service(monkeypatch):
    async def boom(db, **kw):
        raise AssertionError("must not be called")

    monkeypatch.setattr(fb, "apply_redisposition", boom)
    with pytest.raises(HTTPException) as exc:
        run(
            fb.apply_redisposition_endpoint(
                fb.RedispositionApplyRequest(alert_ids=[str(uuid.uuid4()), "x"], new_disposition="benign", confirmation_token="t"),
                user(),
                FakeDB(),
            )
        )
    assert exc.value.status_code == 422


# --- GET /overrides, /summary ----------------------------------------------------------------------------------------------------


def test_list_overrides_is_scoped_to_tenant_and_passes_the_limit(monkeypatch):
    seen = {}

    async def fake_list(db, **kw):
        seen.update(kw)
        return [{"key": "k", "tags": ["a"], "reason": None, "created_at": None, "value": {"x": 1}}]

    monkeypatch.setattr(fb, "list_overrides", fake_list)
    u = user()
    out = run(fb.list_overrides_endpoint(u, FakeDB(), limit=7))
    assert seen == {"tenant_id": u.tenant_id, "limit": 7} and out[0].key == "k"


def test_summary_counts_each_verdict_separately_and_keeps_benign_true_positive_out_of_false_positive():
    rows = [("false_positive", 4), ("benign_true_positive", 2), ("true_positive", 3), ("benign", 1), ("escalate", 5), ("something_else", 6)]
    u, db = user(), FakeDB(summary_rows=rows)
    out = run(fb.get_override_summary(u, db))
    assert (out.false_positive_corrections, out.benign_true_positive_corrections, out.true_positive_corrections) == (4, 2, 3)
    assert (out.benign_corrections, out.escalate_corrections) == (1, 5)
    assert out.total_overrides == 21, "unrecognised dispositions still count toward the total"
    assert has(db.executed[0], u.tenant_id) and "IS NOT NULL" in sql(db.executed[0])


def test_summary_with_no_rows_is_all_zero():
    out = run(fb.get_override_summary(user(), FakeDB()))
    assert out.model_dump() == {
        "total_overrides": 0,
        "false_positive_corrections": 0,
        "true_positive_corrections": 0,
        "benign_true_positive_corrections": 0,
        "benign_corrections": 0,
        "escalate_corrections": 0,
    }


def test_summary_tolerates_null_counts():
    out = run(fb.get_override_summary(user(), FakeDB(summary_rows=[("benign", None)])))
    assert out.benign_corrections == 0 and out.total_overrides == 0
