"""A shared (tenantless) detection proposal can be READ by every tenant but not CHANGED by any of them.

_load_proposal admits `tenant_id IS NULL` rows for every caller, and the endpoints that change a proposal (comment, evaluate-rule, backtest, attach-eval, decide, promote) used the same lookup. Shown on real Postgres with a seeded tenantless proposal: tenant A commented on it (200) and tenant B rejected it (200),
and it was rejected FOR EVERYONE. Nothing creates a tenantless proposal today (no migration seeds one, every creator stamps a tenant), so this is hardening for the day one is seeded: writes to it are now a 403 "Shared proposals are read-only.", reading it still works, another tenant's proposal is still a plain 404.
The promote edit branch also refuses a shared base rule (PATCH /detection/rules edits only the caller's own rules; promotion must not be a way around that). The database cannot hold a tenantless RULE (detection_rules.tenant_id is NOT NULL), so that guard is defence in depth.
"""
import ast
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import detection_proposals as dp
from app.models.detection_proposal import DetectionRuleProposal

TID = uuid.uuid4()


def user(tenant=None):
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant or TID, role="admin", email="a@example.test")


def proposal(tenant="mine", **over):
    base = dict(id=uuid.uuid4(), tenant_id=TID if tenant == "mine" else tenant, base_rule_id=None, promoted_rule_id=None, name="p", description=None, rule_language="sigma", rule_body="title: x", category="c", severity="medium", confidence=50,
                mitre_tactics=[], mitre_techniques=[], tags=[], status="proposed", eval_result={}, review_comments=[], proposed_by_id=None, decided_by_id=None, decision_comment=None, decided_at=None, source=None, github_pr_url=None,
                created_at=datetime.now(UTC), updated_at=datetime.now(UTC))
    base.update(over)
    return DetectionRuleProposal(**base)


class FakeDB:
    """execute() answers queued results through scalar_one_or_none(); statements are recorded."""

    def __init__(self, *payloads):
        self.queue, self.statements = list(payloads), []
        self.commit, self.refresh, self.add, self.rollback = AsyncMock(), AsyncMock(), MagicMock(), AsyncMock()
        self.execute = AsyncMock(side_effect=self._execute)

    async def _execute(self, stmt, *a, **k):
        self.statements.append(stmt)
        res = MagicMock()
        payload = self.queue.pop(0) if self.queue else None
        res.scalar_one_or_none.return_value = payload
        res.scalars.return_value.all.return_value = payload if isinstance(payload, list) else []
        return res


@pytest.mark.asyncio
class TestTheLoader:
    async def test_a_shared_proposal_can_be_read(self):
        shared = proposal(tenant=None)
        assert await dp._load_proposal(FakeDB(shared), shared.id, TID) is shared
        assert await dp._load_proposal(FakeDB(shared), shared.id, TID, write=False) is shared

    async def test_a_shared_proposal_cannot_be_written(self):
        shared = proposal(tenant=None)
        with pytest.raises(HTTPException) as exc:
            await dp._load_proposal(FakeDB(shared), shared.id, TID, write=True)
        assert exc.value.status_code == 403 and exc.value.detail == "Shared proposals are read-only."

    async def test_the_callers_own_proposal_can_be_written(self):
        mine = proposal()
        assert await dp._load_proposal(FakeDB(mine), mine.id, TID, write=True) is mine

    @pytest.mark.parametrize("write", [False, True])
    async def test_a_missing_or_foreign_proposal_is_a_404_whatever_the_mode(self, write):
        """The query excludes other tenants' rows, so a foreign proposal comes back as no row at all."""
        with pytest.raises(HTTPException) as exc:
            await dp._load_proposal(FakeDB(None), uuid.uuid4(), TID, write=write)
        assert exc.value.status_code == 404 and exc.value.detail == "Proposal not found"

    async def test_the_query_still_admits_only_the_callers_tenant_or_shared_rows(self):
        db = FakeDB(proposal())
        await dp._load_proposal(db, uuid.uuid4(), TID)
        sql = " ".join(str(db.statements[0].compile()).split()).lower()
        assert "tenant_id = " in sql and "tenant_id is null" in sql and " or " in sql
        assert TID in db.statements[0].compile().params.values()

    async def test_the_default_is_read_only_semantics_so_a_forgotten_flag_cannot_widen_access(self):
        import inspect

        assert inspect.signature(dp._load_proposal).parameters["write"].default is False


@pytest.mark.asyncio
class TestEveryWriterRefusesASharedProposal:
    cases = [
        ("comment_on_proposal", lambda: dp.ReviewCommentRequest.model_construct()),
        ("evaluate_rule", lambda: dp.EvaluateRuleRequest.model_construct()),
        ("backtest_proposal", lambda: dp.BacktestProposalRequest.model_construct()),
        ("attach_eval_result", lambda: dp.EvalAttachRequest.model_construct()),
        ("decide_proposal", lambda: dp.DecisionRequest(decision="reject", comment="x")),
    ]

    @pytest.mark.parametrize("name,req", cases, ids=[c[0] for c in cases])
    async def test_it_is_a_403_and_nothing_is_changed_or_committed(self, name, req):
        shared = proposal(tenant=None)
        db = FakeDB(shared)
        with pytest.raises(HTTPException) as exc:
            await getattr(dp, name)(proposal_id=shared.id, request=req(), current_user=user(), db=db)
        assert exc.value.status_code == 403 and exc.value.detail == "Shared proposals are read-only."
        db.commit.assert_not_awaited()
        db.add.assert_not_called()
        assert shared.status == "proposed" and shared.review_comments == [] and shared.decided_by_id is None

    async def test_promote_refuses_a_shared_proposal_too(self):
        shared = proposal(tenant=None, status="approved")
        db = FakeDB(shared)
        with pytest.raises(HTTPException) as exc:
            await dp.promote_proposal(proposal_id=shared.id, current_user=user(), db=db)
        assert exc.value.status_code == 403
        db.commit.assert_not_awaited()

    async def test_reading_a_shared_proposal_still_works(self):
        shared = proposal(tenant=None)
        out = await dp.get_proposal(proposal_id=shared.id, current_user=user(), db=FakeDB(shared))
        assert out.id == shared.id and out.tenant_id is None

    async def test_the_callers_own_proposal_is_still_decided(self):
        mine = proposal()
        db = FakeDB(mine)
        out = await dp.decide_proposal(proposal_id=mine.id, request=dp.DecisionRequest(decision="reject", comment="no"), current_user=user(), db=db)
        assert out.status == "rejected" and mine.decided_by_id is not None
        db.commit.assert_awaited()


@pytest.mark.asyncio
class TestPromoteWillNotEditASharedRule:
    def rule(self, tenant):
        return SimpleNamespace(id=uuid.uuid4(), tenant_id=tenant, version=3)

    async def test_a_tenantless_base_rule_is_refused(self):
        rule = self.rule(None)
        p = proposal(status="approved", base_rule_id=rule.id)
        db = FakeDB(p, rule)
        with pytest.raises(HTTPException) as exc:
            await dp.promote_proposal(proposal_id=p.id, current_user=user(), db=db)
        assert exc.value.status_code == 403 and "Shared rules cannot be edited" in exc.value.detail
        assert len(db.statements) == 2  # the proposal and the rule lookups, and no UPDATE
        db.commit.assert_not_awaited()

    async def test_another_tenants_base_rule_is_refused_even_if_one_were_ever_returned(self):
        rule = self.rule(uuid.uuid4())
        p = proposal(status="approved", base_rule_id=rule.id)
        db = FakeDB(p, rule)
        with pytest.raises(HTTPException) as exc:
            await dp.promote_proposal(proposal_id=p.id, current_user=user(), db=db)
        assert exc.value.status_code == 403
        assert len(db.statements) == 2

    async def test_the_callers_own_base_rule_is_edited_as_before(self):
        rule = self.rule(TID)
        p = proposal(status="approved", base_rule_id=rule.id)
        db = FakeDB(p, rule)
        out = await dp.promote_proposal(proposal_id=p.id, current_user=user(), db=db)
        assert out.status == "promoted" and p.promoted_rule_id == rule.id
        assert any("UPDATE" in str(s).upper() for s in db.statements[2:])
        db.commit.assert_awaited()


class TestTheWiring:
    def calls(self):
        tree = ast.parse(Path(dp.__file__).read_text(encoding="utf-8"))
        out = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.AsyncFunctionDef):
                for c in ast.walk(n):
                    if isinstance(c, ast.Call) and ast.unparse(c.func) == "_load_proposal":
                        out[n.name] = {k.arg: ast.unparse(k.value) for k in c.keywords}
        return out

    @pytest.mark.parametrize("fn", ["comment_on_proposal", "evaluate_rule", "backtest_proposal", "attach_eval_result", "decide_proposal", "promote_proposal"])
    def test_each_writer_asks_for_write_access(self, fn):
        assert self.calls()[fn] == {"write": "True"}

    def test_the_reader_does_not(self):
        assert self.calls()["get_proposal"] == {}

    def test_there_are_exactly_these_callers(self):
        assert set(self.calls()) == {"get_proposal", "comment_on_proposal", "evaluate_rule", "backtest_proposal", "attach_eval_result", "decide_proposal", "promote_proposal"}
