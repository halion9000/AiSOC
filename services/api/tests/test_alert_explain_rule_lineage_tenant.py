"""CROSS-TENANT READ, FIXED: an alert's explanation could show ANOTHER tenant's detection rule.

The explanation looks up "the rule that produced this alert". Its first, highest-confidence branch takes an id from the alert's own raw_event or tags (a `rule:<uuid>` tag), and loaded the rule BY ID ALONE. Those fields are set by whoever submits the alert, so tenant B could name tenant A's rule id and the explanation of B's own alert returned A's rule name,
description, severity and language (shown on real Postgres through the two-tenant flows; the owner's own alert naming its own rule is the control that proves the explanation does show a matched rule). The other branches in the service were already tenant-scoped.
"""
import ast
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services import alert_explain as ae

MINE, THEIRS = uuid.uuid4(), uuid.uuid4()


class FakeDB:
    def __init__(self, *payloads):
        self.queue, self.executed = list(payloads), []
        self.execute = AsyncMock(side_effect=self._execute)

    async def _execute(self, stmt, *a, **k):
        comp = stmt.compile()
        self.executed.append((" ".join(str(comp).split()), dict(comp.params)))
        payload = self.queue.pop(0) if self.queue else None
        res = MagicMock()
        res.scalar_one_or_none.return_value = payload
        res.scalars.return_value.all.return_value = []
        return res


def alert(rid, **over):
    base = dict(raw_event={}, tags=[f"rule:{rid}"], tenant_id=MINE, mitre_techniques=[], category=None)
    base.update(over)
    return SimpleNamespace(**base)


@pytest.mark.asyncio
class TestTheExplicitRuleLookup:
    async def test_the_lookup_is_scoped_to_the_alerts_tenant_or_platform_rules(self):
        rid = uuid.uuid4()
        db = FakeDB(None)
        await ae._resolve_rule_lineage(db, alert(rid))
        sql, params = db.executed[0]
        assert "detection_rules.id = " in sql and "detection_rules.tenant_id = " in sql and "detection_rules.tenant_id IS NULL" in sql and " OR " in sql
        assert rid in params.values() and MINE in params.values()

    async def test_another_tenants_rule_is_not_returned_as_the_match(self):
        """The scoped query finds no row for a foreign rule id, so there is no explicit match (and nothing else to match on here)."""
        rule, confidence, method = await ae._resolve_rule_lineage(FakeDB(None), alert(uuid.uuid4()))
        assert (rule, confidence, method) == (None, "none", "none")

    async def test_the_callers_own_rule_is_still_the_high_confidence_match(self):
        mine = SimpleNamespace(id=uuid.uuid4(), tenant_id=MINE, name="mine")
        rule, confidence, method = await ae._resolve_rule_lineage(FakeDB(mine), alert(mine.id))
        assert rule is mine and confidence == "high" and method == "raw_event"

    async def test_the_raw_event_reference_is_scoped_the_same_way(self):
        rid = uuid.uuid4()
        db = FakeDB(None)
        await ae._resolve_rule_lineage(db, alert(rid, tags=[], raw_event={"rule_id": str(rid)}))
        sql, params = db.executed[0]
        assert "detection_rules.tenant_id = " in sql and MINE in params.values()


def test_every_detection_rule_select_in_the_service_names_the_tenant():
    src = Path(ae.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    bad = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))]:
        for stmt in [s for s in ast.walk(fn) if isinstance(s, (ast.Assign, ast.Expr, ast.Return, ast.AnnAssign))]:
            text = ast.get_source_segment(src, stmt) or ""
            if "select(DetectionRule)" in text and ".where(" in text and "tenant" not in text.lower() and "filters" not in text:
                bad.append(f"{fn.name}: {' '.join(text.split())[:90]}")
    assert bad == []
