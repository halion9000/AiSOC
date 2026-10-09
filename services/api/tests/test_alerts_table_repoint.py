"""Queries that targeted the never-created `aisoc_alerts` / `aisoc_detection_rules` tables now read `alerts` / `detection_rules`, scoped to the caller's tenant.

No migration creates aisoc_alerts, so these failed (or were silently swallowed): the case timeline never showed a linked alert, /detection-loop/suggest crashed (ProgrammingError, caught only once reached), the identity timeline returned nothing, and the rule preview always fell back to the UI's built-in samples.
Two of the old queries had NO tenant filter (the case timeline's alert lookup and the whole identity timeline); they were inert only because the table was missing. Checked on real Postgres with two tenants: each sees only its own alerts (a case referencing the other tenant's alert shows no linked alert), a literal `%`
matches nothing, the suggestion endpoint creates its proposal, and the preview samples each tenant's own alerts.
It also guards the mistake that broke the identity timeline route while this was being written: a helper function inserted between a route decorator and its handler silently binds the route to the helper.
"""
import ast
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1.deps import CurrentUser

APP = Path(__file__).resolve().parent.parent / "app"
EP = APP / "api" / "v1" / "endpoints"
TID = uuid.uuid4()


def user():
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TID, role="admin", email="a@example.test")


def norm(stmt) -> str:
    return " ".join(str(stmt).split())


class FakeDB:
    """Records (sql, bound params) for each execute(); answers fetchone/fetchall/mappings from queued payloads (a list payload = fetchall rows, otherwise fetchone)."""

    def __init__(self, *payloads):
        self.queue, self.executed = list(payloads), []
        self.added = []
        self.add, self.commit = MagicMock(side_effect=self.added.append), AsyncMock()
        self.execute = AsyncMock(side_effect=self._execute)

        class SP:
            async def __aenter__(s):
                return s

            async def __aexit__(s, *a):
                return False

        self.begin_nested = MagicMock(side_effect=lambda: SP())

    async def _execute(self, stmt, params=None, *a, **k):
        try:
            bound = dict(stmt.compile().params)
        except Exception:  # noqa: BLE001
            bound = {}
        self.executed.append((norm(stmt), {**bound, **(params or {})}))
        payload = self.queue.pop(0) if self.queue else None
        res = MagicMock()
        res.fetchone.return_value = payload if not isinstance(payload, list) else None
        res.fetchall.return_value = payload if isinstance(payload, list) else []
        res.mappings.return_value.all.return_value = payload if isinstance(payload, list) else []
        return res


def literals(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docs = {id(n.body[0].value) for n in ast.walk(tree) if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant)}
    return [norm(n.value) for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]


class TestNoRouteIsBoundToAHelper:
    """The identity timeline route answered `422: missing query parameter "techniques"` because a helper was inserted between @router.post(...) and `async def build_timeline`."""

    def test_no_operation_in_the_whole_app_is_bound_to_a_private_function(self):
        from app.main import app

        ops = [(p, m, op.get("operationId", "")) for p, item in app.openapi()["paths"].items() for m, op in item.items() if m in ("get", "post", "put", "patch", "delete")]
        assert len(ops) > 300
        assert [o for o in ops if o[2].startswith("_")] == []

    def test_the_identity_timeline_build_route_is_the_build_function(self):
        from app.main import app

        op = app.openapi()["paths"]["/api/v1/identity-timeline/build"]["post"]
        assert op["operationId"].startswith("build_timeline_")
        assert "techniques" not in [p["name"] for p in op.get("parameters", [])]

    def test_the_helper_is_not_directly_below_a_decorator_in_any_endpoint_module(self):
        """Static form of the same guard: a decorated function must be the next statement after its decorators, by construction; and no `_private` def may carry a router decorator."""
        offenders = []
        for p in sorted(EP.glob("*.py")):
            for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("_") and any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and ast.unparse(d.func.value).endswith("router") for d in n.decorator_list):
                    offenders.append(f"{p.name}:{n.name}")
        assert offenders == []


@pytest.mark.asyncio
class TestDetectionLoopSuggest:
    @pytest.fixture
    def llm(self, monkeypatch):
        from app.api.v1.endpoints import detection_loop as dl

        seen = {}

        async def draft(*, current_sigma, alert_fields, analyst_note):
            seen.update(current_sigma=current_sigma, alert_fields=alert_fields)
            return {"rule_name": "n", "sigma_yaml": "y", "rationale": "r"}

        monkeypatch.setattr(dl, "_llm_draft_sigma", draft)
        return seen

    def alert(self, **over):
        base = dict(rule_id=None, tenant_id=TID, title="Odd PowerShell", severity="high", mitre_techniques=["T1059.001"], raw_event={"proc": "powershell.exe"}, entities={}, iocs=[])
        base.update(over)
        return SimpleNamespace(**base)

    async def run(self, db):
        from app.api.v1.endpoints import detection_loop as dl

        return await dl.suggest_fp_fix(body=dl.SuggestRequest(alert_id=uuid.uuid4(), analyst_note="n"), db=db, user=user())

    async def test_the_alert_comes_from_alerts_scoped_to_the_tenant(self, llm):
        db = FakeDB(self.alert(), None)
        await self.run(db)
        sql, params = db.executed[0]
        assert "FROM alerts WHERE id = :aid AND tenant_id = :tenant_id" in sql and params["tenant_id"] == TID and "aisoc_alerts" not in sql
        assert "SELECT rule_id, tenant_id, title, severity, mitre_techniques, raw_event, entities, iocs FROM alerts" in sql

    async def test_the_evidence_is_composed_from_the_alerts_own_fields(self, llm):
        await self.run(FakeDB(self.alert(), None))
        assert llm["alert_fields"] == {"title": "Odd PowerShell", "severity": "high", "mitre_techniques": ["T1059.001"], "raw_event": {"proc": "powershell.exe"}}

    async def test_empty_fields_are_left_out_of_the_evidence(self, llm):
        await self.run(FakeDB(self.alert(mitre_techniques=[], raw_event={}, entities=None, iocs=[], title=""), None))
        assert llm["alert_fields"] == {"severity": "high"}

    @pytest.mark.parametrize("rule_id", ["sigma-powershell-001", "not a uuid", "det-1", "12345"])
    async def test_a_rule_id_that_is_not_a_uuid_skips_the_rule_lookup(self, llm, rule_id):
        db = FakeDB(self.alert(rule_id=rule_id), None)
        await self.run(db)
        assert not any("FROM detection_rules" in sql for sql, _ in db.executed)
        assert llm["current_sigma"] == "# Rule body not found\n"

    @pytest.mark.parametrize("rule_id", [None, ""])
    async def test_no_rule_id_means_no_rule_lookup(self, llm, rule_id):
        db = FakeDB(self.alert(rule_id=rule_id), None)
        await self.run(db)
        assert not any("detection_rules" in sql for sql, _ in db.executed)

    async def test_a_uuid_rule_id_is_looked_up_in_detection_rules_by_uuid_and_tenant(self, llm):
        rid = uuid.uuid4()
        db = FakeDB(self.alert(rule_id=str(rid)), SimpleNamespace(rule_body="title: Real\n"), None)
        await self.run(db)
        sql, params = db.executed[1]
        assert "FROM detection_rules WHERE id = :rid AND tenant_id = :tenant_id" in sql and "aisoc_detection_rules" not in sql
        assert params["rid"] == rid and isinstance(params["rid"], uuid.UUID) and params["tenant_id"] == TID
        assert llm["current_sigma"] == "title: Real\n"

    async def test_a_non_uuid_rule_id_is_recorded_as_no_base_rule_everywhere_not_a_500(self, llm):
        """base_rule_id is a UUID on the response, the proposal INSERT and the stored suggestion; raw free text there was a validation error (found by this test, missed by the real-database probe whose alerts had no rule id)."""
        db = FakeDB(self.alert(rule_id="sigma-powershell-001"), None)
        out = await self.run(db)
        assert out.base_rule_id is None
        insert = next(p for sql, p in db.executed if "INSERT INTO detection_rule_proposals" in sql)
        assert insert["rid"] is None
        (stored,) = db.added
        assert stored.base_rule_id is None

    async def test_a_uuid_rule_id_is_used_as_a_uuid_everywhere(self, llm):
        rid = uuid.uuid4()
        db = FakeDB(self.alert(rule_id=str(rid)), SimpleNamespace(rule_body="b"), None)
        out = await self.run(db)
        insert = next(p for sql, p in db.executed if "INSERT INTO detection_rule_proposals" in sql)
        (stored,) = db.added
        assert out.base_rule_id == rid and insert["rid"] == rid and isinstance(insert["rid"], uuid.UUID) and stored.base_rule_id == rid

    async def test_a_missing_alert_is_a_404_and_nothing_else_is_queried(self, llm):
        from fastapi import HTTPException

        db = FakeDB(None)
        with pytest.raises(HTTPException) as exc:
            await self.run(db)
        assert exc.value.status_code == 404 and len(db.executed) == 1


@pytest.mark.asyncio
class TestIdentityTimeline:
    def row(self, **over):
        base = dict(id=uuid.uuid4(), created_at=datetime(2026, 10, 9, tzinfo=UTC), severity="high", title="alice logged in oddly", evidence={"k": "v"}, mitre_techniques=["T1078"])
        base.update(over)
        return SimpleNamespace(**base)

    async def build(self, db, value="alice"):
        from app.api.v1.endpoints import identity_timeline as it

        return await it.build_timeline(body=it.BuildTimelineRequest(identity_kind="user", identity_value=value), db=db, user=user())

    async def test_the_alert_query_reads_alerts_scoped_to_the_tenant(self):
        db = FakeDB([self.row()], [])
        await self.build(db)
        sql, params = db.executed[0]
        assert "FROM alerts WHERE tenant_id = :tenant_id AND created_at BETWEEN" in sql and params["tenant_id"] == TID and "aisoc_alerts" not in sql
        assert "raw_event AS evidence" in sql and "mitre_techniques" in sql

    async def test_the_search_text_is_escaped_so_percent_and_underscore_are_literal(self):
        db = FakeDB([], [])
        await self.build(db, value="50%_off\\x")
        sql, params = db.executed[0]
        assert params["pat"] == "%50\\%\\_off\\\\x%" and sql.count("ESCAPE") == 2

    async def test_an_alert_becomes_an_event_with_the_first_technique(self):
        r = self.row(mitre_techniques=[{"id": "T1021"}, "T1078"])
        out = await self.build(FakeDB([r], []))
        e = out.events[0]
        assert (e.event_type, e.source, e.description, e.severity, e.mitre_technique, e.raw) == ("alert", "alerts", "alice logged in oddly", "high", "T1021", {"k": "v"})

    async def test_with_no_technique_it_falls_back_to_the_raw_event(self):
        out = await self.build(FakeDB([self.row(mitre_techniques=[], evidence={"mitre_attack_id": "T1110"})], []))
        assert out.events[0].mitre_technique == "T1110"

    @pytest.mark.parametrize("techniques,expected", [(["T1"], "T1"), ([{"id": "T2"}], "T2"), ([None, "", {"x": 1}, "T3"], "T3"), ([], None), (None, None)])
    def test_first_technique(self, techniques, expected):
        from app.api.v1.endpoints.identity_timeline import _first_technique

        assert _first_technique(techniques) == expected


@pytest.mark.asyncio
class TestBusinessContextPreview:
    async def test_it_samples_the_tenants_own_alerts_from_alerts_with_the_columns_mapped(self):
        from app.api.v1.endpoints import business_context as bc

        db = FakeDB([])
        await bc._fetch_sample_alerts(db, TID, limit=7)
        sql, params = db.executed[0]
        assert "FROM alerts WHERE tenant_id = :tenant_id" in sql and "aisoc_alerts" not in sql and params["tenant_id"] == str(TID) and params["limit"] == 7
        for mapping in ("connector_type AS source", "affected_ips ->> 0 AS src_ip", "affected_hosts ->> 0 AS hostname", "affected_users ->> 0 AS username", "enrichment_data AS metadata"):
            assert mapping in sql
        assert "ORDER BY created_at DESC" in sql

    async def test_rows_are_shaped_for_the_rule_grammar(self):
        from app.api.v1.endpoints import business_context as bc

        row = {"id": uuid.uuid4(), "severity": "high", "title": "t", "source": "okta", "src_ip": "10.0.0.1", "hostname": "h1", "username": "alice", "tags": ["a", "b"], "metadata": {"target": {"tag": "prod"}}}
        out = await bc._fetch_sample_alerts(FakeDB([row]), TID)
        assert out[0]["src_ip"] == "10.0.0.1" and out[0]["hostname"] == "h1" and out[0]["tags"] == ["a", "b"] and out[0]["alert"]["target"] == {"tag": "prod"} and out[0]["source"] == "okta"

    async def test_a_database_failure_is_an_empty_sample_not_an_error(self):
        from app.api.v1.endpoints import business_context as bc

        db = FakeDB()
        db.execute = AsyncMock(side_effect=RuntimeError("down"))
        assert await bc._fetch_sample_alerts(db, TID) == []


@pytest.mark.parametrize("module", ["cases.py", "detection_loop.py", "identity_timeline.py", "business_context.py"])
def test_no_query_reads_the_tables_that_were_never_created(module):
    lits = literals(EP / module)
    assert not [s for s in lits if re.search(r"\b(?:FROM|JOIN|INTO|UPDATE)\s+aisoc_(?:alerts|detection_rules)\b", s)]


def test_the_case_timeline_reads_linked_alerts_from_alerts_scoped_to_the_tenant():
    lits = [s for s in literals(EP / "cases.py") if "SELECT id, title, severity, created_at FROM" in s]
    assert lits == ["SELECT id, title, severity, created_at FROM alerts WHERE id = :id AND tenant_id = :tenant_id"]
