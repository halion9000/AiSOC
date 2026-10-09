"""CROSS-TENANT READ, FIXED: GET /api/v1/graph/attack-path/{case_id}.

get_attack_path asks the (tenant-scoped) knowledge graph first and falls back to a relational reconstruction when the graph is OFFLINE *or returns no nodes*. A case id from another tenant produces exactly "no nodes" in a tenant-scoped graph query, so the fallback ran even with the graph online, and it looked the case up by id alone:
any caller with alerts:read got another tenant's case title, severity, MITRE techniques and alert ids. Shown on real Postgres by the two-tenant flows (tenant B received HTTP 200 with tenant A's case nodes); fixed by passing the caller's tenant into the fallback.
"""
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import graph as graph_mod

MINE = uuid.uuid4()


def user():
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=MINE, role="analyst", email="a@example.test")


class FakeDB:
    def __init__(self, row=None):
        self.row, self.executed = row, []
        self.execute = AsyncMock(side_effect=self._execute)

    async def _execute(self, stmt, *a, **k):
        self.executed.append((" ".join(str(stmt).split()), dict(stmt.compile().params)))
        res = MagicMock()
        res.fetchone.return_value = self.row
        return res


def case_row(**over):
    base = dict(id=uuid.uuid4(), title="the title", severity="high", mitre_techniques=["T1059", {"id": "T1566"}], alert_ids=[uuid.uuid4(), uuid.uuid4()])
    base.update(over)
    return SimpleNamespace(**base)


@pytest.mark.asyncio
class TestTheFallbackHelper:
    async def test_a_case_that_is_not_the_callers_is_none(self):
        db = FakeDB(None)
        assert await graph_mod._attack_path_from_relational(db, str(uuid.uuid4()), MINE) is None

    async def test_the_query_is_scoped_by_tenant_with_bound_parameters(self):
        db = FakeDB(None)
        cid = str(uuid.uuid4())
        await graph_mod._attack_path_from_relational(db, cid, MINE)
        sql, params = db.executed[0]
        assert "WHERE id = CAST(:cid AS UUID) AND tenant_id = :tenant_id" in sql
        assert params["tenant_id"] == MINE and params["cid"] == cid

    async def test_the_callers_own_case_is_still_reconstructed(self):
        row = case_row()
        out = await graph_mod._attack_path_from_relational(FakeDB(row), str(row.id), MINE)
        labels = [n["label"] for n in out["nodes"]]
        assert out["case_id"] == str(row.id) and labels.count("Case") == 1 and labels.count("Technique") == 2 and labels.count("Alert") == 2
        assert out["node_count"] == len(out["nodes"]) and out["edge_count"] == len(out["edges"])

    async def test_the_tenant_is_required(self):
        with pytest.raises(TypeError):
            await graph_mod._attack_path_from_relational(FakeDB(None), str(uuid.uuid4()))


@pytest.mark.asyncio
class TestTheEndpoint:
    async def call(self, monkeypatch, *, graph, db, offline=True):
        monkeypatch.setattr(graph_mod.graph_service, "get_attack_path", graph)
        monkeypatch.setattr(graph_mod, "_is_graph_unavailable", lambda exc: offline)
        return await graph_mod.get_attack_path(case_id=str(uuid.uuid4()), db=db, max_depth=6, current_user=user())

    async def test_graph_offline_and_a_foreign_case_is_a_404_not_the_cases_data(self, monkeypatch):
        db = FakeDB(None)  # the tenant-scoped relational lookup finds nothing
        with pytest.raises(HTTPException) as exc:
            await self.call(monkeypatch, graph=AsyncMock(side_effect=ConnectionError("neo4j down")), db=db)
        assert exc.value.status_code == 404
        assert db.executed[0][1]["tenant_id"] == MINE

    @pytest.mark.parametrize("empty", [{}, None, {"nodes": []}], ids=["empty-dict", "none", "no-nodes"])
    async def test_graph_ONLINE_but_returning_no_nodes_is_the_same_404(self, monkeypatch, empty):
        """The path that made this reachable with the graph up: a foreign case id has no nodes in the tenant-scoped graph, so the fallback runs."""
        db = FakeDB(None)
        with pytest.raises(HTTPException) as exc:
            await self.call(monkeypatch, graph=AsyncMock(return_value=empty), db=db, offline=False)
        assert exc.value.status_code == 404
        assert len(db.executed) == 1 and db.executed[0][1]["tenant_id"] == MINE

    async def test_the_callers_own_case_is_served_by_the_fallback(self, monkeypatch):
        row = case_row()
        out = await self.call(monkeypatch, graph=AsyncMock(side_effect=ConnectionError("down")), db=FakeDB(row))
        assert str(out.case_id) == str(row.id) and out.node_count == len(out.nodes)

    async def test_a_graph_with_nodes_never_touches_the_relational_fallback(self, monkeypatch):
        db = FakeDB(case_row())
        data = {"case_id": "c", "nodes": [{"id": "case:c", "label": "Case", "properties": {}}], "edges": [], "node_count": 1, "edge_count": 0}
        await self.call(monkeypatch, graph=AsyncMock(return_value=data), db=db, offline=False)
        assert db.executed == []

    async def test_the_graph_service_is_asked_with_the_callers_tenant(self, monkeypatch):
        g = AsyncMock(return_value={"case_id": "c", "nodes": [{"id": "x", "label": "Case", "properties": {}}], "edges": [], "node_count": 1, "edge_count": 0})
        await self.call(monkeypatch, graph=g, db=FakeDB(), offline=False)
        assert g.await_args.kwargs["tenant_id"] == str(MINE)


def test_the_endpoint_passes_the_tenant_to_the_fallback():
    import ast
    from pathlib import Path

    tree = ast.parse(Path(graph_mod.__file__).read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "get_attack_path")
    calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and ast.unparse(c.func) == "_attack_path_from_relational"]
    assert len(calls) == 1 and "current_user.tenant_id" in ast.unparse(calls[0])
