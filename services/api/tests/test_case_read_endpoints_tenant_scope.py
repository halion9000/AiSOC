"""CROSS-TENANT DATA LEAK, FIXED: GET /cases/{id}/summary, /postmortem, /investigations and /investigations/{run}/report.pdf.

Found by the two-tenant flows (a new batch covering a case's child endpoints) and confirmed on real Postgres: tenant B, holding only its own login, received tenant A's case title, description, task titles, notes and severity from /summary (JSON and the HTML report), and the title, tasks and severity from /postmortem.
ROOT CAUSE: _resolve_case_id returns a UUID WITHOUT touching the database, on the written premise that "callers must still apply WHERE tenant_id... which they all do". They did not all do it: case_summary.py (which the post-mortem reuses) had no tenant_id anywhere and loaded the case by id alone;
the investigations list forwarded only the id to the agents service; and the PDF endpoint proxied the report with the internal token and no tenant check, although the sibling JSON endpoint had one. The agents service does not scope an internal-token call, so those two depended entirely on the API.
"""
import ast
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import cases as cases_mod
from app.services import case_postmortem, case_summary

APP = Path(__file__).resolve().parent.parent / "app"
MINE, THEIRS = uuid.uuid4(), uuid.uuid4()


def user():
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=MINE, role="analyst", email="a@example.test")


def norm(stmt) -> str:
    return " ".join(str(stmt).split())


class FakeDB:
    """Records (sql, params); fetchone/fetchall answer from queued payloads (a list is fetchall rows)."""

    def __init__(self, *payloads):
        self.queue, self.executed = list(payloads), []
        self.execute = AsyncMock(side_effect=self._execute)

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
        return res


@pytest.mark.asyncio
class TestTheBuildersScopeEveryQueryByTenant:
    @pytest.mark.parametrize("builder", [case_summary.build_case_summary, case_postmortem.build_case_postmortem], ids=["summary", "postmortem"])
    async def test_a_case_that_is_not_the_callers_is_none_and_nothing_else_is_read(self, builder):
        cid = uuid.uuid4()
        db = FakeDB(None)
        assert await builder(db, cid, tenant_id=MINE) is None
        assert len(db.executed) == 1, "once the case is not the caller's, its comments and tasks must not even be queried"
        sql, params = db.executed[0]
        assert "FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id" in sql and params["tenant_id"] == MINE and params["id"] == cid

    @pytest.mark.parametrize("fetch", ["_fetch_comments", "_fetch_tasks"])
    async def test_the_children_are_scoped_by_tenant_too(self, fetch):
        db = FakeDB([])
        await getattr(case_summary, fetch)(db, uuid.uuid4(), MINE)
        sql, params = db.executed[0]
        assert "tenant_id = :tenant_id" in sql and params["tenant_id"] == MINE

    @pytest.mark.parametrize("builder", [case_summary.build_case_summary, case_postmortem.build_case_postmortem], ids=["summary", "postmortem"])
    async def test_the_tenant_is_required_so_a_future_caller_cannot_forget_it(self, builder):
        with pytest.raises(TypeError):
            await builder(FakeDB(None), uuid.uuid4())

    def test_every_sql_literal_in_the_summary_module_names_the_tenant(self):
        src = (APP / "services" / "case_summary.py").read_text(encoding="utf-8")
        sqls = [n.value for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Constant) and isinstance(n.value, str) and " FROM aisoc_" in n.value.upper().replace("\n", " ") + " "]
        sqls += [n.value for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Constant) and isinstance(n.value, str) and "aisoc_case_tasks" in n.value and "FROM" in n.value and n.value not in sqls]
        assert sqls, "found no SQL: the guard has gone blind"
        assert [s for s in sqls if "tenant_id" not in s] == []


@pytest.mark.asyncio
class TestTheSummaryAndPostmortemEndpoints:
    @pytest.mark.parametrize("name,builder", [("case_auto_summary", "build_case_summary"), ("case_auto_postmortem", "build_case_postmortem")])
    async def test_they_pass_the_callers_tenant_to_the_builder(self, monkeypatch, name, builder):
        seen = {}

        async def fake(db, cid, **kw):
            seen.update(kw)
            return None

        monkeypatch.setattr(cases_mod, builder, fake)
        u = user()
        with pytest.raises(HTTPException) as exc:
            await getattr(cases_mod, name)(case_id=str(uuid.uuid4()), db=FakeDB(), user=u, format="json")
        assert exc.value.status_code == 404 and seen == {"tenant_id": u.tenant_id}

    @pytest.mark.parametrize("fmt", ["json", "html"])
    @pytest.mark.parametrize("name", ["case_auto_summary", "case_auto_postmortem"])
    async def test_another_tenants_case_is_a_404_in_every_format(self, name, fmt):
        db = FakeDB(None)  # the tenant-scoped case lookup finds nothing
        with pytest.raises(HTTPException) as exc:
            await getattr(cases_mod, name)(case_id=str(uuid.uuid4()), db=db, user=user(), format=fmt)
        assert exc.value.status_code == 404


def resp(status=200, body=None, content=b"", headers=None):
    return SimpleNamespace(status_code=status, json=lambda: body, text=str(body), content=content, headers=headers or {})


@pytest.mark.asyncio
class TestTheInvestigationsList:
    async def run(self, monkeypatch, db, proxy):
        monkeypatch.setattr(cases_mod, "_agents_proxy", proxy)
        return await cases_mod.list_case_investigations(case_id=str(uuid.uuid4()), db=db, user=user())

    async def test_a_case_that_is_not_the_callers_is_a_404_and_the_agents_service_is_never_asked(self, monkeypatch):
        proxy = AsyncMock()
        with pytest.raises(HTTPException) as exc:
            await self.run(monkeypatch, FakeDB(None), proxy)
        assert exc.value.status_code == 404
        proxy.assert_not_awaited()

    async def test_the_ownership_query_is_tenant_scoped(self, monkeypatch):
        db = FakeDB(SimpleNamespace())
        await self.run(monkeypatch, db, AsyncMock(return_value=resp(200, {"runs": []})))
        sql, params = db.executed[0]
        assert "FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id" in sql and params["tenant_id"] == MINE

    async def test_only_runs_recording_the_callers_tenant_are_returned(self, monkeypatch):
        runs = [{"id": "1", "tenant_id": str(MINE)}, {"id": "2", "tenant_id": str(THEIRS)}, {"id": "3"}]
        out = await self.run(monkeypatch, FakeDB(SimpleNamespace()), AsyncMock(return_value=resp(200, {"runs": runs})))
        assert [r["id"] for r in out["runs"]] == ["1"]

    async def test_an_unreachable_agents_service_is_an_empty_list_not_an_error(self, monkeypatch):
        async def down(*a, **k):
            raise HTTPException(status_code=503, detail="unavailable")

        assert await self.run(monkeypatch, FakeDB(SimpleNamespace()), down) == {"runs": []}

    @pytest.mark.parametrize("status", [404, 500])
    async def test_an_agents_error_status_is_an_empty_list(self, monkeypatch, status):
        assert await self.run(monkeypatch, FakeDB(SimpleNamespace()), AsyncMock(return_value=resp(status, {}))) == {"runs": []}


@pytest.mark.asyncio
class TestRunOwnership:
    async def test_the_helper_returns_the_callers_run(self, monkeypatch):
        run = {"id": "r", "tenant_id": str(MINE)}
        monkeypatch.setattr(cases_mod, "_agents_proxy", AsyncMock(return_value=resp(200, run)))
        assert await cases_mod._require_own_run("r", user()) == run

    @pytest.mark.parametrize("body", [{"id": "r", "tenant_id": str(THEIRS)}, {"id": "r"}, {"id": "r", "tenant_id": None}, ["not", "a", "dict"], "text"])
    async def test_anything_that_is_not_provably_the_callers_is_the_same_404(self, monkeypatch, body):
        monkeypatch.setattr(cases_mod, "_agents_proxy", AsyncMock(return_value=resp(200, body)))
        with pytest.raises(HTTPException) as exc:
            await cases_mod._require_own_run("r", user())
        assert exc.value.status_code == 404 and exc.value.detail == '{"detail":"Investigation run not found"}'

    async def test_an_agents_error_status_is_passed_through(self, monkeypatch):
        monkeypatch.setattr(cases_mod, "_agents_proxy", AsyncMock(return_value=resp(404, "gone")))
        with pytest.raises(HTTPException) as exc:
            await cases_mod._require_own_run("r", user())
        assert exc.value.status_code == 404

    async def test_the_run_id_is_url_encoded_before_it_reaches_the_proxied_path(self, monkeypatch):
        proxy = AsyncMock(return_value=resp(200, {"tenant_id": str(MINE)}))
        monkeypatch.setattr(cases_mod, "_agents_proxy", proxy)
        await cases_mod._require_own_run("a/b?c#d", user())
        assert proxy.await_args.args[1] == "/api/v1/investigations/a%2Fb%3Fc%23d"

    async def test_the_json_run_endpoint_uses_it(self, monkeypatch):
        run = {"id": "r", "tenant_id": str(MINE), "steps": []}
        monkeypatch.setattr(cases_mod, "_agents_proxy", AsyncMock(return_value=resp(200, run)))
        assert await cases_mod.case_investigation_run(case_id="c", run_id="r", user=user()) == run


@pytest.mark.asyncio
class TestTheReportPdf:
    async def test_another_tenants_run_is_a_404_and_the_pdf_is_never_fetched(self, monkeypatch):
        proxy = AsyncMock(return_value=resp(200, {"id": "r", "tenant_id": str(THEIRS)}, content=b"%PDF-SECRET"))
        monkeypatch.setattr(cases_mod, "_agents_proxy", proxy)
        with pytest.raises(HTTPException) as exc:
            await cases_mod.case_investigation_pdf(case_id="c", run_id="r", user=user())
        assert exc.value.status_code == 404
        assert proxy.await_count == 1 and "report.pdf" not in proxy.await_args.args[1], "only the ownership lookup may be made: the PDF itself must not be requested"

    async def test_the_callers_own_run_returns_its_pdf(self, monkeypatch):
        calls = []

        async def proxy(method, path, **kw):
            calls.append(path)
            return resp(200, {"id": "r", "tenant_id": str(MINE)}) if not path.endswith("report.pdf") else resp(200, None, content=b"%PDF-1.7 mine", headers={"content-type": "application/pdf"})

        monkeypatch.setattr(cases_mod, "_agents_proxy", proxy)
        out = await cases_mod.case_investigation_pdf(case_id="c", run_id="r", user=user())
        assert out.body == b"%PDF-1.7 mine" and calls == ["/api/v1/investigations/r", "/api/v1/investigations/r/report.pdf"]

    async def test_a_run_that_records_no_owner_is_refused(self, monkeypatch):
        monkeypatch.setattr(cases_mod, "_agents_proxy", AsyncMock(return_value=resp(200, {"id": "r"}, content=b"%PDF")))
        with pytest.raises(HTTPException) as exc:
            await cases_mod.case_investigation_pdf(case_id="c", run_id="r", user=user())
        assert exc.value.status_code == 404


class TestNoEndpointRelyingOnResolveAloneForAuthorizationRemains:
    """_resolve_case_id does not check ownership of a UUID. Every endpoint that uses it must either run its own tenant-scoped statement on aisoc_cases / its child tables, hand the tenant to a service that does, or call another helper that checks."""

    def test_the_summary_and_postmortem_and_list_do_not_pass_the_bare_id_to_anything_unscoped(self):
        tree = ast.parse((APP / "api" / "v1" / "endpoints" / "cases.py").read_text(encoding="utf-8"))
        fns = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)}
        for name, builder in (("case_auto_summary", "build_case_summary"), ("case_auto_postmortem", "build_case_postmortem")):
            calls = [c for c in ast.walk(fns[name]) if isinstance(c, ast.Call) and ast.unparse(c.func) == builder]
            assert calls and all("tenant_id" in {k.arg for k in c.keywords} for c in calls)
        assert "_require_own_run" in {ast.unparse(c.func) for c in ast.walk(fns["case_investigation_pdf"]) if isinstance(c, ast.Call)}
        assert "_require_own_run" in {ast.unparse(c.func) for c in ast.walk(fns["case_investigation_run"]) if isinstance(c, ast.Call)}
        list_src = ast.unparse(fns["list_case_investigations"])
        assert "tenant_id = :tenant_id" in list_src
