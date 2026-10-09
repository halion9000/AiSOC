"""The Copilot's tools run as the asking user, with the permission of the matching REST endpoint; case search reads aisoc_cases; cases cannot be deleted from the Copilot.

 * execute_copilot_tool received only (name, args, tenant_id). The endpoint checks `copilot:use` and nothing else, the tool docstrings said "Requires alerts:write" / "cases:write", and nothing enforced either, so any user (or API key) holding copilot:use could have the
   model delete alerts. The loop runs whatever the model asks for, up to six tool calls per message, with no confirmation, and tool results (alert titles from monitored systems) flow back into the model's context.
 * search_cases read the old `cases` table, which nothing writes, so the Copilot always said "no cases found".
 * delete_case ran `DELETE FROM cases` on that same table and so always answered "not found". Pointing it at aisoc_cases would have switched on a destructive tool that never worked, while the cases REST API has no delete: it now refuses, truthfully.
"""
import re
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1.deps import CurrentUser
from app.core.security import has_permission
from app import copilot_tools as ct

TID = uuid.uuid4()


def user(role="admin", scopes=None, tenant=None):
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant or TID, role=role, email="a@example.test", scopes=scopes)


@pytest.fixture
def ran(monkeypatch):
    """Replace every tool with a recorder so the gate is tested without a database."""
    calls = []

    def recorder(name):
        async def tool(**kw):
            calls.append((name, kw))
            return {"ran": name}

        return tool

    monkeypatch.setattr(ct, "_COPILOT_TOOL_DISPATCH", {n: recorder(n) for n in ct._COPILOT_TOOL_DISPATCH})
    return calls


@pytest.mark.asyncio
class TestThePermissionGate:
    @pytest.mark.parametrize("role", ["viewer", "soc_analyst", "threat_hunter", "soc_lead", "tenant_admin", "api_service", "admin", "platform_admin"])
    @pytest.mark.parametrize("tool", sorted(ct.TOOL_PERMISSIONS))
    async def test_a_tool_runs_exactly_when_the_role_holds_its_permission(self, ran, role, tool):
        res = await ct.execute_copilot_tool(tool, {}, str(TID), user=user(role))
        allowed = has_permission(role, ct.TOOL_PERMISSIONS[tool])
        assert (res == {"ran": tool}) is allowed and bool(ran) is allowed
        if not allowed:
            assert res == {"error": f"permission denied: {tool} requires {ct.TOOL_PERMISSIONS[tool]}"}

    async def test_the_destructive_tools_need_the_delete_permissions_not_write(self):
        assert ct.TOOL_PERMISSIONS["delete_alert"] == "alerts:delete" and ct.TOOL_PERMISSIONS["delete_case"] == "cases:delete"

    async def test_a_read_only_role_cannot_delete_anything(self, ran):
        for tool in ("delete_alert", "delete_case"):
            assert "permission denied" in (await ct.execute_copilot_tool(tool, {"alert_id": "x", "case_id": "x"}, str(TID), user=user("viewer")))["error"]
        assert ran == []

    async def test_an_api_key_is_limited_to_its_scopes(self, ran):
        k = user("admin", scopes=["copilot:use", "alerts:read"])
        assert (await ct.execute_copilot_tool("search_alerts", {}, str(TID), user=k)) == {"ran": "search_alerts"}
        assert "permission denied" in (await ct.execute_copilot_tool("search_cases", {}, str(TID), user=k))["error"]
        assert "permission denied" in (await ct.execute_copilot_tool("delete_alert", {}, str(TID), user=k))["error"]

    async def test_a_wildcard_scope_or_a_family_scope_grants(self, ran):
        assert (await ct.execute_copilot_tool("delete_alert", {}, str(TID), user=user(scopes=["*"]))) == {"ran": "delete_alert"}
        assert (await ct.execute_copilot_tool("delete_alert", {}, str(TID), user=user(scopes=["alerts:*"]))) == {"ran": "delete_alert"}
        assert "permission denied" in (await ct.execute_copilot_tool("delete_case", {}, str(TID), user=user(scopes=["alerts:*"])))["error"]

    async def test_a_denied_call_never_reaches_the_tool_or_the_database(self, ran, monkeypatch):
        monkeypatch.setattr(ct, "_get_session", AsyncMock(side_effect=AssertionError("must not open a session")))
        await ct.execute_copilot_tool("delete_alert", {"alert_id": str(uuid.uuid4())}, str(TID), user=user("viewer"))
        assert ran == []

    async def test_the_tenant_argument_must_be_the_users_tenant(self, ran):
        res = await ct.execute_copilot_tool("search_alerts", {}, str(uuid.uuid4()), user=user("admin"))
        assert res == {"error": "tenant mismatch"} and ran == []

    async def test_the_tool_is_called_with_the_users_tenant(self, ran):
        await ct.execute_copilot_tool("search_alerts", {"query": "x", "limit": 3}, str(TID), user=user("admin"))
        assert ran == [("search_alerts", {"tenant_id": str(TID), "query": "x", "limit": 3})]

    async def test_an_unknown_tool_is_an_error(self, ran):
        assert await ct.execute_copilot_tool("drop_everything", {}, str(TID), user=user("admin")) == {"error": "unknown tool: drop_everything"}

    async def test_a_tool_with_no_declared_permission_is_not_run(self, ran, monkeypatch):
        async def sneaky(**kw):
            ran.append("sneaky")

        monkeypatch.setitem(ct._COPILOT_TOOL_DISPATCH, "sneaky", sneaky)
        res = await ct.execute_copilot_tool("sneaky", {}, str(TID), user=user("platform_admin"))
        assert "no declared permission" in res["error"] and "sneaky" not in ran

    async def test_omitting_the_user_fails_closed(self, ran):
        with pytest.raises(TypeError):
            await ct.execute_copilot_tool("search_alerts", {}, str(TID))

    async def test_a_model_supplied_tenant_id_cannot_override_the_users(self):
        """args are splatted after tenant_id=...: a duplicate raises instead of overriding, and that is reported, not run."""
        res = await ct.execute_copilot_tool("search_alerts", {"tenant_id": str(uuid.uuid4())}, str(TID), user=user("admin"))
        assert "TypeError" in res["error"]

    async def test_a_tool_that_raises_is_reported_not_propagated(self, monkeypatch):
        async def boom(**kw):
            raise RuntimeError("db down")

        monkeypatch.setitem(ct._COPILOT_TOOL_DISPATCH, "search_alerts", boom)
        assert await ct.execute_copilot_tool("search_alerts", {}, str(TID), user=user("admin")) == {"error": "RuntimeError: db down"}


class TestTheRegistryIsConsistent:
    def test_every_dispatched_tool_declares_a_permission_and_nothing_else_does(self):
        assert set(ct._COPILOT_TOOL_DISPATCH) == set(ct.TOOL_PERMISSIONS)

    def test_every_schema_the_model_is_offered_is_dispatched_and_permissioned(self):
        offered = {s["function"]["name"] for s in ct.COPILOT_TOOL_SCHEMAS}
        assert offered <= set(ct._COPILOT_TOOL_DISPATCH) and offered <= set(ct.TOOL_PERMISSIONS)

    def test_every_declared_permission_is_one_some_role_actually_holds(self):
        from app.core.security import ROLE_PERMISSIONS

        assert all(any(has_permission(r, p) for r in ROLE_PERMISSIONS) for p in ct.TOOL_PERMISSIONS.values())

    def test_the_delete_permissions_are_held_by_fewer_roles_than_the_read_ones(self):
        from app.core.security import ROLE_PERMISSIONS

        holders = lambda p: {r for r in ROLE_PERMISSIONS if has_permission(r, p)}  # noqa: E731
        assert holders("alerts:delete") < holders("alerts:read") and holders("cases:delete") < holders("cases:read")


class FakeSession:
    """Stands in for the tenant-scoped session: records what was executed."""

    def __init__(self, rows=()):
        self.executed, self.rows = [], list(rows)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def execute(self, stmt, *a, **k):
        self.executed.append(stmt)
        res = MagicMock()
        res.fetchall.return_value = self.rows
        res.scalars.return_value.all.return_value = []
        return res


@pytest.fixture
def session(monkeypatch):
    s = FakeSession()

    async def get_session(tid):
        s.tenant = tid
        return s

    monkeypatch.setattr(ct, "_get_session", get_session)
    return s


@pytest.mark.asyncio
class TestSearchCases:
    async def test_it_reads_aisoc_cases_for_the_tenant_not_the_legacy_table(self, session):
        await ct.search_cases(tenant_id=str(TID), query="phish")
        sql = " ".join(str(session.executed[0]).split())
        assert "FROM aisoc_cases" in sql and not re.search(r"FROM cases\b", sql) and "tenant_id = :tenant_id" in sql
        assert session.executed[0].compile().params["tenant_id"] == str(TID) and session.tenant == TID

    async def test_it_selects_columns_aisoc_cases_has(self, session):
        await ct.search_cases(tenant_id=str(TID))
        assert re.search(r"SELECT id, case_number, title, status, severity, created_at FROM aisoc_cases", " ".join(str(session.executed[0]).split()))

    async def test_the_pattern_is_escaped_and_bound(self, session):
        await ct.search_cases(tenant_id=str(TID), query="50%_off")
        stmt = session.executed[0]
        assert "ESCAPE" in str(stmt) and stmt.compile().params["pattern"] == "%50\\%\\_off%"

    async def test_the_limit_is_clamped(self, session):
        for asked, expected in ((10, 10), (999, 50), (0, 1), (-4, 1)):
            session.executed.clear()
            await ct.search_cases(tenant_id=str(TID), limit=asked)
            assert session.executed[0].compile().params["limit"] == expected

    async def test_rows_are_returned_in_the_documented_shape(self, session):
        from datetime import UTC, datetime
        from types import SimpleNamespace

        rid, ts = uuid.uuid4(), datetime(2026, 1, 2, tzinfo=UTC)
        session.rows = [SimpleNamespace(id=rid, case_number=None, title="t", status="new", severity="high", created_at=ts)]
        assert await ct.search_cases(tenant_id=str(TID)) == {"count": 1, "cases": [{"id": str(rid), "case_number": None, "title": "t", "status": "new", "severity": "high", "created_at": ts.isoformat()}]}

    async def test_a_bad_tenant_id_is_an_error_and_nothing_runs(self, session):
        assert await ct.search_cases(tenant_id="nope") == {"error": "invalid tenant_id"} and session.executed == []


@pytest.mark.asyncio
class TestSearchAlertsEscaping:
    async def test_the_pattern_is_escaped_for_both_columns(self, session):
        await ct.search_alerts(tenant_id=str(TID), query="100%")
        params = session.executed[0].compile().params
        assert [v for k, v in params.items() if k.startswith("title") or k.startswith("description")] == ["%100\\%%", "%100\\%%"] and "ESCAPE" in str(session.executed[0])


@pytest.mark.asyncio
class TestDeleteCaseIsRefused:
    async def test_it_refuses_truthfully_and_never_touches_the_database(self, monkeypatch):
        monkeypatch.setattr(ct, "_get_session", AsyncMock(side_effect=AssertionError("must not open a session")))
        res = await ct.delete_case(tenant_id=str(TID), case_id=str(uuid.uuid4()))
        assert set(res) == {"error"} and "not supported" in res["error"] and "close or resolve" in res["error"]

    async def test_even_an_admin_through_the_dispatcher_cannot_delete_a_case(self, monkeypatch):
        monkeypatch.setattr(ct, "_get_session", AsyncMock(side_effect=AssertionError("must not open a session")))
        res = await ct.execute_copilot_tool("delete_case", {"case_id": str(uuid.uuid4())}, str(TID), user=user("platform_admin"))
        assert "not supported" in res["error"]

    def test_the_model_is_told_the_tool_is_unsupported_not_that_it_deletes(self):
        desc = next(s["function"]["description"] for s in ct.COPILOT_TOOL_SCHEMAS if s["function"]["name"] == "delete_case")
        assert "Not supported" in desc and "Permanently delete" not in desc

    def test_no_executable_sql_in_the_module_touches_the_legacy_cases_table(self):
        """Judged on the module's real string literals (docstrings, which explain the old behaviour, are excluded)."""
        import ast
        from pathlib import Path

        tree = ast.parse(Path(ct.__file__).read_text(encoding="utf-8"))
        docstrings = {id(n.body[0].value) for n in ast.walk(tree) if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant)}
        literals = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]
        assert any("aisoc_cases" in s for s in literals), "the case search must name its table"
        assert not [s for s in literals if re.search(r"(FROM|JOIN|INTO|UPDATE)\s+cases\b", s)]
        assert "app.models.case" not in Path(ct.__file__).read_text(encoding="utf-8")
