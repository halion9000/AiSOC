"""The agents service's database work runs as ONE tenant, inside a transaction, under the setting the policies actually read.

Four modules (the investigation ledger, the hunt store, the Splunk evidence loader and the LLM resolver) set `app.tenant_id`, a name the standard policies never read, with a bare `conn.execute` in autocommit mode, where a
transaction-local setting is discarded as soon as the statement ends. The context was never in effect, and since every standard policy also admits "no context", RLS silently admitted everything; only each query's own
`WHERE tenant_id = ...` protected those paths. These tests check ORDER (begin, set_config, then the queries, all in one transaction), the setting NAME, and (statically) that no future query in these modules runs unscoped.
"""
import ast
import pathlib
import uuid

import pytest

from app.core import tenant_scope as ts
from app.hunt import store as hunt_store
from app.investigator import ledger
from app.security import llm_resolver

TENANT = uuid.uuid4()
OTHER = uuid.uuid4()


class FakeConn:
    """Records every call in order. `transaction()` logs BEGIN/COMMIT (ROLLBACK if the body raised)."""

    def __init__(self, rows=None):
        self.events: list[tuple] = []
        self.rows = rows

    def transaction(self):
        conn = self

        class Tx:
            async def __aenter__(self_):
                conn.events.append(("BEGIN",))

            async def __aexit__(self_, exc_type, *a):
                conn.events.append(("ROLLBACK",) if exc_type else ("COMMIT",))
                return False

        return Tx()

    async def execute(self, sql, *args):
        self.events.append(("execute", " ".join(sql.split()), args))
        return "OK"

    async def fetchrow(self, sql, *args):
        self.events.append(("fetchrow", " ".join(sql.split()), args))
        return self.rows

    async def fetch(self, sql, *args):
        self.events.append(("fetch", " ".join(sql.split()), args))
        return []

    async def fetchval(self, sql, *args):
        self.events.append(("fetchval", " ".join(sql.split()), args))
        return None


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        conn = self.conn

        class Acq:
            async def __aenter__(self_):
                return conn

            async def __aexit__(self_, *a):
                return False

        return Acq()


def assert_scoped(events, tenant, *, expect_statements=True):
    """Every data statement ran INSIDE a transaction, AFTER set_config('app.current_tenant_id', tenant), and the transaction committed."""
    depth, scoped, data, seen_set = 0, None, 0, False
    for ev in events:
        if ev[0] == "BEGIN":
            if depth == 0:
                scoped = None  # a NESTED transaction is a savepoint inside the outer one: the tenant setting stays in force
            depth += 1
        elif ev[0] in ("COMMIT", "ROLLBACK"):
            depth -= 1
            if depth == 0:
                scoped = None
        elif ev[0] == "execute" and "set_config" in ev[1]:
            assert depth >= 1, "the tenant setting was applied OUTSIDE a transaction (autocommit): it is discarded at once"
            assert "'app.current_tenant_id'" in ev[1] and "app.tenant_id" not in ev[1].replace("app.current_tenant_id", "")
            assert ev[2] == (str(tenant),)
            scoped, seen_set = str(tenant), True
        elif "FROM tenants" in ev[1]:
            continue  # resolving a tenant reference to an id happens BEFORE there is a tenant to scope to
        else:
            data += 1
            assert depth >= 1, f"a data statement ran outside any transaction: {ev[1][:70]}"
            assert scoped == str(tenant), f"a data statement ran before/without the tenant context: {ev[1][:70]}"
    assert seen_set and depth == 0 and events[-1] == ("COMMIT",), events
    if expect_statements:
        assert data >= 1


class TestTheHelper:
    @pytest.mark.anyio
    async def test_it_opens_a_transaction_then_sets_the_setting_the_policies_read_then_runs_the_body(self):
        conn = FakeConn()
        async with ts.tenant_scope(conn, TENANT) as c:
            assert c is conn
            await conn.execute("SELECT 1")
        assert [e[0] for e in conn.events] == ["BEGIN", "execute", "execute", "COMMIT"]
        assert conn.events[1][1] == "SELECT set_config('app.current_tenant_id', $1, true)" and conn.events[1][2] == (str(TENANT),)

    @pytest.mark.anyio
    async def test_the_setting_is_transaction_local_not_session_level(self):
        """Session level (the 3rd argument false) on a POOLED connection would leave this tenant's context for the next borrower."""
        conn = FakeConn()
        async with ts.tenant_scope(conn, TENANT):
            pass
        assert ", true)" in conn.events[1][1] and ", false)" not in conn.events[1][1]

    @pytest.mark.anyio
    async def test_a_failure_rolls_back_and_propagates(self):
        conn = FakeConn()
        with pytest.raises(RuntimeError, match="boom"):
            async with ts.tenant_scope(conn, TENANT):
                raise RuntimeError("boom")
        assert conn.events[-1] == ("ROLLBACK",)

    @pytest.mark.anyio
    async def test_two_scopes_on_one_connection_each_set_their_own_tenant(self):
        conn = FakeConn()
        async with ts.tenant_scope(conn, TENANT):
            pass
        async with ts.tenant_scope(conn, OTHER):
            pass
        sets = [e[2] for e in conn.events if e[0] == "execute"]
        assert sets == [(str(TENANT),), (str(OTHER),)]

    def test_the_setting_name_is_the_one_the_standard_policies_read(self):
        sql = (pathlib.Path(__file__).resolve().parents[2] / "api" / "migrations" / "002_rls.sql").read_text(encoding="utf-8")
        assert f"current_setting('{ts.RLS_SETTING}')" in sql


@pytest.mark.anyio
class TestEveryCallSiteIsScopedInOrder:
    @pytest.fixture
    def conn(self, monkeypatch):
        c = FakeConn()
        pool = FakePool(c)

        async def get_pool():
            return pool

        monkeypatch.setattr(ledger, "get_pool", get_pool)
        monkeypatch.setattr(hunt_store, "_get_pool", get_pool)
        return c

    async def test_ledger_start_run(self, conn):
        await ledger.start_run(run_id=uuid.uuid4(), case_id="c1", tenant_ref=str(TENANT), alert_summary="s", raw_alert={})
        assert_scoped(conn.events, TENANT)

    async def test_ledger_record_event(self, conn):
        await ledger.record_event(run_id=uuid.uuid4(), tenant_id=TENANT, seq=1, kind="step", agent="a", summary="s")
        assert_scoped(conn.events, TENANT)

    async def test_ledger_record_artifact(self, conn):
        await ledger.record_artifact(run_id=uuid.uuid4(), tenant_id=TENANT, kind="report", content="x")
        assert_scoped(conn.events, TENANT)

    async def test_ledger_complete_run(self, conn):
        await ledger.complete_run(run_id=uuid.uuid4(), tenant_id=TENANT, status="completed")
        assert_scoped(conn.events, TENANT)

    async def test_ledger_persist_auto_triage(self, conn):
        await ledger.persist_auto_triage(run_id=uuid.uuid4(), alert_id="a1", tenant_ref=str(TENANT), alert_summary="s", raw_alert={}, tier="t1", verdict="benign", confidence=0.9, rationale="r")
        assert_scoped(conn.events, TENANT)

    async def test_hunt_list_recent_runs(self, conn):
        await hunt_store.list_recent_runs(tenant_ref=str(TENANT))
        assert_scoped(conn.events, TENANT)

    async def test_hunt_list_recent_findings(self, conn):
        await hunt_store.list_recent_findings(tenant_ref=str(TENANT))
        assert_scoped(conn.events, TENANT)

    async def test_the_llm_resolver_reads_the_credential_inside_the_scope(self):
        conn = FakeConn(rows={"provider": "openai", "base_url": None, "model": "m", "api_key_vault": None, "settings": {}, "enabled": True})
        out = await llm_resolver._fetch_tenant_credential(FakePool(conn), str(TENANT))
        assert out is not None and out["provider"] == "openai"
        assert_scoped(conn.events, TENANT)
        assert ("fetchrow" in [e[0] for e in conn.events]) and conn.events[-2][0] == "fetchrow"

    async def test_two_tenants_on_the_same_pooled_connection_never_share_a_context(self, conn):
        await ledger.complete_run(run_id=uuid.uuid4(), tenant_id=TENANT, status="completed")
        await ledger.complete_run(run_id=uuid.uuid4(), tenant_id=OTHER, status="completed")
        sets = [e[2] for e in conn.events if e[0] == "execute" and "set_config" in e[1]]
        assert sets == [(str(TENANT),), (str(OTHER),)]
        assert [e[0] for e in conn.events].count("BEGIN") == 2 == [e[0] for e in conn.events].count("COMMIT")


class TestNoQueryInThesModulesRunsUnscoped:
    """Static guard: a query added later without tenant_scope would silently bypass RLS again."""

    MODULES = ["app/investigator/ledger.py", "app/hunt/store.py", "app/security/llm_resolver.py", "app/investigator/splunk_evidence.py"]
    # Functions that legitimately run without a tenant to scope to, and why.
    ALLOWED = {
        "_resolve_tenant_id": "resolves a slug/name to an id: there is no tenant to scope to yet",
        "_resolve_tenant_uuid": "same, in the LLM resolver",
        "resolve_tenant": "same, public wrapper",
        "record_suppression": "writes a suppression row keyed by an explicit tenant filter (not RLS-dependent); tracked separately",
        "_insert_finding": "is only ever called with a connection that is already inside tenant_scope (checked below)",
        "sync_catalog": "see test_insert_finding_is_only_called_inside_a_scope",
    }

    def functions(self, rel):
        tree = ast.parse((pathlib.Path(__file__).resolve().parents[1] / rel).read_text(encoding="utf-8"))
        return [n for n in ast.walk(tree) if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))]

    @staticmethod
    def conn_calls(fn):
        """(call node, enclosed-in-tenant_scope?) for every conn.execute/fetch* in fn."""
        found = []

        def visit(node, scoped):
            if isinstance(node, (ast.AsyncWith, ast.With)):
                here = scoped or any(isinstance(i.context_expr, ast.Call) and getattr(i.context_expr.func, "id", "") == "tenant_scope" for i in node.items)
                for child in node.body:
                    visit(child, here)
                return
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "fetch", "fetchrow", "fetchval") and getattr(node.func.value, "id", "") == "conn":
                found.append((node, scoped))
            for child in ast.iter_child_nodes(node):
                visit(child, scoped)

        for stmt in fn.body:
            visit(stmt, False)
        return found

    @pytest.mark.parametrize("rel", MODULES)
    def test_every_conn_query_is_inside_tenant_scope_or_an_explained_exception(self, rel):
        offenders = []
        for fn in self.functions(rel):
            if fn.name in self.ALLOWED:
                continue
            offenders += [(fn.name, call.lineno) for call, scoped in self.conn_calls(fn) if not scoped]
        assert offenders == [], f"{rel}: queries outside tenant_scope: {offenders}"

    @pytest.mark.parametrize("rel", MODULES)
    def test_the_old_setting_name_and_the_old_helper_are_gone(self, rel):
        src = (pathlib.Path(__file__).resolve().parents[1] / rel).read_text(encoding="utf-8")
        assert "app.tenant_id" not in src and "_set_rls_context" not in src

    def test_insert_finding_is_only_called_inside_a_scope(self):
        """_insert_finding takes a connection and does not scope it itself, so it is only safe because record_run calls it inside tenant_scope."""
        fns = {f.name: f for f in self.functions("app/hunt/store.py")}
        calls = [n for n in ast.walk(fns["record_run"]) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_insert_finding"]
        assert calls, "record_run no longer calls _insert_finding: revisit this test"

        def inside(node, target, scoped=False):
            if node is target:
                return scoped
            if isinstance(node, (ast.AsyncWith, ast.With)):
                scoped = scoped or any(isinstance(i.context_expr, ast.Call) and getattr(i.context_expr.func, "id", "") == "tenant_scope" for i in node.items)
            for child in ast.iter_child_nodes(node):
                r = inside(child, target, scoped)
                if r is not None:
                    return r
            return None

        assert all(inside(fns["record_run"], c) is True for c in calls)
