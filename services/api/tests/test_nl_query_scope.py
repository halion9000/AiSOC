"""What /nl-query may read.

The caller's index_pattern was spliced verbatim into the generated `FROM ...` line of an ES|QL query that /execute runs with the SERVER's Elasticsearch credentials, and the vendored grammar check accepts every hostile variant (verified by running it): `FROM *`, `FROM .security-*,.kibana*`, and injected pipeline commands whose `//` also comments out the
translator's own LIMIT. A single Elasticsearch shared by tenants made that a cross-tenant read. When an LLM key is configured the LLM writes the query (steered by the question), so the request field alone is not enough: the FINAL query's source clause is checked too, and an opt-in tenant predicate (NL_QUERY_TENANT_FIELD) can be added for shared deployments.
"""
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import nl_query as nq

TENANT = uuid.uuid4()
GOOD_TAIL = '\n| WHERE @timestamp > NOW() - 24h\n| STATS n = COUNT(*) BY user.name\n| LIMIT 500'


def user():
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="admin", email="a@example.test")


class TestIndexPattern:
    @pytest.mark.parametrize("ok", ["logs-*", "logs-*,aisoc-events-*", "aisoc-events-2026.10.*", "logs-prod", "winlogbeat-8.12-*", "a1b-*", ",".join(f"idx-{i}-*" for i in range(10))])
    def test_names_of_indices_are_accepted(self, ok):
        assert nq.validate_index_pattern(ok) == ok

    @pytest.mark.parametrize(
        "bad",
        ["*", "**", ".security-*", ".kibana*", "_all", "-logs-*", "+logs", "lo*", "a*", "logs-* | EVAL x = 1", "logs-*\n| KEEP user.password", "logs-* ", " logs-*", "logs-*\t", "logs-*;DROP", 'logs-"x"', "logs-`x`", "logs-*//", "logs-*,", ",logs-*", "", "LOGS-*", "logs-ü*", "x" * 101, ",".join(f"idx-{i}-*" for i in range(11))],
        ids=lambda v: repr(v)[:30],
    )
    def test_anything_else_is_refused(self, bad):
        with pytest.raises(nq.QueryScopeError):
            nq.validate_index_pattern(bad)

    def test_a_hostile_pattern_is_a_422_on_both_request_models(self):
        for model in (nq.NLQueryTranslateRequest, nq.NLQueryExecuteRequest):
            with pytest.raises(ValidationError):
                model(question="Show failed logins per user", index_pattern="*")
            with pytest.raises(ValidationError):
                model(question="Show failed logins per user", index_pattern="logs-* | EVAL x = 1")

    def test_the_default_pattern_is_itself_valid(self):
        assert nq.NLQueryTranslateRequest(question="Show failed logins per user").index_pattern == "logs-*,aisoc-events-*"
        assert nq.NLQueryExecuteRequest(question="Show failed logins per user").index_pattern == "logs-*,aisoc-events-*"


class TestFinalQueryScope:
    @pytest.fixture(autouse=True)
    def no_tenant_field(self, monkeypatch):
        monkeypatch.setattr(nq.settings, "NL_QUERY_TENANT_FIELD", "", raising=False)

    @pytest.mark.parametrize("q", ["FROM logs-*,aisoc-events-*" + GOOD_TAIL, "from logs-* | LIMIT 5", "FROM logs-* METADATA _index" + GOOD_TAIL, "FROM logs-*, aisoc-events-*" + GOOD_TAIL, "  FROM logs-prod" + GOOD_TAIL])
    def test_a_query_over_allowed_indices_is_unchanged_without_a_tenant_field(self, q):
        assert nq.enforce_query_scope(q, TENANT) == q

    @pytest.mark.parametrize(
        "q",
        [
            "FROM *" + GOOD_TAIL,
            "FROM .security-*,.kibana*" + GOOD_TAIL,
            "FROM logs-*, .security-*" + GOOD_TAIL,
            "FROM logs-* garbage" + GOOD_TAIL,
            "ROW a = 1",
            "SHOW INFO",
            "// note\nFROM *" + GOOD_TAIL,
            "FROM" + GOOD_TAIL,
            "",
            "| FROM logs-*",
            "FROM logs-* METADATA _index; DROP" + GOOD_TAIL,
        ],
        ids=lambda v: repr(v)[:34],
    )
    def test_what_an_llm_or_anything_else_might_write_but_must_not_run_is_refused(self, q):
        with pytest.raises(nq.QueryScopeError):
            nq.enforce_query_scope(q, TENANT)


class TestTenantPredicate:
    FIELD = "tenant.id"

    @pytest.fixture(autouse=True)
    def with_tenant_field(self, monkeypatch):
        monkeypatch.setattr(nq.settings, "NL_QUERY_TENANT_FIELD", self.FIELD, raising=False)

    def test_it_is_added_right_after_the_source_clause_multiline(self):
        out = nq.enforce_query_scope("FROM logs-*" + GOOD_TAIL, TENANT)
        assert out == f'FROM logs-*\n| WHERE tenant.id == "{TENANT}"' + GOOD_TAIL

    def test_it_is_added_after_a_single_line_pipeline(self):
        assert nq.enforce_query_scope("FROM logs-* | LIMIT 5", TENANT) == f'FROM logs-*\n| WHERE tenant.id == "{TENANT}" | LIMIT 5'

    def test_metadata_stays_with_the_source_clause(self):
        out = nq.enforce_query_scope("FROM logs-* METADATA _index" + GOOD_TAIL, TENANT)
        assert out.startswith(f'FROM logs-* METADATA _index\n| WHERE tenant.id == "{TENANT}"\n| WHERE @timestamp')

    def test_it_comes_before_every_other_command_so_nothing_can_read_around_it(self):
        out = nq.enforce_query_scope("FROM logs-*\n| EVAL x = 1\n| KEEP x", TENANT)
        assert out.index("tenant.id") < out.index("EVAL")

    def test_a_forbidden_source_is_still_refused_when_a_tenant_field_is_set(self):
        with pytest.raises(nq.QueryScopeError):
            nq.enforce_query_scope("FROM *" + GOOD_TAIL, TENANT)

    @pytest.mark.parametrize("field", ['x; DROP', 'a"b', "a b", "1abc", "tenant.id\n| EVAL", "", "x" * 101][:-1], ids=repr)
    def test_a_configured_field_name_that_is_not_a_field_name_is_refused(self, monkeypatch, field):
        monkeypatch.setattr(nq.settings, "NL_QUERY_TENANT_FIELD", field, raising=False)
        if field.strip() == "":
            assert nq.enforce_query_scope("FROM logs-*" + GOOD_TAIL, TENANT) == "FROM logs-*" + GOOD_TAIL  # empty means "not configured"
        else:
            with pytest.raises(nq.QueryScopeError):
                nq.enforce_query_scope("FROM logs-*" + GOOD_TAIL, TENANT)


def translated(esql):
    return SimpleNamespace(esql=esql, spl="spl", kql="kql", explanation="why")


class NoDB:
    """An own-tenant search needs no database: touching it fails the test."""

    def __init__(self):
        self.execute = AsyncMock(side_effect=AssertionError("an own-tenant search must not query the database"))


@pytest.mark.asyncio
class TestEndpoints:
    async def test_translate_refuses_a_generated_query_that_reads_what_it_may_not(self, monkeypatch):
        monkeypatch.setattr(nq, "_translate", AsyncMock(return_value=(translated("FROM *" + GOOD_TAIL), "llm")))
        with pytest.raises(HTTPException) as exc:
            await nq.translate_query(body=nq.NLQueryTranslateRequest(question="Show failed logins per user"), user=user(), db=NoDB())
        assert exc.value.status_code == 422 and "refused" in exc.value.detail

    async def test_execute_runs_nothing_when_the_query_reads_what_it_may_not(self, monkeypatch):
        run = AsyncMock()
        monkeypatch.setattr(nq, "_translate", AsyncMock(return_value=(translated("FROM .security-*" + GOOD_TAIL), "llm")))
        monkeypatch.setattr(nq, "_execute_esql", run)
        monkeypatch.setattr(nq, "resolve_es_credentials", lambda: ("https://es.internal", "key"))
        out = await nq.execute_query(body=nq.NLQueryExecuteRequest(question="Show failed logins per user"), user=user(), db=NoDB())
        assert out.result is None and out.execution_error.startswith("Refusing to execute:")
        run.assert_not_awaited()

    async def test_execute_runs_the_scoped_query_and_reports_it(self, monkeypatch):
        run = AsyncMock(return_value=nq.QueryResult(columns=["n"], rows=[[1]], total_rows=1))
        monkeypatch.setattr(nq.settings, "NL_QUERY_TENANT_FIELD", "tenant.id", raising=False)
        monkeypatch.setattr(nq, "_translate", AsyncMock(return_value=(translated("FROM logs-*" + GOOD_TAIL), "deterministic")))
        monkeypatch.setattr(nq, "_execute_esql", run)
        monkeypatch.setattr(nq, "resolve_es_credentials", lambda: ("https://es.internal", "key"))
        out = await nq.execute_query(body=nq.NLQueryExecuteRequest(question="Show failed logins per user"), user=user(), db=NoDB())
        sent = run.await_args.args[0]
        assert sent == f'FROM logs-*\n| WHERE tenant.id == "{TENANT}"' + GOOD_TAIL and out.esql == sent and out.execution_error is None

    async def test_execute_without_a_tenant_field_runs_the_translators_query_unchanged(self, monkeypatch):
        run = AsyncMock(return_value=nq.QueryResult(columns=["n"], rows=[[1]], total_rows=1))
        monkeypatch.setattr(nq.settings, "NL_QUERY_TENANT_FIELD", "", raising=False)
        q = "FROM logs-*,aisoc-events-*" + GOOD_TAIL
        monkeypatch.setattr(nq, "_translate", AsyncMock(return_value=(translated(q), "deterministic")))
        monkeypatch.setattr(nq, "_execute_esql", run)
        monkeypatch.setattr(nq, "resolve_es_credentials", lambda: ("https://es.internal", "key"))
        await nq.execute_query(body=nq.NLQueryExecuteRequest(question="Show failed logins per user"), user=user(), db=NoDB())
        assert run.await_args.args[0] == q

    async def test_the_scope_check_runs_before_the_server_credentials_are_even_resolved(self, monkeypatch):
        creds = []
        monkeypatch.setattr(nq, "_translate", AsyncMock(return_value=(translated("FROM *" + GOOD_TAIL), "llm")))
        monkeypatch.setattr(nq, "resolve_es_credentials", lambda: creds.append(1) or ("https://es.internal", "key"))
        await nq.execute_query(body=nq.NLQueryExecuteRequest(question="Show failed logins per user"), user=user(), db=NoDB())
        assert creds == []
