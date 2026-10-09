"""Searching across tenants: your own by default, other tenants only for holders of platform:cross_tenant_query.

/nl-query/execute runs with the SERVER's Elasticsearch credentials. Nothing selected (or only your own tenant) searches your own tenant. Choosing other tenants, several tenants, or all of them is a platform-level action: it needs the platform permission AND NL_QUERY_TENANT_FIELD (the field holding each event's tenant),
because without that field the search could not be restricted to the tenants chosen. The predicate is `== "<id>"` for one tenant, `IN (...)` for several and absent for all; a tenant that does not exist is a 404; and anything wider than your own tenant is logged."""
import logging
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import nl_query as nq

HOME, OTHER, THIRD = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
TAIL = "\n| WHERE @timestamp > NOW() - 24h\n| LIMIT 500"
Q = "Show failed logins per user in the last day"


def principal(role="platform_admin", scopes=None):
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=HOME, role=role, email=f"{role}@example.test", scopes=scopes)


@pytest.fixture
def field(monkeypatch):
    monkeypatch.setattr(nq.settings, "NL_QUERY_TENANT_FIELD", "tenant.id", raising=False)


@pytest.fixture
def no_field(monkeypatch):
    monkeypatch.setattr(nq.settings, "NL_QUERY_TENANT_FIELD", "", raising=False)


def req(**kw):
    return nq.NLQueryTranslateRequest(question=Q, **kw)


class TestTheRequest:
    def test_choosing_both_ways_is_refused(self):
        with pytest.raises(ValidationError, match="not both"):
            req(tenant_ids=[OTHER], all_tenants=True)

    def test_an_empty_list_is_refused_rather_than_meaning_everything_or_nothing(self):
        with pytest.raises(ValidationError, match="at least one"):
            req(tenant_ids=[])

    def test_the_default_selects_nothing(self):
        r = req()
        assert r.tenant_ids is None and r.all_tenants is False

    def test_at_most_fifty_tenants_and_only_uuids(self):
        req(tenant_ids=[uuid.uuid4() for _ in range(50)])
        with pytest.raises(ValidationError):
            req(tenant_ids=[uuid.uuid4() for _ in range(51)])
        with pytest.raises(ValidationError):
            req(tenant_ids=["not-a-uuid"])
        with pytest.raises(ValidationError):
            req(tenant_ids=['x"] | DROP'])

    def test_the_execute_request_has_the_same_fields(self):
        assert nq.NLQueryExecuteRequest(question=Q, tenant_ids=[OTHER]).tenant_ids == [OTHER]
        with pytest.raises(ValidationError):
            nq.NLQueryExecuteRequest(question=Q, tenant_ids=[OTHER], all_tenants=True)


class TestResolvingTheScope:
    @pytest.mark.parametrize("kw", [{}, {"tenant_ids": [HOME]}, {"tenant_ids": [HOME, HOME]}])
    @pytest.mark.parametrize("role", ["viewer", "tenant_admin", "admin", "platform_admin"])
    def test_nothing_or_only_your_own_tenant_is_always_own_for_everyone(self, role, kw, field):
        assert nq.resolve_tenant_scope(req(**kw), principal(role)) == nq.TenantScope("own", (str(HOME),))

    @pytest.mark.parametrize("kw", [{"tenant_ids": [OTHER]}, {"tenant_ids": [HOME, OTHER]}, {"all_tenants": True}])
    @pytest.mark.parametrize("role", ["viewer", "soc_analyst", "tenant_admin", "admin"])
    def test_anything_wider_is_a_403_without_the_platform_permission(self, role, kw, field):
        with pytest.raises(HTTPException) as exc:
            nq.resolve_tenant_scope(req(**kw), principal(role))
        assert exc.value.status_code == 403 and nq.CROSS_TENANT_PERMISSION in exc.value.detail

    def test_the_wildcard_admin_does_not_hold_it(self, field):
        with pytest.raises(HTTPException) as exc:
            nq.resolve_tenant_scope(req(all_tenants=True), principal("admin"))
        assert exc.value.status_code == 403

    def test_a_platform_admin_can_select_tenants(self, field):
        scope = nq.resolve_tenant_scope(req(tenant_ids=[OTHER, THIRD]), principal("platform_admin"))
        assert scope == nq.TenantScope("selected", (str(OTHER), str(THIRD)))

    def test_selecting_your_own_and_another_is_selected_with_both(self, field):
        assert nq.resolve_tenant_scope(req(tenant_ids=[HOME, OTHER]), principal()).tenant_ids == (str(HOME), str(OTHER))

    def test_duplicates_are_removed_keeping_order(self, field):
        assert nq.resolve_tenant_scope(req(tenant_ids=[OTHER, THIRD, OTHER]), principal()).tenant_ids == (str(OTHER), str(THIRD))

    def test_a_platform_admin_can_search_all_tenants(self, field):
        assert nq.resolve_tenant_scope(req(all_tenants=True), principal()) == nq.TenantScope("all")

    def test_an_api_key_with_the_exact_scope_can(self, field):
        assert nq.resolve_tenant_scope(req(all_tenants=True), principal("viewer", scopes=[nq.CROSS_TENANT_PERMISSION])).kind == "all"

    @pytest.mark.parametrize("scopes", [["*"], ["platform:*"], ["lake:query"]])
    def test_a_wildcard_key_cannot(self, scopes, field):
        with pytest.raises(HTTPException) as exc:
            nq.resolve_tenant_scope(req(all_tenants=True), principal("platform_admin", scopes=scopes))
        assert exc.value.status_code == 403

    @pytest.mark.parametrize("kw", [{"tenant_ids": [OTHER]}, {"all_tenants": True}])
    def test_without_the_tenant_field_a_wider_search_is_a_422_that_explains_why(self, kw, no_field):
        with pytest.raises(HTTPException) as exc:
            nq.resolve_tenant_scope(req(**kw), principal())
        assert exc.value.status_code == 422 and "NL_QUERY_TENANT_FIELD" in exc.value.detail

    def test_without_the_tenant_field_your_own_search_is_unaffected(self, no_field):
        assert nq.resolve_tenant_scope(req(), principal("viewer")).kind == "own"

    def test_the_permission_is_checked_before_the_field(self, no_field):
        with pytest.raises(HTTPException) as exc:
            nq.resolve_tenant_scope(req(all_tenants=True), principal("tenant_admin"))
        assert exc.value.status_code == 403  # a non-holder learns nothing about how the deployment is configured


class FakeDB:
    def __init__(self, *payloads):
        self.queue, self.statements = list(payloads), []
        self.execute = AsyncMock(side_effect=self._execute)

    async def _execute(self, stmt, *a, **k):
        comp = stmt.compile()
        self.statements.append((" ".join(str(comp).split()), dict(comp.params)))
        res = MagicMock()
        res.scalars.return_value.all.return_value = self.queue.pop(0) if self.queue else []
        return res


@pytest.mark.asyncio
class TestTenantsMustExist:
    async def test_a_missing_tenant_is_a_404_naming_it(self):
        db = FakeDB([OTHER])
        with pytest.raises(HTTPException) as exc:
            await nq._require_tenants_exist(db, nq.TenantScope("selected", (str(OTHER), str(THIRD))))
        assert exc.value.status_code == 404 and str(THIRD) in exc.value.detail and str(OTHER) not in exc.value.detail

    async def test_all_present_passes(self):
        await nq._require_tenants_exist(FakeDB([OTHER, THIRD]), nq.TenantScope("selected", (str(OTHER), str(THIRD))))

    @pytest.mark.parametrize("scope", [nq.TenantScope("own", (str(HOME),)), nq.TenantScope("all")])
    async def test_own_and_all_make_no_database_call(self, scope):
        db = FakeDB()
        await nq._require_tenants_exist(db, scope)
        db.execute.assert_not_awaited()


class TestThePredicate:
    def scoped(self, scope, esql="FROM logs-*" + TAIL):
        return nq.enforce_query_scope(esql, HOME, scope)

    def test_the_default_is_the_callers_tenant_exactly_as_before(self, field):
        assert nq.enforce_query_scope("FROM logs-*" + TAIL, HOME) == f'FROM logs-*\n| WHERE tenant.id == "{HOME}"' + TAIL

    def test_one_selected_tenant_uses_equality(self, field):
        assert self.scoped(nq.TenantScope("selected", (str(OTHER),))) == f'FROM logs-*\n| WHERE tenant.id == "{OTHER}"' + TAIL

    def test_several_selected_tenants_use_in(self, field):
        assert self.scoped(nq.TenantScope("selected", (str(OTHER), str(THIRD)))) == f'FROM logs-*\n| WHERE tenant.id IN ("{OTHER}", "{THIRD}")' + TAIL

    def test_all_tenants_adds_no_predicate(self, field):
        assert self.scoped(nq.TenantScope("all")) == "FROM logs-*" + TAIL

    def test_without_a_tenant_field_no_scope_adds_a_predicate(self, no_field):
        for scope in (nq.TenantScope("own", (str(HOME),)), nq.TenantScope("selected", (str(OTHER),)), nq.TenantScope("all")):
            assert self.scoped(scope) == "FROM logs-*" + TAIL

    def test_the_source_is_still_enforced_whatever_the_scope(self, field):
        for scope in (nq.TenantScope("own", (str(HOME),)), nq.TenantScope("selected", (str(OTHER),)), nq.TenantScope("all")):
            with pytest.raises(nq.QueryScopeError):
                self.scoped(scope, "FROM *" + TAIL)

    def test_a_scope_holding_something_that_is_not_a_uuid_is_refused_never_interpolated(self, field):
        with pytest.raises(nq.QueryScopeError):
            self.scoped(nq.TenantScope("selected", ('x") | DROP | WHERE ("',)))

    def test_the_predicate_precedes_every_other_command_for_a_selection_too(self, field):
        out = self.scoped(nq.TenantScope("selected", (str(OTHER), str(THIRD))), "FROM logs-*\n| EVAL x = 1\n| KEEP x")
        assert out.index("IN (") < out.index("EVAL")


def translated(esql):
    return SimpleNamespace(esql=esql, spl="spl", kql="kql", explanation="why")


@pytest.mark.asyncio
class TestEndpoints:
    async def test_a_non_holder_choosing_other_tenants_is_refused_before_anything_else_happens(self, monkeypatch, field):
        tr, db = AsyncMock(), FakeDB()
        monkeypatch.setattr(nq, "_translate", tr)
        with pytest.raises(HTTPException) as exc:
            await nq.execute_query(body=nq.NLQueryExecuteRequest(question=Q, tenant_ids=[OTHER]), user=principal("tenant_admin"), db=db)
        assert exc.value.status_code == 403
        tr.assert_not_awaited()
        db.execute.assert_not_awaited()

    async def test_a_selection_is_validated_then_run_with_an_in_predicate_and_reported(self, monkeypatch, field):
        run = AsyncMock(return_value=nq.QueryResult(columns=["n"], rows=[[1]], total_rows=1))
        monkeypatch.setattr(nq, "_translate", AsyncMock(return_value=(translated("FROM logs-*" + TAIL), "deterministic")))
        monkeypatch.setattr(nq, "_execute_esql", run)
        monkeypatch.setattr(nq, "resolve_es_credentials", lambda: ("https://es.internal", "key"))
        out = await nq.execute_query(body=nq.NLQueryExecuteRequest(question=Q, tenant_ids=[OTHER, THIRD]), user=principal(), db=FakeDB([OTHER, THIRD]))
        assert run.await_args.args[0] == f'FROM logs-*\n| WHERE tenant.id IN ("{OTHER}", "{THIRD}")' + TAIL
        assert out.tenant_scope == "selected" and out.tenant_ids == [str(OTHER), str(THIRD)] and out.esql == run.await_args.args[0]

    async def test_a_nonexistent_selected_tenant_runs_nothing(self, monkeypatch, field):
        run = AsyncMock()
        monkeypatch.setattr(nq, "_translate", AsyncMock(return_value=(translated("FROM logs-*" + TAIL), "deterministic")))
        monkeypatch.setattr(nq, "_execute_esql", run)
        monkeypatch.setattr(nq, "resolve_es_credentials", lambda: ("https://es.internal", "key"))
        with pytest.raises(HTTPException) as exc:
            await nq.execute_query(body=nq.NLQueryExecuteRequest(question=Q, tenant_ids=[OTHER]), user=principal(), db=FakeDB([]))
        assert exc.value.status_code == 404
        run.assert_not_awaited()

    async def test_all_tenants_runs_without_a_tenant_predicate(self, monkeypatch, field):
        run = AsyncMock(return_value=nq.QueryResult(columns=["n"], rows=[[1]], total_rows=1))
        monkeypatch.setattr(nq, "_translate", AsyncMock(return_value=(translated("FROM logs-*" + TAIL), "deterministic")))
        monkeypatch.setattr(nq, "_execute_esql", run)
        monkeypatch.setattr(nq, "resolve_es_credentials", lambda: ("https://es.internal", "key"))
        out = await nq.execute_query(body=nq.NLQueryExecuteRequest(question=Q, all_tenants=True), user=principal(), db=FakeDB())
        assert run.await_args.args[0] == "FROM logs-*" + TAIL and out.tenant_scope == "all" and out.tenant_ids is None

    async def test_the_default_runs_the_callers_tenant_and_says_so(self, monkeypatch, field):
        run = AsyncMock(return_value=nq.QueryResult(columns=["n"], rows=[[1]], total_rows=1))
        monkeypatch.setattr(nq, "_translate", AsyncMock(return_value=(translated("FROM logs-*" + TAIL), "deterministic")))
        monkeypatch.setattr(nq, "_execute_esql", run)
        monkeypatch.setattr(nq, "resolve_es_credentials", lambda: ("https://es.internal", "key"))
        out = await nq.execute_query(body=nq.NLQueryExecuteRequest(question=Q), user=principal("tenant_admin"), db=FakeDB())
        assert 'WHERE tenant.id == "' + str(HOME) in run.await_args.args[0] and out.tenant_scope == "own" and out.tenant_ids == [str(HOME)]

    async def test_translate_reports_the_scope_too(self, monkeypatch, field):
        monkeypatch.setattr(nq, "_translate", AsyncMock(return_value=(translated("FROM logs-*" + TAIL), "deterministic")))
        out = await nq.translate_query(body=req(tenant_ids=[OTHER]), user=principal(), db=FakeDB([OTHER]))
        assert out.tenant_scope == "selected" and out.tenant_ids == [str(OTHER)] and f'== "{OTHER}"' in out.esql

    async def test_a_wider_search_is_logged_and_an_own_search_is_not(self, monkeypatch, field, caplog):
        monkeypatch.setattr(nq, "_translate", AsyncMock(return_value=(translated("FROM logs-*" + TAIL), "deterministic")))
        with caplog.at_level(logging.INFO, logger=nq.logger.name):
            await nq.translate_query(body=req(), user=principal(), db=FakeDB())
            assert not [r for r in caplog.records if "cross_tenant" in r.getMessage()]
            u = principal()
            await nq.translate_query(body=req(all_tenants=True), user=u, db=FakeDB())
            await nq.translate_query(body=req(tenant_ids=[OTHER]), user=u, db=FakeDB([OTHER]))
        msgs = [r.getMessage() for r in caplog.records if "nl_query.cross_tenant" in r.getMessage()]
        assert len(msgs) == 2 and str(u.user_id) in msgs[0] and "scope=all" in msgs[0] and "scope=selected" in msgs[1] and str(OTHER) in msgs[1]


@pytest.mark.asyncio
class TestTheTenantListForTheSelector:
    def tenant(self, name):
        return SimpleNamespace(id=uuid.uuid4(), name=name, slug=name.lower())

    async def test_a_non_holder_sees_only_their_own_tenant_and_the_query_is_restricted_to_it(self, field):
        db = FakeDB([self.tenant("Home")])
        out = await nq.list_searchable_tenants(user=principal("tenant_admin"), db=db)
        assert out.cross_tenant_enabled is False and [t.name for t in out.tenants] == ["Home"] and out.own_tenant_id == HOME
        sql, params = db.statements[0]
        assert "tenants.id =" in sql and HOME in params.values()

    async def test_a_holder_with_the_field_set_sees_every_tenant_ordered_by_name_with_a_cap(self, field):
        db = FakeDB([self.tenant("A"), self.tenant("B")])
        out = await nq.list_searchable_tenants(user=principal("platform_admin"), db=db)
        assert out.cross_tenant_enabled is True and [t.name for t in out.tenants] == ["A", "B"]
        sql, _ = db.statements[0]
        assert "ORDER BY tenants.name" in sql and "LIMIT" in sql and "WHERE" not in sql

    async def test_a_holder_without_the_field_is_not_offered_other_tenants(self, no_field):
        db = FakeDB([self.tenant("Home")])
        out = await nq.list_searchable_tenants(user=principal("platform_admin"), db=db)
        assert out.cross_tenant_enabled is False and "tenants.id =" in db.statements[0][0]

    async def test_an_api_key_with_the_exact_scope_is_a_holder(self, field):
        db = FakeDB([self.tenant("A")])
        out = await nq.list_searchable_tenants(user=principal("viewer", scopes=[nq.CROSS_TENANT_PERMISSION]), db=db)
        assert out.cross_tenant_enabled is True

    async def test_a_wildcard_key_is_not(self, field):
        out = await nq.list_searchable_tenants(user=principal("platform_admin", scopes=["*"]), db=FakeDB([self.tenant("Home")]))
        assert out.cross_tenant_enabled is False
