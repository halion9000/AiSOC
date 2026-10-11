"""`cross_tenant_reads`: the explicit way to say "this read is across tenants on purpose".

Why it exists (measured on a real Postgres, see docs/security/rls-fail-closed-plan.md): the MSSP rule resolver reads rules the PARENT owns
while resolving for the child. That works today only because a plain get_db session carries no tenant and the RLS policies are fail-open.
Tagging that session with the child's tenant (step 3 of the plan) made the real resolver return NOTHING for the child, and so would
fail-closed policies. These tests pin the mechanism that survives both; the opt-in Postgres test beside them pins the behaviour against a
real database.
They use a recording fake session, because the suite runs without a database.
"""

import inspect
import uuid

import pytest
from app.db.rls import cross_tenant_reads
from app.services import mssp_rule_resolver as resolver

TENANT = str(uuid.uuid4())


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class FakeSession:
    """Records every statement as ('read'|'clear'|'set', value). `current` is what current_setting() returns when the block starts."""

    def __init__(self, current=None, tag=None, dialect="postgresql"):
        self.current, self.info, self.log = current, ({"rls_tenant_id": tag} if tag else {}), []
        self._dialect = dialect

    def get_bind(self):
        from types import SimpleNamespace

        return SimpleNamespace(dialect=SimpleNamespace(name=self._dialect))

    async def execute(self, statement, params=None):
        sql = str(statement)
        if "current_setting" in sql:
            self.log.append(("read", None))
            return _Result(self.current)
        if "set_config" in sql and params:
            self.log.append(("set", params["t"]))
            self.current = params["t"]
        elif "set_config" in sql:
            self.log.append(("clear", ""))
            self.current = ""
        return _Result(None)


@pytest.mark.asyncio
async def test_the_tenant_setting_is_cleared_for_the_length_of_the_block():
    session = FakeSession(current=None)
    async with cross_tenant_reads(session):
        assert session.current == "", "inside the block no tenant is set (an empty string is the same as unset for current_tenant_id())"
    assert [kind for kind, _ in session.log][:2] == ["read", "clear"]


@pytest.mark.asyncio
async def test_a_session_with_no_tenant_is_left_exactly_as_it_was():
    """Today's get_db session: nothing to restore, so no statement is sent on exit (the block is a no-op for it)."""
    session = FakeSession(current=None)
    async with cross_tenant_reads(session):
        pass
    assert [kind for kind, _ in session.log] == ["read", "clear"] and "rls_tenant_id" not in session.info


@pytest.mark.asyncio
async def test_a_tenant_scoped_session_gets_its_tenant_back_so_it_is_never_left_wider_than_it_was():
    session = FakeSession(current=TENANT)
    async with cross_tenant_reads(session):
        assert session.current == ""
    assert session.current == TENANT and session.log[-1] == ("set", TENANT)


@pytest.mark.asyncio
async def test_a_tagged_session_is_untagged_inside_the_block_so_the_hook_cannot_reapply_the_tenant_then_retagged():
    session = FakeSession(current=TENANT, tag=TENANT)
    async with cross_tenant_reads(session):
        assert "rls_tenant_id" not in session.info, "the per-transaction hook reads this tag; inside the block it must not find one"
    assert session.info["rls_tenant_id"] == TENANT


@pytest.mark.asyncio
async def test_when_the_block_fails_the_tag_is_restored_and_the_error_propagates_without_a_statement_on_the_failed_transaction():
    session = FakeSession(current=TENANT, tag=TENANT)
    with pytest.raises(RuntimeError, match="boom"):
        async with cross_tenant_reads(session):
            raise RuntimeError("boom")
    assert session.info["rls_tenant_id"] == TENANT, "the next transaction must be tagged again"
    assert session.log[-1] == (
        "clear",
        "",
    ), "no re-apply statement is sent on a failed transaction (it would itself raise); the rollback resets the setting"


@pytest.mark.asyncio
async def test_nested_blocks_do_not_restore_the_outer_blocks_cleared_state_early():
    session = FakeSession(current=TENANT, tag=TENANT)
    async with cross_tenant_reads(session):
        async with cross_tenant_reads(session):
            assert session.current == ""
        assert session.current == "", "leaving the inner block must not re-scope the outer one"
        assert "rls_tenant_id" not in session.info, "after the inner block exits the outer block must still be untagged"
    assert session.current == TENANT and session.info["rls_tenant_id"] == TENANT


@pytest.mark.asyncio
async def test_a_cancelled_block_still_restores_the_tag():
    import asyncio

    session = FakeSession(current=TENANT, tag=TENANT)
    with pytest.raises(asyncio.CancelledError):
        async with cross_tenant_reads(session):
            raise asyncio.CancelledError
    assert session.info["rls_tenant_id"] == TENANT


@pytest.mark.asyncio
@pytest.mark.parametrize("dialect", ["sqlite", "mysql", "mssql"])
async def test_on_a_database_without_row_level_security_the_block_is_a_no_op(dialect):
    """RLS is a PostgreSQL feature. The unit tests run the resolver on SQLite, and sending current_setting()/set_config() there fails (14
    existing tests did exactly that before this check)."""
    session = FakeSession(current="never-read", tag=TENANT, dialect=dialect)
    async with cross_tenant_reads(session):
        assert session.info["rls_tenant_id"] == TENANT, "nothing is untagged where nothing is cleared"
    assert session.log == [] and session.current == "never-read"


@pytest.mark.asyncio
async def test_a_mock_session_is_left_completely_alone_and_raises_no_never_awaited_warning(recwarn):
    """test_mssp_rule_resolver.py scripts an AsyncMock session's execute() responses in order; the block must not consume one, and an
    AsyncMock's get_bind() is a coroutine."""
    from unittest.mock import AsyncMock

    session = AsyncMock()
    session.info = {"rls_tenant_id": TENANT}
    async with cross_tenant_reads(session):
        pass
    session.execute.assert_not_awaited()
    assert session.info == {"rls_tenant_id": TENANT}
    import gc

    gc.collect()
    assert not [w for w in recwarn if "never awaited" in str(w.message)]


@pytest.mark.asyncio
async def test_on_postgresql_the_block_does_send_its_statements():
    """The positive control for the test above: the same fake with the postgresql dialect DOES clear, so the no-op test is not passing for
    the wrong reason."""
    session = FakeSession(current=TENANT, dialect="postgresql")
    async with cross_tenant_reads(session):
        pass
    assert [kind for kind, _ in session.log] == ["read", "clear", "set"]


class TestTheResolverUsesIt:
    @pytest.mark.asyncio
    async def test_the_real_resolver_body_runs_inside_the_block_and_the_result_passes_through(self, monkeypatch):
        session = FakeSession(current=TENANT, tag=TENANT)
        seen = {}

        async def fake_body(db, tenant_id, **kwargs):
            seen["current"], seen["tagged"], seen["kwargs"] = db.current, "rls_tenant_id" in db.info, kwargs
            return ["sentinel"]

        monkeypatch.setattr(resolver, "_resolve_effective_rules", fake_body)
        result = await resolver.resolve_effective_rules(session, uuid.uuid4(), include_packs=False, only_active=False)
        assert result == ["sentinel"]
        assert seen["current"] == "" and seen["tagged"] is False, "the body must run with no tenant set and no tag"
        assert seen["kwargs"]["include_packs"] is False and seen["kwargs"]["only_active"] is False, "every option reaches the body"
        assert session.current == TENANT and session.info["rls_tenant_id"] == TENANT, "and the session is scoped again afterwards"

    @pytest.mark.asyncio
    async def test_an_error_in_the_body_propagates_and_the_session_is_retagged(self, monkeypatch):
        session = FakeSession(current=TENANT, tag=TENANT)

        async def broken(db, tenant_id, **kwargs):
            raise ValueError("resolver bug")

        monkeypatch.setattr(resolver, "_resolve_effective_rules", broken)
        with pytest.raises(ValueError, match="resolver bug"):
            await resolver.resolve_effective_rules(session, uuid.uuid4())
        assert session.info["rls_tenant_id"] == TENANT

    def test_the_public_signature_is_unchanged_so_no_caller_needed_to_change(self):
        public, inner = inspect.signature(resolver.resolve_effective_rules), inspect.signature(resolver._resolve_effective_rules)
        assert (
            list(public.parameters)
            == list(inner.parameters)
            == ["db", "tenant_id", "include_builtin", "include_packs", "rule_ids", "rule_language", "category", "only_active"]
        )
        assert all(
            public.parameters[n].default == inner.parameters[n].default and public.parameters[n].kind == inner.parameters[n].kind
            for n in public.parameters
        )

    @pytest.mark.asyncio
    async def test_the_count_function_inherits_it_because_it_calls_the_resolver(self, monkeypatch):
        session = FakeSession(current=TENANT, tag=TENANT)
        observed = {}

        async def fake_body(db, tenant_id, **kwargs):
            observed["cleared"] = db.current == ""
            return []

        async def no_parent(db, tenant_id):
            return None

        monkeypatch.setattr(resolver, "_resolve_effective_rules", fake_body)
        monkeypatch.setattr(resolver, "_actual_parent_id", no_parent)
        counts = await resolver.count_effective_rules(session, uuid.uuid4())
        assert observed["cleared"] is True and counts["total"] == 0
