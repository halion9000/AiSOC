"""A rule pack may contain only the PARENT's own rules (or a platform built-in), at write time AND at read time.

Found by a scan for platform/MSSP-guarded handlers that read RLS-covered models, and reproduced on a real Postgres as the restricted role:
`POST /mssp/rule-packs/{pack_id}/rules` checked that the PACK was the caller's but fetched the rule with a plain `db.get(DetectionRule,
rule_id)` and checked only that it existed, so a holder of mssp:manage could attach ANY tenant's rule to its pack; the pack applies to its
children, so the child's effective rules then included (and `resolve_effective_rules` returned the body of) a stranger's private rule. It
needs the rule's id (a random UUID), which lowers the severity but it is a missing authorization check, independent of RLS: the session
has no tenant set, so no policy was protecting it.
Two layers, both tested here: the route refuses the link (the SAME 404 as for an id that does not exist, so it is not an existence
oracle), and the resolver only returns pack rules the pack's parent owns, or built-ins, which also neutralises links already sitting in
deployed databases. Real SQLite engine, as test_mssp_cross_tenant.py.
"""

import asyncio
import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import mssp
from app.db.database import Base
from app.models.detection_rule import DetectionRule
from app.models.mssp import MSSPDelegation, MSSPRuleOverride, MSSPRulePack, MSSPRulePackAssignment, MSSPRulePackRule, MSSPTenantNote
from app.models.tenant import Tenant
from app.services.mssp_rule_resolver import count_effective_rules, resolve_effective_rules
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

TABLES = [
    m.__table__
    for m in (
        Tenant,
        DetectionRule,
        MSSPRuleOverride,
        MSSPRulePack,
        MSSPRulePackAssignment,
        MSSPRulePackRule,
        MSSPTenantNote,
        MSSPDelegation,
    )
]


def run(coro_fn):
    async def main():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as c:
            await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=TABLES))
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:

            def tenant(name, parent=None):
                t = Tenant(id=uuid.uuid4(), name=name, slug=f"{name}-{uuid.uuid4().hex[:6]}", parent_tenant_id=parent)
                s.add(t)
                return t

            parent = tenant("msp")
            await s.flush()
            child, stranger = tenant("customer", parent=parent.id), tenant("stranger")
            await s.flush()

            def rule(name, owner, builtin=False):
                r = DetectionRule(
                    id=uuid.uuid4(),
                    name=name,
                    rule_language="sigma",
                    rule_body="body-of-" + name,
                    category="x",
                    tenant_id=owner,
                    is_builtin=builtin,
                    status="active",
                )
                s.add(r)
                return r

            world = SimpleNamespace(
                parent=parent,
                child=child,
                stranger=stranger,
                own=rule("parents-own-rule", parent.id),
                builtin=rule("platform-builtin", None, builtin=True),
                foreign=rule("STRANGERS-PRIVATE-RULE", stranger.id),
                childs=rule("childs-own-rule", child.id),
                caller=SimpleNamespace(tenant_id=parent.id),
            )
            world.pack = MSSPRulePack(id=uuid.uuid4(), parent_tenant_id=parent.id, name="pack")
            s.add(world.pack)
            await s.flush()
            s.add(MSSPRulePackAssignment(id=uuid.uuid4(), pack_id=world.pack.id, child_tenant_id=child.id, enabled=True))
            await s.commit()
            try:
                return await coro_fn(s, world)
            finally:
                await engine.dispose()

    return asyncio.run(main())


async def _add(s, w, rule_id):
    return await mssp.add_rule_to_pack(pack_id=w.pack.id, body=mssp.RulePackRuleAdd(rule_id=rule_id), db=s, current_user=w.caller)


async def _linked(s, w):
    return {r for (r,) in (await s.execute(select(MSSPRulePackRule.rule_id).where(MSSPRulePackRule.pack_id == w.pack.id))).all()}


class TestTheRoute:
    def test_the_parents_own_rule_can_be_added(self):
        async def go(s, w):
            assert (await _add(s, w, w.own.id))["status"] == "ok"
            assert await _linked(s, w) == {w.own.id}

        run(go)

    def test_a_platform_builtin_can_be_added(self):
        async def go(s, w):
            await _add(s, w, w.builtin.id)
            assert await _linked(s, w) == {w.builtin.id}

        run(go)

    def test_another_tenants_rule_is_refused_and_nothing_is_linked(self):
        async def go(s, w):
            with pytest.raises(HTTPException) as refused:
                await _add(s, w, w.foreign.id)
            assert refused.value.status_code == 404
            assert await _linked(s, w) == set()

        run(go)

    def test_even_the_managed_childs_own_rule_is_refused(self):
        """The pack is the PARENT's: a rule the child authored is the child's, not the parent's to redistribute."""

        async def go(s, w):
            with pytest.raises(HTTPException) as refused:
                await _add(s, w, w.childs.id)
            assert refused.value.status_code == 404 and await _linked(s, w) == set()

        run(go)

    def test_the_refusal_is_identical_to_the_one_for_an_id_that_does_not_exist_so_it_is_not_an_existence_oracle(self):
        async def go(s, w):
            with pytest.raises(HTTPException) as foreign:
                await _add(s, w, w.foreign.id)
            with pytest.raises(HTTPException) as missing:
                await _add(s, w, uuid.uuid4())
            assert (
                (foreign.value.status_code, foreign.value.detail)
                == (missing.value.status_code, missing.value.detail)
                == (404, "Detection rule not found")
            )

        run(go)

    def test_a_pack_that_is_not_the_callers_is_still_refused_first(self):
        async def go(s, w):
            outsider = SimpleNamespace(tenant_id=w.stranger.id)
            with pytest.raises(HTTPException) as refused:
                await mssp.add_rule_to_pack(pack_id=w.pack.id, body=mssp.RulePackRuleAdd(rule_id=w.foreign.id), db=s, current_user=outsider)
            assert refused.value.detail == "Rule pack not found"

        run(go)


class TestTheResolver:
    def test_a_link_that_already_exists_to_a_strangers_rule_does_not_reach_the_child(self):
        """The data the route used to allow, written straight into the table as it may already be in a deployed database."""

        async def go(s, w):
            s.add_all([MSSPRulePackRule(pack_id=w.pack.id, rule_id=w.foreign.id), MSSPRulePackRule(pack_id=w.pack.id, rule_id=w.own.id)])
            await s.commit()
            names = {r.name for r in await resolve_effective_rules(s, w.child.id)}
            assert "STRANGERS-PRIVATE-RULE" not in names and "parents-own-rule" in names

        run(go)

    def test_the_parents_own_rules_and_builtins_still_reach_the_child_through_the_pack(self):
        """include_builtin=False removes the resolver's separate built-in layer, so the PACK is the only way a built-in can appear:
        without this the test passed even when the pack filter dropped built-ins."""

        async def go(s, w):
            s.add_all([MSSPRulePackRule(pack_id=w.pack.id, rule_id=w.own.id), MSSPRulePackRule(pack_id=w.pack.id, rule_id=w.builtin.id)])
            await s.commit()
            resolved = {r.name: r for r in await resolve_effective_rules(s, w.child.id, include_builtin=False)}
            assert resolved["parents-own-rule"].source == "pack"
            assert resolved["platform-builtin"].source == "pack", "a built-in the parent put in its pack must still reach the child"

        run(go)

    def test_the_count_does_not_include_the_foreign_rule_either(self):
        async def go(s, w):
            s.add(MSSPRulePackRule(pack_id=w.pack.id, rule_id=w.foreign.id))
            await s.commit()
            assert (await count_effective_rules(s, w.child.id))["pack"] == 0

        run(go)

    def test_the_resolver_with_packs_switched_off_is_unaffected(self):
        async def go(s, w):
            s.add(MSSPRulePackRule(pack_id=w.pack.id, rule_id=w.own.id))
            await s.commit()
            names = {r.name for r in await resolve_effective_rules(s, w.child.id, include_packs=False)}
            assert "parents-own-rule" not in names

        run(go)


class TestOverrides:
    """`POST /mssp/overrides` verified the CHILD but not the rule: any rule id was accepted, so the foreign key alone was an existence
    oracle for other tenants' rule ids (and an unhandled IntegrityError). The rule must be one that can reach the child: a built-in,
    the parent's own, or the child's own."""

    @staticmethod
    async def _override(s, w, rule_id, child=None):
        body = mssp.RuleOverrideCreate(child_tenant_id=(child or w.child).id, rule_id=rule_id, action="exclude")
        return await mssp.create_rule_override(body=body, db=s, current_user=SimpleNamespace(tenant_id=w.parent.id, id=uuid.uuid4()))

    def test_a_builtin_the_parents_own_rule_and_the_childs_own_rule_can_be_overridden(self):
        async def go(s, w):
            for rule in (w.builtin, w.own, w.childs):
                assert (await self._override(s, w, rule.id)).rule_id == rule.id

        run(go)

    def test_another_tenants_rule_is_refused_with_the_same_404_as_a_missing_id(self):
        async def go(s, w):
            with pytest.raises(HTTPException) as foreign:
                await self._override(s, w, w.foreign.id)
            with pytest.raises(HTTPException) as missing:
                await self._override(s, w, uuid.uuid4())
            assert (
                (foreign.value.status_code, foreign.value.detail)
                == (missing.value.status_code, missing.value.detail)
                == (404, "Detection rule not found")
            )
            stored = (await s.execute(select(MSSPRuleOverride))).scalars().all()
            assert stored == []

        run(go)

    def test_the_child_check_still_comes_first(self):
        async def go(s, w):
            with pytest.raises(HTTPException) as refused:
                await self._override(s, w, w.own.id, child=w.stranger)
            assert refused.value.detail == "Child tenant not found"

        run(go)
