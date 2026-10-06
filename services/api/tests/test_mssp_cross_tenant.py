"""MSSP cross-tenant integrity, against a REAL database engine (in-memory SQLite).

The attack these tests pin down: any logged-in user, in any tenant, could file a
rule override naming a VICTIM's tenant id as the "child" with action "exclude".
The rule resolver matched overrides on child_tenant_id alone, so the victim's
detection rule silently stopped applying. Built-in rule ids are identical in every
tenant, so the attacker needed nothing but the victim's tenant id.

Two fixes, both tested here:
  1. the handlers refuse to write a child that is not the caller's own
  2. the resolver only honours overrides / pack assignments that come from the
     child's REAL parent, which also neutralises rows already sitting in a database
"""
import asyncio
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.v1.endpoints import mssp
from app.db.database import Base
from app.models.detection_rule import DetectionRule
from app.models.mssp import MSSPDelegation, MSSPRuleOverride, MSSPRulePack, MSSPRulePackAssignment, MSSPRulePackRule, MSSPTenantNote
from app.models.tenant import Tenant
from app.services.mssp_rule_resolver import count_effective_rules, resolve_effective_rules

TABLES = [m.__table__ for m in (Tenant, DetectionRule, MSSPRuleOverride, MSSPRulePack, MSSPRulePackAssignment, MSSPRulePackRule, MSSPTenantNote, MSSPDelegation)]


def run(coro_fn):
    """Run `coro_fn(session, world)` against a fresh seeded in-memory database."""

    async def main():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as c:
            await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=TABLES))
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            def tenant(name, parent=None):
                t = Tenant(id=uuid.uuid4(), name=name, slug=f"{name}-{uuid.uuid4().hex[:6]}", parent_tenant_id=parent)
                s.add(t)
                return t

            mssp_parent = tenant("mssp-parent")
            await s.flush()
            world = SimpleNamespace(
                parent=mssp_parent,
                child=tenant("customer", parent=mssp_parent.id),
                attacker=tenant("attacker"),
                victim=tenant("victim"),  # an ordinary tenant with no MSSP parent
            )
            world.rule = DetectionRule(id=uuid.uuid4(), name="Impossible travel", rule_language="sigma", rule_body="x", category="identity",
                                       tenant_id=None, is_builtin=True, status="active")
            s.add(world.rule)
            await s.commit()
            try:
                return await coro_fn(s, world)
            finally:
                await engine.dispose()

    return asyncio.run(main())


def _override(parent, child, rule, action="exclude"):
    return MSSPRuleOverride(id=uuid.uuid4(), parent_tenant_id=parent.id, child_tenant_id=child.id, rule_id=rule.id, action=action)


def _ids(rules):
    return {r.id for r in rules}


# ------------------------------------------------------------------ resolver ----
def test_the_real_parents_override_still_works():
    async def go(s, w):
        s.add(_override(w.parent, w.child, w.rule))
        await s.commit()
        return _ids(await resolve_effective_rules(s, w.child.id))

    assert run(go) == set(), "the legitimate parent's exclude must still take effect"


def test_attackers_override_naming_a_victim_with_no_parent_does_nothing():
    async def go(s, w):
        s.add(_override(w.attacker, w.victim, w.rule))
        await s.commit()
        return w.rule.id in _ids(await resolve_effective_rules(s, w.victim.id))

    assert run(go) is True, "the victim's detection rule was disabled by another tenant"


def test_attackers_override_naming_someone_elses_child_does_nothing():
    async def go(s, w):
        s.add(_override(w.attacker, w.child, w.rule))  # the child belongs to mssp-parent, not the attacker
        await s.commit()
        return w.rule.id in _ids(await resolve_effective_rules(s, w.child.id))

    assert run(go) is True


def test_the_excluded_counter_ignores_the_attackers_row_too():
    async def go(s, w):
        s.add(_override(w.attacker, w.victim, w.rule))
        s.add(_override(w.parent, w.child, w.rule))
        await s.commit()
        return (await count_effective_rules(s, w.victim.id))["excluded"], (await count_effective_rules(s, w.child.id))["excluded"]

    assert run(go) == (0, 1)


def test_a_customize_override_cannot_lower_a_victims_severity_either():
    async def go(s, w):
        ov = _override(w.attacker, w.victim, w.rule, action="customize")
        ov.severity_override = "low"
        s.add(ov)
        await s.commit()
        return [r.severity for r in await resolve_effective_rules(s, w.victim.id) if r.id == w.rule.id]

    assert run(go) != ["low"]


def test_a_pack_from_a_tenant_that_is_not_the_parent_is_not_applied():
    async def go(s, w):
        pack = MSSPRulePack(id=uuid.uuid4(), parent_tenant_id=w.attacker.id, name="evil pack")
        own_rule = DetectionRule(id=uuid.uuid4(), name="attacker rule", rule_language="sigma", rule_body="x", category="x",
                                 tenant_id=w.attacker.id, is_builtin=False, status="active")
        s.add_all([pack, own_rule])
        await s.flush()
        s.add(MSSPRulePackRule(pack_id=pack.id, rule_id=own_rule.id))
        s.add(MSSPRulePackAssignment(id=uuid.uuid4(), pack_id=pack.id, child_tenant_id=w.child.id, enabled=True))
        await s.commit()
        return own_rule.id in _ids(await resolve_effective_rules(s, w.child.id))

    assert run(go) is False


# ------------------------------------------------------------------ handlers ----
def _caller(tenant):
    return SimpleNamespace(id=uuid.uuid4(), tenant_id=tenant.id, role="tenant_admin")


def test_handlers_refuse_a_child_that_is_not_the_callers():
    async def go(s, w):
        me = _caller(w.attacker)
        refused = {}
        for name, call in {
            "override": lambda: mssp.create_rule_override(SimpleNamespace(child_tenant_id=w.victim.id, rule_id=w.rule.id, action="exclude", note=None,
                                                                          severity_override=None, parameter_overrides=None), db=s, current_user=me),
            "delegation": lambda: mssp.create_delegation(SimpleNamespace(child_tenant_id=w.victim.id, granted_role="soc_analyst", expires_at=None), db=s, current_user=me),
            "note": lambda: mssp.create_note(SimpleNamespace(child_id=w.victim.id, body="x"), db=s, current_user=me),
        }.items():
            try:
                await call()
                refused[name] = False
            except HTTPException as e:
                refused[name] = e.status_code == 404
        return refused

    assert run(go) == {"override": True, "delegation": True, "note": True}


def test_a_parent_can_still_write_for_its_own_child():
    async def go(s, w):
        me = _caller(w.parent)
        await mssp.create_rule_override(SimpleNamespace(child_tenant_id=w.child.id, rule_id=w.rule.id, action="exclude", note=None,
                                                        severity_override=None, parameter_overrides=None), db=s, current_user=me)
        await mssp.create_note(SimpleNamespace(child_id=w.child.id, body="hello"), db=s, current_user=me)
        await mssp.create_delegation(SimpleNamespace(child_tenant_id=w.child.id, granted_role="soc_analyst", expires_at=None), db=s, current_user=me)
        return w.rule.id in _ids(await resolve_effective_rules(s, w.child.id))

    assert run(go) is False  # the override it just created applies to its own child


@pytest.mark.parametrize("role", ["platform_admin", "admin", "not-a-role"])
def test_a_delegation_cannot_grant_a_wildcard_or_made_up_role(role):
    async def go(s, w):
        try:
            await mssp.create_delegation(SimpleNamespace(child_tenant_id=w.child.id, granted_role=role, expires_at=None), db=s, current_user=_caller(w.parent))
            return None
        except HTTPException as e:
            return e.status_code

    assert run(go) == 422


@pytest.mark.parametrize("role", ["tenant_admin", "soc_lead", "soc_analyst", "threat_hunter", "viewer"])
def test_ordinary_roles_remain_delegable(role):
    async def go(s, w):
        return await mssp.create_delegation(SimpleNamespace(child_tenant_id=w.child.id, granted_role=role, expires_at=None), db=s, current_user=_caller(w.parent))

    assert run(go).granted_role == role
