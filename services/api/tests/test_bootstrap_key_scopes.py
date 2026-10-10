"""Bootstrap keeps an existing key's SECRET but brings its scopes to exactly what is wanted now.

Before this, `_ensure_key` returned "kept-existing" and never touched an existing key's scopes. So a scope added to CORE_KEY_SCOPES (rules:read, for Cipher's detection-engineering tools) reached only fresh installs, and every deployment already running would have got 403s from the new tools until someone
rotated the key and handed the new secret to CORE. A real database (SQLite) is used so the filters by name and tenant are really exercised.
"""
import asyncio
import logging
import uuid

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.db.database import Base
from app.models.tenant import ApiKey, Tenant, User
from app.scripts import bootstrap_production as bp

OLD = ["alerts:read", "alerts:write", "cases:read", "cases:write", "connectors:read"]
NEW = [*OLD, "rules:read"]
OWNER = uuid.uuid4()
OTHER_TENANT = uuid.uuid4()


@pytest.fixture
def world(tmp_path, monkeypatch):
    # The real default tenant id (0000...0001) is a hex string made only of DIGITS; SQLite gives a column declared UUID numeric affinity and would store it as the integer 1
    # (Postgres stores a real UUID). So these tests use a default tenant id that contains hex letters. What is under test is how keys are chosen and changed, not the id.
    monkeypatch.setattr(bp, "DEFAULT_TENANT_ID", uuid.UUID("abcdef00-0000-0000-0000-000000000001"))
    path = tmp_path / "keys.db"
    sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync, tables=[Tenant.__table__, User.__table__, ApiKey.__table__])
    factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool), expire_on_commit=False)

    def add(name="core-hud", scopes=None, active=True, tenant=None, secret="hash-1", prefix="ak_1"):
        with Session(sync, expire_on_commit=False) as s:
            key = ApiKey(tenant_id=tenant or bp.DEFAULT_TENANT_ID, user_id=OWNER, name=name, key_prefix=prefix, hashed_key=secret, scopes=list(scopes if scopes is not None else OLD), is_active=active)
            s.add(key)
            s.commit()
            return key.id

    def rows():
        with Session(sync) as s:
            return {k.id: k for k in s.scalars(select(ApiKey))}

    async def ensure(scopes=None, rotate=False, name="core-hud"):
        async with factory() as session:
            out = await bp._ensure_key(session, name, scopes if scopes is not None else NEW, OWNER, rotate)
            await session.commit()
            return out

    class W:
        pass

    w = W()
    w.add, w.rows, w.ensure = add, rows, lambda *a, **k: asyncio.run(ensure(*a, **k))
    yield w
    sync.dispose()


class TestTheScopes:
    def test_core_key_scopes_are_exactly_these_and_include_the_detection_rules_read(self):
        assert sorted(bp.CORE_KEY_SCOPES) == sorted(NEW)

    def test_the_key_is_still_least_privilege_nothing_that_writes_rules_runs_queries_or_deletes(self):
        for scope in bp.CORE_KEY_SCOPES:
            assert scope not in {"*", "rules:write", "lake:query", "playbooks:execute"} and not scope.endswith(":delete"), scope
        assert "rules:write" not in bp.CORE_KEY_SCOPES and "lake:query" not in bp.CORE_KEY_SCOPES

    def test_the_agents_service_key_did_not_change(self):
        assert sorted(bp.AGENTS_KEY_SCOPES) == ["alerts:read", "cases:read"]


class TestAFreshInstall:
    def test_a_key_is_issued_with_exactly_the_scopes_and_its_secret_is_returned_once(self, world):
        raw, status = world.ensure()
        assert status == "created" and raw
        (key,) = world.rows().values()
        assert key.name == "core-hud" and key.is_active and sorted(key.scopes) == sorted(NEW) and key.tenant_id == bp.DEFAULT_TENANT_ID and key.hashed_key != raw


class TestAnExistingKey:
    def test_the_same_scopes_in_any_order_is_kept_untouched_and_says_nothing(self, world, caplog):
        kid = world.add(scopes=list(reversed(NEW)))
        with caplog.at_level(logging.WARNING):
            assert world.ensure() == (None, "kept-existing")
        assert world.rows()[kid].scopes == list(reversed(NEW)), "an equal set is not rewritten"
        assert not [r for r in caplog.records if "scopes updated" in r.getMessage()]

    def test_a_missing_scope_is_added_in_place_the_secret_and_the_row_unchanged_and_the_change_is_logged(self, world, caplog):
        kid = world.add(scopes=OLD, secret="hash-original", prefix="ak_orig")
        with caplog.at_level(logging.WARNING):
            assert world.ensure() == (None, "scopes-updated")
        key = world.rows()[kid]
        assert sorted(key.scopes) == sorted(NEW) and key.hashed_key == "hash-original" and key.key_prefix == "ak_orig" and key.is_active
        assert len(world.rows()) == 1, "no second key"
        message = next(r.getMessage() for r in caplog.records if "scopes updated" in r.getMessage())
        assert "'core-hud'" in message and "same secret" in message and "['rules:read']" in message and "removed none" in message

    def test_an_extra_scope_is_taken_away_least_privilege_is_restored(self, world, caplog):
        kid = world.add(scopes=[*NEW, "alerts:delete", "lake:query"])
        with caplog.at_level(logging.WARNING):
            assert world.ensure() == (None, "scopes-updated")
        assert sorted(world.rows()[kid].scopes) == sorted(NEW)
        message = next(r.getMessage() for r in caplog.records if "scopes updated" in r.getMessage())
        assert "removed ['alerts:delete', 'lake:query']" in message and "added none" in message

    def test_adding_and_removing_at_once(self, world):
        kid = world.add(scopes=["alerts:read", "alerts:delete"])
        assert world.ensure() == (None, "scopes-updated")
        assert sorted(world.rows()[kid].scopes) == sorted(NEW)

    def test_every_active_key_of_that_name_is_updated(self, world):
        a, b = world.add(secret="h1"), world.add(secret="h2", prefix="ak_2")
        assert world.ensure() == (None, "scopes-updated")
        assert all(sorted(world.rows()[k].scopes) == sorted(NEW) for k in (a, b))

    def test_an_inactive_key_is_left_alone_and_a_fresh_one_is_issued_when_only_inactive_ones_exist(self, world):
        dead = world.add(active=False)
        raw, status = world.ensure()
        assert status == "created" and raw
        assert world.rows()[dead].scopes == OLD and world.rows()[dead].is_active is False
        assert len(world.rows()) == 2

    def test_a_key_with_another_name_or_in_another_tenant_is_never_touched(self, world):
        other_name = world.add(name="agents-service", scopes=["alerts:read"])
        other_tenant = world.add(tenant=OTHER_TENANT)
        kid = world.add()
        assert world.ensure() == (None, "scopes-updated")
        assert world.rows()[other_name].scopes == ["alerts:read"] and world.rows()[other_tenant].scopes == OLD
        assert sorted(world.rows()[kid].scopes) == sorted(NEW)

    def test_a_key_with_no_scopes_recorded_is_brought_to_the_wanted_ones(self, world):
        kid = world.add(scopes=[])
        assert world.ensure() == (None, "scopes-updated")
        assert sorted(world.rows()[kid].scopes) == sorted(NEW)

    def test_duplicates_in_the_wanted_list_do_not_cause_a_change(self, world):
        world.add(scopes=NEW)
        assert world.ensure(scopes=[*NEW, "rules:read", "alerts:read"]) == (None, "kept-existing")

    def test_running_it_twice_changes_once(self, world):
        world.add(scopes=OLD)
        assert world.ensure() == (None, "scopes-updated")
        assert world.ensure() == (None, "kept-existing")


class TestRotation:
    def test_rotating_revokes_the_old_key_leaves_its_scopes_alone_and_issues_a_new_one_with_the_wanted_scopes(self, world):
        old = world.add(scopes=OLD)
        raw, status = world.ensure(rotate=True)
        assert status == "rotated" and raw
        rows = world.rows()
        assert rows[old].is_active is False and rows[old].scopes == OLD
        (new,) = [k for k in rows.values() if k.id != old]
        assert new.is_active and sorted(new.scopes) == sorted(NEW)


class TestTheContractWithCore:
    def test_the_status_for_core_is_one_core_does_not_branch_on(self):
        """CORE's setup (hud/src/aisoc-production.ts) branches on `core_api_key` (a newly issued secret) and on the AGENTS key's status 'kept-existing'; it ignores the core key's status string, so 'scopes-updated' is harmless there."""
        import inspect

        src = inspect.getsource(bp.run)
        assert "result[\"core_api_key\"], result[\"core_key_status\"] = key, status" in src
