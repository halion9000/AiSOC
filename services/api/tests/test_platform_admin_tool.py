"""The platform_admin tool (list / grant / revoke) and migration 067.

The original primary administrator is a platform_admin by default (bootstrap_production for new installs, migration 067 for existing ones); this tool gives the role to specific people or takes it away when you have database access. Revoking the LAST active platform_admin is refused unless --force is given,
because nobody could then administer the platform."""
import json
import re
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.scripts import platform_admin as pa

API = Path(__file__).resolve().parent.parent


def user(email, role="admin", active=True):
    return SimpleNamespace(id=uuid.uuid4(), email=email, role=role, is_active=active, tenant_id=uuid.uuid4())


class FakeSession:
    """Answers queued results in order; records every statement."""

    def __init__(self, *payloads):
        self.queue, self.statements, self.bound = list(payloads), [], []
        self.commit = AsyncMock()
        self.execute = AsyncMock(side_effect=self._execute)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def _execute(self, stmt, *a, **k):
        self.statements.append(" ".join(str(stmt.compile()).split()).upper())
        self.bound.append(dict(stmt.compile().params))
        payload = self.queue.pop(0) if self.queue else None
        res = MagicMock()
        res.scalar_one_or_none.return_value = payload
        res.scalar_one.return_value = payload
        res.scalars.return_value.all.return_value = payload if isinstance(payload, list) else []
        return res

    @property
    def updates(self):
        return [s for s in self.statements if s.startswith("UPDATE")]

    @property
    def written_roles(self):
        """The role value each UPDATE actually sets (what lands in the database, not what the tool reports)."""
        return [b.get("role") for st, b in zip(self.statements, self.bound) if st.startswith("UPDATE")]


@pytest.fixture
def session(monkeypatch):
    def install(*payloads):
        s = FakeSession(*payloads)
        monkeypatch.setattr("app.db.database.AsyncSessionLocal", lambda: s)
        return s

    return install


@pytest.mark.asyncio
class TestList:
    async def test_it_lists_the_platform_admins_with_their_state(self, session):
        a, b = user("a@example.com", "platform_admin"), user("b@example.com", "platform_admin", active=False)
        s = session([a, b])
        out = await pa.run("list")
        assert out["ok"] and [x["email"] for x in out["platform_admins"]] == ["a@example.com", "b@example.com"]
        assert [x["active"] for x in out["platform_admins"]] == [True, False]
        assert s.updates == []


@pytest.mark.asyncio
class TestGrant:
    async def test_it_makes_a_user_a_platform_admin(self, session):
        u = user("new@example.com", "tenant_admin")
        s = session(u, None)
        out = await pa.run("grant", "NEW@Example.com")
        assert out == {"ok": True, "email": "new@example.com", "role": "platform_admin", "previous_role": "tenant_admin", "changed": True}
        assert len(s.updates) == 1 and "USERS" in s.updates[0]
        assert s.written_roles == ["platform_admin"]  # what is WRITTEN, not just what is reported
        s.commit.assert_awaited_once()

    async def test_the_email_lookup_is_case_insensitive(self, session):
        s = session(user("x@example.com"), None)
        await pa.run("grant", "X@EXAMPLE.COM")
        assert "LOWER(" in s.statements[0]

    async def test_an_unknown_email_is_an_error_and_changes_nothing(self, session):
        s = session(None)
        with pytest.raises(pa.PlatformAdminError, match="No user"):
            await pa.run("grant", "ghost@example.com")
        assert s.updates == []

    async def test_a_deactivated_account_cannot_be_granted_platform_power(self, session):
        s = session(user("old@example.com", "admin", active=False))
        with pytest.raises(pa.PlatformAdminError, match="deactivated"):
            await pa.run("grant", "old@example.com")
        assert s.updates == []
        s.commit.assert_not_awaited()

    async def test_granting_to_an_existing_platform_admin_changes_nothing(self, session):
        s = session(user("pa@example.com", "platform_admin"))
        out = await pa.run("grant", "pa@example.com")
        assert out["changed"] is False and s.updates == []
        s.commit.assert_not_awaited()

    async def test_an_email_is_required(self, session):
        session()
        with pytest.raises(pa.PlatformAdminError, match="--email"):
            await pa.run("grant", None)


@pytest.mark.asyncio
class TestRevoke:
    async def test_it_demotes_to_tenant_admin_by_default_when_others_remain(self, session):
        s = session(user("pa@example.com", "platform_admin"), 1)
        out = await pa.run("revoke", "pa@example.com")
        assert out["role"] == "tenant_admin" and out["previous_role"] == "platform_admin" and out["changed"] is True
        assert len(s.updates) == 1 and s.written_roles == ["tenant_admin"]
        s.commit.assert_awaited_once()

    async def test_it_can_demote_to_a_chosen_role_and_writes_exactly_that_role(self, session):
        s = session(user("pa@example.com", "platform_admin"), 2)
        out = await pa.run("revoke", "pa@example.com", to_role="viewer")
        assert out["role"] == "viewer"
        assert s.written_roles == ["viewer"]

    async def test_the_last_active_platform_admin_cannot_be_revoked(self, session):
        s = session(user("only@example.com", "platform_admin"), 0)
        with pytest.raises(pa.PlatformAdminError, match="last active platform_admin"):
            await pa.run("revoke", "only@example.com")
        assert s.updates == []
        s.commit.assert_not_awaited()

    async def test_force_overrides_the_last_admin_protection(self, session):
        s = session(user("only@example.com", "platform_admin"), 0)
        out = await pa.run("revoke", "only@example.com", force=True)
        assert out["changed"] is True and len(s.updates) == 1 and s.written_roles == ["tenant_admin"]

    async def test_the_count_of_others_excludes_the_user_and_inactive_accounts(self, session):
        s = session(user("pa@example.com", "platform_admin"), 1)
        await pa.run("revoke", "pa@example.com")
        count_sql = s.statements[1]
        assert "COUNT" in count_sql and "USERS.ID !=" in count_sql and "IS_ACTIVE IS NOT" in count_sql

    @pytest.mark.parametrize("bad", ["platform_admin", "overlord", ""])
    async def test_the_target_role_must_be_a_known_non_platform_role(self, session, bad):
        s = session(user("pa@example.com", "platform_admin"), 5)
        with pytest.raises(pa.PlatformAdminError, match="--to-role"):
            await pa.run("revoke", "pa@example.com", to_role=bad)
        assert s.updates == []

    async def test_revoking_from_someone_who_is_not_a_platform_admin_changes_nothing(self, session):
        s = session(user("t@example.com", "tenant_admin"))
        out = await pa.run("revoke", "t@example.com")
        assert out["changed"] is False and s.updates == []

    async def test_an_unknown_action_is_an_error(self, session):
        session(user("a@example.com"))
        with pytest.raises(pa.PlatformAdminError, match="Unknown action"):
            await pa.run("promote", "a@example.com")


class TestCommandLine:
    def test_a_success_prints_json_and_exits_zero(self, monkeypatch, capsys):
        monkeypatch.setattr(pa, "run", AsyncMock(return_value={"ok": True, "platform_admins": []}))
        assert pa.main(["list"]) == 0
        assert json.loads(capsys.readouterr().out)["ok"] is True

    def test_an_error_prints_json_and_exits_one(self, monkeypatch, capsys):
        monkeypatch.setattr(pa, "run", AsyncMock(side_effect=pa.PlatformAdminError("nope")))
        assert pa.main(["revoke", "--email", "a@example.com"]) == 1
        assert json.loads(capsys.readouterr().out) == {"ok": False, "error": "nope"}

    def test_the_arguments_reach_run(self, monkeypatch):
        run = AsyncMock(return_value={"ok": True})
        monkeypatch.setattr(pa, "run", run)
        pa.main(["revoke", "--email", "a@example.com", "--to-role", "viewer", "--force"])
        run.assert_awaited_once_with("revoke", "a@example.com", to_role="viewer", force=True)

    def test_grant_and_revoke_require_an_email(self):
        for argv in (["grant"], ["revoke"]):
            with pytest.raises(SystemExit):
                pa.main(argv)


class TestMigration067:
    sql = (API / "migrations" / "067_primary_admin_platform_role.sql").read_text(encoding="utf-8")

    def norm(self):
        return " ".join(re.sub(r"--[^\n]*", "", self.sql).split())

    def test_it_is_transactional_and_follows_066(self):
        names = sorted(p.name for p in (API / "migrations").glob("*.sql"))
        assert self.sql.count("BEGIN;") == 1 and self.sql.count("COMMIT;") == 1
        assert names.index("067_primary_admin_platform_role.sql") == names.index("066_clean_user_object_repr.sql") + 1

    def test_it_promotes_exactly_one_user_the_earliest_active_admin(self):
        n = self.norm()
        assert "UPDATE users SET role = 'platform_admin'" in n
        assert "WHERE role = 'admin' AND is_active IS NOT FALSE ORDER BY created_at ASC NULLS LAST, id ASC LIMIT 1" in n

    def test_it_never_overrides_an_existing_platform_admin(self):
        assert "AND NOT EXISTS (SELECT 1 FROM users WHERE role = 'platform_admin')" in self.norm()

    def test_it_touches_nothing_else(self):
        n = self.norm()
        assert n.count("UPDATE ") == 1 and "DELETE" not in n.upper() and "DROP" not in n.upper() and "INSERT" not in n.upper()
