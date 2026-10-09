"""The seeded default admin (admin@aisoc.local, public password hash) after a production bootstrap.

Bootstrap applies migrations first, and migration 067 promotes the earliest ACTIVE admin to platform_admin: on a fresh database that is this account. Bootstrap then disables it. Before this fix it stayed platform_admin while disabled (found by bootstrapping an empty database and listing the users): harmless, since it cannot log in, but a disabled
account must not keep elevated rights and it showed up as a platform administrator. It is now demoted to viewer when it is disabled, and an install already in that state is repaired."""
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.scripts import bootstrap_production as bp

HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3EEbF7FtRS"  # the public seed hash


def seeded(role="admin", active=True, hashed=HASH, email=bp.SEEDED_ADMIN_EMAIL):
    return SimpleNamespace(id=bp.SEEDED_ADMIN_ID, email=email, role=role, is_active=active, hashed_password=hashed)


class TestPlan:
    @pytest.mark.parametrize("role", ["admin", "platform_admin", "tenant_admin", "soc_analyst"])
    def test_an_active_seeded_admin_is_disabled_and_demoted_whatever_it_held(self, role):
        newly, values = bp.plan_seeded_admin_update(seeded(role=role))
        assert newly is True
        assert values == {"is_active": False, "hashed_password": "!disabled-by-bootstrap", "role": "viewer"}

    def test_a_disabled_account_that_still_holds_platform_admin_is_repaired_without_reporting_a_new_disable(self):
        newly, values = bp.plan_seeded_admin_update(seeded(role="platform_admin", active=False, hashed="!disabled-by-bootstrap"))
        assert newly is False and values["role"] == "viewer" and values["is_active"] is False

    def test_a_disabled_account_still_holding_the_old_admin_role_is_demoted_too(self):
        newly, values = bp.plan_seeded_admin_update(seeded(role="admin", active=False, hashed="!disabled-by-bootstrap"))
        assert newly is False and values["role"] == "viewer"

    def test_one_already_disabled_and_a_viewer_is_left_alone(self):
        assert bp.plan_seeded_admin_update(seeded(role="viewer", active=False, hashed="!disabled-by-bootstrap")) == (False, None)

    def test_an_inactive_account_whose_hash_is_still_the_public_one_is_treated_as_not_yet_locked(self):
        newly, values = bp.plan_seeded_admin_update(seeded(role="viewer", active=False, hashed=HASH))
        assert newly is True and values["hashed_password"] == "!disabled-by-bootstrap"

    def test_an_active_account_with_a_locked_looking_hash_is_still_disabled(self):
        newly, values = bp.plan_seeded_admin_update(seeded(role="viewer", active=True, hashed="!disabled-by-bootstrap"))
        assert newly is True and values["is_active"] is False

    def test_a_missing_hash_does_not_crash(self):
        newly, values = bp.plan_seeded_admin_update(seeded(role="viewer", active=False, hashed=None))
        assert newly is True and values is not None

    def test_nothing_happens_when_there_is_no_seeded_account(self):
        assert bp.plan_seeded_admin_update(None) == (False, None)

    def test_a_different_account_with_the_seeded_id_but_another_email_is_never_touched(self):
        assert bp.plan_seeded_admin_update(seeded(email="someone@liveoak.example")) == (False, None)

    def test_the_replacement_hash_can_never_verify_as_a_password(self):
        from app.core.security import verify_password

        for attempt in ("admin", "!disabled-by-bootstrap", "", "password", "Fresh-Install-Passw0rd!"):
            assert verify_password(attempt, bp.SEEDED_ADMIN_DISABLED_HASH) is False


class TestWiring:
    src = (Path(__file__).resolve().parent.parent / "app" / "scripts" / "bootstrap_production.py").read_text(encoding="utf-8")

    def test_run_applies_the_plan_and_reports_it(self):
        assert "newly_disabled, seeded_values = plan_seeded_admin_update(seeded)" in self.src
        assert 'update(User).where(User.id == SEEDED_ADMIN_ID).values(**seeded_values)' in self.src
        assert 'result["default_admin_disabled"] = newly_disabled' in self.src

    def test_the_demotion_target_is_not_an_elevated_role(self):
        from app.core.security import ROLE_PERMISSIONS

        perms = ROLE_PERMISSIONS[bp.SEEDED_ADMIN_DISABLED_ROLE]
        assert "*" not in perms and not any(p.endswith(":admin") or p.endswith(":write") for p in perms)

    def test_the_real_admin_is_still_created_as_platform_admin(self):
        assert re.search(r'role="platform_admin"', self.src)
