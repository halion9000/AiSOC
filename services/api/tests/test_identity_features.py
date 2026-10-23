"""Features for directory audit entries, and the multi-factor counts."""

from datetime import UTC, datetime
from types import SimpleNamespace

from app.api.v1.endpoints.identity import counts_for_mfa
from app.services.directory_scoring import directory_features, is_role_change, sensitivity_of

NOON = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def test_role_changes_app_consent_and_policy_changes_are_the_most_sensitive():
    for activity in (
        "Add member to role",
        "Add eligible member to role",
        "Remove member from role",
        "Consent to application",
        "Add service principal credentials",
        "Update conditional access policy",
    ):
        assert sensitivity_of(activity, on_others=True) == 3, activity


def test_password_resets_security_methods_and_new_users_matter_but_less():
    for activity in (
        "Reset user password",
        "User registered security info",
        "Add Passkey (device-bound)",
        "Add Windows Hello for Business credential",
        "Add user",
        "Invite external user",
        "Update StsRefreshTokenValidFrom Timestamp",
    ):
        assert sensitivity_of(activity, on_others=True) == 2, activity


def test_updating_your_own_user_is_routine_but_updating_someone_elses_matters():
    assert sensitivity_of("Update user", on_others=False) == 1
    assert sensitivity_of("Update user", on_others=True) == 2
    assert sensitivity_of("Add member to group", on_others=True) == 1, "a group change is not a role change"


def test_features_say_who_did_what_to_whom_and_when():
    f = directory_features(occurred_at=NOON, activity="Reset user password", success=True, actor="Admin@x.com", target="bob@x.com")
    assert f == {"hour_of_day": 12.0, "sensitivity": 2.0, "failed": 0.0, "on_others": 1.0, "security_method": 0.0, "role_change": 0.0}
    own = directory_features(
        occurred_at=NOON, activity="User registered security info", success=True, actor="bob@x.com", target="BOB@x.com"
    )
    assert own["on_others"] == 0.0 and own["security_method"] == 1.0, "the same person in a different case is still themselves"
    role = directory_features(occurred_at=NOON, activity="Add member to role", success=False, actor="a@x.com", target="b@x.com")
    assert (role["role_change"], role["failed"], role["sensitivity"]) == (1.0, 1.0, 3.0)
    assert (
        directory_features(occurred_at=NOON, activity="Add group", success=True, actor="a@x.com", target=None)["on_others"] == 0.0
    ), "no target is not 'someone else'"
    assert is_role_change("Add member to role") and not is_role_change("Add member to group")


def user(**over):
    base = {
        "enabled": True,
        "licensed": True,
        "user_type": "Member",
        "registered": True,
        "ca_enforced": False,
        "security_defaults": False,
        "per_user": None,
        "admin": False,
    }
    base.update(over)
    return SimpleNamespace(**base)


def test_counts_separate_required_not_required_and_missing_and_ignore_accounts_that_are_not_people():
    users = [
        user(ca_enforced=True),
        user(per_user="enforced"),
        user(security_defaults=True),
        user(registered=True),
        user(registered=False),
        user(registered=False, admin=True),
        user(registered=False, licensed=False),
        user(registered=False, enabled=False),
        user(registered=False, user_type="Guest"),
    ]
    assert counts_for_mfa(users) == {"people": 6, "with_mfa": 3, "not_required": 1, "without_mfa": 2, "admins_without_mfa": 1, "registration_unknown": 0}


def test_a_per_user_setting_of_disabled_does_not_count_as_required():
    assert counts_for_mfa([user(per_user="disabled")])["not_required"] == 1
    assert counts_for_mfa([])["people"] == 0
