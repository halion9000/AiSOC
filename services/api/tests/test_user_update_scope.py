"""Updating a user is scoped to the caller's tenant by the UPDATE itself, not only by the load before it.

`users` has no row-level security (it is read before any tenant is known, at sign-in), so every statement that changes a user carries its
own tenant predicate. update_user loads the user with the caller's tenant id first (404 otherwise) and then applies the privilege checks;
the UPDATE used to be `WHERE id = :user_id` alone,
safe only because of that order. Found by sweeping every ORM statement on a table without row-level security (14 of 31 had no tenant
mention: 13 are the caller's own row, the key-to-user lookup, operator CLIs, passkey and password sign-in, and the platform-wide
account-name lookups, all by design).
"""

import inspect
import re

from app.api.v1.endpoints import tenants


def _source() -> str:
    return inspect.getsource(tenants.update_user)


def test_the_update_carries_the_callers_tenant():
    assert "update(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id).values(**updates)" in _source()


def test_the_load_before_it_is_still_scoped_and_answers_404_for_another_tenants_user():
    source = _source()
    assert "select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id)" in source
    assert 'status_code=status.HTTP_404_NOT_FOUND, detail="User not found"' in source


def test_no_statement_in_the_handler_changes_a_user_without_the_tenant():
    for statement in re.findall(r"update\(User\)[^\n]*", _source()):
        assert "User.tenant_id == current_user.tenant_id" in statement, statement


def test_the_privilege_checks_still_come_before_any_write():
    source = _source()
    assert source.index("can_grant_role") < source.index("update(User)") and source.index(
        "You cannot change your own role."
    ) < source.index("update(User)")
