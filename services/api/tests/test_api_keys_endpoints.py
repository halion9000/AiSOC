"""API key endpoints: the raw key is shown once and only its hash is stored, everything is tenant-scoped, and revoking deactivates.

Scope-holding (nobody can mint a key wider than themselves) is covered in test_platform_permissions.py; this file covers the rest of the
endpoint behavior. NOT VERIFIED LIVE: the session is a fake, so SQL execution and the real ORM refresh were not exercised.
"""

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import api_keys as ak
from app.models.tenant import ApiKey
from fastapi import HTTPException
from pydantic import ValidationError

TENANT = uuid.uuid4()


def run(coro):
    return asyncio.run(coro)


def admin(scopes=None, tenant=TENANT):
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant, role="admin", email="a@example.test", scopes=scopes)


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class FakeDB:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.statements = []
        self.added = []
        self.commits = 0

    async def execute(self, statement):
        self.statements.append(statement)
        return _Result(self.rows)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.commits += 1

    async def refresh(self, obj):
        obj.id = obj.id or uuid.uuid4()
        obj.created_at = obj.created_at or datetime.now(UTC)


def literal(statement) -> str:
    return str(statement.compile(compile_kwargs={"literal_binds": True}))


def stored_key(**over):
    base = dict(  # noqa: C408
        id=uuid.uuid4(),
        tenant_id=TENANT,
        user_id=uuid.uuid4(),
        name="k",
        key_prefix="aisoc_abc123",
        hashed_key="h" * 64,
        scopes=["alerts:read"],
        is_active=True,
        expires_at=None,
        last_used_at=None,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    base.update(over)
    return ApiKey(**base)


# --- scopes ----------------------------------------------------------------------------------------------------------------------


def test_validate_scopes_accepts_known_and_lists_every_unknown_one():
    ak._validate_scopes(["alerts:read", "*"])
    ak._validate_scopes([])
    with pytest.raises(HTTPException) as exc:
        ak._validate_scopes(["alerts:read", "alerts:fly", "root"])
    assert exc.value.status_code == 422
    assert "alerts:fly" in exc.value.detail and "root" in exc.value.detail.split("Valid scopes")[0]


def test_every_valid_scope_is_checked_by_some_route_or_granted_by_a_role():
    """A scope no route checks and no role grants is a dead entry: a key carrying it can do nothing, and the docs promise otherwise."""
    from app.core.security import known_permissions
    from app.main import app
    from route_introspect import required_permissions, walk_routes

    checked = {p for _, route in walk_routes(app.routes) for p in required_permissions(route)}
    dead = {s for s in ak.VALID_SCOPES if s != "*"} - known_permissions() - checked
    assert not dead, f"scopes a key can carry that nothing uses: {sorted(dead)}"


# --- create ----------------------------------------------------------------------------------------------------------------------


def test_create_returns_the_raw_key_once_and_stores_only_its_hash():
    db, user = FakeDB(), admin()
    out = run(ak.create_api_key(ak.CreateApiKeyRequest(name="ci", scopes=["alerts:read"]), db, user))
    assert out.key.startswith("aisoc_") and out.key.startswith(out.prefix) and len(out.prefix) == 12
    (row,) = db.added
    assert row.hashed_key == hashlib.sha256(out.key.encode()).hexdigest()
    assert out.key not in {row.hashed_key, row.key_prefix, row.name}
    assert row.tenant_id == user.tenant_id and row.user_id == user.user_id and row.is_active is True
    assert row.scopes == ["alerts:read"] and db.commits == 1 and out.expires_at is None


def test_create_keys_are_unique():
    keys = {run(ak.create_api_key(ak.CreateApiKeyRequest(name="n"), FakeDB(), admin())).key for _ in range(5)}
    assert len(keys) == 5


def test_create_sets_expiry_from_now():
    before = datetime.now(UTC)
    out = run(ak.create_api_key(ak.CreateApiKeyRequest(name="n", expires_in_days=30), FakeDB(), admin()))
    assert before + timedelta(days=30) <= out.expires_at <= datetime.now(UTC) + timedelta(days=30)


def test_create_refuses_invalid_scopes_before_storing_anything():
    db = FakeDB()
    with pytest.raises(HTTPException) as exc:
        run(ak.create_api_key(ak.CreateApiKeyRequest(name="n", scopes=["nope"]), db, admin()))
    assert exc.value.status_code == 422 and db.added == [] and db.commits == 0


def test_create_refuses_scopes_the_creator_does_not_hold():
    db = FakeDB()
    narrow = admin(scopes=["alerts:read", "users:write"])
    with pytest.raises(HTTPException) as exc:
        run(ak.create_api_key(ak.CreateApiKeyRequest(name="n", scopes=["alerts:write"]), db, narrow))
    assert exc.value.status_code == 403 and db.added == []


@pytest.mark.parametrize(
    "bad", [{"name": ""}, {"name": "x" * 256}, {"name": "n", "expires_in_days": 0}, {"name": "n", "expires_in_days": 3651}]
)
def test_create_request_bounds(bad):
    with pytest.raises(ValidationError):
        ak.CreateApiKeyRequest(**bad)


# --- read ------------------------------------------------------------------------------------------------------------------------


def test_list_is_scoped_to_the_callers_tenant_newest_first_and_never_includes_the_hash():
    other = uuid.uuid4()
    db = FakeDB([stored_key(name="one")])
    out = run(ak.list_api_keys(db, admin(tenant=other)))
    sql = literal(db.statements[0])
    assert str(other).replace("-", "") in sql.replace("-", "") and "ORDER BY api_keys.created_at DESC" in sql
    assert [o.name for o in out] == ["one"]
    assert "hashed_key" not in out[0].model_dump()


def test_get_is_scoped_by_id_and_tenant_and_404s_when_absent():
    key = stored_key()
    db = FakeDB([key])
    user = admin()
    assert run(ak.get_api_key(key.id, db, user)).id == key.id
    sql = literal(db.statements[0]).replace("-", "")
    assert str(key.id).replace("-", "") in sql and str(user.tenant_id).replace("-", "") in sql
    with pytest.raises(HTTPException) as exc:
        run(ak.get_api_key(uuid.uuid4(), FakeDB(), user))
    assert exc.value.status_code == 404


def test_out_model_maps_prefix_and_defaults_missing_scopes_to_empty():
    out = ak._api_key_to_out(stored_key(scopes=None, key_prefix="aisoc_zzzzzz"))
    assert out.prefix == "aisoc_zzzzzz" and out.scopes == []


# --- update ----------------------------------------------------------------------------------------------------------------------


def test_patch_changes_only_what_was_sent():
    key = stored_key(name="old", scopes=["alerts:read"])
    db = FakeDB([key])
    user = admin()
    out = run(ak.update_api_key(key.id, ak.UpdateApiKeyRequest(name="new"), db, user))
    assert str(user.tenant_id).replace("-", "") in literal(db.statements[0]).replace("-", ""), (
        "update must be scoped to the caller's tenant"
    )
    assert out.name == "new" and key.scopes == ["alerts:read"] and key.expires_at is None and db.commits == 1


def test_patch_scopes_are_validated_and_must_be_held():
    key = stored_key()
    with pytest.raises(HTTPException) as exc:
        run(ak.update_api_key(key.id, ak.UpdateApiKeyRequest(scopes=["nope"]), FakeDB([key]), admin()))
    assert exc.value.status_code == 422
    with pytest.raises(HTTPException) as exc:
        run(ak.update_api_key(key.id, ak.UpdateApiKeyRequest(scopes=["alerts:write"]), FakeDB([key]), admin(scopes=["users:write"])))
    assert exc.value.status_code == 403
    assert key.scopes == ["alerts:read"], "a refused update must leave the key untouched"


def test_patch_resets_expiry_from_now_and_404s_for_another_tenants_key():
    key = stored_key()
    run(ak.update_api_key(key.id, ak.UpdateApiKeyRequest(expires_in_days=7), FakeDB([key]), admin()))
    assert key.expires_at > datetime.now(UTC) + timedelta(days=6)
    with pytest.raises(HTTPException) as exc:
        run(ak.update_api_key(uuid.uuid4(), ak.UpdateApiKeyRequest(name="x"), FakeDB(), admin()))
    assert exc.value.status_code == 404


# --- revoke ----------------------------------------------------------------------------------------------------------------------


def test_revoke_deactivates_without_deleting_and_404s_when_absent():
    key = stored_key()
    db = FakeDB([key])
    user = admin()
    assert run(ak.revoke_api_key(key.id, db, user)) is None
    sql = literal(db.statements[0]).replace("-", "")
    assert str(user.tenant_id).replace("-", "") in sql and str(key.id).replace("-", "") in sql, (
        "revoke must be scoped to the caller's tenant"
    )
    assert key.is_active is False and db.commits == 1
    with pytest.raises(HTTPException) as exc:
        run(ak.revoke_api_key(uuid.uuid4(), FakeDB(), admin()))
    assert exc.value.status_code == 404
