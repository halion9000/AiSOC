"""Production bootstrap for a self-hosted AiSOC (idempotent).

Run inside the api container once the database is up:

    AISOC_BOOTSTRAP_ADMIN_PASSWORD=... \\
    python -m app.scripts.bootstrap_production --admin-email you@example.com

What it does, in order (every step is safe to repeat):
  1. Applies every SQL migration and FAILS if any did not apply. (The plain
     runner logs failures and still exits 0; that would leave a half-built
     production schema.)
  2. Verifies every ORM table exists, and fails otherwise.
  3. Disables the seeded default admin (admin@aisoc.local, created by
     001_init.sql with a password hash that is public in the repository).
  4. Creates the real admin from --admin-email with the password supplied in
     AISOC_BOOTSTRAP_ADMIN_PASSWORD (never on the command line). If that
     email already exists it is left untouched.
  5. Issues CORE's integration API key ("core-hud") with only the scopes CORE
     uses. If an active one exists it is kept and no key is printed, unless
     --rotate-core-key is given (old key revoked, new key printed).
  6. Issues the agents service's own read-only key ("agents-service") the same
     way (--rotate-agents-key to replace it). CORE passes it to the agents
     container as AGENTS_API_TOKEN.

The last line of output is machine-readable:
    AISOC_BOOTSTRAP_RESULT {"ok": true, ...}
The raw API key appears there once and is never stored by AiSOC (only its hash).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import uuid

DEFAULT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
SEEDED_ADMIN_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")
SEEDED_ADMIN_EMAIL = "admin@aisoc.local"
CORE_KEY_NAME = "core-hud"
# Exactly what CORE calls: alerts (read, claim/escalate/snooze), cases and
# investigations (cases:*), and connector listing/health. No delete rights,
# no playbook execution, no connector changes.
CORE_KEY_SCOPES = ["alerts:read", "alerts:write", "cases:read", "cases:write", "connectors:read"]
# The agents service's own key, for background calls it makes without a user
# behind them (attack-path, blast-radius and neighbor graphs during an
# investigation). Those endpoints need only an authenticated caller; read-only.
AGENTS_KEY_NAME = "agents-service"
AGENTS_KEY_SCOPES = ["alerts:read", "cases:read"]
RESULT_MARKER = "AISOC_BOOTSTRAP_RESULT "
MIN_PASSWORD_LENGTH = 12
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class BootstrapError(RuntimeError):
    """A step failed; the message says what and how to fix it."""


def validate_inputs(email: str, password: str | None) -> None:
    if not _EMAIL_RE.match(email or ""):
        raise BootstrapError(f"--admin-email {email!r} is not a valid email address.")
    if email.strip().lower() == SEEDED_ADMIN_EMAIL:
        raise BootstrapError(f"{SEEDED_ADMIN_EMAIL} is the seeded default account; choose a real email.")
    if password is not None and len(password) < MIN_PASSWORD_LENGTH:
        raise BootstrapError(f"The admin password must be at least {MIN_PASSWORD_LENGTH} characters.")


def missing_migrations(files: list[str], applied: set[str]) -> list[str]:
    """Migration files that are not recorded as applied (pure; unit-tested)."""
    return sorted(f for f in files if f not in applied)


async def _apply_migrations_strict() -> int:
    from app.scripts import run_migrations as rm  # noqa: PLC0415

    await rm.main()
    files = sorted(p.name for p in rm.MIGRATIONS_DIR.iterdir() if p.suffix == ".sql")
    dsn, kwargs = rm._asyncpg_dsn(str(rm.settings.DATABASE_URL))
    import asyncpg  # noqa: PLC0415

    conn = await asyncpg.connect(dsn, timeout=10, **kwargs)
    try:
        applied = {r["name"] for r in await conn.fetch("SELECT name FROM aisoc_schema_migrations")}
    finally:
        await conn.close()
    missing = missing_migrations(files, applied)
    if missing:
        raise BootstrapError(
            f"{len(missing)} migration(s) did not apply: {', '.join(missing[:5])}"
            f"{' ...' if len(missing) > 5 else ''}. See the log above for the SQL error."
        )
    return len(files)


async def _verify_orm_tables(session) -> None:
    import app.models  # noqa: F401,PLC0415  (registers every model)
    from sqlalchemy import text  # noqa: PLC0415

    from app.db.database import Base  # noqa: PLC0415

    rows = await session.execute(
        text("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()")
    )
    present = {r[0] for r in rows}
    missing = sorted(set(Base.metadata.tables) - present)
    if missing:
        raise BootstrapError(f"ORM tables missing after migrations: {', '.join(missing)}. Add a SQL migration for them.")


async def _ensure_key(session, name: str, scopes: list[str], owner_id, rotate: bool) -> tuple[str | None, str]:
    """Keep an active key named `name`, or issue one. Returns (raw key or None, status).

    The raw key is returned ONLY when issued now (it is shown once; AiSOC stores
    its hash). With rotate=True any active key of that name is revoked first.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    from sqlalchemy import select  # noqa: PLC0415

    from app.core.security import generate_api_key  # noqa: PLC0415
    from app.models.tenant import ApiKey  # noqa: PLC0415

    active = (
        await session.execute(
            select(ApiKey).where(ApiKey.name == name, ApiKey.tenant_id == DEFAULT_TENANT_ID, ApiKey.is_active.is_(True))
        )
    ).scalars().all()
    if active and not rotate:
        return None, "kept-existing"
    for old in active:
        old.is_active = False
    raw_key, prefix, hashed_key = generate_api_key()
    session.add(
        ApiKey(
            tenant_id=DEFAULT_TENANT_ID,
            user_id=owner_id,
            name=name,
            key_prefix=prefix,
            hashed_key=hashed_key,
            scopes=list(scopes),
            is_active=True,
            expires_at=None,
            created_at=datetime.now(UTC),
        )
    )
    return raw_key, ("rotated" if active else "created")


async def run(email: str, password: str | None, rotate_core_key: bool, rotate_agents_key: bool = False) -> dict:
    from datetime import UTC, datetime  # noqa: PLC0415

    from sqlalchemy import select, update  # noqa: PLC0415

    from app.core.security import generate_api_key, get_password_hash  # noqa: PLC0415
    from app.db.database import AsyncSessionLocal  # noqa: PLC0415
    from app.models.tenant import ApiKey, User  # noqa: PLC0415

    email = email.strip().lower()
    result: dict = {"ok": False, "admin_email": email}
    result["migrations"] = await _apply_migrations_strict()

    async with AsyncSessionLocal() as session:
        await _verify_orm_tables(session)

        # 3. Disable the seeded default admin (public password hash).
        seeded = (await session.execute(select(User).where(User.id == SEEDED_ADMIN_ID))).scalar_one_or_none()
        if seeded is not None and seeded.email == SEEDED_ADMIN_EMAIL and (seeded.is_active or seeded.hashed_password[:1] != "!"):
            await session.execute(
                update(User).where(User.id == SEEDED_ADMIN_ID).values(is_active=False, hashed_password="!disabled-by-bootstrap")
            )
            result["default_admin_disabled"] = True
        else:
            result["default_admin_disabled"] = False

        # 4. The real admin.
        admin = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if admin is None:
            if not password:
                raise BootstrapError(
                    "AISOC_BOOTSTRAP_ADMIN_PASSWORD is required to create the admin account (it does not exist yet)."
                )
            admin = User(
                id=uuid.uuid4(),
                tenant_id=DEFAULT_TENANT_ID,
                email=email,
                username=email,
                hashed_password=get_password_hash(password),
                # The primary administrator is the one default holder of PLATFORM permissions (plugin administration, tenant onboarding, cross-tenant search). Others get them only by being granted
                # the role deliberately (python -m app.scripts.platform_admin grant --email ...).
                role="platform_admin",
                is_active=True,
                is_verified=True,
            )
            session.add(admin)
            await session.flush()
            result["admin_created"] = True
        else:
            result["admin_created"] = False

        # 5. CORE's integration key, 6. the agents service's own key.
        key, status = await _ensure_key(session, CORE_KEY_NAME, CORE_KEY_SCOPES, admin.id, rotate_core_key)
        result["core_api_key"], result["core_key_status"] = key, status
        key, status = await _ensure_key(session, AGENTS_KEY_NAME, AGENTS_KEY_SCOPES, admin.id, rotate_agents_key)
        result["agents_api_key"], result["agents_key_status"] = key, status

        await session.commit()

    result["ok"] = True
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--rotate-core-key", action="store_true")
    parser.add_argument("--rotate-agents-key", action="store_true")
    args = parser.parse_args(argv)
    password = os.environ.get("AISOC_BOOTSTRAP_ADMIN_PASSWORD") or None
    try:
        validate_inputs(args.admin_email, password)
        result = asyncio.run(run(args.admin_email, password, args.rotate_core_key, args.rotate_agents_key))
    except BootstrapError as exc:
        print(RESULT_MARKER + json.dumps({"ok": False, "error": str(exc)}))
        return 1
    print(RESULT_MARKER + json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
