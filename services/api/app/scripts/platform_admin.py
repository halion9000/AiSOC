"""List, grant or revoke PLATFORM administrators.

A platform_admin holds the platform-level permissions that no other role has (plugins:admin, mssp:onboard, platform:cross_tenant_query): the ones that act on every tenant, not just the caller's own. The original primary administrator is one by default (migration 067 and bootstrap_production);
this tool gives the role to specific people, or takes it away, from the command line when you have database access. Inside the product, an existing platform_admin can do the same for users of their own tenant through PATCH /api/v1/tenants/me/users/{id}.

    python -m app.scripts.platform_admin list
    python -m app.scripts.platform_admin grant  --name hal.liveoak          (or --email person@example.com)
    python -m app.scripts.platform_admin revoke --name hal.liveoak [--to-role tenant_admin] [--force]

Name the person by ACCOUNT NAME (`--name`, what they sign in with; an account need not have an email) or by email (`--email`); exactly one.

Revoking the LAST active platform_admin is refused (nobody could then administer the platform) unless --force is given. A person's open sessions pick up the change on their next request.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

PLATFORM_ROLE = "platform_admin"


class PlatformAdminError(RuntimeError):
    pass


async def run(action: str, email: str | None = None, *, name: str | None = None, to_role: str = "tenant_admin", force: bool = False) -> dict:
    from sqlalchemy import func, select, update  # noqa: PLC0415

    from app.core.security import ROLE_PERMISSIONS  # noqa: PLC0415
    from app.db.database import AsyncSessionLocal  # noqa: PLC0415
    from app.models.tenant import User  # noqa: PLC0415
    from app.services.user_lookup import find_user_by_account_name, find_user_by_email  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        if action == "list":
            rows = (await session.execute(select(User).where(User.role == PLATFORM_ROLE).order_by(User.created_at))).scalars().all()
            return {"ok": True, "platform_admins": [{"account_name": u.account_name, "email": u.email, "tenant_id": str(u.tenant_id), "active": bool(u.is_active)} for u in rows]}

        if bool(email) == bool(name):
            raise PlatformAdminError("give exactly one of --name (the account name) or --email")
        if name:
            user = await find_user_by_account_name(session, name)
            if user is None:
                raise PlatformAdminError(f"No user with the account name {name.strip().lower()!r}.")
        else:
            if "@" not in email:
                raise PlatformAdminError(f"{email!r} is not an email address. To name a person by their account name, use --name.")
            user = await find_user_by_email(session, email)
            if user is None:
                raise PlatformAdminError(f"No user with the email {email.strip().lower()!r}.")
        who = {"account_name": user.account_name, "email": user.email}
        label = user.account_name

        if action == "grant":
            if user.is_active is False:
                raise PlatformAdminError(f"{label} is deactivated; reactivate the account before granting platform power.")
            if user.role == PLATFORM_ROLE:
                return {"ok": True, **who, "role": PLATFORM_ROLE, "changed": False}
            previous = user.role
            await session.execute(update(User).where(User.id == user.id).values(role=PLATFORM_ROLE))
            await session.commit()
            return {"ok": True, **who, "role": PLATFORM_ROLE, "previous_role": previous, "changed": True}

        if action == "revoke":
            if user.role != PLATFORM_ROLE:
                return {"ok": True, **who, "role": user.role, "changed": False}
            if to_role not in ROLE_PERMISSIONS or to_role == PLATFORM_ROLE:
                raise PlatformAdminError(f"--to-role must be a known role other than {PLATFORM_ROLE}: {', '.join(sorted(r for r in ROLE_PERMISSIONS if r != PLATFORM_ROLE))}.")
            others = (
                await session.execute(select(func.count()).select_from(User).where(User.role == PLATFORM_ROLE, User.id != user.id, User.is_active.is_not(False)))
            ).scalar_one()
            if others == 0 and not force:
                raise PlatformAdminError(f"{label} is the last active platform_admin: nobody could administer the platform afterwards. Grant the role to someone else first, or pass --force.")
            await session.execute(update(User).where(User.id == user.id).values(role=to_role))
            await session.commit()
            return {"ok": True, **who, "role": to_role, "previous_role": PLATFORM_ROLE, "changed": True}

        raise PlatformAdminError(f"Unknown action {action!r}.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list")
    grant = sub.add_parser("grant")
    who = grant.add_mutually_exclusive_group(required=True)
    who.add_argument("--name", help="the person's account name")
    who.add_argument("--email", help="or their email address")
    revoke = sub.add_parser("revoke")
    who = revoke.add_mutually_exclusive_group(required=True)
    who.add_argument("--name", help="the person's account name")
    who.add_argument("--email", help="or their email address")
    revoke.add_argument("--to-role", default="tenant_admin")
    revoke.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(run(args.action, getattr(args, "email", None), name=getattr(args, "name", None), to_role=getattr(args, "to_role", "tenant_admin"), force=getattr(args, "force", False)))
    except PlatformAdminError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
