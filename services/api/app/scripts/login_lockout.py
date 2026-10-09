"""See who is locked out of signing in, and lift a lock.

Failed sign-ins are counted (app.services.login_throttle); too many for one address, or from one client address, lock further attempts out for the rest of the window. The lock ends by itself, but anyone able to send a few wrong passwords for an
address can lock that person out for up to the window, so an operator with database access can end it at once:

    python -m app.scripts.login_lockout list
    python -m app.scripts.login_lockout clear --email person@example.com
    python -m app.scripts.login_lockout clear --ip 203.0.113.7
    python -m app.scripts.login_lockout clear --all

`list` shows each address and client address that is locked now, with how long is left. `clear` deletes the recorded failures (so the count restarts); it does not unlock an account that is disabled, and it changes no password.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from typing import Any


class LoginLockoutError(RuntimeError):
    pass


async def run(action: str, *, email: str | None = None, ip: str | None = None, all_failures: bool = False, session_factory: Any = None, now: datetime | None = None) -> dict:
    from sqlalchemy import delete, select  # noqa: PLC0415

    from app.models.login_failure import LoginFailure  # noqa: PLC0415
    from app.services.login_throttle import _aware, email_key, limits, window  # noqa: PLC0415

    if session_factory is None:
        from app.db.database import AsyncSessionLocal as session_factory  # noqa: PLC0415,N813
    now = now or datetime.now(UTC)
    async with session_factory() as session:
        if action == "list":
            rows = (await session.execute(select(LoginFailure.email_key, LoginFailure.client_ip, LoginFailure.created_at).where(LoginFailure.created_at > now - window()).order_by(LoginFailure.created_at.desc()))).all()
            out: dict[str, Any] = {"ok": True, "window_minutes": round(window().total_seconds() / 60), "locked_addresses": [], "locked_clients": []}
            per_address, per_client = limits()
            for kind, index, limit, field in (("locked_addresses", 0, per_address, "address"), ("locked_clients", 1, per_client, "client_ip")):
                groups: dict[str, list[datetime]] = {}
                for row in rows:
                    key = row[index]
                    if key:
                        groups.setdefault(key, []).append(_aware(row[2]))
                for key, times in sorted(groups.items()):
                    if len(times) >= limit:  # times are newest first: the oldest of the latest `limit` leaving the window ends the lock
                        left = (times[limit - 1] + window() - now).total_seconds()
                        out[kind].append({field: key, "recent_failures": len(times), "seconds_left": max(0, round(left))})
            return out
        if action != "clear":
            raise LoginLockoutError(f"unknown action {action!r}")
        chosen = [bool(email), bool(ip), bool(all_failures)]
        if sum(chosen) != 1:
            raise LoginLockoutError("give exactly one of --email, --ip, --all")
        stmt = delete(LoginFailure)
        if email:
            stmt = stmt.where(LoginFailure.email_key == email_key(email))
        elif ip:
            stmt = stmt.where(LoginFailure.client_ip == ip.strip())
        result = await session.execute(stmt)
        await session.commit()
        return {"ok": True, "cleared_failures": result.rowcount}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="login_lockout", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list", help="who is locked now")
    clear = sub.add_parser("clear", help="lift a lock by deleting recorded failures")
    clear.add_argument("--email")
    clear.add_argument("--ip")
    clear.add_argument("--all", dest="all_failures", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(run(args.action, email=getattr(args, "email", None), ip=getattr(args, "ip", None), all_failures=getattr(args, "all_failures", False)))
    except LoginLockoutError as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
