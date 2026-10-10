"""Command line for the platform alert email setting (for an operator with database access; the same rules as the API).

    python -m app.scripts.alert_email status
    python -m app.scripts.alert_email set [--recipients a@x.example,b@x.example] [--min-severity high] [--enable | --disable]
    python -m app.scripts.alert_email test

`status` also says which ALERT_EMAIL_* environment variables are missing (by name, never the values). `test` sends one test message through the real sender to the configured recipients. Output is JSON; exit 0 on success, 1 on a refusal.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys


class AlertEmailCliError(RuntimeError):
    pass


async def run(action: str, *, recipients: str | None = None, min_severity: str | None = None, enable: bool | None = None) -> dict:
    from app.api.v1.endpoints.platform_alert_email import _status  # noqa: PLC0415
    from app.db.database import AsyncSessionLocal  # noqa: PLC0415
    from app.services.alert_email.graph import GraphMailer, MailError, scrub  # noqa: PLC0415
    from app.services.alert_email.settings_store import InvalidSettings, get_settings, update_settings  # noqa: PLC0415

    async with AsyncSessionLocal() as db:
        if action == "status":
            out = _status(await get_settings(db)).model_dump(mode="json")
            await db.commit()
            return {"ok": True, **out}
        if action == "set":
            if recipients is None and min_severity is None and enable is None:
                raise AlertEmailCliError("give at least one of --recipients, --min-severity, --enable, --disable")
            try:
                row = await update_settings(db, updated_by="cli", enabled=enable, min_severity=min_severity, recipients=None if recipients is None else [r for r in recipients.split(",") if r.strip()])
            except InvalidSettings as exc:
                raise AlertEmailCliError(str(exc)) from None
            return {"ok": True, **_status(row).model_dump(mode="json")}
        if action == "test":
            cfg = await get_settings(db)
            to = [str(r) for r in (cfg.recipients or [])]
            mailer = GraphMailer.from_settings()
            if not to:
                raise AlertEmailCliError("add at least one recipient first (set --recipients)")
            if not mailer.configured:
                from app.api.v1.endpoints.platform_alert_email import missing_credentials  # noqa: PLC0415

                raise AlertEmailCliError("these environment variables are not set: " + ", ".join(missing_credentials()))
            try:
                await mailer.send(to, "[AiSOC] Test email: alert email is working", "This is a test of AiSOC's alert email, requested from the command line. If you can read this, the Microsoft Graph setup works.\n")
            except MailError as exc:
                raise AlertEmailCliError(scrub(str(exc), (mailer.client_secret,))) from None
            return {"ok": True, "sent_to": to}
    raise AlertEmailCliError(f"unknown action {action!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("status")
    sub.add_parser("test")
    st = sub.add_parser("set")
    st.add_argument("--recipients", help="comma-separated email addresses (replaces the list)")
    st.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"])
    group = st.add_mutually_exclusive_group()
    group.add_argument("--enable", dest="enable", action="store_true", default=None)
    group.add_argument("--disable", dest="enable", action="store_false")
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(run(args.action, recipients=getattr(args, "recipients", None), min_severity=getattr(args, "min_severity", None), enable=getattr(args, "enable", None)))
    except AlertEmailCliError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
