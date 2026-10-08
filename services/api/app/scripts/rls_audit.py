"""Report whether row-level security (RLS) actually protects this database, and where it does not.

READ-ONLY: it only queries the catalog (pg_roles, pg_class, pg_policies, information_schema). It changes nothing and reads no tenant data.

    python -m app.scripts.rls_audit                  # human-readable report
    python -m app.scripts.rls_audit --json           # machine-readable
    python -m app.scripts.rls_audit --strict         # exit 1 if any policy is DEFECTIVE (see below)
    python -m app.scripts.rls_audit --require-enforced   # also exit 1 if the connected role bypasses RLS
    python -m app.scripts.rls_audit --check-default-password   # ALSO try to log in as aisoc_app with its published password (an authentication attempt: opt-in)

It answers four questions:
  1. Does RLS apply to the role this connection uses at all? (A PostgreSQL superuser, or a role with BYPASSRLS, ignores every policy. The default compose connects as the bootstrap superuser.)
  2. Of the tenant-scoped tables (those with a tenant_id column), how many have RLS enabled?
  3. Is any table's RLS on with NO policy (default-deny for a non-owner role)?
  4. Is any policy DEFECTIVE: it reads a setting nothing sets, or it raises an error when no tenant context has been set?
  5. About the non-superuser role `aisoc_app` (migration 002): can it TRUNCATE the append-only audit_log (it could until migration 062: TRUNCATE ignores RLS and row triggers), and, only with
     --check-default-password, does it still accept the password published in the repository?

Policy kinds:
  standard                a tenant context restricts to that tenant; NO context admits the row (the endpoints filter by tenant themselves). The shape used by almost every table.
  strict_context          works only if the code sets a tenant context first; with none, the table looks empty and writes are refused. Fine for code that always sets one, a bug for code that does not.
  raises_without_context  calls current_setting('app.current_tenant_id') WITHOUT the missing-ok flag: EVERY query raises until something has set it on that connection. A defect.
  wrong_setting           reads a setting other than app.current_tenant_id, which nothing sets. A defect.
  other                   anything else (review by hand).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from urllib.parse import quote, urlsplit, urlunsplit
from dataclasses import asdict, dataclass, field
from typing import Any

STANDARD_SETTING = "app.current_tenant_id"
APP_ROLE = "aisoc_app"
PUBLISHED_APP_PASSWORD = "changeme"  # migration 002
# The tables RLS deliberately does not cover (migration 002: authentication would be circular).
INTENTIONALLY_UNCOVERED = frozenset({"users", "tenants", "aisoc_schema_migrations"})
DEFECTS = ("raises_without_context", "wrong_setting")
_SETTING = re.compile(r"current_setting\('([^']+)'::text(?:,\s*(true|false))?\)")


def classify_policy(qual: str | None) -> str:
    """Name the shape of a policy's USING expression (see the module docstring)."""
    q = qual or ""
    if "current_tenant_id()" in q:
        return "standard" if "IS NULL" in q else "strict_context"
    m = _SETTING.search(q)
    if m:
        name, missing_ok = m.group(1), m.group(2) == "true"
        if name != STANDARD_SETTING:
            return "wrong_setting"
        return "strict_context" if missing_ok else "raises_without_context"
    return "other"


@dataclass
class Report:
    role: str = ""
    superuser: bool = False
    bypassrls: bool = False
    tables: int = 0
    tenant_scoped: list[str] = field(default_factory=list)
    covered: list[str] = field(default_factory=list)
    uncovered: list[str] = field(default_factory=list)  # tenant-scoped, RLS off, not intentionally excluded
    excluded: list[str] = field(default_factory=list)  # tenant-scoped, RLS off, deliberately
    no_policy: list[str] = field(default_factory=list)  # RLS on, zero policies
    policies: dict[str, list[dict[str, str]]] = field(default_factory=dict)  # kind -> [{table, policy, using}]
    # About `aisoc_app`: exists (bool), can_truncate_audit_log (bool|None: None if unknown), default_password_accepted (bool|None: None = not checked or could not tell)
    app_role: dict[str, Any] = field(default_factory=dict)

    @property
    def bypasses_rls(self) -> bool:
        return self.superuser or self.bypassrls

    @property
    def defects(self) -> list[dict[str, str]]:
        found = [p for kind in DEFECTS for p in self.policies.get(kind, [])] + [{"table": t, "policy": "(none)", "using": "RLS enabled but no policy: invisible and unwritable for a non-owner role"} for t in self.no_policy]
        if self.app_role.get("can_truncate_audit_log") is True:
            found.append({"table": "audit_log", "policy": f"({APP_ROLE} privileges)", "using": f"{APP_ROLE} can TRUNCATE the append-only audit_log (TRUNCATE ignores RLS and row triggers): apply migration 062"})
        if self.app_role.get("default_password_accepted") is True:
            found.append({"table": "(role)", "policy": f"({APP_ROLE} password)", "using": f"{APP_ROLE} still accepts the password published in the repository: set a real one (scripts/provision_app_role.sql)"})
        return found


def build_report(*, role: tuple[str, bool, bool], tables: list[str], tenant_tables: set[str], rls_enabled: set[str], policies: list[dict[str, Any]], app_role: dict[str, Any] | None = None) -> Report:
    r = Report(role=role[0], superuser=role[1], bypassrls=role[2], tables=len(tables), app_role=dict(app_role or {}))
    r.tenant_scoped = sorted(t for t in tables if t in tenant_tables)
    r.covered = [t for t in r.tenant_scoped if t in rls_enabled]
    off = [t for t in r.tenant_scoped if t not in rls_enabled]
    r.excluded = [t for t in off if t in INTENTIONALLY_UNCOVERED]
    r.uncovered = [t for t in off if t not in INTENTIONALLY_UNCOVERED]
    with_policy = {p["tablename"] for p in policies}
    r.no_policy = sorted(t for t in tables if t in rls_enabled and t not in with_policy)
    for p in policies:
        kind = classify_policy(p.get("qual") or p.get("with_check"))
        r.policies.setdefault(kind, []).append({"table": p["tablename"], "policy": p["policyname"], "using": (p.get("qual") or p.get("with_check") or "")[:110]})
    return r


def render(r: Report) -> str:
    out = [f"Connected as role '{r.role}': superuser={r.superuser} bypassrls={r.bypassrls}"]
    out.append("  RLS is BYPASSED for this role: tenant isolation rests entirely on the application's own tenant filters." if r.bypasses_rls else "  RLS is ENFORCED for this role.")
    total = len(r.tenant_scoped)
    pct = round(100 * len(r.covered) / total) if total else 0
    out += ["", f"{r.tables} tables; {total} are tenant-scoped (have a tenant_id column); RLS is enabled on {len(r.covered)} of them ({pct}%)."]
    if r.uncovered:
        out.append(f"{len(r.uncovered)} tenant-scoped tables have NO RLS (isolation there is application filters only, whatever the role):")
        out += [f"  {', '.join(r.uncovered[i:i + 4])}" for i in range(0, len(r.uncovered), 4)]
    if r.excluded:
        out.append(f"(deliberately excluded: {', '.join(r.excluded)})")
    counts = ", ".join(f"{k}={len(v)}" for k, v in sorted(r.policies.items()))
    out += ["", f"Policies by shape: {counts or 'none'}"]
    for kind in ("raises_without_context", "wrong_setting", "other", "strict_context"):
        for p in r.policies.get(kind, []):
            tag = "DEFECT" if kind in DEFECTS else "note  "
            out.append(f"  {tag} {kind}: {p['table']}.{p['policy']}: {p['using']}")
    for t in r.no_policy:
        out.append(f"  DEFECT no_policy: {t}: RLS enabled but no policy")
    if r.app_role.get("exists"):
        out += ["", f"Role {APP_ROLE}:"]
        trunc = r.app_role.get("can_truncate_audit_log")
        out.append(f"  can TRUNCATE audit_log: {'YES (DEFECT: apply migration 062)' if trunc else 'no' if trunc is False else 'unknown'}")
        pw = r.app_role.get("default_password_accepted")
        out.append("  accepts the published password: " + ("YES (DEFECT: set a real password)" if pw else "no" if pw is False else "not checked (use --check-default-password)" if "default_password_accepted" not in r.app_role else "could not tell"))
    out += ["", f"{len(r.defects)} defect(s)."]
    return "\n".join(out)


async def collect(conn: Any) -> Report:
    me = await conn.fetchrow("SELECT current_user AS name, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
    tables = [x["relname"] for x in await conn.fetch("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY 1")]
    tenant_tables = {x["table_name"] for x in await conn.fetch("SELECT table_name FROM information_schema.columns WHERE table_schema = 'public' AND column_name = 'tenant_id'")}
    rls = {x["relname"] for x in await conn.fetch("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity")}
    pols = [dict(x) for x in await conn.fetch("SELECT tablename, policyname, qual, with_check FROM pg_policies WHERE schemaname = 'public'")]
    exists = bool(await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", APP_ROLE))
    can_truncate = bool(await conn.fetchval("SELECT has_table_privilege($1, 'public.audit_log', 'TRUNCATE')", APP_ROLE)) if exists and "audit_log" in tables else None
    return build_report(role=(me["name"], me["rolsuper"], me["rolbypassrls"]), tables=tables, tenant_tables=tenant_tables, rls_enabled=rls, policies=pols, app_role={"exists": exists, "can_truncate_audit_log": can_truncate})


def with_credentials(dsn: str, user: str, password: str) -> str:
    """The same DSN, but for another user (password percent-encoded)."""
    parts = urlsplit(dsn)
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, f"{quote(user, safe='')}:{quote(password, safe='')}@{host}", parts.path, parts.query, parts.fragment))


async def default_password_accepted(dsn: str, kwargs: dict[str, Any], connect: Any = None) -> bool | None:
    """True if `aisoc_app` accepts its published password, False if it is refused, None if it could not be determined (unreachable, no such role...). This is an AUTHENTICATION ATTEMPT, so it only runs on request."""
    import asyncpg  # noqa: PLC0415

    connect = connect or asyncpg.connect
    try:
        conn = await connect(with_credentials(dsn, APP_ROLE, PUBLISHED_APP_PASSWORD), timeout=10, **kwargs)
    except asyncpg.exceptions.InvalidPasswordError:
        return False
    except Exception:  # noqa: BLE001
        return None
    await conn.close()
    return True


def exit_code(r: Report, *, strict: bool, require_enforced: bool) -> int:
    return 1 if (strict and r.defects) or (require_enforced and r.bypasses_rls) else 0


async def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Report where row-level security does and does not protect this database (read-only).")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any policy is defective")
    ap.add_argument("--require-enforced", action="store_true", help="exit 1 if the connected role bypasses RLS")
    ap.add_argument("--check-default-password", action="store_true", help=f"also try to log in as {APP_ROLE} with its published password (an authentication attempt)")
    args = ap.parse_args(argv)
    from app.core.config import settings  # noqa: PLC0415
    from app.scripts.run_migrations import _asyncpg_dsn, _connect  # noqa: PLC0415  (the same DATABASE_URL handling as the migration runner)

    # The SERVICE's own connection (DATABASE_URL), never the migration connection: the audit reports on the role the services run as, and MIGRATION_DATABASE_URL may well be the owner.
    conn = await _connect(str(settings.DATABASE_URL))
    try:
        report = await collect(conn)
    finally:
        await conn.close()
    if args.check_default_password and report.app_role.get("exists"):
        dsn, kwargs = _asyncpg_dsn(str(settings.DATABASE_URL))
        report.app_role["default_password_accepted"] = await default_password_accepted(dsn, kwargs)
    print(json.dumps({**asdict(report), "bypasses_rls": report.bypasses_rls, "defects": report.defects}, indent=2) if args.json else render(report))
    return exit_code(report, strict=args.strict, require_enforced=args.require_enforced)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
