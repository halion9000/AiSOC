"""The non-superuser role setup: migration 062, scripts/provision_app_role.sql and the docker-compose.rls.yml overlay.

Why these exist (all verified on a real Postgres): every service connects as the bootstrap superuser, which bypasses RLS; the role meant for the job, `aisoc_app`, had a password published in the repository and, via migration 002's
`GRANT ALL`, the TRUNCATE privilege, which ignores RLS and row triggers and so could erase the append-only audit_log. Docker is not available where this is tested, so the SQL behaviour was verified against real Postgres by hand and
these tests pin the SHAPE: what the script may and may not contain, and, by emulating compose's merge, what configuration each service would actually receive.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
SQL = (ROOT / "scripts" / "provision_app_role.sql").read_text(encoding="utf-8")
MIG062 = (ROOT / "services" / "api" / "migrations" / "062_aisoc_app_least_privilege.sql").read_text(encoding="utf-8")
BASE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
OVERLAY_TEXT = (ROOT / "docker-compose.rls.yml").read_text(encoding="utf-8")
OVERLAY = yaml.safe_load(OVERLAY_TEXT)


def code(text: str) -> str:
    """The text with SQL comments removed, so assertions are about what RUNS."""
    return "\n".join(re.sub(r"--.*$", "", line) for line in text.splitlines())


def merged() -> dict:
    """Compose's merge, for the parts used here: maps merge recursively; scalars and lists in the overlay replace."""

    def merge(a, b):
        if isinstance(a, dict) and isinstance(b, dict):
            return {**a, **{k: merge(a.get(k), v) if k in a else v for k, v in b.items()}}
        return b

    return merge(BASE, OVERLAY)["services"]


SQL_CODE, MIG_CODE = code(SQL), code(MIG062)


class TestTheProvisioningScript:
    def test_the_password_comes_from_the_environment_never_the_file_or_a_command_line(self):
        assert r"\getenv app_pw AISOC_APP_DB_PASSWORD" in SQL_CODE
        assert not re.search(r"PASSWORD\s+'", SQL_CODE, re.I), "a literal password in the script"
        assert not re.search(r"-v\s+app_pw", SQL), "the usage must not put the password on a command line"

    def test_the_password_is_only_ever_interpolated_into_the_validation_and_the_alter_role(self):
        uses = [line.strip() for line in SQL_CODE.splitlines() if ":'app_pw'" in line]
        assert len(uses) == 2 and any("ALTER ROLE aisoc_app" in u and "PASSWORD :'app_pw'" in u for u in uses) and any("length(:'app_pw')" in u for u in uses)

    def test_it_never_echoes_or_selects_the_password(self):
        assert not re.search(r"\\echo|\\qecho|\\set\s+ECHO|SELECT[^;\n]*:'?app_pw", SQL_CODE.replace("length(:'app_pw') >= 16 AND :'app_pw' NOT IN", ""), re.I)

    def test_it_refuses_a_missing_short_or_published_password(self):
        assert r"\if :{?app_pw}" in SQL_CODE and "is not set" in SQL_CODE
        assert "length(:'app_pw') >= 16" in SQL_CODE and "NOT IN ('changeme', 'aisoc_dev_secret')" in SQL_CODE
        assert SQL_CODE.count("RAISE EXCEPTION") == 2

    def test_errors_stop_the_script(self):
        assert r"\set ON_ERROR_STOP on" in SQL_CODE

    def test_the_role_can_never_bypass_rls_or_administer_anything(self):
        alter = re.search(r"ALTER ROLE aisoc_app WITH ([^;]*);", SQL_CODE).group(1)
        for attribute in ("LOGIN", "NOSUPERUSER", "NOBYPASSRLS", "NOCREATEDB", "NOCREATEROLE", "NOREPLICATION"):
            assert attribute in alter.split(), attribute
        assert not re.search(r"(?<!NO)(SUPERUSER|BYPASSRLS|CREATEROLE|CREATEDB|REPLICATION)\b", re.sub(r"NO(SUPERUSER|BYPASSRLS|CREATEROLE|CREATEDB|REPLICATION)", "", alter))

    def test_it_creates_the_role_only_if_missing(self):
        assert "WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app')" in SQL_CODE and r"\gexec" in SQL_CODE

    def test_privileges_are_data_access_only_never_all(self):
        assert not re.search(r"GRANT\s+ALL", SQL_CODE, re.I), "migration 002's GRANT ALL is exactly what this removes"
        assert "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aisoc_app" in SQL_CODE
        assert "REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM aisoc_app" in SQL_CODE
        assert "REVOKE CREATE ON SCHEMA public FROM aisoc_app" in SQL_CODE

    def test_later_tables_get_the_same_not_all(self):
        assert "REVOKE ALL ON TABLES FROM aisoc_app" in SQL_CODE
        assert "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aisoc_app" in SQL_CODE
        assert SQL_CODE.count("FOR ROLE %I") == 3 and "current_user" in SQL_CODE  # whoever runs it owns the tables the migrations create

    def test_it_ends_with_a_summary_that_cannot_contain_the_password(self):
        tail = SQL_CODE.strip().splitlines()[-1]
        assert tail.startswith("SELECT rolname AS role, rolsuper") and "app_pw" not in tail


class TestMigration062:
    def test_it_only_takes_privileges_away(self):
        assert not re.search(r"\bGRANT\b", MIG_CODE, re.I)
        assert len(re.findall(r"\bREVOKE\b", MIG_CODE, re.I)) == 2

    @pytest.mark.parametrize("privilege", ["TRUNCATE", "REFERENCES", "TRIGGER"])
    def test_each_dangerous_privilege_is_revoked_for_existing_and_future_tables(self, privilege):
        assert re.search(rf"REVOKE [^;]*\b{privilege}\b[^;]* ON ALL TABLES IN SCHEMA public FROM aisoc_app", MIG_CODE)
        assert re.search(rf"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE [^;]*\b{privilege}\b[^;]* ON TABLES FROM aisoc_app", MIG_CODE)

    def test_the_data_privileges_are_left_alone(self):
        assert not re.search(r"REVOKE[^;]*\b(SELECT|INSERT|UPDATE|DELETE)\b", MIG_CODE, re.I)

    def test_it_does_nothing_if_the_role_does_not_exist(self):
        assert "IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app')" in MIG_CODE

    def test_the_migration_that_granted_all_is_still_there_and_is_not_edited(self):
        """062 corrects 002 instead of rewriting history (002 is already applied everywhere)."""
        assert "GRANT ALL ON ALL TABLES IN SCHEMA public TO aisoc_app" in (ROOT / "services/api/migrations/002_rls.sql").read_text(encoding="utf-8")


class TestTheOverlay:
    services = merged()

    def test_only_actions_and_agents_are_switched_to_the_app_role(self):
        users = {name: re.search(r"://([^:]+):", svc["environment"]["DATABASE_URL"]).group(1) for name, svc in self.services.items() if "DATABASE_URL" in svc.get("environment", {})}
        assert users["actions"] == "aisoc_app" and users["agents"] == "aisoc_app"
        assert {n: u for n, u in users.items() if n not in ("actions", "agents")} == {n: "aisoc" for n in users if n not in ("actions", "agents")}

    def test_the_api_is_deliberately_not_switched_and_says_why(self):
        assert "api" not in OVERLAY["services"] and "migration" in OVERLAY_TEXT.split("`api` is deliberately NOT switched")[1]

    def test_postgres_itself_is_untouched(self):
        assert "postgres" not in OVERLAY["services"] and self.services["postgres"] == BASE["services"]["postgres"]

    def test_the_password_is_required_and_has_no_default_anywhere(self):
        refs = re.findall(r"\$\{AISOC_APP_DB_PASSWORD([^}]*)\}", OVERLAY_TEXT)
        assert len(refs) == 3 and all(r.startswith(":?") for r in refs), refs  # the one-shot and the two URLs: all required
        assert not re.search(r"AISOC_APP_DB_PASSWORD:-", OVERLAY_TEXT)

    def test_no_secret_is_written_into_the_overlay(self):
        assert not re.search(r"changeme|aisoc_dev_secret(?!\})", re.sub(r"\$\{POSTGRES_PASSWORD:-aisoc_dev_secret\}", "", OVERLAY_TEXT))

    def test_the_connection_url_keeps_the_same_host_database_and_driver_as_the_base(self):
        base = BASE["services"]["actions"]["environment"]["DATABASE_URL"]
        for name in ("actions", "agents"):
            url = self.services[name]["environment"]["DATABASE_URL"]
            assert url.startswith("postgresql+asyncpg://aisoc_app:") and url.endswith("@postgres:5432/aisoc") and base.endswith("@postgres:5432/aisoc")

    @pytest.mark.parametrize("name", ["actions", "agents"])
    def test_they_wait_for_the_role_setup_and_keep_their_other_dependencies(self, name):
        deps = self.services[name]["depends_on"]
        assert deps["db-roles"] == {"condition": "service_completed_successfully"}
        assert set(BASE["services"][name]["depends_on"]) <= set(deps)

    def test_the_role_setup_is_a_one_shot_that_runs_the_script_as_the_owner(self):
        job = self.services["db-roles"]
        assert job["restart"] == "no" and job["depends_on"]["postgres"]["condition"] == "service_healthy"
        assert job["command"][:3] == ["psql", "-v", "ON_ERROR_STOP=1"] and job["command"][-1] == "/provision_app_role.sql"
        env = job["environment"]
        assert env["PGUSER"] == "aisoc" and env["PGHOST"] == "postgres" and env["PGDATABASE"] == "aisoc" and env["PGPASSWORD"].startswith("${POSTGRES_PASSWORD")

    def test_the_script_it_mounts_exists(self):
        mount = self.services["db-roles"]["volumes"][0]
        src, dst, mode = mount.split(":")
        assert (ROOT / src).is_file() and dst == "/provision_app_role.sql" and mode == "ro"

    def test_the_image_has_a_psql_new_enough_for_getenv(self):
        """\\getenv needs psql 15+: an older image would fail at the first line of the script."""
        major = int(re.search(r"postgres:(\d+)", self.services["db-roles"]["image"]).group(1))
        assert major >= 15 and re.search(r"postgres:(\d+)", BASE["services"]["postgres"]["image"]).group(1) == str(major)

    def test_the_overlay_adds_no_published_ports_and_changes_no_other_service(self):
        assert set(OVERLAY["services"]) == {"db-roles", "actions", "agents"}
        assert all("ports" not in v for v in OVERLAY["services"].values())

    def test_the_activation_instructions_name_every_variable_and_the_way_back(self):
        assert "AISOC_APP_DB_PASSWORD=" in OVERLAY_TEXT and "Remove those three lines to go back" in OVERLAY_TEXT
        assert "COMPOSE_FILE=docker-compose.yml,docker-compose.rls.yml" in OVERLAY_TEXT

    def test_the_separator_is_stated_so_the_same_instructions_work_on_windows_and_linux(self):
        """Compose's default COMPOSE_FILE separator is `;` on Windows and `:` elsewhere; a colon-separated value silently fails on Windows."""
        assert "COMPOSE_PATH_SEPARATOR=," in OVERLAY_TEXT and "COMPOSE_FILE=docker-compose.yml:" not in OVERLAY_TEXT
