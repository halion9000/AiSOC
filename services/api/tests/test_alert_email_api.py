"""The platform alert email API and command line: PLATFORM ADMINISTRATORS ONLY.

A real SQLite database and the real router (mounted under /api/v1 as in production), with a signed token for every built-in role. The Microsoft sender is replaced by a recorder; the real sender is tested in test_alert_email.py, and the whole path was run against real Postgres.
"""
import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from app.api.v1.endpoints import auth
from app.api.v1.endpoints import platform_alert_email as pae
from app.core.config import settings
from app.core.security import ROLE_PERMISSIONS, create_access_token
from app.db.database import Base
from app.models.alert_email import AlertEmailLog, PlatformAlertEmailSettings
from app.models.login_failure import LoginFailure
from app.models.tenant import ApiKey, Tenant, User
from app.scripts import alert_email as cli
from app.services.alert_email.graph import MailError

SECRET = "api-test-secret-VALUE-31ef"
from pathlib import Path  # noqa: E402

APP_FILE = Path(__file__).resolve().parent.parent / "app" / "api" / "v1" / "endpoints" / "platform_alert_email.py"
URL = "/api/v1/platform/alert-email"


class Recorder:
    """Stands in for the Graph sender."""

    client_secret = SECRET

    def __init__(self, configured=True, error=None):
        self.configured, self.error, self.sent = configured, error, []

    async def send(self, to, subject, text):
        if self.error:
            raise self.error
        self.sent.append((list(to), subject, text))


@pytest.fixture
def world(tmp_path, monkeypatch):
    path = tmp_path / "ae_api.db"
    sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync, tables=[Tenant.__table__, User.__table__, ApiKey.__table__, LoginFailure.__table__, PlatformAlertEmailSettings.__table__, AlertEmailLog.__table__])
    t = Tenant(id=uuid.uuid4(), name="Live Oak IT", slug="live-oak-" + uuid.uuid4().hex[:6])
    other = Tenant(id=uuid.uuid4(), name="Acme Corp", slug="acme-" + uuid.uuid4().hex[:6])
    users = {role: User(id=uuid.uuid4(), tenant_id=t.id, email=f"{role}@msp.example", username=role, hashed_password="x", role=role) for role in ROLE_PERMISSIONS}
    with Session(sync, expire_on_commit=False) as s:
        s.add_all([t, other, *users.values(), PlatformAlertEmailSettings(id=1, enabled=False, min_severity="high", recipients=[], consecutive_failures=0)])  # the singleton row migration 073 inserts
        s.commit()
    factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool), expire_on_commit=False)

    async def not_revoked(jti):
        return False

    monkeypatch.setattr(deps, "is_revoked", not_revoked)
    monkeypatch.setattr(deps, "is_dev_mode", lambda: False)
    audits: list[dict] = []

    async def record(**kw):
        audits.append(kw)

    monkeypatch.setattr(pae, "emit_audit", record)
    mailer = Recorder()
    monkeypatch.setattr(pae, "_mailer", lambda: mailer)
    monkeypatch.setattr(pae, "_last_test_at", None)
    for name, value in (("ALERT_EMAIL_GRAPH_TENANT_ID", "T"), ("ALERT_EMAIL_GRAPH_CLIENT_ID", "C"), ("ALERT_EMAIL_GRAPH_CLIENT_SECRET", SECRET), ("ALERT_EMAIL_SENDER", "alerts@msp.example")):
        monkeypatch.setattr(settings, name, value)
    monkeypatch.setattr(settings, "ALERT_EMAIL_WORKER_ENABLED", True)
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(pae.router, prefix="/api/v1")

    async def session():
        async with factory() as s:
            yield s

    app.dependency_overrides[deps.get_db] = session
    token = lambda u: create_access_token({"sub": str(u.id), "tenant_id": str(u.tenant_id), "role": u.role, "email": u.email})  # noqa: E731
    yield SimpleNamespace(client=TestClient(app), sync=sync, factory=factory, users=users, tenant=t, other=other, audits=audits, mailer=mailer, auth=lambda who: {"Authorization": "Bearer " + token(users[who])}, set_mailer=lambda m: monkeypatch.setattr(pae, "_mailer", lambda: m))
    sync.dispose()


def get(world, who="platform_admin", path=""):
    return world.client.get(URL + path, headers=world.auth(who))


def put(world, body, who="platform_admin"):
    return world.client.put(URL, json=body, headers=world.auth(who))


def row(world):
    with Session(world.sync) as s:
        return s.get(PlatformAlertEmailSettings, 1)


NON_PLATFORM = [r for r in ROLE_PERMISSIONS if r != "platform_admin"]


class TestOnlyPlatformAdministrators:
    @pytest.mark.parametrize("role", NON_PLATFORM)
    @pytest.mark.parametrize("method,path,body", [("get", "", None), ("put", "", {"enabled": False}), ("post", "/test", None), ("get", "/log", None)])
    def test_every_other_role_is_refused_on_every_route_including_a_tenants_own_administrators(self, world, role, method, path, body):
        r = getattr(world.client, method)(URL + path, headers=world.auth(role), **({"json": body} if body is not None else {}))
        assert r.status_code == 403, f"{role} {method.upper()} {path}: {r.status_code}"
        assert world.audits == [] and world.mailer.sent == []

    @pytest.mark.parametrize("method,path", [("get", ""), ("put", ""), ("post", "/test"), ("get", "/log")])
    def test_the_unauthenticated_are_refused(self, world, method, path):
        assert getattr(world.client, method)(URL + path).status_code in (401, 403)

    def test_a_refused_change_changes_nothing(self, world):
        put(world, {"recipients": ["evil@attacker.example"], "enabled": True}, who="admin")
        assert get(world).json()["recipients"] == [] and not get(world).json()["enabled"]

    def test_every_route_names_the_permission_in_plain_sight_and_it_is_the_cross_tenant_one(self):
        """The literal is written on each route so a reviewer (and tests/route_auth_scan.py) can see it; this keeps it from drifting away from the constant the rest of the platform uses."""
        import re

        from app.services.tenant_selection import CROSS_TENANT_PERMISSION

        src = (APP_FILE).read_text(encoding="utf-8")
        assert CROSS_TENANT_PERMISSION == "platform:cross_tenant_query"
        assert len(re.findall(r'@router\.(?:get|put|post)\(', src)) == 4
        assert len(re.findall(r'Depends\(require_permission\("platform:cross_tenant_query"\)\)', src)) == 4

    def test_the_permission_is_the_platform_one_which_a_wildcard_does_not_grant(self):
        from app.core.security import PLATFORM_PERMISSIONS

        assert "platform:cross_tenant_query" in PLATFORM_PERMISSIONS and ROLE_PERMISSIONS["platform_admin"]
        assert not any("platform:cross_tenant_query" in perms or "*" in perms for r, perms in ROLE_PERMISSIONS.items() if r != "platform_admin" and "platform:cross_tenant_query" in perms)


class TestStatus:
    def test_a_fresh_install_has_everything_off(self, world):
        j = get(world).json()
        assert (j["enabled"], j["min_severity"], j["recipients"], j["enabled_since"], j["last_sent_at"], j["last_error"], j["consecutive_failures"]) == (False, "high", [], None, None, None, 0)

    def test_it_says_whether_the_deployment_can_send_and_which_variables_are_missing_by_name_only(self, world, monkeypatch):
        j = get(world).json()
        assert j["credentials_configured"] is True and j["missing_credentials"] == [] and j["worker_enabled"] is True and j["sender"] == "alerts@msp.example"
        monkeypatch.setattr(settings, "ALERT_EMAIL_GRAPH_CLIENT_SECRET", "")
        monkeypatch.setattr(settings, "ALERT_EMAIL_SENDER", "")
        j = get(world).json()
        assert j["credentials_configured"] is False and j["missing_credentials"] == ["ALERT_EMAIL_GRAPH_CLIENT_SECRET", "ALERT_EMAIL_SENDER"] and j["sender"] is None

    def test_no_credential_value_is_ever_in_a_response(self, world):
        put(world, {"recipients": ["ops@msp.example"], "enabled": True})
        for r in (get(world), get(world, path="/log"), put(world, {"min_severity": "low"})):
            assert SECRET not in r.text and "client_secret" not in r.text.lower().replace("alert_email_graph_client_secret", "")

    def test_it_warns_when_on_but_the_worker_is_off_or_variables_are_missing(self, world, monkeypatch):
        put(world, {"recipients": ["ops@msp.example"], "enabled": True})
        assert get(world).json()["warnings"] == []
        monkeypatch.setattr(settings, "ALERT_EMAIL_WORKER_ENABLED", False)
        monkeypatch.setattr(settings, "ALERT_EMAIL_SENDER", "")
        w = get(world).json()["warnings"]
        assert any("ALERT_EMAIL_WORKER_ENABLED" in x for x in w) and any("ALERT_EMAIL_SENDER" in x for x in w)

    def test_there_are_no_warnings_while_it_is_off(self, world, monkeypatch):
        monkeypatch.setattr(settings, "ALERT_EMAIL_WORKER_ENABLED", False)
        monkeypatch.setattr(settings, "ALERT_EMAIL_SENDER", "")
        assert get(world).json()["warnings"] == []

    def test_it_reports_the_last_error_and_failure_count_the_worker_stored(self, world):
        with Session(world.sync) as s:
            r = s.get(PlatformAlertEmailSettings, 1)
            r.last_error, r.last_error_at, r.consecutive_failures = "HTTP 403 ErrorAccessDenied", datetime(2026, 10, 10, tzinfo=UTC), 4
            s.commit()
        j = get(world).json()
        assert (j["last_error"], j["consecutive_failures"]) == ("HTTP 403 ErrorAccessDenied", 4)


class TestChangingTheSetting:
    def test_it_sets_the_recipients_severity_and_switches_on_and_starts_the_clock(self, world):
        r = put(world, {"recipients": ["Ops@MSP.example", "lead@msp.example"], "min_severity": "critical", "enabled": True})
        j = r.json()
        assert r.status_code == 200 and j["enabled"] is True and j["min_severity"] == "critical" and j["recipients"] == ["ops@msp.example", "lead@msp.example"]
        assert j["enabled_since"] is not None and j["updated_by"] == "platform_admin@msp.example" and j["updated_at"] is not None
        assert row(world).enabled is True and list(row(world).recipients) == ["ops@msp.example", "lead@msp.example"]

    def test_a_partial_change_leaves_the_rest(self, world):
        put(world, {"recipients": ["ops@msp.example"], "min_severity": "medium", "enabled": True})
        put(world, {"min_severity": "low"})
        r = row(world)
        assert (r.enabled, r.min_severity, list(r.recipients)) == (True, "low", ["ops@msp.example"])

    def test_it_cannot_be_switched_on_without_a_recipient(self, world):
        r = put(world, {"enabled": True})
        assert r.status_code == 422 and "recipient" in r.json()["detail"] and row(world).enabled is False and world.audits == []

    @pytest.mark.parametrize("bad", ["Ops <ops@msp.example>", "ops@msp.example\nBcc: x@y.example", "ops@msp.example,b@msp.example", "nope", ""])
    def test_a_recipient_that_is_not_a_plain_address_is_refused_and_nothing_changes(self, world, bad):
        put(world, {"recipients": ["keep@msp.example"]})
        r = put(world, {"recipients": [bad], "min_severity": "low"})
        assert r.status_code == 422 and list(row(world).recipients) == ["keep@msp.example"] and row(world).min_severity == "high"

    @pytest.mark.parametrize("body", [{}, {"min_severity": "urgent"}, {"min_severity": "HIGH"}, {"enabled": "maybe"}, {"recipients": "ops@msp.example"}, {"unknown": 1}, {"enabled": True, "client_secret": "x"}, {"recipients": [f"u{i}@msp.example" for i in range(51)]}])
    def test_an_invalid_body_is_a_422(self, world, body):
        assert put(world, body).status_code == 422

    @pytest.mark.parametrize("extra", [{"client_secret": "x"}, {"sender": "evil@attacker.example"}, {"graph_tenant_id": "t"}, {"updated_by": "someone-else"}, {"enabled_since": "2020-01-01T00:00:00Z"}, {"last_error": None}])
    def test_an_unknown_field_is_refused_even_alongside_valid_ones_and_nothing_changes(self, world, extra):
        """Credentials are environment variables only, and the bookkeeping fields belong to the server: a valid change must not be able to smuggle any of them in with it."""
        r = put(world, {"min_severity": "low", "recipients": ["ops@msp.example"], **extra})
        assert r.status_code == 422
        assert row(world).min_severity == "high" and list(row(world).recipients or []) == [] and row(world).updated_by_label is None and world.audits == []

    def test_more_than_twenty_recipients_is_refused_with_a_reason(self, world):
        r = put(world, {"recipients": [f"u{i}@msp.example" for i in range(21)]})
        assert r.status_code == 422 and "at most 20" in r.json()["detail"]

    def test_the_change_is_audited_with_before_and_after_and_which_fields_changed(self, world):
        put(world, {"recipients": ["ops@msp.example"], "enabled": True})
        put(world, {"min_severity": "critical"})
        first, second = world.audits
        assert first["action"] == second["action"] == "platform:alert_email_updated" and first["resource"] == "platform_alert_email"
        assert first["tenant_id"] == world.tenant.id and first["actor_id"] == world.users["platform_admin"].id and first["actor_email"] == "platform_admin@msp.example"
        assert first["changes"]["before"] == {"enabled": False, "min_severity": "high", "recipients": []} and first["changes"]["after"] == {"enabled": True, "min_severity": "high", "recipients": ["ops@msp.example"]}
        assert first["changes"]["changed"] == ["enabled", "recipients"] and second["changes"]["changed"] == ["min_severity"]

    def test_an_audit_failure_means_the_change_is_not_kept(self, world, monkeypatch):
        async def boom(**kw):
            raise RuntimeError("audit store down")

        monkeypatch.setattr(pae, "emit_audit", boom)
        with pytest.raises(RuntimeError):
            put(world, {"recipients": ["ops@msp.example"]})
        assert list(row(world).recipients or []) == [], "settings and audit event commit together or not at all"

    def test_switching_off_and_on_again_restarts_the_clock(self, world):
        put(world, {"recipients": ["ops@msp.example"], "enabled": True})
        with Session(world.sync) as s:
            r = s.get(PlatformAlertEmailSettings, 1)
            r.enabled_since = datetime(2020, 1, 1)
            s.commit()
        put(world, {"enabled": False})
        put(world, {"enabled": True})
        assert row(world).enabled_since > datetime(2025, 1, 1)


class TestTheTestEmail:
    def test_it_sends_one_message_to_the_recipients_through_the_real_sender_path(self, world):
        put(world, {"recipients": ["ops@msp.example", "lead@msp.example"]})
        r = world.client.post(URL + "/test", headers=world.auth("platform_admin"))
        assert r.status_code == 200 and r.json() == {"sent_to": ["ops@msp.example", "lead@msp.example"]}
        (to, subject, body), = world.mailer.sent
        assert to == ["ops@msp.example", "lead@msp.example"] and "Test email" in subject and "platform_admin@msp.example" in body and "No action is needed" in body

    def test_it_needs_a_recipient(self, world):
        r = world.client.post(URL + "/test", headers=world.auth("platform_admin"))
        assert r.status_code == 409 and "recipient" in r.json()["detail"] and world.mailer.sent == []

    def test_it_names_the_missing_variables_and_sends_nothing_when_not_configured(self, world):
        put(world, {"recipients": ["ops@msp.example"]})
        world.set_mailer(Recorder(configured=False))
        settings.ALERT_EMAIL_SENDER = ""
        r = world.client.post(URL + "/test", headers=world.auth("platform_admin"))
        assert r.status_code == 409 and "ALERT_EMAIL_SENDER" in r.json()["detail"]

    @pytest.mark.parametrize("permanent", [True, False])
    def test_a_microsoft_refusal_is_a_502_with_the_reason_and_never_the_secret(self, world, permanent):
        put(world, {"recipients": ["ops@msp.example"]})
        world.set_mailer(Recorder(error=MailError(f"Microsoft Graph refused the message: HTTP 403 ErrorAccessDenied {SECRET}", permanent=permanent)))
        r = world.client.post(URL + "/test", headers=world.auth("platform_admin"))
        assert r.status_code == 502 and "ErrorAccessDenied" in r.json()["detail"] and SECRET not in r.text

    def test_it_is_rate_limited_so_it_cannot_flood_the_mailbox(self, world):
        put(world, {"recipients": ["ops@msp.example"]})
        assert world.client.post(URL + "/test", headers=world.auth("platform_admin")).status_code == 200
        r = world.client.post(URL + "/test", headers=world.auth("platform_admin"))
        assert r.status_code == 429 and r.headers["Retry-After"] == "10" and len(world.mailer.sent) == 1

    def test_a_refused_test_does_not_use_up_the_rate_limit(self, world):
        r = world.client.post(URL + "/test", headers=world.auth("platform_admin"))
        assert r.status_code == 409
        put(world, {"recipients": ["ops@msp.example"]})
        assert world.client.post(URL + "/test", headers=world.auth("platform_admin")).status_code == 200

    def test_a_failed_send_still_counts_against_the_limit_and_sends_no_audit_event(self, world):
        put(world, {"recipients": ["ops@msp.example"]})
        world.audits.clear()
        world.set_mailer(Recorder(error=MailError("HTTP 503", permanent=False)))
        assert world.client.post(URL + "/test", headers=world.auth("platform_admin")).status_code == 502
        assert world.audits == []
        assert world.client.post(URL + "/test", headers=world.auth("platform_admin")).status_code == 429

    def test_a_successful_test_is_audited(self, world):
        put(world, {"recipients": ["ops@msp.example"]})
        world.audits.clear()
        world.client.post(URL + "/test", headers=world.auth("platform_admin"))
        (event,) = world.audits
        assert event["action"] == "platform:alert_email_test_sent" and event["changes"] == {"recipient_count": 1} and event["actor_id"] == world.users["platform_admin"].id

    def test_a_hostile_actor_label_cannot_forge_lines_in_the_message(self, world, monkeypatch):
        put(world, {"recipients": ["ops@msp.example"]})
        u = world.users["platform_admin"]
        hostile = deps.CurrentUser(user_id=u.id, tenant_id=u.tenant_id, role=u.role, email="x\r\nBcc: evil@x.example")
        asyncio.run(self._call(world, hostile))
        body = world.mailer.sent[0][2]
        assert "\r" not in body.split("\n\n")[0] and "\nBcc:" not in body

    async def _call(self, world, user):
        async with world.factory() as s:
            return await pae.send_test_email(current_user=user, db=s)


class TestTheLog:
    def seed(self, world, n=3):
        with Session(world.sync) as s:
            for i in range(n):
                s.add(AlertEmailLog(alert_id=uuid.uuid4(), alert_tenant_id=world.other.id, severity="high", title=f"alert {i}", batch_id=uuid.uuid4(), recipient_count=2, sent_at=datetime(2026, 10, 10, 12, 0) + timedelta(minutes=i)))
            s.commit()

    def test_it_lists_the_emailed_alerts_newest_first_with_their_tenant(self, world):
        self.seed(world)
        j = get(world, path="/log").json()
        assert [x["title"] for x in j] == ["alert 2", "alert 1", "alert 0"] and {x["tenant_name"] for x in j} == {"Acme Corp"} and j[0]["recipient_count"] == 2

    def test_the_limit_is_bounded(self, world):
        self.seed(world, 5)
        assert len(get(world, path="/log?limit=2").json()) == 2
        for bad in ("0", "201", "-1", "abc"):
            assert get(world, path=f"/log?limit={bad}").status_code == 422

    def test_an_empty_log_is_an_empty_list(self, world):
        assert get(world, path="/log").json() == []


class TestTheCommandLine:
    def test_status_prints_json_without_credentials(self, world, monkeypatch, capsys):
        monkeypatch.setattr("app.db.database.AsyncSessionLocal", world.factory)
        assert cli.main(["status"]) == 0
        out = capsys.readouterr().out
        assert json.loads(out)["ok"] is True and json.loads(out)["enabled"] is False and SECRET not in out

    def test_set_changes_the_setting_and_records_cli_as_the_actor(self, world, monkeypatch, capsys):
        monkeypatch.setattr("app.db.database.AsyncSessionLocal", world.factory)
        assert cli.main(["set", "--recipients", "A@msp.example, b@msp.example,", "--min-severity", "critical", "--enable"]) == 0
        j = json.loads(capsys.readouterr().out)
        assert j["recipients"] == ["a@msp.example", "b@msp.example"] and j["min_severity"] == "critical" and j["enabled"] is True and j["updated_by"] == "cli"

    def test_disable_switches_it_off(self, world, monkeypatch, capsys):
        monkeypatch.setattr("app.db.database.AsyncSessionLocal", world.factory)
        cli.main(["set", "--recipients", "a@msp.example", "--enable"])
        cli.main(["set", "--disable"])
        assert row(world).enabled is False

    @pytest.mark.parametrize("argv", [["set"], ["set", "--enable"], ["set", "--recipients", "not an address"], ["set", "--recipients", "a@msp.example", "--enable", "--disable"]])
    def test_a_refusal_is_json_and_exit_one_or_a_usage_error_and_changes_nothing(self, world, monkeypatch, capsys, argv):
        monkeypatch.setattr("app.db.database.AsyncSessionLocal", world.factory)
        try:
            code = cli.main(argv)
        except SystemExit as e:  # argparse: --enable with --disable
            code = e.code
        assert code in (1, 2)
        assert row(world).enabled is False and list(row(world).recipients or []) == [] and row(world).min_severity == "high", "a refused command changes nothing"

    def test_test_sends_through_the_sender(self, world, monkeypatch, capsys):
        monkeypatch.setattr("app.db.database.AsyncSessionLocal", world.factory)
        rec = Recorder()
        monkeypatch.setattr("app.services.alert_email.graph.GraphMailer.from_settings", classmethod(lambda cls, **kw: rec))
        cli.main(["set", "--recipients", "a@msp.example"])
        capsys.readouterr()
        assert cli.main(["test"]) == 0 and rec.sent[0][0] == ["a@msp.example"] and json.loads(capsys.readouterr().out)["sent_to"] == ["a@msp.example"]

    def test_test_without_recipients_or_credentials_is_refused(self, world, monkeypatch, capsys):
        monkeypatch.setattr("app.db.database.AsyncSessionLocal", world.factory)
        monkeypatch.setattr("app.services.alert_email.graph.GraphMailer.from_settings", classmethod(lambda cls, **kw: Recorder(configured=False)))
        assert cli.main(["test"]) == 1 and "recipient" in json.loads(capsys.readouterr().out)["error"]
        cli.main(["set", "--recipients", "a@msp.example"])
        capsys.readouterr()
        assert cli.main(["test"]) == 1 and "not set" in json.loads(capsys.readouterr().out)["error"]

    def test_a_microsoft_refusal_is_scrubbed(self, world, monkeypatch, capsys):
        monkeypatch.setattr("app.db.database.AsyncSessionLocal", world.factory)
        monkeypatch.setattr("app.services.alert_email.graph.GraphMailer.from_settings", classmethod(lambda cls, **kw: Recorder(error=MailError(f"HTTP 403 {SECRET}", permanent=True))))
        cli.main(["set", "--recipients", "a@msp.example"])
        capsys.readouterr()
        assert cli.main(["test"]) == 1
        out = capsys.readouterr().out
        assert SECRET not in out and "HTTP 403" in out

    def test_the_docstring_lists_the_three_commands(self):
        assert all(x in cli.__doc__ for x in ("status", "set", "test"))
