"""Emailing alerts to PLATFORM administrators through Microsoft Graph (optional, off by default).

Tested against a MOCK Graph (httpx's MockTransport) and a real SQLite database; the worker was also run against real Postgres with a stand-in Graph server (see the commit message). It has NOT been run against a real Microsoft tenant: the first real send should be
done with the platform setting's test email.
"""
import asyncio
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import Column, DateTime, MetaData, String, Table, Uuid, create_engine, insert, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.db.database import Base
from app.models.alert_email import AlertEmailLog, PlatformAlertEmailSettings
from app.models.tenant import Tenant
from app.services.alert_email import compose, settings_store
from app.services.alert_email.graph import GraphMailer, MailError, scrub
from app.workers import alert_email_worker as worker

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
SECRET = "s3cret-client-value-9d1f"
APP = Path(__file__).resolve().parent.parent / "app"


# ---------------------------------------------------------------- the Graph sender, against a mock Graph
class MockGraph:
    """Records every request and answers from a script. Each handler entry is a (status, json_body, headers) tuple or an exception to raise."""

    def __init__(self, token_script=None, send_script=None):
        self.requests: list[httpx.Request] = []
        self.token_script = list(token_script or [(200, {"access_token": "tok-1", "expires_in": 3600}, {})])
        self.send_script = list(send_script or [(202, None, {})])

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        script = self.token_script if "/oauth2/v2.0/token" in request.url.path else self.send_script
        item = script.pop(0) if len(script) > 1 else script[0]
        if isinstance(item, Exception):
            raise item
        status, body, headers = item
        return httpx.Response(status, json=body, headers=headers) if body is not None else httpx.Response(status, headers=headers)

    def mailer(self, **kw):
        client = httpx.AsyncClient(transport=httpx.MockTransport(self.handler))
        defaults = dict(tenant_id="entra-tenant", client_id="client-1", client_secret=SECRET, sender="alerts@msp.example", client=client)
        return GraphMailer(**{**defaults, **kw})


def send(mailer, to=("ops@msp.example",), subject="subj", text="body"):
    return asyncio.run(mailer.send(list(to), subject, text))


class TestTheGraphRequests:
    def test_it_asks_for_a_token_with_the_client_credentials_flow_and_sends_plain_text_from_the_mailbox(self):
        g = MockGraph()
        send(g.mailer(), to=("a@msp.example", "b@msp.example"), subject="Hello", text="Line one\nLine two")
        token_req, send_req = g.requests
        assert token_req.method == "POST" and str(token_req.url) == "https://login.microsoftonline.com/entra-tenant/oauth2/v2.0/token"
        form = dict(httpx.QueryParams(token_req.content.decode()))
        assert form == {"client_id": "client-1", "client_secret": SECRET, "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"}
        assert str(send_req.url) == "https://graph.microsoft.com/v1.0/users/alerts@msp.example/sendMail" and send_req.headers["Authorization"] == "Bearer tok-1"
        import json

        body = json.loads(send_req.content)
        assert body == {"message": {"subject": "Hello", "body": {"contentType": "Text", "content": "Line one\nLine two"}, "toRecipients": [{"emailAddress": {"address": "a@msp.example"}}, {"emailAddress": {"address": "b@msp.example"}}]}, "saveToSentItems": False}

    def test_the_sender_mailbox_is_url_encoded_but_keeps_its_at_sign(self):
        g = MockGraph()
        send(g.mailer(sender="first+last@msp.example"))
        assert g.requests[1].url.raw_path.decode().endswith("/users/first%2Blast@msp.example/sendMail")

    def test_the_authority_and_graph_urls_can_be_changed_for_other_clouds_or_a_stand_in(self):
        g = MockGraph()
        send(g.mailer(base_url="https://graph.microsoft.us/v1.0/", authority="https://login.microsoftonline.us/"))
        assert str(g.requests[0].url).startswith("https://login.microsoftonline.us/entra-tenant/") and str(g.requests[1].url).startswith("https://graph.microsoft.us/v1.0/users/")

    def test_a_token_is_reused_until_a_minute_before_it_expires_then_renewed(self):
        clock = [1000.0]
        g = MockGraph(token_script=[(200, {"access_token": "tok-1", "expires_in": 3600}, {}), (200, {"access_token": "tok-2", "expires_in": 3600}, {})])
        m = g.mailer(monotonic=lambda: clock[0])
        send(m), send(m)
        assert [r.url.path.endswith("/token") for r in g.requests] == [True, False, False]
        clock[0] += 3600 - 61
        send(m)
        assert sum(r.url.path.endswith("/token") for r in g.requests) == 1
        clock[0] += 5
        send(m)
        assert sum(r.url.path.endswith("/token") for r in g.requests) == 2 and g.requests[-1].headers["Authorization"] == "Bearer tok-2"

    def test_a_401_on_the_send_is_retried_once_with_a_fresh_token(self):
        g = MockGraph(token_script=[(200, {"access_token": "old", "expires_in": 3600}, {}), (200, {"access_token": "new", "expires_in": 3600}, {})], send_script=[(401, {"error": {"code": "InvalidAuthenticationToken"}}, {}), (202, None, {})])
        send(g.mailer())
        assert [r.headers.get("Authorization") for r in g.requests if r.url.path.endswith("/sendMail")] == ["Bearer old", "Bearer new"]

    def test_a_second_401_is_permanent(self):
        g = MockGraph(send_script=[(401, {"error": {"code": "InvalidAuthenticationToken", "message": "expired"}}, {})])
        with pytest.raises(MailError) as e:
            send(g.mailer())
        assert e.value.permanent is True and "InvalidAuthenticationToken" in str(e.value)
        assert sum(r.url.path.endswith("/sendMail") for r in g.requests) == 2, "exactly one retry"

    @pytest.mark.parametrize("status", [400, 403, 404, 413])
    def test_a_refusal_that_will_not_fix_itself_is_permanent(self, status):
        g = MockGraph(send_script=[(status, {"error": {"code": "ErrorAccessDenied", "message": "Access is denied."}}, {})])
        with pytest.raises(MailError) as e:
            send(g.mailer())
        assert e.value.permanent is True and f"HTTP {status}" in str(e.value) and "ErrorAccessDenied" in str(e.value)

    @pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
    def test_throttling_and_server_errors_are_transient(self, status):
        g = MockGraph(send_script=[(status, {"error": {"code": "TooManyRequests"}}, {"Retry-After": "17"})])
        with pytest.raises(MailError) as e:
            send(g.mailer())
        assert e.value.permanent is False and e.value.retry_after == 17.0

    @pytest.mark.parametrize("header,expected", [("not-a-number", None), ("-5", None), ("999999", None), ("0", 0.0), ("30", 30.0)])
    def test_the_retry_after_hint_is_only_trusted_when_sensible(self, header, expected):
        g = MockGraph(send_script=[(429, {"error": {"code": "x"}}, {"Retry-After": header})])
        with pytest.raises(MailError) as e:
            send(g.mailer())
        assert e.value.retry_after == expected

    def test_a_refused_token_request_is_permanent_and_never_shows_the_secret(self):
        g = MockGraph(token_script=[(401, {"error": "invalid_client", "error_description": f"AADSTS7000215: Invalid client secret provided {SECRET}"}, {})])
        with pytest.raises(MailError) as e:
            send(g.mailer())
        assert e.value.permanent is True and "invalid_client" in str(e.value) and SECRET not in str(e.value) and "***" in str(e.value)

    def test_a_token_server_error_is_transient(self):
        g = MockGraph(token_script=[(503, {"error": "temporarily_unavailable"}, {})])
        with pytest.raises(MailError) as e:
            send(g.mailer())
        assert e.value.permanent is False

    @pytest.mark.parametrize("exc", [httpx.ConnectError("boom"), httpx.ReadTimeout("slow"), httpx.RemoteProtocolError("bad")])
    def test_a_network_failure_is_transient_and_says_only_what_kind(self, exc):
        g = MockGraph(send_script=[exc])
        with pytest.raises(MailError) as e:
            send(g.mailer())
        assert e.value.permanent is False and type(exc).__name__ in str(e.value) and "boom" not in str(e.value)

    @pytest.mark.parametrize("token_body", [{"nothing": 1}, {"access_token": 5, "expires_in": "soon"}])
    def test_a_token_response_that_is_not_understood_is_transient(self, token_body):
        g = MockGraph(token_script=[(200, token_body, {})])
        with pytest.raises(MailError) as e:
            send(g.mailer())
        assert e.value.permanent is False

    def test_a_graph_error_that_quotes_the_secret_or_the_token_is_scrubbed_and_limited(self):
        g = MockGraph(send_script=[(403, {"error": {"code": "Denied", "message": f"bad {SECRET} and tok-1 " + "x" * 600}}, {})])
        with pytest.raises(MailError) as e:
            send(g.mailer())
        text = str(e.value)
        assert SECRET not in text and "tok-1" not in text and len(text) < 330

    def test_an_error_body_that_is_not_json_still_gives_a_status(self):
        def handler(request):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3600}) if request.url.path.endswith("/token") else httpx.Response(502, text="<html>Bad gateway</html>")

        m = GraphMailer(tenant_id="t", client_id="c", client_secret=SECRET, sender="a@b.example", client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        with pytest.raises(MailError) as e:
            send(m)
        assert "HTTP 502" in str(e.value) and e.value.permanent is False

    def test_without_credentials_nothing_is_sent_and_it_is_a_permanent_error(self):
        g = MockGraph()
        for missing in ("tenant_id", "client_id", "client_secret", "sender"):
            m = g.mailer(**{missing: ""})
            assert m.configured is False
            with pytest.raises(MailError) as e:
                send(m)
            assert e.value.permanent is True
        assert g.requests == []

    def test_no_recipients_is_refused_before_any_request(self):
        g = MockGraph()
        with pytest.raises(MailError):
            asyncio.run(g.mailer().send([], "s", "b"))
        assert g.requests == []

    def test_scrub_replaces_every_secret_and_truncates(self):
        assert scrub("a SECRET b SECRET c", ("SECRET",)) == "a *** b *** c"
        assert scrub("x" * 1000, ()).endswith("...") and len(scrub("x" * 1000, ())) == 240
        assert scrub("line1\n  line2", ()) == "line1 line2"

    def test_from_settings_reads_the_environment_settings(self, monkeypatch):
        for name, value in (("ALERT_EMAIL_GRAPH_TENANT_ID", "T"), ("ALERT_EMAIL_GRAPH_CLIENT_ID", "C"), ("ALERT_EMAIL_GRAPH_CLIENT_SECRET", "S"), ("ALERT_EMAIL_SENDER", "m@x.example")):
            monkeypatch.setattr(settings, name, value)
        m = GraphMailer.from_settings()
        assert (m.tenant_id, m.client_id, m.client_secret, m.sender, m.configured) == ("T", "C", "S", "m@x.example", True)


# ---------------------------------------------------------------- the composer, against hostile alert text
def line(title="Impossible travel", severity="high", tenant="Acme Corp", rule="geo-1", source="okta", age=0, id=None):
    return compose.AlertLine(id=id or uuid.uuid4(), tenant_name=tenant, title=title, severity=severity, rule_name=rule, connector_type=source, created_at=NOW - timedelta(minutes=age))


class TestTheEmailText:
    @pytest.mark.parametrize("hostile", ["a\nBcc: attacker@evil.example", "a\r\nSubject: forged", "a\x00b\x1bc", "a\u202eb", "a\u2028b\u2029c", "a\u200bb\u200fc\ufeffd", "tab\there"])
    def test_nothing_in_an_alert_can_start_a_new_line_or_inject_a_header_or_reverse_text(self, hostile):
        subject, body = compose.build_message([line(title=hostile)], pending_more=0, min_severity="high")
        assert "\n" not in subject and "\r" not in subject
        for forbidden in ("\r", "\x00", "\x1b", "\u202e", "\u2028", "\u2029", "\u200b", "\u200f", "\ufeff", "\t"):
            assert forbidden not in subject and forbidden not in body
        assert not any(l.lstrip().lower().startswith(("bcc:", "subject:")) for l in body.split("\n"))

    @pytest.mark.parametrize("raw,shown", [("go to http://evil.example/x", "hxxp://evil.example/x"), ("see HTTPS://Evil.example", "hxxps://Evil.example"), ("a https://x.y and http://z.w", "hxxps://x.y and hxxp://z.w")])
    def test_links_in_alert_text_are_defanged(self, raw, shown):
        assert shown in compose.build_message([line(title=raw)], pending_more=0, min_severity="high")[1]
        assert "http://" not in compose.build_message([line(title=raw, tenant=raw, rule=raw, source=raw)], pending_more=0, min_severity="high")[1]

    def test_every_untrusted_field_is_limited_and_marked_when_cut(self):
        _, body = compose.build_message([line(title="T" * 900, tenant="N" * 400, rule="R" * 400, source="S" * 400)], pending_more=0, min_severity="high")
        assert "T" * 201 not in body and "N" * 81 not in body and "R" * 81 not in body and "S" * 81 not in body and "..." in body

    def test_the_subject_is_one_short_line_with_the_count_and_the_highest_severity(self):
        subject, _ = compose.build_message([line(severity="medium"), line(severity="critical", title="Ransomware"), line(severity="high")], pending_more=0, min_severity="medium")
        assert subject == "[AiSOC] 3 alerts, highest CRITICAL: Ransomware"
        assert compose.build_message([line()], pending_more=0, min_severity="high")[0].startswith("[AiSOC] 1 alert, highest HIGH")
        assert len(compose.build_message([line(title="x" * 5000)], pending_more=0, min_severity="high")[0]) <= 150

    def test_the_most_severe_alert_comes_first_and_older_before_newer_within_a_severity(self):
        a, b, c = line(title="med", severity="medium", age=1), line(title="crit", severity="critical", age=5), line(title="high-old", severity="high", age=30)
        d = line(title="high-new", severity="high", age=2)
        _, body = compose.build_message([a, d, b, c], pending_more=0, min_severity="medium")
        assert [body.index(t) for t in ("crit", "high-old", "high-new", "med")] == sorted(body.index(t) for t in ("crit", "high-old", "high-new", "med"))

    def test_each_alert_names_its_tenant_severity_rule_source_and_time(self):
        _, body = compose.build_message([line(tenant="Acme Corp", title="Impossible travel", severity="critical", rule="geo-1", source="okta", age=3)], pending_more=0, min_severity="high")
        assert "[CRITICAL] Acme Corp: Impossible travel" in body and "rule: geo-1 | source: okta | 2026-10-10 11:57 UTC" in body

    def test_the_link_is_the_consoles_own_address_plus_the_alert_uuid_and_only_when_configured(self):
        aid = uuid.uuid4()
        with_link = compose.build_message([line(id=aid)], pending_more=0, min_severity="high", console_base_url="https://console.msp.example/")[1]
        assert f"  https://console.msp.example/alerts/{aid}" in with_link
        for base in ("", "ftp://x", "javascript:alert(1)", "console.msp.example"):
            assert "/alerts/" not in compose.build_message([line(id=aid)], pending_more=0, min_severity="high", console_base_url=base)[1], base

    def test_the_description_and_raw_events_are_never_part_of_it(self):
        assert [f.name for f in __import__("dataclasses").fields(compose.AlertLine)] == ["id", "tenant_name", "title", "severity", "rule_name", "connector_type", "created_at"]

    @pytest.mark.parametrize("n,text", [(1, "1 more alert is waiting"), (2, "2 more alerts are waiting")])
    def test_pending_alerts_are_mentioned_in_the_singular_and_plural(self, n, text):
        assert text in compose.build_message([line()], pending_more=n, min_severity="high")[1]
        assert "waiting" not in compose.build_message([line()], pending_more=0, min_severity="high")[1]

    def test_an_unknown_severity_is_shown_as_info_not_as_whatever_was_sent(self):
        _, body = compose.build_message([line(severity="<script>alert(1)</script>")], pending_more=0, min_severity="info")
        assert "[INFO]" in body and "<script>" not in body

    def test_the_message_is_plain_text_and_says_who_it_is_for_and_that_the_names_are_untrusted(self):
        _, body = compose.build_message([line()], pending_more=0, min_severity="high")
        assert "platform administrators only" in body and "untrusted" in body and "<html" not in body.lower()


# ---------------------------------------------------------------- the platform setting
@pytest.fixture
def world(tmp_path):
    path = tmp_path / "alert_email.db"
    sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync, tables=[Tenant.__table__, PlatformAlertEmailSettings.__table__, AlertEmailLog.__table__])
    meta = MetaData()
    alerts = Table("alerts", meta, Column("id", Uuid, primary_key=True), Column("tenant_id", Uuid), Column("title", String), Column("severity", String), Column("created_at", DateTime(timezone=True)), Column("rule_name", String), Column("connector_type", String))
    meta.create_all(sync)
    ta, tb = Tenant(id=uuid.uuid4(), name="Acme Corp", slug="acme-" + uuid.uuid4().hex[:6]), Tenant(id=uuid.uuid4(), name="Globex", slug="globex-" + uuid.uuid4().hex[:6])
    with Session(sync, expire_on_commit=False) as s:
        s.add_all([ta, tb])
        s.commit()
    factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool), expire_on_commit=False)
    w = SimpleNamespace(sync=sync, factory=factory, alerts=alerts, ta=ta, tb=tb, mailer=None)

    def add(tenant, title="An alert", severity="high", age=1.0, rule="rule-1", source="okta"):
        aid = uuid.uuid4()
        with sync.begin() as c:
            c.execute(insert(alerts).values(id=aid, tenant_id=tenant.id, title=title, severity=severity, created_at=NOW - timedelta(minutes=age), rule_name=rule, connector_type=source))
        return aid

    w.add = add
    yield w
    sync.dispose()


def db(world, fn):
    async def go():
        async with world.factory() as s:
            return await fn(s)

    return asyncio.run(go())


class TestRecipientsAndTheSetting:
    @pytest.mark.parametrize("bad", ["Ops <ops@msp.example>", "ops@msp.example\nBcc: x@y.example", "ops@msp.example,other@msp.example", "ops @msp.example", "ops@", "@msp.example", "ops@localhost", "", "ops@msp..example", "a" * 70 + "@msp.example", "<ops@msp.example>", "ops@msp.example;x@y.example"])
    def test_anything_that_is_not_a_plain_address_is_refused(self, bad):
        with pytest.raises(settings_store.InvalidSettings):
            settings_store.normalize_recipients([bad])

    def test_surrounding_whitespace_including_a_stray_carriage_return_is_trimmed_not_refused(self):
        assert settings_store.normalize_recipients(["ops@msp.example\r", "\tb@msp.example\n"]) == ["ops@msp.example", "b@msp.example"]

    def test_addresses_are_trimmed_lower_cased_and_deduplicated_in_order(self):
        assert settings_store.normalize_recipients(["  Ops@MSP.example ", "ops@msp.example", "b@msp.example", "OPS@msp.example"]) == ["ops@msp.example", "b@msp.example"]

    def test_at_most_twenty_recipients(self):
        assert len(settings_store.normalize_recipients([f"u{i}@msp.example" for i in range(20)])) == 20
        with pytest.raises(settings_store.InvalidSettings):
            settings_store.normalize_recipients([f"u{i}@msp.example" for i in range(21)])

    @pytest.mark.parametrize("not_a_list", ["ops@msp.example", {"a": 1}, None, 5])
    def test_the_recipients_must_be_a_list(self, not_a_list):
        with pytest.raises(settings_store.InvalidSettings):
            settings_store.normalize_recipients(not_a_list)

    def test_the_row_is_created_everything_off_when_missing(self, world):
        row = db(world, settings_store.get_settings)
        assert (row.enabled, row.min_severity, list(row.recipients), row.enabled_since, row.consecutive_failures) == (False, "high", [], None, 0)

    def test_it_cannot_be_switched_on_without_a_recipient(self, world):
        with pytest.raises(settings_store.InvalidSettings, match="at least one recipient"):
            db(world, lambda s: settings_store.update_settings(s, updated_by="hal", enabled=True))

    def test_switching_on_starts_the_clock_and_staying_on_does_not_restart_it(self, world):
        first = NOW
        db(world, lambda s: settings_store.update_settings(s, updated_by="hal", recipients=["ops@msp.example"], enabled=True, now=first))
        db(world, lambda s: settings_store.update_settings(s, updated_by="hal", min_severity="critical", enabled=True, now=first + timedelta(hours=5)))
        row = db(world, settings_store.get_settings)
        assert row.enabled and row.enabled_since.replace(tzinfo=UTC) == first and row.min_severity == "critical"

    def test_switching_off_and_on_again_restarts_the_clock_so_the_gap_is_never_mailed(self, world):
        db(world, lambda s: settings_store.update_settings(s, updated_by="hal", recipients=["ops@msp.example"], enabled=True, now=NOW))
        db(world, lambda s: settings_store.update_settings(s, updated_by="hal", enabled=False, now=NOW + timedelta(hours=1)))
        db(world, lambda s: settings_store.update_settings(s, updated_by="hal", enabled=True, now=NOW + timedelta(hours=9)))
        assert db(world, settings_store.get_settings).enabled_since.replace(tzinfo=UTC) == NOW + timedelta(hours=9)

    @pytest.mark.parametrize("bad", ["", "urgent", "HIGH", "None", "5"])
    def test_the_minimum_severity_must_be_a_known_one(self, world, bad):
        with pytest.raises(settings_store.InvalidSettings):
            db(world, lambda s: settings_store.update_settings(s, updated_by="hal", min_severity=bad))

    def test_it_records_who_changed_it_and_when_and_limits_the_label(self, world):
        db(world, lambda s: settings_store.update_settings(s, updated_by="x" * 500, recipients=["ops@msp.example"], now=NOW))
        row = db(world, settings_store.get_settings)
        assert len(row.updated_by_label) == 200 and row.updated_at.replace(tzinfo=UTC) == NOW

    def test_a_refused_change_changes_nothing(self, world):
        db(world, lambda s: settings_store.update_settings(s, updated_by="hal", recipients=["ops@msp.example"]))
        with pytest.raises(settings_store.InvalidSettings):
            db(world, lambda s: settings_store.update_settings(s, updated_by="hal", min_severity="low", recipients=["not an address"]))
        row = db(world, settings_store.get_settings)
        assert list(row.recipients) == ["ops@msp.example"] and row.min_severity == "high"


# ---------------------------------------------------------------- the worker, against a real database
class FakeMailer:
    client_secret = SECRET

    def __init__(self, configured=True, error=None):
        self.configured, self.error, self.sent = configured, error, []

    async def send(self, to, subject, text):
        if self.error:
            raise self.error
        self.sent.append((list(to), subject, text))


def turn_on(world, *, since=None, severity="high", recipients=("ops@msp.example",)):
    db(world, lambda s: settings_store.update_settings(s, updated_by="hal", recipients=list(recipients), min_severity=severity, enabled=True, now=since or NOW - timedelta(hours=2)))


def cycle(world, mailer, now=NOW):
    return asyncio.run(worker.run_once(session_factory=world.factory, mailer=mailer, now=now))


def logged(world):
    with Session(world.sync) as s:
        return {r.alert_id for r in s.scalars(select(AlertEmailLog))}


def cfg(world):
    return db(world, settings_store.get_settings)


class TestWhatTheWorkerSends:
    def test_nothing_happens_while_it_is_switched_off(self, world):
        world.add(world.ta)
        m = FakeMailer()
        assert cycle(world, m).skipped == "disabled" and m.sent == [] and logged(world) == set()

    def test_nothing_is_sent_without_a_recipient(self, world):
        db(world, lambda s: settings_store.update_settings(s, updated_by="hal", recipients=["ops@msp.example"], enabled=True, now=NOW - timedelta(hours=2)))
        with world.sync.begin() as c:
            c.exec_driver_sql("update platform_alert_email_settings set recipients = '[]'")
        world.add(world.ta)
        m = FakeMailer()
        assert cycle(world, m).skipped == "no_recipients" and m.sent == []

    def test_without_credentials_it_sends_nothing_and_says_why_on_the_setting_once(self, world):
        turn_on(world)
        world.add(world.ta)
        m = FakeMailer(configured=False)
        r = cycle(world, m)
        assert r.skipped == "not_configured" and "not configured" in cfg(world).last_error and m.sent == [] and logged(world) == set()
        first_error_at = cfg(world).last_error_at
        cycle(world, m, now=NOW + timedelta(minutes=5))
        assert cfg(world).last_error_at == first_error_at, "the same message is not rewritten every cycle"

    def test_it_emails_one_message_to_all_recipients_listing_the_alerts_and_logs_each(self, world):
        turn_on(world, recipients=["ops@msp.example", "lead@msp.example"])
        a, b = world.add(world.ta, title="Impossible travel", severity="critical"), world.add(world.tb, title="Malware beaconing", severity="high")
        m = FakeMailer()
        r = cycle(world, m)
        assert r.sent == 2 and len(m.sent) == 1
        to, subject, body = m.sent[0]
        assert to == ["ops@msp.example", "lead@msp.example"] and "2 alerts, highest CRITICAL" in subject
        assert "Acme Corp: Impossible travel" in body and "Globex: Malware beaconing" in body
        assert logged(world) == {a, b}
        row = cfg(world)
        assert row.last_sent_at is not None and row.last_error is None and row.consecutive_failures == 0

    @pytest.mark.parametrize("minimum,expected", [("critical", {"critical"}), ("high", {"critical", "high"}), ("medium", {"critical", "high", "medium"}), ("low", {"critical", "high", "medium", "low"}), ("info", {"critical", "high", "medium", "low", "info"})])
    def test_only_alerts_at_or_above_the_severity_are_sent(self, world, minimum, expected):
        turn_on(world, severity=minimum)
        ids = {s: world.add(world.ta, title=f"{s} alert", severity=s) for s in ("critical", "high", "medium", "low", "info")}
        cycle(world, FakeMailer())
        assert logged(world) == {ids[s] for s in expected}

    def test_switching_it_on_never_mails_the_backlog_only_alerts_created_after(self, world):
        old = world.add(world.ta, title="before", severity="critical", age=30)
        turn_on(world, since=NOW - timedelta(minutes=10))
        new = world.add(world.ta, title="after", severity="critical", age=2)
        m = FakeMailer()
        cycle(world, m)
        assert logged(world) == {new} and old not in logged(world) and "before" not in m.sent[0][2]

    def test_alerts_older_than_the_maximum_age_are_never_mailed_even_if_the_feature_is_older(self, world, monkeypatch):
        monkeypatch.setattr(settings, "ALERT_EMAIL_MAX_ALERT_AGE_HOURS", 1)
        turn_on(world, since=NOW - timedelta(hours=48))
        stale, fresh = world.add(world.ta, title="stale", age=61), world.add(world.ta, title="fresh", age=59)
        cycle(world, FakeMailer())
        assert logged(world) == {fresh} and stale not in logged(world)

    def test_an_alert_is_never_mailed_twice(self, world):
        turn_on(world)
        world.add(world.ta)
        m = FakeMailer()
        cycle(world, m), cycle(world, m, now=NOW + timedelta(minutes=1))
        assert len(m.sent) == 1 and cycle(world, m, now=NOW + timedelta(minutes=2)).skipped == "nothing_to_send"

    def test_a_new_alert_after_a_send_goes_out_in_the_next_cycle_only(self, world):
        turn_on(world)
        world.add(world.ta, title="first")
        m = FakeMailer()
        cycle(world, m)
        world.add(world.ta, title="second", age=0.5)
        cycle(world, m, now=NOW + timedelta(minutes=1))
        assert len(m.sent) == 2 and "second" in m.sent[1][2] and "first" not in m.sent[1][2]

    def test_a_storm_is_one_capped_message_per_cycle_most_severe_first_and_nothing_is_lost_or_repeated(self, world):
        turn_on(world, severity="low")
        ids = [world.add(world.ta, title=f"a{i}", severity="low", age=60 - i) for i in range(45)]
        crit = world.add(world.ta, title="THE-CRITICAL", severity="critical", age=1)
        m = FakeMailer()
        sizes = [cycle(world, m, now=NOW + timedelta(minutes=k)).sent for k in range(4)]
        assert sizes == [20, 20, 6, 0] and len(m.sent) == 3
        assert "THE-CRITICAL" in m.sent[0][2], "the critical alert is in the first message although it is the newest"
        assert logged(world) == set(ids) | {crit}, "46 alerts, each exactly once"
        assert "26 more alerts are waiting" in m.sent[0][2] and "6 more alerts are waiting" in m.sent[1][2] and "waiting" not in m.sent[2][2]

    def test_the_cap_is_a_setting(self, world, monkeypatch):
        monkeypatch.setattr(settings, "ALERT_EMAIL_MAX_ALERTS_PER_EMAIL", 3)
        turn_on(world)
        for i in range(7):
            world.add(world.ta, title=f"a{i}")
        assert [cycle(world, FakeMailer(), now=NOW + timedelta(minutes=k)).sent for k in range(4)] == [3, 3, 1, 0]

    def test_an_alert_from_a_deleted_tenant_still_goes_out_as_unknown(self, world):
        turn_on(world)
        with world.sync.begin() as c:
            c.execute(insert(world.alerts).values(id=uuid.uuid4(), tenant_id=uuid.uuid4(), title="orphan", severity="high", created_at=NOW - timedelta(minutes=1), rule_name=None, connector_type=None))
        m = FakeMailer()
        assert cycle(world, m).sent == 1 and "unknown tenant: orphan" in m.sent[0][2]

    def test_hostile_alert_text_does_not_reach_the_message_as_anything_but_one_defanged_line(self, world):
        turn_on(world)
        world.add(world.ta, title="x\nBcc: evil@x.example http://phish.example", rule="r\u202e")
        m = FakeMailer()
        cycle(world, m)
        _, subject, body = m.sent[0]
        assert "\n" not in subject and "hxxp://phish.example" in body and "http://phish" not in body and "\u202e" not in body

    def test_the_console_link_is_included_when_the_public_address_is_set(self, world, monkeypatch):
        monkeypatch.setattr(settings, "CONSOLE_PUBLIC_BASE_URL", "https://console.msp.example")
        turn_on(world)
        aid = world.add(world.ta)
        m = FakeMailer()
        cycle(world, m)
        assert f"https://console.msp.example/alerts/{aid}" in m.sent[0][2]

    def test_a_row_that_arrives_with_a_naive_timestamp_is_handled(self, world):
        turn_on(world)
        world.add(world.ta)
        assert cycle(world, FakeMailer()).sent == 1


class TestWhenSendingFails:
    @pytest.mark.parametrize("permanent", [True, False])
    def test_nothing_is_marked_sent_the_error_is_stored_scrubbed_and_the_failures_are_counted(self, world, permanent):
        turn_on(world)
        a = world.add(world.ta)
        m = FakeMailer(error=MailError(f"Microsoft Graph refused the message: HTTP 403 Denied {SECRET}", permanent=permanent))
        r = cycle(world, m)
        row = cfg(world)
        assert r.sent == 0 and r.error and logged(world) == set() and a is not None
        assert SECRET not in row.last_error and "HTTP 403" in row.last_error and row.consecutive_failures == 1 and row.last_error_at is not None
        cycle(world, m, now=NOW + timedelta(minutes=1))
        assert cfg(world).consecutive_failures == 2

    def test_fixing_the_problem_sends_the_backlog_and_clears_the_error(self, world):
        turn_on(world)
        ids = {world.add(world.ta, title=f"a{i}") for i in range(3)}
        broken = FakeMailer(error=MailError("HTTP 403 Denied", permanent=True))
        cycle(world, broken)
        cycle(world, broken, now=NOW + timedelta(minutes=1))
        assert logged(world) == set() and cfg(world).consecutive_failures == 2
        fixed = FakeMailer()
        r = cycle(world, fixed, now=NOW + timedelta(minutes=2))
        row = cfg(world)
        assert r.sent == 3 and logged(world) == ids and row.last_error is None and row.consecutive_failures == 0 and len(fixed.sent) == 1

    def test_a_long_outage_cannot_dump_a_pile_of_stale_alerts_on_anyone(self, world, monkeypatch):
        monkeypatch.setattr(settings, "ALERT_EMAIL_MAX_ALERT_AGE_HOURS", 2)
        turn_on(world, since=NOW - timedelta(hours=10))
        stale = world.add(world.ta, title="stale", age=130)
        fresh = world.add(world.ta, title="fresh", age=10)
        broken = FakeMailer(error=MailError("HTTP 503", permanent=False))
        cycle(world, broken)
        r = cycle(world, FakeMailer(), now=NOW + timedelta(minutes=5))
        assert logged(world) == {fresh} and stale not in logged(world) and r.sent == 1

    def test_if_another_copy_logged_some_of_the_same_alerts_the_message_is_not_repeated_and_the_rest_are_still_recorded(self, world):
        """Two copies of the worker at once (the lock is fail-open if Redis is down). The first commit collides on the primary key; the message DID go out, so the fallback must record the alerts that are NOT already logged, or they would be emailed again next cycle."""
        from sqlalchemy.exc import IntegrityError

        turn_on(world)
        a, b, c = world.add(world.ta, title="a"), world.add(world.ta, title="b"), world.add(world.ta, title="c")

        def other_copy_logs_a():
            with Session(world.sync) as s:
                s.add(AlertEmailLog(alert_id=a, alert_tenant_id=world.ta.id, severity="high", title="a", batch_id=uuid.uuid4(), recipient_count=1, sent_at=NOW))
                s.commit()

        class Colliding:
            def __init__(self, real):
                self.real, self.tripped = real, False

            async def commit(self):
                if not self.tripped:
                    self.tripped = True
                    raise IntegrityError("insert", {}, Exception("duplicate key"))
                return await self.real.commit()

            async def rollback(self):
                await self.real.rollback()
                other_copy_logs_a()  # visible once the failed transaction has let go

            def __getattr__(self, name):
                return getattr(self.real, name)

        class Factory:
            def __call__(self):
                outer = self

                class Ctx:
                    async def __aenter__(self):
                        outer.inner = world.factory()
                        return Colliding(await outer.inner.__aenter__())

                    async def __aexit__(self, *exc):
                        return await outer.inner.__aexit__(*exc)

                return Ctx()

        m = FakeMailer()
        r = asyncio.run(worker.run_once(session_factory=Factory(), mailer=m, now=NOW))
        assert len(m.sent) == 1 and r.sent == 3 and logged(world) == {a, b, c}, "the other copy's row is kept, ours are added: nothing is left to be emailed again"
        assert cycle(world, m, now=NOW + timedelta(minutes=1)).skipped == "nothing_to_send" and len(m.sent) == 1
        assert cfg(world).last_sent_at is not None and cfg(world).consecutive_failures == 0

    def test_old_log_rows_are_purged_every_cycle(self, world, monkeypatch):
        monkeypatch.setattr(settings, "ALERT_EMAIL_LOG_RETENTION_DAYS", 30)
        turn_on(world)
        with Session(world.sync) as s:
            s.add_all([AlertEmailLog(alert_id=uuid.uuid4(), alert_tenant_id=world.ta.id, severity="high", title="old", batch_id=uuid.uuid4(), recipient_count=1, sent_at=NOW - timedelta(days=31)), AlertEmailLog(alert_id=uuid.uuid4(), alert_tenant_id=world.ta.id, severity="high", title="recent", batch_id=uuid.uuid4(), recipient_count=1, sent_at=NOW - timedelta(days=29))])
            s.commit()
        cycle(world, FakeMailer())
        with Session(world.sync) as s:
            assert sorted(r.title for r in s.scalars(select(AlertEmailLog))) == ["recent"]


class TestTheLoop:
    def run_loop(self, results, monkeypatch, interval=60):
        monkeypatch.setattr(settings, "ALERT_EMAIL_POLL_INTERVAL_SECONDS", interval)
        script = list(results)
        sleeps: list[float] = []

        async def fake_run_once(**kw):
            item = script.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item

        async def fake_sleep(seconds):
            sleeps.append(seconds)
            if not script:
                raise asyncio.CancelledError

        monkeypatch.setattr(worker, "run_once", fake_run_once)
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(worker.run_forever(mailer_factory=lambda: FakeMailer(), sleep=fake_sleep))
        return sleeps

    def test_it_waits_the_interval_when_all_is_well(self, monkeypatch):
        ok = worker.RunResult(sent=1)
        assert self.run_loop([ok, ok, ok, ok], monkeypatch) == [60, 60, 60, 60]

    def test_it_waits_longer_and_longer_while_cycles_fail_and_resets_on_success(self, monkeypatch):
        bad, ok = worker.RunResult(error="x"), worker.RunResult(sent=1)
        assert self.run_loop([bad, bad, bad, ok, bad, ok], monkeypatch) == [120, 240, 480, 60, 120, 60]

    def test_the_wait_is_capped_at_sixteen_times_the_interval(self, monkeypatch):
        bad = worker.RunResult(error="x")
        sleeps = self.run_loop([bad] * 9 + [worker.RunResult()], monkeypatch)
        assert max(sleeps) == 60 * 16

    def test_a_cycle_that_raises_does_not_stop_the_loop_and_counts_as_a_failure(self, monkeypatch):
        assert self.run_loop([RuntimeError("db down"), worker.RunResult(sent=1), worker.RunResult()], monkeypatch) == [120, 60, 60]

    def test_cancellation_is_not_swallowed(self, monkeypatch):
        async def fake_run_once(**kw):
            raise asyncio.CancelledError

        monkeypatch.setattr(worker, "run_once", fake_run_once)
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(worker.run_forever(mailer_factory=lambda: FakeMailer(), sleep=lambda s: asyncio.sleep(0)))


class TestWiringAndTheTables:
    MIG = " ".join((APP.parent / "migrations" / "073_platform_alert_email.sql").read_text().split())

    def test_it_is_off_by_default_and_the_loop_is_only_started_when_switched_on(self):
        assert settings.ALERT_EMAIL_WORKER_ENABLED is False
        src = (APP / "main.py").read_text(encoding="utf-8")
        assert "if settings.ALERT_EMAIL_WORKER_ENABLED:" in src and 'job_name="alert_email"' in src and "alert_email_task.cancel()" in src and "run_alert_email" in src

    @pytest.mark.parametrize("name,low", [("ALERT_EMAIL_POLL_INTERVAL_SECONDS", 5), ("ALERT_EMAIL_MAX_ALERTS_PER_EMAIL", 1), ("ALERT_EMAIL_MAX_ALERT_AGE_HOURS", 1), ("ALERT_EMAIL_LOG_RETENTION_DAYS", 1)])
    def test_the_numeric_settings_have_floors_so_nobody_configures_a_hot_loop_or_zero_alerts(self, name, low):
        assert any(getattr(m, "ge", None) == low for m in type(settings).model_fields[name].metadata)

    def test_the_defaults(self):
        assert (settings.ALERT_EMAIL_POLL_INTERVAL_SECONDS, settings.ALERT_EMAIL_MAX_ALERTS_PER_EMAIL, settings.ALERT_EMAIL_MAX_ALERT_AGE_HOURS) == (60, 20, 24)

    def test_the_credentials_are_empty_by_default_and_the_secret_is_only_ever_read_from_the_environment(self):
        assert settings.ALERT_EMAIL_GRAPH_CLIENT_SECRET == "" and settings.ALERT_EMAIL_SENDER == ""
        assert "ALERT_EMAIL_GRAPH_CLIENT_SECRET" not in self.MIG and "client_secret" not in self.MIG.lower()

    def test_the_setting_is_a_singleton_the_database_enforces(self):
        assert "id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1)" in self.MIG and "ON CONFLICT (id) DO NOTHING" in self.MIG

    def test_the_severity_is_checked_and_the_log_is_keyed_by_alert(self):
        assert "CHECK (min_severity IN ('info', 'low', 'medium', 'high', 'critical'))" in self.MIG
        assert "alert_id UUID PRIMARY KEY" in self.MIG

    def test_the_tables_carry_no_tenant_id_column_so_no_row_level_security_is_owed(self):
        assert "tenant_id UUID" not in self.MIG.replace("alert_tenant_id UUID", "")

    def test_the_migration_creates_what_the_models_declare(self):
        for model in (PlatformAlertEmailSettings, AlertEmailLog):
            for column_ in model.__table__.columns:
                assert column_.name in self.MIG, column_.name

    def test_no_log_line_in_the_worker_or_the_sender_mentions_recipients_or_secrets(self):
        for path in ("workers/alert_email_worker.py", "services/alert_email/graph.py"):
            for n, text in enumerate((APP / path).read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"\blogger\.\w+\(", text):
                    assert not re.search(r"recipient|secret|token|subject|body", text, re.I), f"{path}:{n}: {text.strip()}"
