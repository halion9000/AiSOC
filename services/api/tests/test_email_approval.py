"""Signed approve/deny links for the e-mail approval fallback: the token can be neither forged nor stretched, and the e-mail cannot be used to smuggle markup."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from app.services import email_approval as ea

SECRET = "s3cret-signing-key"
NOW = 1_800_000_000.0


def _decode(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))


def _encode(envelope: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(envelope).encode()).rstrip(b"=").decode()


def _issue(**over):
    args = {"decision": "approved", "action_id": "act-1", "case_id": "case-1", "secret": SECRET, "now": NOW}
    args.update(over)
    return ea.issue_token(**args)


def test_a_token_round_trips_with_what_it_was_issued_for():
    tok = ea.verify_token(_issue(), secret=SECRET, now=NOW + 10)
    assert (tok.decision, tok.action_id, tok.case_id) == ("approved", "act-1", "case-1")
    assert tok.expires_at == int(NOW) + ea.DEFAULT_TTL_SECONDS


def test_the_token_is_one_url_safe_string():
    token = _issue()
    assert token == token.strip()
    assert all(c.isalnum() or c in "-_" for c in token), "no padding, no characters that need URL-encoding"


def test_a_token_expires_at_its_stamp_and_not_before():
    token = _issue(ttl_seconds=600)
    ea.verify_token(token, secret=SECRET, now=NOW + 600)
    with pytest.raises(ea.EmailApprovalError, match="expired"):
        ea.verify_token(token, secret=SECRET, now=NOW + 601)


def test_a_ttl_below_a_minute_is_raised_to_a_minute():
    token = _issue(ttl_seconds=1)
    assert ea.verify_token(token, secret=SECRET, now=NOW + 59).expires_at == int(NOW) + 60


def test_the_wrong_secret_is_a_signature_mismatch():
    with pytest.raises(ea.EmailApprovalError, match="signature mismatch"):
        ea.verify_token(_issue(), secret="another-secret", now=NOW)


@pytest.mark.parametrize(
    "field,value",
    [("d", "rejected"), ("a", "act-2"), ("c", "case-2"), ("e", int(NOW) + 10_000_000)],
)
def test_changing_any_signed_field_breaks_the_signature(field, value):
    """Flip approve to deny, point it at another action or case, or push the expiry out: each is caught."""
    envelope = _decode(_issue())
    envelope[field] = value
    with pytest.raises(ea.EmailApprovalError, match="signature mismatch"):
        ea.verify_token(_encode(envelope), secret=SECRET, now=NOW)


def test_the_approve_and_deny_tokens_are_not_interchangeable():
    approve, reject = _issue(decision="approved"), _issue(decision="rejected")
    assert approve != reject
    assert ea.verify_token(reject, secret=SECRET, now=NOW).decision == "rejected"


@pytest.mark.parametrize(
    "bad", ["", "not base64 at all!!", "e30", _encode({"d": "approved"}), _encode({"d": "maybe", "a": "x", "e": 1, "s": "x"})]
)
def test_malformed_or_incomplete_tokens_are_refused_with_a_clear_error(bad):
    with pytest.raises(ea.EmailApprovalError):
        ea.verify_token(bad, secret=SECRET, now=NOW)


def test_a_string_expiry_is_not_accepted():
    envelope = _decode(_issue())
    envelope["e"] = str(envelope["e"])
    with pytest.raises(ea.EmailApprovalError, match="expires_at"):
        ea.verify_token(_encode(envelope), secret=SECRET, now=NOW)


def test_it_refuses_to_issue_or_verify_without_a_secret_and_to_issue_for_an_unknown_decision_or_no_action():
    with pytest.raises(ea.EmailApprovalError, match="secret is empty"):
        _issue(secret="")
    with pytest.raises(ea.EmailApprovalError, match="secret is empty"):
        ea.verify_token(_issue(), secret="", now=NOW)
    with pytest.raises(ea.EmailApprovalError, match="unsupported decision"):
        _issue(decision="maybe")
    with pytest.raises(ea.EmailApprovalError, match="action_id is required"):
        _issue(action_id="")


def test_the_url_carries_the_token_as_one_query_parameter():
    url = ea.approval_url(base_url="https://aisoc.example/", decision="approved", action_id="a", case_id="c", secret=SECRET, now=NOW)
    assert url.startswith("https://aisoc.example/v1/actions/email-decide?token=")
    token = url.split("token=", 1)[1]
    assert ea.verify_token(token, secret=SECRET, now=NOW).action_id == "a"


class _Mailer:
    def __init__(self):
        self.sent: list[dict] = []

    async def send(self, **kwargs):
        self.sent.append(kwargs)
        return {"id": "<msg-1>"}


async def test_the_e_mail_goes_to_every_recipient_with_a_working_approve_and_deny_link():
    mailer = _Mailer()
    resp = await ea.send_approval_email(
        recipients=["a@x.test", "b@x.test"],
        case={"id": "case-1", "case_number": "AC-7"},
        action={"id": "act-1", "action_type": "isolate_host", "target": "LAPTOP-1", "rationale": "ransomware behaviour"},
        api_base_url="https://api.test",
        web_base_url="https://app.test",
        secret=SECRET,
        mailer=mailer,
        now=NOW,
    )
    assert resp == {"id": "<msg-1>"}
    (sent,) = mailer.sent
    assert sent["to"] == ["a@x.test", "b@x.test"]
    assert "AC-7" in sent["subject"] and "isolate_host" in sent["subject"]
    lines = {line.split(":", 1)[0]: line.split(": ", 1)[1] for line in sent["text"].splitlines() if line.startswith(("Approve", "Deny"))}
    approve = ea.verify_token(lines["Approve"].split("token=", 1)[1], secret=SECRET, now=NOW)
    deny = ea.verify_token(lines["Deny"].split("token=", 1)[1], secret=SECRET, now=NOW)
    assert (approve.decision, deny.decision) == ("approved", "rejected")
    assert approve.action_id == deny.action_id == "act-1"
    assert "https://app.test/cases/case-1" in sent["text"]


async def test_it_refuses_to_send_with_no_recipient_or_no_action_id():
    base = {
        "case": {"id": "c"},
        "api_base_url": "https://api.test",
        "web_base_url": "https://app.test",
        "secret": SECRET,
        "mailer": _Mailer(),
    }
    with pytest.raises(ea.EmailApprovalError, match="no recipients"):
        await ea.send_approval_email(recipients=[], action={"id": "a"}, **base)
    with pytest.raises(ea.EmailApprovalError, match=r"action\.id"):
        await ea.send_approval_email(recipients=["a@x.test"], action={}, **base)
    assert base["mailer"].sent == []


def test_text_the_agent_wrote_cannot_put_markup_or_a_second_link_into_the_e_mail():
    """The rationale and target come from an agent's own words about an alert; the page they are shown on must treat them as text."""
    subject, text, html = ea.render_approval_email(
        case={"id": "c", "case_number": "AC-1"},
        action={
            "action_type": "block_ip",
            "target": "<img src=x onerror=alert(1)>",
            "rationale": "<a href='https://evil.test'>Approve here</a>",
        },
        approve_url="https://api.test/approve?token=t1",
        reject_url="https://api.test/deny?token=t2",
        web_base_url="https://app.test",
    )
    assert "<a href='https://evil.test'>" not in html
    assert "<img src=x" not in html
    assert "&lt;a href=" in html
    assert html.count("<a href=") == 2, "only the real Approve and Deny links are links"
    assert "Approve: https://api.test/approve?token=t1" in text


async def test_mailgun_posts_to_the_domain_with_basic_auth_and_surfaces_a_failure():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"id": "<m>", "message": "Queued"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    mg = ea.MailgunClient(api_key="key-1", domain="mg.test", from_addr="a@mg.test", client=client)
    assert (await mg.send(to=["x@y.test"], subject="s", html="<p>h</p>", text="t"))["id"] == "<m>"
    assert str(seen[0].url) == "https://api.mailgun.net/v3/mg.test/messages"
    assert seen[0].headers["authorization"].startswith("Basic ")
    assert b"x%40y.test" in seen[0].content or b"x@y.test" in seen[0].content

    failing = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"message": "Forbidden"})))
    with pytest.raises(httpx.HTTPStatusError):
        await ea.MailgunClient(api_key="bad", domain="mg.test", client=failing).send(to=["x@y.test"], subject="s", html="h", text="t")
    await client.aclose()
    await failing.aclose()


async def test_mailgun_without_its_settings_refuses_before_any_request(monkeypatch):
    monkeypatch.delenv("MAILGUN_API_KEY", raising=False)
    monkeypatch.delenv("MAILGUN_DOMAIN", raising=False)
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: pytest.fail("no request should be made")))
    with pytest.raises(ea.EmailApprovalError, match="not configured"):
        await ea.MailgunClient(client=client).send(to=["x@y.test"], subject="s", html="h", text="t")
    await client.aclose()
