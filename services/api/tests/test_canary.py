"""The honeytoken tripwire: public by design, identical answers, forwards real visits, bounded."""

from __future__ import annotations

import uuid

import pytest
from app.api.v1.endpoints import canary
from starlette.requests import Request


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    canary.reset_limits()
    sent: list[dict] = []

    async def fake_forward(payload):
        sent.append(payload)

    async def no_alert(*_a, **_k):
        return None

    monkeypatch.setattr(canary, "_forward", fake_forward)
    monkeypatch.setattr(canary, "_raise_alert", no_alert)  # the database part is tested separately below
    yield sent
    canary.reset_limits()


def req(headers=None, peer="8.8.8.8"):
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw, "client": (peer, 50000)})


async def visit(token, **kw):
    return await canary.canary_visit(token, req(**kw))


@pytest.mark.asyncio
async def test_a_visit_to_a_token_is_forwarded_with_the_visitor_and_answers_with_a_pixel(clean):
    token = str(uuid.uuid4())
    out = await visit(token, headers={"User-Agent": "curl/8.0", "Referer": "http://wiki/page"})
    assert out.status_code == 200 and out.media_type == "image/gif" and out.body[:6] == b"GIF89a"
    (payload,) = clean
    assert payload["token_id"] == token and payload["source_ip"] == "8.8.8.8" and payload["user_agent"] == "curl/8.0"
    assert payload["headers"] == {"referer": "http://wiki/page"} and payload["body"] == {"via": "canary-link"}


@pytest.mark.asyncio
async def test_junk_and_unknown_ids_get_the_same_answer_and_a_junk_id_is_never_forwarded(clean):
    good = await visit(str(uuid.uuid4()))
    for junk in ("not-a-uuid", "../../etc/passwd", "1" * 500, "", "%00"):
        out = await visit(junk)
        assert out.status_code == good.status_code and out.body == good.body and out.headers["content-type"] == good.headers["content-type"]
    assert len(clean) == 1, "only the well-formed id was forwarded"


@pytest.mark.asyncio
async def test_the_answer_is_not_cached_and_does_not_reveal_whether_the_token_exists(clean):
    out = await visit(str(uuid.uuid4()))
    assert out.headers["cache-control"] == "no-store"
    assert len(out.body) < 100


@pytest.mark.asyncio
async def test_one_token_cannot_flood_the_service(clean):
    token = str(uuid.uuid4())
    for _ in range(canary._PER_TOKEN_PER_MINUTE + 25):
        out = await visit(token)
        assert out.status_code == 200, "past the limit the visitor still sees the normal answer"
    assert len(clean) == canary._PER_TOKEN_PER_MINUTE


@pytest.mark.asyncio
async def test_many_different_ids_cannot_flood_it_either(monkeypatch, clean):
    monkeypatch.setattr(canary, "_OVERALL_PER_MINUTE", 20)
    for _ in range(60):
        await visit(str(uuid.uuid4()))
    assert len(clean) == 20


def test_the_limits_free_up_after_a_minute():
    token = "t"
    for _ in range(canary._PER_TOKEN_PER_MINUTE):
        assert canary._allowed(token, 1000.0)
    assert not canary._allowed(token, 1001.0)
    assert canary._allowed(token, 1062.0)


@pytest.mark.parametrize(
    "peer,xff,expected",
    [
        ("8.8.8.8", None, "8.8.8.8"),
        ("8.8.8.8", "198.51.100.7", "8.8.8.8"),  # a public peer is not a proxy of ours: its header is not believed
        ("172.18.0.5", "198.51.100.7", "198.51.100.7"),  # our console in front: the address it appended
        ("172.18.0.5", "6.6.6.6, 198.51.100.7", "198.51.100.7"),  # earlier entries were sent by the visitor
        ("127.0.0.1", "garbage", "127.0.0.1"),
        ("172.18.0.5", None, "172.18.0.5"),
    ],
)
def test_the_visitors_address_is_the_one_our_own_proxy_saw_not_one_the_visitor_claimed(peer, xff, expected):
    assert canary.client_ip(peer, xff) == expected


@pytest.mark.asyncio
async def test_failing_to_reach_the_honeytokens_service_changes_nothing_for_the_visitor(monkeypatch):
    import httpx

    class Boom:
        def __init__(self, *a, **k): ...
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            raise httpx.ConnectError("down")

    monkeypatch.undo()  # use the real _forward against a client that cannot connect
    monkeypatch.setattr(canary.httpx, "AsyncClient", Boom)
    out = await canary.canary_visit(str(uuid.uuid4()), req())
    assert out.status_code == 200 and out.body[:6] == b"GIF89a"


# ── the alert a visit raises ─────────────────────────────────────────────────────────────────────────────────────────────

from datetime import UTC, datetime  # noqa: E402

TOKEN = {
    "id": uuid.UUID("11111111-1111-4111-8111-111111111111"),
    "tenant_id": uuid.UUID("00000000-0000-0000-0000-000000000001"),
    "name": "Finance wiki bait",
    "token_type": "url",
}
NOW = datetime(2026, 10, 18, 15, 30, tzinfo=UTC)


def test_the_alert_names_the_token_the_visitor_and_is_high_severity_and_tagged():
    spec = canary.alert_for_visit(TOKEN, "198.51.100.7", "curl/8.0", NOW)
    assert spec["tenant_id"] == TOKEN["tenant_id"]
    assert spec["override_title"] == "Honeytoken opened: Finance wiki bait"
    assert "198.51.100.7" in spec["override_description"] and "curl/8.0" in spec["override_description"]
    assert spec["override_severity"] == "high" and spec["override_tags"] == ["honeytoken", "deception"]
    assert spec["connector_type"] == "honeytoken"
    assert spec["events"][0]["client"] == {"ipAddress": "198.51.100.7"}, "the visitor becomes an IP on the alert"


def test_one_alert_per_token_per_hour_by_idempotency_key():
    a = canary.alert_for_visit(TOKEN, "1.1.1.1", None, NOW)
    b = canary.alert_for_visit(TOKEN, "2.2.2.2", None, NOW.replace(minute=59))
    c = canary.alert_for_visit(TOKEN, "1.1.1.1", None, NOW.replace(hour=16))
    other = canary.alert_for_visit({**TOKEN, "id": uuid.uuid4()}, "1.1.1.1", None, NOW)
    assert a["idempotency_key"] == b["idempotency_key"] != c["idempotency_key"] != other["idempotency_key"]
    assert a["idempotency_key"] == "honeytoken-11111111-1111-4111-8111-111111111111-2026101815"


def test_the_key_fits_the_alert_submit_rules_so_the_unique_index_accepts_it():
    import re

    assert re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", canary.alert_for_visit(TOKEN, None, None, NOW)["idempotency_key"])


def test_an_unknown_address_gives_an_alert_without_an_ip_and_a_long_name_is_cut():
    spec = canary.alert_for_visit({**TOKEN, "name": "x" * 900}, None, None, NOW)
    assert spec["events"][0]["client"] == {} and len(spec["override_title"]) <= 500 and " from " not in spec["override_description"]


def test_the_alert_the_spec_describes_can_really_be_built_by_the_alert_code():
    from app.api.v1.endpoints.alerts import _synthesise_alert_from_events

    alert = _synthesise_alert_from_events(**canary.alert_for_visit(TOKEN, "198.51.100.7", "curl/8.0", NOW))
    assert alert.title == "Honeytoken opened: Finance wiki bait" and alert.severity == "high"
    assert alert.tenant_id == TOKEN["tenant_id"] and alert.idempotency_key.startswith("honeytoken-")
    assert "198.51.100.7" in (alert.affected_ips or []) and "honeytoken" in (alert.tags or [])


@pytest.mark.asyncio
async def test_a_failure_writing_the_alert_never_reaches_the_visitor(monkeypatch):
    async def boom(_id):
        raise RuntimeError("db down")

    monkeypatch.undo()  # use the real _raise_alert
    monkeypatch.setattr(canary, "_lookup_token", boom)
    await canary._raise_alert(uuid.uuid4(), "1.1.1.1", None)  # must not raise


@pytest.mark.asyncio
async def test_an_unknown_token_raises_no_alert(monkeypatch):
    stored = []

    async def none(_id):
        return None

    async def store(spec):
        stored.append(spec)
        return True

    monkeypatch.undo()
    monkeypatch.setattr(canary, "_lookup_token", none)
    monkeypatch.setattr(canary, "_store_alert", store)
    await canary._raise_alert(uuid.uuid4(), "1.1.1.1", None)
    assert stored == []


@pytest.mark.asyncio
async def test_a_known_token_stores_one_alert_built_from_the_visit(monkeypatch):
    stored = []

    async def found(_id):
        return TOKEN

    async def store(spec):
        stored.append(spec)
        return True

    monkeypatch.undo()
    monkeypatch.setattr(canary, "_lookup_token", found)
    monkeypatch.setattr(canary, "_store_alert", store)
    await canary._raise_alert(TOKEN["id"], "198.51.100.7", "curl/8.0")
    (spec,) = stored
    assert spec["override_title"] == "Honeytoken opened: Finance wiki bait" and spec["tenant_id"] == TOKEN["tenant_id"]
