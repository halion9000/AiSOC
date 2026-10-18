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

    monkeypatch.setattr(canary, "_forward", fake_forward)
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
