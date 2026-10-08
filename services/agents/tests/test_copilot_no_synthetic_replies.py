"""The copilot answers with the language model's words, or says it cannot. It never answers with canned analysis.

app/api/copilot.py used to fall back to one of five hard-coded paragraphs, cycling in order and unrelated to the question ("this IP was seen in 3 other alerts", "attacker dwell
time appears short (< 2 hours)"), whenever OPENAI_API_KEY was unset OR the model call failed for any reason. They were returned as the normal assistant reply and stored in the
conversation, so an analyst could read invented findings as the copilot's analysis of their case. Now the endpoints answer HTTP 503 with the reason and store nothing for the turn.
"""
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import copilot

CANNED_FRAGMENTS = [
    "I've analysed the alert context",
    "credential-access activity. The parent process",
    "The entity risk score is elevated",
    "this IP was seen in 3 other alerts",
    "attacker dwell time appears short",
]
CHAT = "/api/v1/copilot/chat"
STREAM = "/api/v1/copilot/chat/stream"


@pytest.fixture
def client():
    copilot._CONVERSATIONS.clear()
    app = FastAPI()
    app.include_router(copilot.router)
    yield TestClient(app)
    copilot._CONVERSATIONS.clear()


def _configure_model(monkeypatch, *, reply=None, error=None, seen=None):
    """Pretend an API key and model alias exist, and make the model call return `reply` or raise `error`."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")

    async def fake_request(**kwargs):
        if seen is not None:
            seen.append(kwargs["messages"])
        if error is not None:
            raise error
        return {"choices": [{"message": {"content": reply}}]}

    monkeypatch.setattr("app.llm.contract.safe_chat_completions_request", fake_request)
    monkeypatch.setattr("app.llm.factory.resolve_model_alias", lambda alias: "test-model")
    monkeypatch.setattr("app.llm.factory.chat_completions_url", lambda: "http://llm.invalid/v1/chat/completions")


def _no_canned_text(text: str) -> None:
    for fragment in CANNED_FRAGMENTS:
        assert fragment not in text, f"canned analysis is back: {fragment!r}"


def test_the_canned_replies_no_longer_exist():
    assert not hasattr(copilot, "_SYNTHETIC_REPLIES")
    assert not hasattr(copilot, "_synthetic_reply")


def test_with_no_api_key_it_says_so_and_stores_nothing(client, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    response = client.post(CHAT, json={"message": "Is this IP malicious?"})
    assert response.status_code == 503
    assert "no language-model API key is configured" in response.json()["detail"]
    _no_canned_text(response.text)
    assert client.get("/api/v1/copilot/conversations").json()["conversations"] == []


def test_when_the_model_call_fails_it_says_so_and_stores_nothing(client, monkeypatch):
    _configure_model(monkeypatch, error=RuntimeError("upstream exploded"))
    response = client.post(CHAT, json={"message": "Summarise the case"})
    assert response.status_code == 503
    assert "could not be reached (RuntimeError)" in response.json()["detail"]
    _no_canned_text(response.text)
    assert client.get("/api/v1/copilot/conversations").json()["conversations"] == []


def test_repeated_failures_never_cycle_through_canned_text(client, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    for _ in range(len(CANNED_FRAGMENTS) + 2):
        response = client.post(CHAT, json={"message": "anything"})
        assert response.status_code == 503
        _no_canned_text(response.text)


def test_a_failed_turn_keeps_the_earlier_conversation_and_leaves_no_dangling_question(client, monkeypatch):
    _configure_model(monkeypatch, reply="First real answer")
    first = client.post(CHAT, json={"message": "First question"}).json()
    conv_id = first["conversationId"]
    assert first["reply"]["content"] == "First real answer"

    _configure_model(monkeypatch, error=RuntimeError("down"))
    assert client.post(CHAT, json={"message": "Second question", "conversationId": conv_id}).status_code == 503

    messages = client.get(f"/api/v1/copilot/conversations/{conv_id}").json()["messages"]
    assert [m["content"] for m in messages] == ["First question", "First real answer"]  # the failed question is not left behind to be duplicated on retry


def test_a_working_model_gives_exactly_its_own_words_and_stores_the_turn(client, monkeypatch):
    seen: list = []
    _configure_model(monkeypatch, reply="This sender domain was registered yesterday.", seen=seen)
    response = client.post(CHAT, json={"message": "Why is this phishing?"})
    assert response.status_code == 200
    body = response.json()
    assert body["reply"]["content"] == "This sender domain was registered yesterday."
    assert body["reply"]["role"] == "assistant"
    assert seen[0][-1] == {"role": "user", "content": "Why is this phishing?"}
    stored = client.get(f"/api/v1/copilot/conversations/{body['conversationId']}").json()["messages"]
    assert [m["role"] for m in stored] == ["user", "assistant"]


def test_the_streaming_endpoint_is_a_real_error_not_a_stream_of_invented_words(client, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    response = client.post(STREAM, json={"message": "What happened?"})
    assert response.status_code == 503
    assert "cannot answer right now" in response.json()["detail"]
    _no_canned_text(response.text)
    assert client.get("/api/v1/copilot/conversations").json()["conversations"] == []


def test_the_streaming_endpoint_streams_the_models_own_words(client, monkeypatch):
    _configure_model(monkeypatch, reply="Block the sender and reset the password.")
    response = client.post(STREAM, json={"message": "What now?"})
    assert response.status_code == 200
    frames = [json.loads(line) for line in response.text.strip().split("\n")]
    deltas = "".join(f.get("delta", "") for f in frames if not f.get("done"))
    assert deltas == "Block the sender and reset the password."
    assert frames[-1]["done"] is True
    stored = client.get(f"/api/v1/copilot/conversations/{frames[-1]['conversationId']}").json()["messages"]
    assert stored[-1]["content"] == "Block the sender and reset the password."
