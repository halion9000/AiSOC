"""The contextual Copilot actions tell the truth about why they could not answer, and bound what they send to a paid model.

Defects fixed here (these routes had no tests):
  1. A FAILED model request returned the "OPENAI_API_KEY is not configured" placeholder: false (the key is set), it sent operators to fix configuration that was not broken, and the real error was only in the log.
  2. A missing model client library streamed a placeholder with `fallback: false`, so it showed as a 70%-confidence answer.
  3. A stream that failed midway emitted an error frame and then a footer claiming confidence 0.7 and the follow-up suggestions, as if it had succeeded.
  4. `question` was unbounded (straight into a paid model prompt), and the docs claimed calls are written to the investigation ledger when only a log line is written.
The routes themselves hold no state and no tenant data (the entity comes from the caller's own screen); the caller's tenant and user now appear in the log line for audit.
"""
import importlib.util
import json
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.api import contextual

pytestmark = pytest.mark.skipif(importlib.util.find_spec("langchain_openai") is None, reason="langchain_openai is not installed in this environment")

BASE = "/api/v1/contextual"
BODY = {"page": "alerts", "action": "explain", "entity_id": "a-1", "entity": {"title": "Encoded PowerShell"}}
SECRET = "sk-live-SECRET-key-fragment-12345"


class Spy:
    """Stands in for the structlog logger and records (level, event, fields)."""

    def __init__(self):
        self.records = []

    def info(self, event, **kw):
        self.records.append(("info", event, kw))

    def warning(self, event, **kw):
        self.records.append(("warning", event, kw))

    def exception(self, event, **kw):
        self.records.append(("exception", event, kw))

    def events(self):
        return [r[1] for r in self.records]

    def find(self, event):
        return next(r[2] for r in self.records if r[1] == event)


@pytest.fixture
def log(monkeypatch):
    spy = Spy()
    monkeypatch.setattr(contextual, "logger", spy)
    return spy


def make_client(caller=None) -> TestClient:
    app = FastAPI()
    app.include_router(contextual.router)

    @app.middleware("http")
    async def set_caller(request: Request, call_next):
        if caller is not None:
            request.state.caller = caller
        return await call_next(request)

    return TestClient(app, raise_server_exceptions=False)


def with_model(monkeypatch, answer="## Analysis\n\nLooks like a benign admin script.", tokens=42, fail=None):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    async def fake_invoke(llm, messages):
        if fail is not None:
            raise fail
        return SimpleNamespace(content=answer, response_metadata={"token_usage": {"total_tokens": tokens}})

    monkeypatch.setattr(contextual, "safe_ainvoke", fake_invoke)


def stream_frames(client, body=None):
    r = client.post(f"{BASE}/action/stream", json=body or BODY)
    assert r.status_code == 200, r.text
    return [json.loads(line) for line in r.text.splitlines() if line.strip()]


class TestWhenAModelIsAvailable:
    def test_the_answer_is_the_models_and_is_not_a_placeholder(self, monkeypatch, log):
        with_model(monkeypatch)
        body = make_client().post(f"{BASE}/action", json=BODY).json()
        assert body["content"].startswith("## Analysis") and body["fallback"] is False and body["confidence"] == 0.7
        assert log.find("contextual.action.done")["tokens"] == 42 and log.find("contextual.action.done")["fallback"] is False

    def test_the_stream_carries_the_models_words_then_a_successful_footer(self, monkeypatch, log):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

        async def fake_stream(llm, messages):
            for word in ("Looks ", "benign."):
                yield SimpleNamespace(content=word)

        monkeypatch.setattr(contextual, "safe_astream", fake_stream)
        frames = stream_frames(make_client())
        assert frames[0]["fallback"] is False
        assert "".join(f["delta"] for f in frames if "delta" in f) == "Looks benign."
        assert frames[-1]["done"] is True and frames[-1]["confidence"] == 0.7 and len(frames[-1]["suggestions"]) > 0


class TestWhenNoKeyIsConfigured:
    def test_the_placeholder_is_labelled_and_says_the_key_is_missing(self, monkeypatch, log):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        body = make_client().post(f"{BASE}/action", json=BODY).json()
        assert body["fallback"] is True and body["confidence"] == 0.0
        assert "OPENAI_API_KEY" in body["content"] and "not configured" in body["content"].lower()

    def test_the_stream_header_flags_it_and_the_footer_claims_no_confidence(self, monkeypatch, log):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        frames = stream_frames(make_client())
        assert frames[0]["fallback"] is True
        assert "OPENAI_API_KEY" in "".join(f["delta"] for f in frames if "delta" in f)
        assert frames[-1]["done"] is True and frames[-1]["confidence"] == 0.0


class TestWhenTheModelRequestFails:
    """The key IS configured: telling the operator it is not sends them to fix something that is not broken."""

    def test_the_response_says_the_request_failed_and_not_that_the_key_is_missing(self, monkeypatch, log):
        with_model(monkeypatch, fail=RuntimeError("429 rate limited"))
        body = make_client().post(f"{BASE}/action", json=BODY).json()
        assert body["fallback"] is True and body["confidence"] == 0.0
        assert "request failed" in body["content"].lower() and "RuntimeError" in body["content"]
        assert "OPENAI_API_KEY" not in body["content"] and "not configured" not in body["content"].lower()
        assert "not a configuration problem" in body["content"].lower()

    def test_the_error_message_itself_is_not_shown_to_the_user_only_its_class(self, monkeypatch, log):
        """An exception message can carry internal URLs or key fragments."""
        with_model(monkeypatch, fail=RuntimeError(f"401 from http://litellm.internal:4000 key={SECRET}"))
        content = make_client().post(f"{BASE}/action", json=BODY).json()["content"]
        assert SECRET not in content and "litellm.internal" not in content and "RuntimeError" in content

    def test_the_real_error_is_still_logged_for_the_operator(self, monkeypatch, log):
        with_model(monkeypatch, fail=RuntimeError("429 rate limited"))
        make_client().post(f"{BASE}/action", json=BODY)
        assert "429 rate limited" in log.find("contextual.action.llm_error")["error"]

    def test_the_failure_is_reported_in_the_done_log_as_a_fallback(self, monkeypatch, log):
        with_model(monkeypatch, fail=ValueError("bad"))
        make_client().post(f"{BASE}/action", json=BODY)
        assert log.find("contextual.action.done")["fallback"] is True and log.find("contextual.action.done")["tokens"] == 0


class TestWhenTheModelClientIsNotInstalled:
    @pytest.fixture(autouse=True)
    def uninstalled(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setattr(contextual, "_unavailable_reason", lambda: "not_installed")

    def test_it_says_so_and_is_flagged_as_a_placeholder(self, log):
        body = make_client().post(f"{BASE}/action", json=BODY).json()
        assert body["fallback"] is True and body["confidence"] == 0.0
        assert "not installed" in body["content"].lower() and "not configured" not in body["content"].lower()

    def test_the_stream_flags_it_in_the_header_instead_of_presenting_a_placeholder_as_an_answer(self, log):
        """The header used to say fallback:false (the key IS set), so the UI showed a placeholder at 70% confidence."""
        frames = stream_frames(make_client())
        assert frames[0]["fallback"] is True
        assert "not installed" in "".join(f["delta"] for f in frames if "delta" in f).lower()
        assert frames[-1]["confidence"] == 0.0


class TestTheRealAvailabilityProbe:
    """The tests above stub _unavailable_reason(); these run the REAL probe. `sys.modules[name] = None` makes `import name` raise ImportError, exactly as a missing package does."""

    def test_a_missing_client_library_is_detected_for_real(self, monkeypatch):
        import sys

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        assert contextual._unavailable_reason() is None  # present: usable
        monkeypatch.setitem(sys.modules, "langchain_openai", None)
        assert contextual._unavailable_reason() == "not_installed"

    def test_no_key_wins_over_everything(self, monkeypatch):
        import sys

        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        assert contextual._unavailable_reason() == "not_configured"
        monkeypatch.setitem(sys.modules, "langchain_openai", None)
        assert contextual._unavailable_reason() == "not_configured"

    def test_end_to_end_a_missing_library_is_a_labelled_placeholder_not_an_answer(self, monkeypatch, log):
        import sys

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setitem(sys.modules, "langchain_openai", None)
        body = make_client().post(f"{BASE}/action", json=BODY).json()
        assert body["fallback"] is True and body["confidence"] == 0.0 and "not installed" in body["content"].lower()
        frames = stream_frames(make_client())
        assert frames[0]["fallback"] is True and frames[-1]["confidence"] == 0.0


class TestWhenTheStreamFailsMidway:
    @pytest.fixture(autouse=True)
    def failing_stream(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

        async def fake_stream(llm, messages):
            yield SimpleNamespace(content="Partial ")
            raise RuntimeError("connection reset")

        monkeypatch.setattr(contextual, "safe_astream", fake_stream)

    def test_an_error_frame_is_sent_and_the_footer_does_not_claim_success(self, log):
        frames = stream_frames(make_client())
        assert frames[0]["fallback"] is False
        assert [f for f in frames if "error" in f] == [{"error": "Streaming failed. Please try again."}]
        footer = frames[-1]
        assert footer["done"] is True
        assert footer["confidence"] == 0.0, "the footer claimed 70% confidence after the stream had failed"
        assert footer["suggestions"] == [], "follow-up suggestions were offered for an answer that did not complete"

    def test_the_error_does_not_leak_the_exception_and_is_logged_with_context(self, log):
        r = make_client({"kind": "user", "tenant_id": "t-1", "user_id": "u-1"}).post(f"{BASE}/action/stream", json=BODY)
        assert "connection reset" not in r.text
        rec = log.find("contextual.stream.error")
        assert rec["page"] == "alerts" and rec["tenant_id"] == "t-1" and rec["user_id"] == "u-1"

    def test_the_words_received_before_the_failure_are_still_delivered(self, log):
        frames = stream_frames(make_client())
        assert "".join(f["delta"] for f in frames if "delta" in f) == "Partial "


class TestInputIsBounded:
    @pytest.fixture(autouse=True)
    def model(self, monkeypatch):
        with_model(monkeypatch)

    @pytest.mark.parametrize("path", ["/action", "/action/stream"])
    @pytest.mark.parametrize("field,limit", [("question", 4000), ("entity_id", 200), ("case_id", 200), ("page", 64), ("action", 64)])
    def test_an_oversized_field_is_refused_before_any_model_call(self, field, limit, path):
        body = {**BODY, field: "x" * (limit + 1)}
        assert make_client().post(f"{BASE}{path}", json=body).status_code == 422

    def test_a_question_at_the_limit_is_accepted(self):
        assert make_client().post(f"{BASE}/action", json={**BODY, "question": "q" * 4000}).status_code == 200

    def test_an_oversized_question_never_reaches_the_model(self, monkeypatch):
        calls = []

        async def spy(llm, messages):
            calls.append(1)
            return SimpleNamespace(content="x", response_metadata={})

        monkeypatch.setattr(contextual, "safe_ainvoke", spy)
        make_client().post(f"{BASE}/action", json={**BODY, "question": "x" * 4001})
        assert calls == []

    @pytest.mark.parametrize("page,action", [("alerts", "nope"), ("nope", "explain"), ("", "")])
    def test_an_unknown_action_is_a_400_not_a_model_call(self, page, action):
        assert make_client().post(f"{BASE}/action", json={**BODY, "page": page, "action": action}).status_code == 400


class TestTheCallerIsInTheAuditLog:
    def test_an_authenticated_callers_tenant_and_user_are_logged(self, monkeypatch, log):
        with_model(monkeypatch)
        make_client({"kind": "user", "tenant_id": "tenant-a", "user_id": "user-7"}).post(f"{BASE}/action", json={**BODY, "case_id": "case-9"})
        rec = log.find("contextual.action.done")
        assert rec["tenant_id"] == "tenant-a" and rec["user_id"] == "user-7" and rec["case_id"] == "case-9"

    def test_the_apis_proxy_and_development_have_no_tenant_to_log(self, monkeypatch, log):
        with_model(monkeypatch)
        make_client({"kind": "internal"}).post(f"{BASE}/action", json=BODY)
        make_client().post(f"{BASE}/action", json=BODY)
        assert [r[2]["tenant_id"] for r in log.records if r[1] == "contextual.action.done"] == [None, None]

    def test_a_failure_is_attributed_too(self, monkeypatch, log):
        with_model(monkeypatch, fail=RuntimeError("boom"))
        make_client({"kind": "user", "tenant_id": "tenant-a", "user_id": "user-7"}).post(f"{BASE}/action", json=BODY)
        assert log.find("contextual.action.llm_error")["tenant_id"] == "tenant-a"


class TestTheCatalogueIsConsistent:
    """The module promises its catalogue is kept in sync with the UI and the prompts."""

    def test_every_catalogued_action_has_a_prompt_and_every_prompt_is_catalogued(self):
        listed = {(page, item["key"] if "key" in item else item["action"]) for page, items in contextual._ACTION_CATALOGUE.items() for item in items}
        assert listed == set(contextual._SYSTEM_PROMPTS)

    def test_the_catalogue_endpoint_serves_it(self):
        pages = make_client().get(f"{BASE}/actions").json()["pages"]
        assert set(pages) == set(contextual._ACTION_CATALOGUE) and all(pages[p] for p in pages)

    def test_every_catalogued_action_actually_runs(self, monkeypatch):
        with_model(monkeypatch)
        for page, action in contextual._SYSTEM_PROMPTS:
            r = make_client().post(f"{BASE}/action", json={"page": page, "action": action, "entity_id": "x"})
            assert r.status_code == 200 and r.json()["fallback"] is False, (page, action)


class TestEachRouteIsWiredToItsHandler:
    """A decorator that ends up on the wrong function is invisible to linters and to every test that never calls the route: an edit once left `/action` bound to a helper that returned the caller's tenant."""

    def test_every_route_maps_to_the_function_that_serves_it(self):
        routes = {(sorted(r.methods - {"HEAD"})[0], r.path): r.endpoint.__name__ for r in contextual.router.routes}
        assert routes == {
            ("GET", f"{BASE}/actions"): "list_actions",
            ("POST", f"{BASE}/action"): "run_action",
            ("POST", f"{BASE}/action/stream"): "run_action_stream",
        }

    def test_the_action_route_returns_the_documented_response_shape(self, monkeypatch):
        with_model(monkeypatch)
        body = make_client().post(f"{BASE}/action", json=BODY).json()
        assert {"id", "page", "action", "entity_id", "title", "content", "confidence", "suggestions", "citations", "model", "elapsed_ms", "fallback", "created_at"} <= set(body)


class TestNothingIsStored:
    def test_the_module_holds_no_per_call_state(self):
        mutable = [n for n, v in vars(contextual).items() if isinstance(v, (list, set)) and not n.startswith("__")]
        assert mutable == []  # no stores to leak across tenants; the only dicts are the constant catalogues
