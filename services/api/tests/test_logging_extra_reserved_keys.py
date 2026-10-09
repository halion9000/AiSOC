"""A logging call must never pass a key that Python reserves on a LogRecord through `extra=`.

`logger.info("...", extra={"created": True})` raises `KeyError: Attempt to overwrite 'created' in LogRecord`. In a request handler that runs AFTER the database commit, that is a 500 for an action that actually succeeded: PUT /oauth/app/{connector_type} and the LLM-credential upsert both returned 500 on every save for this reason (the row was stored, the caller was told it failed).
This scans every logging call in app/ whose `extra` is a dict literal and fails on any reserved key."""
import ast
import logging
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent / "app"
# Every attribute a LogRecord already has (and the two that logging computes): passing any of these in `extra` raises.
RESERVED = frozenset(logging.LogRecord("n", logging.INFO, "p", 1, "m", None, None).__dict__) | {"message", "asctime"}
LEVELS = {"debug", "info", "warning", "error", "exception", "critical", "log"}


def offending_calls(source: str) -> list[tuple[int, str]]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in LEVELS:
            for kw in node.keywords:
                if kw.arg == "extra" and isinstance(kw.value, ast.Dict):
                    found += [(node.lineno, k.value) for k in kw.value.keys if isinstance(k, ast.Constant) and k.value in RESERVED]
    return found


def test_the_reserved_set_is_what_logging_really_rejects():
    for key in ("created", "name", "msg", "args", "module", "process", "thread", "message", "asctime"):
        assert key in RESERVED
    log = logging.getLogger("reserved-key-probe")
    # The record is only built when the level is enabled: at the default WARNING an INFO call returns before it could raise, so the bug only appears where INFO is on (the API's default).
    log.setLevel(logging.INFO)
    for key in ("created", "message", "name"):
        with pytest.raises(KeyError):
            log.info("x", extra={key: 1})
    log.info("x", extra={"was_created": True, "tenant": "t"})  # the renamed keys are fine


def test_the_scanner_finds_the_bug_it_exists_for():
    assert offending_calls('logger.info("x", extra={"tenant": 1, "created": existing is None})') == [(1, "created")]
    assert offending_calls('log.error("x", extra={"message": 1, "name": 2})') == [(1, "message"), (1, "name")]
    assert offending_calls('logger.info("x", extra={"was_created": True})') == []
    assert offending_calls('payload = {"created": True}') == []  # a plain dict is not a log call


def test_no_logging_call_in_the_api_passes_a_reserved_key_through_extra():
    problems = []
    for path in sorted(APP.rglob("*.py")):
        for line, key in offending_calls(path.read_text(encoding="utf-8", errors="replace")):
            problems.append(f"{path.relative_to(APP.parent)}:{line}: extra={{{key!r}: ...}}")
    assert not problems, "logging raises KeyError for these, which is a 500 after the commit:\n  " + "\n  ".join(problems)
