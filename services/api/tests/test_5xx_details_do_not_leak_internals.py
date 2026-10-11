"""A 5xx response must not carry the text of the underlying exception when that text names infrastructure.

FOUND by fuzzing the OpenAPI spec against a real server with the dependent services not running: the responses read `Graph query failed:
Couldn't connect to localhost:7687 (resolved to ('127.0.0.1:7687',))`, `Agents service unavailable: [Errno -2] Name or service not known`,
`lake backend error: ... Connection refused (localhost:9000)`: internal hostnames, ports and driver text, shown to any caller who can read
that data.
Fixed here: the five graph query routes (one helper that LOGS the exception and answers a generic 503), the agents proxy, and the ITSM
webhook (`Failed to apply inbound status: {exc}`, answered to an EXTERNAL system: a SQLAlchemy exception's text includes the SQL statement
and its parameter values).
NOT changed, and listed with a reason below so the list can only shrink: the credential-vault diagnostics (connector admins only; they name
the AISOC_CREDENTIAL_KEY variable and say what is wrong, no key material), the lake/query-error sites (where the text can be the analyst's
own query error), the SSO protocol errors, and the marketplace index parse error.
"""

import ast
import logging
import re
from pathlib import Path

import httpx
import pytest
import sqlalchemy.exc as sa_exc
from app.api.v1.endpoints import cases, graph
from fastapi import HTTPException

APP = Path(graph.__file__).resolve().parents[3]


def test_the_premise_a_sqlalchemy_exceptions_text_includes_the_sql_and_its_parameters():
    """Why interpolating `{exc}` into a response leaks: this is what the text of a database error contains."""
    exc = sa_exc.IntegrityError(
        "INSERT INTO case_status_history (case_id, new_status) VALUES (%s, %s)",
        {"case_id": "11111111-2222-3333-4444-555555555555", "new_status": "closed"},
        Exception("duplicate key"),
    )
    text = str(exc)
    assert "[SQL:" in text and "case_status_history" in text and "11111111-2222-3333-4444-555555555555" in text


class TestTheGraphQueryFailure:
    INTERNAL = "Couldn't connect to neo4j-internal.corp:7687 (resolved to ('10.1.2.3:7687',))"

    def test_it_is_a_generic_503_with_no_host_port_or_driver_text(self):
        response = graph._query_failed(RuntimeError(self.INTERNAL))
        assert isinstance(response, HTTPException) and response.status_code == 503 and response.detail == "Graph query failed"
        assert not re.search(r"neo4j-internal|10\.1\.2\.3|7687|resolved", str(response.detail))

    def test_the_full_exception_is_logged_server_side_so_an_operator_can_still_diagnose(self, caplog):
        with caplog.at_level(logging.WARNING, logger=graph.logger.name):
            graph._query_failed(RuntimeError(self.INTERNAL))
        assert "neo4j-internal.corp:7687" in caplog.text and "RuntimeError" in caplog.text

    def test_no_http_exception_in_the_graph_module_puts_an_exception_in_its_detail(self):
        """Only an EXCEPTION variable is the problem: `Case {case_id} not found` (the caller's own input, in a 404) is fine and is not
        flagged."""
        tree = ast.parse(Path(graph.__file__).read_text(encoding="utf-8"))
        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "HTTPException":
                for kw in node.keywords:
                    if kw.arg == "detail" and isinstance(kw.value, ast.JoinedStr):
                        for part in kw.value.values:
                            base = part.value if isinstance(part, ast.FormattedValue) else None
                            while isinstance(base, ast.Attribute):
                                base = base.value
                            if isinstance(base, ast.Name) and base.id in {"exc", "e", "err", "error", "ex"}:
                                offenders.append(node.lineno)
        assert not offenders, f"graph.py interpolates an exception into an HTTPException detail at lines {offenders}"

    def test_the_guard_does_catch_the_original_pattern(self):
        """Positive control: the original code, parsed the same way, IS flagged (so the test above cannot pass by being blind)."""
        original = 'raise HTTPException(status_code=503, detail=f"Graph query failed: {exc}")\n'
        flagged = [
            n
            for n in ast.walk(ast.parse(original))
            if isinstance(n, ast.Call)
            and getattr(n.func, "id", None) == "HTTPException"
            and any(
                isinstance(kw.value, ast.JoinedStr)
                and any(
                    isinstance(p, ast.FormattedValue) and isinstance(p.value, ast.Name) and p.value.id == "exc" for p in kw.value.values
                )
                for kw in n.keywords
                if kw.arg == "detail"
            )
        ]
        assert len(flagged) == 1

    def test_the_five_query_failure_sites_all_go_through_the_helper(self):
        assert Path(graph.__file__).read_text(encoding="utf-8").count("raise _query_failed(exc) from exc") == 5


@pytest.mark.asyncio
async def test_the_agents_proxy_does_not_put_the_connection_error_in_the_response(monkeypatch, caplog):
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, *a, **k):
            raise httpx.ConnectError("[Errno -2] Name or service not known (agents.internal.corp:8001)")

    monkeypatch.setattr(cases.httpx, "AsyncClient", _Client)
    with caplog.at_level(logging.ERROR):
        with pytest.raises(HTTPException) as refused:
            await cases._agents_proxy("GET", "/api/v1/playbooks")
    assert refused.value.status_code == 503 and refused.value.detail == "Agents service unavailable"
    assert not re.search(r"agents\.internal|8001|Errno", str(refused.value.detail))
    assert "agents_proxy.request_failed" in caplog.text, "the failure is still logged for the operator"


def test_the_itsm_webhook_does_not_return_the_text_of_a_failed_apply_to_the_external_caller():
    source = (APP / "api/v1/endpoints/inbox_itsm.py").read_text(encoding="utf-8")
    assert 'detail="Failed to apply inbound status"' in source and "Failed to apply inbound status: {" not in source
    assert "inbox_itsm.apply_failed" in source, "the full exception stays in the log"


# ── the ratchet ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
# Sites that still put an exception's text in a 5xx detail, by file, with why. This can only SHRINK: a new site fails the build until it is
# either made generic or listed here with a reason.
STILL_INTERPOLATING = {
    "api/v1/endpoints/connectors.py": (
        3,
        "credential-vault diagnostics, connector admins only: name the AISOC_CREDENTIAL_KEY variable and say what is wrong; no key material (reviewed, left on purpose)",  # noqa: E501
    ),
    "api/v1/endpoints/lake.py": (
        2,
        "lake backend error: generic for a CONNECTION failure (clickhouse.py classifies it and logs the detail); "
        "otherwise the server's own message about the analyst's query, which is useful to them (reviewed, left on purpose)",
    ),
    "api/v1/endpoints/detection_proposals.py": (
        1,
        "lake query failed: inherits clickhouse.py's generic connection-failure message; "
        "a server-reported query error is the analyst's own (reviewed)",
    ),
    "api/v1/endpoints/detection_rules.py": (
        1,
        "lake query failed: inherits clickhouse.py's generic connection-failure message; "
        "a server-reported query error is the analyst's own (reviewed)",
    ),
    "api/v1/endpoints/marketplace.py": (
        1,
        "a JSON parse error of a local index file: names a line and column, no path: low risk, NOT reviewed further",
    ),
    "auth/oidc.py": (
        2,
        "OIDC discovery failure (502): includes the HTTP client's text, which names the configured issuer URL: NOT yet narrowed",
    ),
    "auth/saml.py": (1, "an unexpected SAML error (500): the exception text is returned after being logged: NOT yet narrowed"),
}


def _sites():
    found = {}

    def five_xx(call):
        for kw in call.keywords:
            if kw.arg == "status_code":
                v = kw.value
                if isinstance(v, ast.Constant) and isinstance(v.value, int):
                    return 500 <= v.value < 600
                if isinstance(v, ast.Attribute):
                    return bool(re.search(r"HTTP_5\d\d", v.attr))
        return False

    for path in sorted(APP.rglob("*.py")):
        rel = str(path.relative_to(APP))
        if rel.startswith("tests/"):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and getattr(node.func, "id", getattr(node.func, "attr", None)) == "HTTPException"
                and five_xx(node)
            ):
                for kw in node.keywords:
                    if kw.arg == "detail" and isinstance(kw.value, ast.JoinedStr):
                        for part in kw.value.values:
                            base = part.value if isinstance(part, ast.FormattedValue) else None
                            while isinstance(base, ast.Attribute):
                                base = base.value
                            if isinstance(base, ast.Name) and base.id in {"exc", "e", "err", "error", "ex"}:
                                found[rel] = found.get(rel, 0) + 1
    return found


def test_the_sites_that_put_an_exception_in_a_5xx_detail_are_exactly_the_listed_ones_and_only_shrink():
    found = _sites()
    allowed = {f: n for f, (n, _) in STILL_INTERPOLATING.items()}
    assert (
        found.keys() <= allowed.keys()
    ), f"NEW site(s) (make the detail generic and log the exception, or list it above with a reason): {sorted(set(found) - set(allowed))}"
    assert all(found[f] <= allowed[f] for f in found), {f: (found[f], allowed[f]) for f in found if found[f] > allowed[f]}
    assert (
        found == allowed
    ), f"a listed site was fixed: lower the number or remove the entry: {({f: (found.get(f, 0), allowed[f]) for f in allowed if found.get(f, 0) != allowed[f]})}"  # noqa: E501


def test_the_ratchet_sees_what_it_claims_to_and_every_entry_has_a_reason():
    assert sum(_sites().values()) >= 10, "the scan found almost nothing: it would pass vacuously"
    assert all(reason.strip() for _, reason in STILL_INTERPOLATING.values())
    assert "api/v1/endpoints/graph.py" not in _sites() and "api/v1/endpoints/inbox_itsm.py" not in _sites()
