"""The graph upsert routes answer 503 when the graph database cannot be reached, not an unhandled 500.

FOUND by fuzzing the OpenAPI spec against a real server with Neo4j not running: POST /graph/entities/{alert,case,host,user} each returned a
raw HTTP 500 (neo4j ServiceUnavailable escaped the handler), while the graph QUERY routes already answered 503. A connectivity failure is
now a 503 with a generic message (the driver's own text names the internal host and port); any OTHER exception still propagates, so a real
bug stays a visible 500.
"""

import inspect
import re
import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import graph
from fastapi import HTTPException

TENANT = uuid.uuid4()
USER = SimpleNamespace(tenant_id=TENANT)

HANDLERS = {
    "host": (graph.upsert_host, graph.UpsertHostRequest(host_id="h1", hostname="srv"), "upsert_host"),
    "user": (graph.upsert_user, graph.UpsertUserRequest(user_id="u1", username="pat"), "upsert_user"),
    "alert": (graph.upsert_alert_graph, graph.UpsertAlertGraphRequest(alert_id="a1", title="t", severity="high"), "upsert_alert_node"),
    "case": (graph.upsert_case_graph, graph.UpsertCaseGraphRequest(case_id="c1", title="t", severity="high"), "upsert_case_node"),
}


class ServiceUnavailable(Exception):
    """Stands in for neo4j.exceptions.ServiceUnavailable: the classifier matches by NAME, as it does for the query routes."""


def _patch(monkeypatch, service_fn, raises=None):
    async def fake(**kwargs):
        if raises is not None:
            raise raises
        return None

    monkeypatch.setattr(graph.graph_service, service_fn, fake)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(HANDLERS))
async def test_a_graph_database_that_cannot_be_reached_is_a_503_not_a_500(monkeypatch, kind):
    handler, payload, service_fn = HANDLERS[kind]
    _patch(monkeypatch, service_fn, ServiceUnavailable("Couldn't connect to neo4j-internal.corp:7687 (resolved to ('10.1.2.3:7687',))"))
    with pytest.raises(HTTPException) as refused:
        await handler(payload, USER)
    assert refused.value.status_code == 503 and refused.value.detail == "The graph service is unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(HANDLERS))
async def test_the_503_does_not_reveal_the_internal_host_or_port(monkeypatch, kind):
    handler, payload, service_fn = HANDLERS[kind]
    _patch(monkeypatch, service_fn, ServiceUnavailable("Couldn't connect to neo4j-internal.corp:7687 (resolved to ('10.1.2.3:7687',))"))
    with pytest.raises(HTTPException) as refused:
        await handler(payload, USER)
    assert not re.search(r"neo4j-internal|10\.1\.2\.3|7687", str(refused.value.detail))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [
        "Connect call failed ('127.0.0.1', 7687)",
        "Connection refused",
        "Name or service not known",
        "getaddrinfo failed",
        "Cannot resolve address foo:7687",
    ],
)
async def test_every_connectivity_marker_the_query_routes_recognise_is_recognised_here_too(monkeypatch, message):
    handler, payload, service_fn = HANDLERS["alert"]
    _patch(monkeypatch, service_fn, OSError(message))
    with pytest.raises(HTTPException) as refused:
        await handler(payload, USER)
    assert refused.value.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(HANDLERS))
async def test_an_error_that_is_not_about_connectivity_still_propagates_so_a_real_bug_stays_visible(monkeypatch, kind):
    handler, payload, service_fn = HANDLERS[kind]
    _patch(monkeypatch, service_fn, ValueError("a genuine bug in the query"))
    with pytest.raises(ValueError, match="genuine bug"):
        await handler(payload, USER)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(HANDLERS))
async def test_when_the_graph_is_up_the_handler_answers_exactly_as_before(monkeypatch, kind):
    handler, payload, service_fn = HANDLERS[kind]
    called = {}

    async def fake(**kwargs):
        called.update(kwargs)

    monkeypatch.setattr(graph.graph_service, service_fn, fake)
    result = await handler(payload, USER)
    assert result["status"] == "ok" and called["tenant_id"] == str(
        TENANT
    ), "the caller's tenant, never one from the payload, is what the graph write is scoped to"


@pytest.mark.asyncio
async def test_an_http_exception_raised_inside_the_write_is_not_swallowed_or_rewritten():
    async def boom():
        raise HTTPException(status_code=409, detail="conflict")

    with pytest.raises(HTTPException) as e:
        await graph._or_503(boom())
    assert e.value.status_code == 409 and e.value.detail == "conflict"


@pytest.mark.asyncio
async def test_an_http_exception_whose_text_merely_mentions_a_connection_marker_is_not_turned_into_a_503():
    """The passthrough clause only matters for this input: without it the marker in the message would reclassify a deliberate 409 as 'graph
    unavailable'."""

    async def refused():
        raise HTTPException(status_code=409, detail="Connection refused by the duplicate-entity policy")

    with pytest.raises(HTTPException) as e:
        await graph._or_503(refused())
    assert e.value.status_code == 409 and "duplicate-entity policy" in e.value.detail


def test_every_graph_write_in_the_endpoints_module_goes_through_the_wrapper():
    """A guard for the future: a new graph_service.upsert_* call that is not wrapped would be a raw 500 whenever the graph is down."""
    source = inspect.getsource(graph)
    calls = re.findall(r"graph_service\.(upsert_\w+)\(", source)
    assert len(calls) == 4, "an upsert route was added or removed: check it is wrapped, then update this number"
    wrapped = re.findall(r"_or_503\(\s*graph_service\.(upsert_\w+)\(", source)  # \s*: the formatter may wrap the call onto the next line
    assert sorted(calls) == sorted(wrapped), f"not wrapped in _or_503: {sorted(set(calls) - set(wrapped))}"
