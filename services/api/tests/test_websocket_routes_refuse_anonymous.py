"""Every WebSocket route refuses a client with no (or garbage) credentials and sends it nothing; a new WebSocket route must be listed with
a reason.

WHY THIS EXISTS: the survey that produced test_unauthenticated_and_login_only_routes.py called every operation in the OpenAPI schema, and
WebSocket routes are not in OpenAPI, and `route_introspect.walk_routes` yields HTTP routes only, so neither the survey nor that guard has
ever looked at them. Enumerating them (by descending into the included routers, which this FastAPI version wraps in `_IncludedRouter`)
found two, and connecting to each with no credentials:
* `/api/v1/graph_ws/stream` accepts the handshake and then closes with 1008 (policy violation), sending nothing: authentication is checked
by hand in the handler.
* `/graphql` (strawberry's WebSocket transport) raises a TypeError before anything is accepted: its context getter depends on
`get_current_user`, which needs an HTTP Request, so dependency resolution fails on a WebSocket scope. That is FAIL-CLOSED BY ACCIDENT, not
by design, and the schema defines no subscriptions, so the transport serves nothing. I tried switching the transport off with
`subscription_protocols=[]` and it made no difference (the error is raised before the protocol check), so that change was reverted rather
than left in the tree.
The risk this pins is the opposite one: someone makes that dependency WebSocket-aware to get rid of the TypeError and the endpoint starts
accepting anonymous connections. If that happens, or a new WebSocket route is added without authentication, this fails.
Limits, stated: a client that authenticates correctly is not exercised here (graph_ws has its own tests); and "sends nothing" is checked
for the first message only.
"""

import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

import pytest
from app.main import app
from fastapi import FastAPI, WebSocket
from fastapi.routing import APIWebSocketRoute
from starlette.routing import WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

WAIT_SECONDS = 3

WEBSOCKET_ROUTES = {
    "/api/v1/graph_ws/stream": (
        "the live graph feed: authenticated by hand in the handler "
        "(session token, tenant rebound from the resolved user, gated on graph:read)"
    ),
    "/graphql": (
        "strawberry's WebSocket transport: the schema defines no subscriptions and the context getter needs an HTTP Request, "
        "so it fails closed; pinned so it stays closed"
    ),
}


def walk_ws(routes, prefix=""):
    """Every WebSocket route with its full path, descending into included routers (their prefix is carried in include_context)."""
    for route in routes:
        if isinstance(route, APIWebSocketRoute | WebSocketRoute):
            yield prefix + route.path, route
        elif hasattr(route, "original_router"):
            context = getattr(route, "include_context", None)
            yield from walk_ws(route.original_router.routes, prefix + (getattr(context, "prefix", "") or ""))


def outcome(application, path, **connect) -> str:
    """What an anonymous client gets: 'refused:<code>', 'closed:<code>' (accepted, then closed, sent nothing), 'error' (the server raised:
    fails
    closed), 'SENT:<first message>', or 'OPEN' (accepted and then SILENT: the server is waiting for the client to speak).
    The wait for a first message is BOUNDED. Without that, the regression this guards against (a socket that accepts an anonymous client
    and waits for
    it, as strawberry's transport does until connection_init) would HANG the test run instead of failing it."""
    url = re.sub(r"\{[^}]+\}", lambda m: str(uuid.uuid4()), path)
    client = TestClient(application, raise_server_exceptions=False)
    pool = ThreadPoolExecutor(max_workers=1)
    # Captured BEFORE the block exits: closing a socket the server is still waiting on raises at __exit__, which would override a return.
    result = None
    try:
        with client.websocket_connect(url, **connect) as ws:
            future = pool.submit(ws.receive_text)
            try:
                result = f"SENT:{future.result(timeout=WAIT_SECONDS)[:60]}"
            except WebSocketDisconnect as closed:
                result = f"closed:{closed.code}"
            except FutureTimeout:
                result = "OPEN"
    except WebSocketDisconnect as refused:
        result = result or f"refused:{refused.code}"
    except Exception:
        result = result or "error"
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return result


def gets_nothing(result: str) -> bool:
    """Neither data nor an OPEN connection waiting for the client: an anonymous client that is merely left connected is already past the
    door."""
    return not result.startswith("SENT:") and result != "OPEN"


# ── the real application ──────────────────────────────────────────────────────────────────────────────────────────────
def test_the_set_of_websocket_routes_is_exactly_the_listed_one():
    found = {path for path, _ in walk_ws(app.routes)}
    assert found == set(WEBSOCKET_ROUTES), (
        f"new WebSocket route(s) (authenticate them, then list them with a reason): {sorted(found - set(WEBSOCKET_ROUTES))}; "
        f"listed but gone: {sorted(set(WEBSOCKET_ROUTES) - found)}"
    )


@pytest.mark.parametrize("path", sorted(WEBSOCKET_ROUTES))
def test_a_client_with_no_credentials_gets_nothing(path):
    assert gets_nothing(outcome(app, path)), outcome(app, path)


@pytest.mark.parametrize("path", sorted(WEBSOCKET_ROUTES))
@pytest.mark.parametrize(
    "connect",
    [
        {"headers": {"Authorization": "Bearer not-a-real-token"}},
        {"headers": {"Cookie": "access_token=not-a-real-token"}},
        {"subprotocols": ["graphql-transport-ws"]},
        {"subprotocols": ["graphql-ws"]},
    ],
    ids=["garbage bearer", "garbage cookie", "graphql-transport-ws", "graphql-ws"],
)
def test_garbage_credentials_or_a_subprotocol_get_nothing_either(path, connect):
    assert gets_nothing(outcome(app, path, **connect))


GRAPH = "/api/v1/graph_ws/stream"
REFUSED_AT_AUTHENTICATION = "closed:1008"


@pytest.mark.parametrize("query", ["", "?token=", "?token=not-a-real-token", "?ticket=not-a-real-ticket"])
def test_the_graph_stream_is_refused_AT_AUTHENTICATION_not_merely_silent(query):
    """1008 (policy violation) is the handler's refusal at authentication. A client that got PAST authentication and then could not reach
    the upstream feed
    (which does not exist in tests) would also send nothing but would be closed with 1011 'upstream error', so 'sent nothing' alone could
    not tell an
    authentication bypass from a refusal; the close code can."""
    assert outcome(app, GRAPH + query) == REFUSED_AT_AUTHENTICATION


def test_an_api_key_shaped_token_is_refused_or_fails_closed_but_never_gets_past_authentication():
    """An `aisoc_` token takes the API-key path, which looks the key up in the DATABASE; this test environment has none, so the lookup
    raises and the
    connection fails closed ('error') instead of the handler's own 1008. Either is a refusal. What it must never be is 1011 ('upstream
    error': the
    client got past authentication and the proxy tried the upstream feed) or any data."""
    assert outcome(app, GRAPH + "?token=aisoc_not-a-real-key") in {REFUSED_AT_AUTHENTICATION, "error"}


@pytest.mark.parametrize(
    "connect", [{"headers": {"Authorization": "Bearer not-a-real-token"}}, {"headers": {"Cookie": "access_token=not-a-real-token"}}]
)
def test_the_graph_stream_reads_its_token_only_from_the_query_string_so_headers_and_cookies_do_not_help(connect):
    assert outcome(app, GRAPH, **connect) == REFUSED_AT_AUTHENTICATION


def test_the_scan_sees_the_real_websocket_routes():
    """Guards the guard: an enumeration that silently found nothing (as the first attempt did) would make every test above pass."""
    assert len(list(walk_ws(app.routes))) >= 2


# ── controls ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def _synthetic():
    mini = FastAPI()

    @mini.websocket("/open")
    async def open_socket(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text("hello, anonymous")
        await websocket.close()

    @mini.websocket("/refusing")
    async def refusing_socket(websocket: WebSocket):
        await websocket.close(code=1008)

    @mini.websocket("/accepting-then-closing")
    async def closing_socket(websocket: WebSocket):
        await websocket.accept()
        await websocket.close(code=1008)

    @mini.websocket("/accepting-then-waiting")
    async def waiting_socket(websocket: WebSocket):
        await websocket.accept()
        await websocket.receive_text()  # waits for the client to speak, like a GraphQL transport waiting for connection_init

    @mini.websocket("/raising")
    async def raising_socket(websocket: WebSocket):
        raise TypeError("dependency could not be resolved")

    return mini


def test_control_the_probe_detects_a_socket_that_talks_to_an_anonymous_client():
    assert outcome(_synthetic(), "/open") == "SENT:hello, anonymous"


def test_control_a_socket_that_accepts_and_waits_is_reported_OPEN_and_does_not_hang_the_run():
    assert outcome(_synthetic(), "/accepting-then-waiting") == "OPEN"
    assert not gets_nothing("OPEN") and not gets_nothing("SENT:hi") and gets_nothing("closed:1008") and gets_nothing("error")


def test_control_the_probe_tells_refused_closed_and_error_apart():
    mini = _synthetic()
    assert (outcome(mini, "/refusing"), outcome(mini, "/accepting-then-closing"), outcome(mini, "/raising")) == (
        "refused:1008",
        "closed:1008",
        "error",
    )


def test_control_the_walker_finds_websocket_routes_and_ignores_http_ones():
    mini = _synthetic()

    @mini.get("/http-only")
    async def http_only():
        return {}

    assert sorted(path for path, _ in walk_ws(mini.routes)) == [
        "/accepting-then-closing",
        "/accepting-then-waiting",
        "/open",
        "/raising",
        "/refusing",
    ]
