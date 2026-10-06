"""The API's calls to the agents service carry the shared internal token.

The agents service requires authentication in production; the API has already
authenticated the user, so its proxies vouch with x-internal-token. In
development (no token configured) nothing is sent.
"""
import asyncio

import httpx
import pytest
import respx

from app.api.v1.endpoints import cases as cases_ep
from app.api.v1.endpoints import playbooks as playbooks_ep
from app.core.config import settings
from app.graphql import query as gql


def _calls(token: str, monkeypatch) -> list[httpx.Request]:
    monkeypatch.setattr(settings, "REALTIME_INTERNAL_TOKEN", token)
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host__regex=r".*").mock(return_value=httpx.Response(200, json=[]))

        async def go():
            await playbooks_ep._proxy("GET", "")
            await cases_ep._agents_proxy("GET", "/api/v1/investigations")
            await gql._proxy_get("")

        asyncio.run(go())
        return [c.request for c in route.calls]


def test_all_three_call_sites_send_the_internal_token(monkeypatch):
    reqs = _calls("internal-secret-123", monkeypatch)
    assert len(reqs) == 3
    assert all(r.headers.get("x-internal-token") == "internal-secret-123" for r in reqs)


def test_nothing_is_sent_in_development(monkeypatch):
    reqs = _calls("", monkeypatch)
    assert len(reqs) == 3
    assert all("x-internal-token" not in r.headers for r in reqs)
