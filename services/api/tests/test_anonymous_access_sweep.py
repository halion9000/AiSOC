"""In production, NO route answers an anonymous request except an explicit public list.

Found by sending an anonymous request to every route of a production-mode API:
about 35 answered, including writes (deployment config, air-gap bundles, STIX
indicator creation, compliance evidence collection) and LLM-backed endpoints
anyone could use to spend the owner's LLM budget. The API has no global login
check: each handler must opt in, and many never did.

This test is the net under all of it: it probes every route in the OpenAPI
schema with NO credentials, in production mode, and fails for any route that is
not on PUBLIC below. To make a new route public you must add it here, with a
reason, where a reviewer will see it.
"""

import asyncio
import re

import httpx
import pytest
from app.api.v1 import deps
from app.main import app

UUID = "00000000-0000-0000-0000-0000000000aa"
BODY_METHODS = {"POST", "PUT", "PATCH"}

# (METHOD, path template) -> why anonymous callers are allowed.
PUBLIC = {
    ("POST", "/api/v1/auth/login"): "sign-in",
    ("POST", "/api/v1/auth/refresh"): "token refresh (the refresh token is the credential)",
    ("GET", "/auth/oidc/login"): "SSO flow (fails closed with 501 when unconfigured)",
    ("GET", "/auth/oidc/callback"): "SSO flow",
    ("GET", "/auth/oidc/logout"): "SSO flow",
    ("GET", "/auth/saml/login"): "SSO flow (fails closed with 501 when unconfigured)",
    ("POST", "/auth/saml/acs"): "SSO flow",
    ("GET", "/auth/saml/logout"): "SSO flow",
    ("GET", "/auth/saml/metadata"): "SAML service-provider metadata is public by design",
    ("GET", "/health"): "container health check",
    ("GET", "/api/v1/health"): "reachability probe for the web console",
    ("GET", "/api/v1/oauth/callback"): "OAuth redirect target (validates its own state)",
    ("POST", "/api/v1/passkeys/authenticate/begin"): "passkey sign-in",
    ("POST", "/api/v1/passkeys/authenticate/finish"): "passkey sign-in",
    ("GET", "/api/v1/push/public-key"): "VAPID public key is public by design",
    ("GET", "/api/v1/r/{slug}"): "public share links for replays",
    ("POST", "/api/v1/waitlist/signup"): "public marketing signup",
    ("POST", "/api/v1/inbox/itsm/{tenant_token}/{connector_instance_id}"): (
        "inbound ITSM webhook: authenticated by the secret tenant_token in the URL plus the "
        "vendor signature, and answers 401 on a mismatch (the 500 here is only the fake database)"
    ),
    ("POST", "/api/v1/inbox/core-feed/{tenant_token}/status"): (
        "CORE's per-run report: authenticated by the secret core-feed token in the URL (only an active token with the core-feed label is accepted; "
        "anything else is a 401 in the handler), and it can only write that tenant's own core_feed rows (the 422 here is the empty body)"
    ),
    ("POST", "/api/v1/inbox/core-feed/{tenant_token}/closed"): (
        "CORE's closed-incident report: authenticated by the secret core-feed token in the URL (401 in the handler otherwise); it can only resolve that tenant's own alerts "
        "that are still new, matched on the incident id (the 422 here is the empty body)"
    ),
    ("POST", "/api/v1/inbox/core-feed/{tenant_token}/clients"): (
        "CORE's list of a vendor's clients: authenticated by the secret core-feed token in the URL (401 in the handler otherwise); it can only add or rename that tenant's own client-mapping rows (the 422 here is the empty body)"
    ),
    ("POST", "/api/v1/inbox/core-feed/{tenant_token}/tickets"): (
        "CORE's list of the PSA tickets linked to open incidents: authenticated by the secret core-feed token in the URL (401 in the handler otherwise); it can only add ticket details to that feed's own alerts (the 422 here is the empty body)"
    ),
    ("GET", "/api/v1/canary/{token_id}"): (
        "The honeytoken tripwire: a planted link must work for someone who has no AiSOC account, so it cannot require sign-in. It answers every id the same way (a one pixel image), forwards only a well-formed UUID, is rate limited per token and overall, and returns nothing about the token"
    ),
    ("POST", "/api/v1/inbox/core-feed/{tenant_token}/device-names"): (
        "CORE's names for the devices vendor incidents were raised on: authenticated by the secret core-feed token in the URL (401 in the handler otherwise); it can only fill an EMPTY host list on that feed's own alerts (the 422 here is the empty body)"
    ),
    ("POST", "/api/v1/inbox/core-feed/{tenant_token}/devices"): (
        "CORE's list of a tool's devices: authenticated by the secret core-feed token in the URL (401 in the handler otherwise); it can only add or update devices under that feed's own client tenants, and only for clients already mapped (the 422 here is the empty body)"
    ),
    ("POST", "/api/v1/inbox/core-feed/{tenant_token}/state"): (
        "CORE's open-incident state report: authenticated by the secret core-feed token in the URL (401 in the handler otherwise); it can only write that tenant's own alerts' vendor state (the 422 here is the empty body)"
    ),
    ("POST", "/api/v1/inbox/core-feed/{tenant_token}/actions/claim"): (
        "CORE collects the vendor actions analysts queued: authenticated by the secret core-feed token in the URL (401 in the handler otherwise); only that tenant's pending actions, each handed out once (the 422 here is the empty body)"
    ),
    ("POST", "/api/v1/inbox/core-feed/{tenant_token}/sync-requests/claim"): (
        "CORE collects the Sync requests analysts made on the Connectors page: authenticated by the secret core-feed token in the URL (401 in the handler otherwise); only that tenant's own pending requests, each handed out once (the 422 here is the empty body)"
    ),
    ("POST", "/api/v1/inbox/core-feed/{tenant_token}/actions/{action_id}/result"): (
        "CORE reports how a claimed vendor action went: authenticated by the secret core-feed token in the URL (401 in the handler otherwise); only a claimed action of that tenant can be answered (the 422 here is the empty body)"
    ),
    ("GET", "/api/v1/community/detections"): "public community catalog (global content, no tenant data)",
    ("GET", "/api/v1/community/detections/{detection_id}"): "public community catalog",
    ("GET", "/api/v1/community/playbooks"): "public community catalog",
    ("GET", "/api/v1/community/plugins"): "public community catalog",
    ("GET", "/api/v1/community/plugins/{plugin_id}"): "public community catalog",
}


def _all_routes() -> list[tuple[str, str]]:
    return sorted(
        (m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops if m in ("get", "post", "put", "patch", "delete")
    )


async def _status(client: httpx.AsyncClient, method: str, path: str):
    url = re.sub(r"\{[^}]+\}", UUID, path)

    async def ask(timeout: float):
        r = await asyncio.wait_for(client.request(method, url, json={} if method in BODY_METHODS else None), timeout=timeout)
        return r.status_code

    try:
        try:
            # All routes are asked at once, so on a busy machine a route that WILL refuse can miss a short deadline. A timeout is only believed once the route has been
            # asked again with a longer one, by when the rest of the sweep is done: a route that really streams still times out then.
            return await ask(6)
        except TimeoutError:
            return await ask(20)
    except TimeoutError:
        return "kept the connection open (streaming) without credentials"
    except Exception as exc:  # a route that blows up without credentials has not refused them
        return f"error: {type(exc).__name__}"


async def _sweep() -> dict[tuple[str, str], object]:
    async def fake_db():
        yield None  # a guarded route must refuse BEFORE touching the database

    app.dependency_overrides[deps.get_db] = fake_db
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            routes = _all_routes()
            results = await asyncio.gather(*[_status(client, m, p) for m, p in routes])
            return dict(zip(routes, results, strict=False))
    finally:
        app.dependency_overrides.pop(deps.get_db, None)


@pytest.fixture
def production(monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(deps, "is_dev_mode", lambda: False)
    # /metrics decides from the cached settings value; in a real production process it refuses
    monkeypatch.setattr(main_module, "_metrics_environment_is_dev", lambda: False)


def test_the_sweep_sees_the_whole_api():
    assert len(_all_routes()) > 350, "the OpenAPI schema is incomplete: the sweep would prove nothing"


def test_only_the_documented_public_routes_answer_without_credentials(production):
    results = asyncio.run(_sweep())
    exposed = sorted(f"{m:6} {p}  -> {status}" for (m, p), status in results.items() if status not in (401, 403) and (m, p) not in PUBLIC)
    assert not exposed, (
        f"{len(exposed)} route(s) answered an ANONYMOUS request in production. Add a login/permission "
        "dependency, or (only if it is truly public) add it to PUBLIC with a reason:\n  " + "\n  ".join(exposed)
    )


def test_every_public_entry_is_a_real_route():
    routes = set(_all_routes())
    stale = sorted(f"{m} {p}" for (m, p) in PUBLIC if (m, p) not in routes)
    assert not stale, f"PUBLIC lists routes that no longer exist (remove them): {stale}"
