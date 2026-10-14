"""The routes anyone can reach, and the routes any logged-in person can reach, are exactly the listed ones, each with a reason.

Found by calling all 461 operations with no credentials against a live server, on a development AND a production-configured one (23 and 22
answered anything but 401/403; the one difference is `/metrics`, token-gated outside development): the public surface was right, but
nothing PINNED it, so a new route added without an authentication dependency would have been noticed only by someone repeating that
exercise. Two sets are pinned here:
1. OPEN: no sign-in dependency at all (login itself, SSO callbacks, health probes, public listings, webhooks that check their own secret).
2. LOGIN-ONLY WITH NO CHECK IN THE HANDLER: needs a login but declares no permission AND the handler body contains no permission or role
check. (A login-only route whose handler checks a permission inside, like the autonomy-policy and business-context mutations that need
`settings:write`, is guarded and is not listed; the classifier cannot see inside a handler, so the inside is searched for the check.)
A new route in either set fails the build until it is added below WITH A REASON, and an entry whose route has been fixed or removed fails
too, so the lists can only shrink on their own. Controls built from a synthetic app prove the classifier still tells the four kinds apart.
Limits, stated: the in-handler search is a text search for a permission/role check, not proof the check is right; a route protected by a
router-level dependency is classified by what the dependency tree shows; the dynamic evidence behind the OPEN list was gathered on a
scratch database; and WebSocket routes are NOT covered here (they are not in OpenAPI and
`walk_routes` yields HTTP routes only): see test_websocket_routes_refuse_anonymous.py.
"""

import inspect
import re

from app.api.v1.deps import get_current_user, require_permission
from app.core.route_introspect import access_kind, walk_routes
from app.main import app
from fastapi import Depends, FastAPI

INLINE_CHECK = re.compile(
    r"require_permission|require_permission_db|\.holds\(|has_permission|require_admin|is_platform|\.role\b|require_signed_in_session|permissions?\b"
)

# ── reasons (shared) ──────────────────────────────────────────────────────────────────────────────────────────────────────
ENTRY = "sign-in entry point: it has to be reachable before there is a session"
SSO = "SSO redirect or callback: the browser reaches it before there is a session; it validates its own state or assertion"
PROBE = "health or liveness probe: carries no tenant data"
PUBLIC_CATALOG = "public catalog browse: shows approved entries only (the listing filters on status)"
OWN = "acts only on the caller's own account, credential, subscription or preference"
OWN_VIEWS = "the caller's own saved views: every handler filters on SavedView.user_id == the caller"

OPEN_ROUTES: dict[tuple[str, str], str] = {
    ("POST", "/api/v1/auth/login"): ENTRY + " (locked after repeated failures, see login_throttle)",
    ("POST", "/api/v1/auth/refresh"): ENTRY + " (refresh token)",
    ("POST", "/api/v1/passkeys/authenticate/begin"): ENTRY + " (passkey sign-in)",
    ("POST", "/api/v1/passkeys/authenticate/finish"): ENTRY + " (passkey sign-in)",
    ("GET", "/auth/oidc/login"): SSO,
    ("GET", "/auth/oidc/callback"): SSO,
    ("GET", "/auth/oidc/logout"): SSO,
    ("GET", "/auth/oidc/userinfo"): "bearer token checked in the handler: 401 without one",
    ("POST", "/auth/saml/acs"): SSO + " (answers python-saml error codes only)",
    ("GET", "/auth/saml/login"): SSO,
    ("GET", "/auth/saml/logout"): SSO,
    ("GET", "/auth/saml/metadata"): "the service provider's public SAML metadata: public by design",
    ("GET", "/api/v1/oauth/callback"): "OAuth redirect target: the state parameter is validated in the handler (400 without it)",
    ("GET", "/api/v1/community/detections"): PUBLIC_CATALOG,
    ("GET", "/api/v1/community/detections/{detection_id}"): PUBLIC_CATALOG,
    ("GET", "/api/v1/community/playbooks"): PUBLIC_CATALOG,
    ("GET", "/api/v1/community/plugins"): PUBLIC_CATALOG,
    ("GET", "/api/v1/community/plugins/{plugin_id}"): PUBLIC_CATALOG,
    ("GET", "/api/v1/health"): PROBE,
    ("GET", "/health"): PROBE,
    ("GET", "/livez"): PROBE,
    ("GET", "/readyz"): PROBE,
    (
        "GET",
        "/metrics",
    ): (
        "token-gated inside the handler (METRICS_TOKEN); open only in development, "
        "401 in production (verified on a production-configured server)"
    ),
    ("GET", "/api/v1/push/public-key"): "the Web Push VAPID public key: public by design",
    (
        "GET",
        "/api/v1/r/{slug}",
    ): "a published replay: public once a person publishes it (publishing needs a signed-in session, never an API key)",
    ("POST", "/api/v1/waitlist/signup"): "public form, rate-limited per client address (resolved through the trusted-proxy resolver)",
    (
        "POST",
        "/api/v1/inbox/itsm/{tenant_token}/{connector_instance_id}",
    ): "ITSM webhook: authenticated by the secret in the path, checked in the handler (401 without it)",
    (
        "POST",
        "/api/v1/inbox/core-feed/{tenant_token}/status",
    ): "CORE's per-run report: authenticated by the core-feed token in the path, checked in the handler (401 without it); can only write that tenant's core_feed rows",
    (
        "POST",
        "/api/v1/inbox/core-feed/{tenant_token}/closed",
    ): "CORE's closed-in-vendor report: authenticated by the core-feed token in the path, checked in the handler (401 without it); can only resolve that tenant's still-new alerts",
    (
        "POST",
        "/api/v1/inbox/core-feed/{tenant_token}/state",
    ): "CORE's open-incident state report: authenticated by the core-feed token in the path, checked in the handler (401 without it); can only write that tenant's own alerts' vendor state",
    (
        "POST",
        "/api/v1/inbox/core-feed/{tenant_token}/actions/claim",
    ): "CORE collects queued vendor actions: authenticated by the core-feed token in the path, checked in the handler (401 without it); only that tenant's pending actions, each handed out once",
    (
        "POST",
        "/api/v1/inbox/core-feed/{tenant_token}/actions/{action_id}/result",
    ): "CORE reports a claimed vendor action's outcome: authenticated by the core-feed token in the path, checked in the handler (401 without it); only a claimed action of that tenant can be answered",
}

LOGIN_ONLY_NO_CHECK: dict[tuple[str, str], str] = {
    ("POST", "/api/v1/auth/logout"): OWN,
    ("GET", "/api/v1/auth/me"): OWN,
    ("PATCH", "/api/v1/auth/me/preferences"): OWN,
    ("GET", "/api/v1/tenants/me/identity"): "the caller's own tenant's name and identity",
    ("GET", "/api/v1/oncall/me"): OWN,
    ("PUT", "/api/v1/oncall/me"): OWN,
    ("POST", "/api/v1/passkeys/register/begin"): OWN,
    ("POST", "/api/v1/passkeys/register/finish"): OWN,
    ("GET", "/api/v1/passkeys/credentials"): OWN,
    ("DELETE", "/api/v1/passkeys/credentials/{credential_id}"): OWN + " (a credential is revoked only by its owner)",
    ("POST", "/api/v1/push/subscribe"): OWN,
    ("POST", "/api/v1/push/unsubscribe"): OWN,
    ("POST", "/api/v1/push/test"): OWN + " (a test notification to the caller's own devices)",
    ("GET", "/api/v1/saved-views"): OWN_VIEWS,
    ("POST", "/api/v1/saved-views"): OWN_VIEWS,
    ("PATCH", "/api/v1/saved-views/{view_id}"): OWN_VIEWS,
    ("DELETE", "/api/v1/saved-views/{view_id}"): OWN_VIEWS,
    ("GET", "/api/v1/marketplace"): "read-only browsing: documented as open to any login (test_guarded_routers_matrix.py)",
    ("GET", "/api/v1/marketplace/installed"): "read-only browsing of what the caller's tenant installed: open to any login by design",
    ("GET", "/api/v1/marketplace/mitre"): "read-only ATT&CK coverage: open to any login by design",
    ("GET", "/api/v1/health/pipeline"): "read-only pipeline status for the caller's own tenant (every query is scoped to user.tenant_id)",
    ("POST", "/api/v1/phishing/submit"): "any person may report a suspicious email: that is the point of the route",
    (
        "POST",
        "/api/v1/community/plugins/publish",
    ): (
        "submits a plugin for MODERATION (it is pending until approved). "
        "Whether publishing should need a permission is a product decision, not decided here"
    ),
    (
        "POST",
        "/api/v1/community/plugins/{plugin_id}/rate",
    ): "one rating per person, approved plugins only, never your own (integrity fixed earlier)",
    ("GET", "/graphql"): "every resolver checks its own permission (test_graphql_authorization.py)",
    ("POST", "/graphql"): "every resolver checks its own permission (test_graphql_authorization.py)",
}


def has_inline_check(endpoint) -> bool:
    try:
        return bool(INLINE_CHECK.search(inspect.getsource(endpoint)))
    except (OSError, TypeError):
        return False


def classify(routes) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """(open, login-only with no check inside the handler) as {(METHOD, path)} for a route table."""
    open_, login_only = set(), set()
    for path, route in walk_routes(routes):
        kind = access_kind(route)
        for method in route.methods - {"HEAD", "OPTIONS"}:
            if kind == "open":
                open_.add((method, path))
            elif kind == "signed-in" and not has_inline_check(route.endpoint):
                login_only.add((method, path))
    return open_, login_only


def diff(actual: set, allowed: dict) -> tuple[list, list]:
    return sorted(actual - set(allowed)), sorted(set(allowed) - actual)


# ── the real application ──────────────────────────────────────────────────────────────────────────────────────────────
def test_the_set_of_routes_anyone_can_reach_is_exactly_the_listed_one():
    open_, _ = classify(app.routes)
    new, stale = diff(open_, OPEN_ROUTES)
    assert not new, f"routes with NO sign-in dependency that are not listed (add authentication, or list them with a reason): {new}"
    assert not stale, f"listed as open but no longer open (drop them from OPEN_ROUTES): {stale}"


def test_the_set_of_login_only_routes_with_no_check_in_the_handler_is_exactly_the_listed_one():
    _, login_only = classify(app.routes)
    new, stale = diff(login_only, LOGIN_ONLY_NO_CHECK)
    assert (
        not new
    ), f"routes any logged-in user can call, with no permission or role check anywhere (add one, or list them with a reason): {new}"
    assert not stale, f"listed but now guarded or removed (drop them from LOGIN_ONLY_NO_CHECK): {stale}"


def test_every_entry_has_a_reason_and_no_route_is_in_both_lists():
    assert all(reason.strip() for reason in [*OPEN_ROUTES.values(), *LOGIN_ONLY_NO_CHECK.values()])
    assert not (set(OPEN_ROUTES) & set(LOGIN_ONLY_NO_CHECK))


def test_the_scan_sees_the_application_and_its_listed_routes_exist_in_it():
    """Guards the guard: an empty route table would make both comparisons pass."""
    open_, login_only = classify(app.routes)
    assert (
        len(open_) >= 20 and len(login_only) >= 20 and ("POST", "/api/v1/auth/login") in open_ and ("GET", "/api/v1/auth/me") in login_only
    )


# ── controls: the classifier tells the four kinds apart ──────────────────────────────────────────────────────────────────
def _synthetic():
    mini = FastAPI()

    @mini.get("/open")
    async def open_route():
        return {}

    @mini.get("/login-only")
    async def login_only_route(user=Depends(get_current_user)):
        return {}

    @mini.get("/guarded")
    async def guarded_route(user=Depends(require_permission("alerts:read"))):
        return {}

    @mini.post("/login-only-but-checked-inside")
    async def checked_inside_route(user=Depends(get_current_user)):
        await user.require_permission_db("settings:write", None)
        return {}

    return mini


def test_control_the_classifier_tells_open_login_only_guarded_and_checked_inside_apart():
    mini = _synthetic()
    kinds = {
        path: access_kind(route)
        for path, route in walk_routes(mini.routes)
        if path in {"/open", "/login-only", "/guarded", "/login-only-but-checked-inside"}
    }
    assert kinds == {"/open": "open", "/login-only": "signed-in", "/guarded": "permission", "/login-only-but-checked-inside": "signed-in"}
    open_, login_only = classify(mini.routes)
    assert ("GET", "/open") in open_
    assert ("GET", "/login-only") in login_only
    assert ("POST", "/login-only-but-checked-inside") not in login_only, "a check inside the handler counts as guarded"
    assert ("GET", "/guarded") not in open_ | login_only


def test_control_a_new_unlisted_route_is_reported_as_new_and_a_listed_but_gone_one_as_stale():
    mini = _synthetic()
    open_, login_only = classify(mini.routes)
    new, stale = diff(open_, {("GET", "/gone"): "was open once"})
    assert new == [("GET", "/open")] and stale == [("GET", "/gone")]
    assert diff(login_only, {("GET", "/login-only"): "listed"}) == ([], [])
