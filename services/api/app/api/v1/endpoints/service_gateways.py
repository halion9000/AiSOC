"""Authenticated gateways to the honeytokens and purple-team services.

Why this exists. The console's honeytokens and purple-team pages call `/api/v1/honeytokens/...` and
`/api/v1/purple-team/...` on their own origin, i.e. the API, which served neither. Those pages therefore had no working
backend path. The alternative (pointing the browser at the services directly) would have been unsafe: the services
performed NO authentication, trusted a caller-supplied `tenant_id`, and several routes (`atomics/run`, `caldera/run`)
launch adversary simulations.

Now the console calls the API, which requires a login and a per-route permission, decides WHICH tenant a request is for
(always the caller's own: a `tenant_id` the browser sends is replaced, never trusted, in the query string and, for routes
that take one, in the JSON body), and calls the service with that service's own bearer token. The caller's credentials are
never forwarded. The services themselves also scope every ID-keyed route by tenant, so isolation does not rest on this
gateway alone.

Not proxied on purpose: `POST /honeytokens/webhook/trigger`, the callback planted canaries use to report an access. Its
only credential is the unguessable token id, so it cannot sit behind a login or a service token.

Permissions: reads need `alerts:read`; creating or revoking a honeytoken, `alerts:write`; deleting one, `alerts:delete`;
recording purple-team results, drift snapshots and tabletop activity, `rules:write`; syncing the Atomic library and RUNNING
a simulation (`atomics/run`, `caldera/run`), `settings:write`, which is deliberately the narrow, admin-level choice.
"""
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.api.v1.deps import AuthUser, require_permission

router = APIRouter()

_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_BODY_BYTES = 1_000_000
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


@dataclass(frozen=True)
class GatewayRoute:
    method: str
    path: str  # relative to the service prefix; identical on both sides
    permission: str
    body_tenant: bool = False  # the service's request body carries a tenant_id: replace it with the caller's


@dataclass(frozen=True)
class Gateway:
    name: str
    prefix: str  # public path here, and the service's path prefix after /api/v1
    url_env: str
    default_url: str
    token_env: str
    routes: tuple[GatewayRoute, ...]


R, W, D, RW, S = "alerts:read", "alerts:write", "alerts:delete", "rules:write", "settings:write"

GATEWAYS: tuple[Gateway, ...] = (
    Gateway(
        name="honeytokens",
        prefix="honeytokens",
        url_env="HONEYTOKENS_SERVICE_URL",
        default_url="http://honeytokens:8005",
        token_env="AISOC_HONEYTOKENS_SERVICE_TOKEN",
        routes=(
            GatewayRoute("POST", "", W, body_tenant=True),
            GatewayRoute("GET", "", R),
            GatewayRoute("GET", "/{token_id}", R),
            GatewayRoute("PATCH", "/{token_id}/revoke", W),
            GatewayRoute("DELETE", "/{token_id}", D),
            GatewayRoute("GET", "/{token_id}/triggers", R),
        ),
    ),
    Gateway(
        name="purple-team",
        prefix="purple-team",
        url_env="PURPLE_TEAM_SERVICE_URL",
        default_url="http://purple-team:8006",
        token_env="AISOC_PURPLE_TEAM_SERVICE_TOKEN",
        routes=(
            GatewayRoute("POST", "/atomics/sync", S),
            GatewayRoute("GET", "/atomics", R),
            GatewayRoute("POST", "/atomics/run", S, body_tenant=True),
            GatewayRoute("GET", "/caldera/health", R),
            GatewayRoute("GET", "/caldera/abilities", R),
            GatewayRoute("GET", "/caldera/adversaries", R),
            GatewayRoute("GET", "/caldera/operations", R),
            GatewayRoute("POST", "/caldera/run", S, body_tenant=True),
            GatewayRoute("GET", "/executions", R),
            GatewayRoute("PATCH", "/executions/{execution_id}/detection", RW),
            GatewayRoute("GET", "/coverage", R),
            GatewayRoute("POST", "/drift/snapshot", RW),
            GatewayRoute("GET", "/drift/snapshots", R),
            GatewayRoute("GET", "/drift/latest", R),
            GatewayRoute("POST", "/tabletop", RW, body_tenant=True),
            GatewayRoute("GET", "/tabletop", R),
            GatewayRoute("GET", "/tabletop/{session_id}", R),
            GatewayRoute("POST", "/tabletop/{session_id}/findings", RW),
            GatewayRoute("PATCH", "/tabletop/{session_id}/complete", RW),
        ),
    ),
)


def _safe_path_params(params: Mapping[str, str]) -> dict[str, str]:
    """A path segment is spliced into the upstream URL, so it must be a plain identifier ('..' and '/' never are)."""
    out: dict[str, str] = {}
    for key, value in params.items():
        if not _SEGMENT.match(value) or ".." in value:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid {key}")
        out[key] = value
    return out


async def _forward(gw: Gateway, route: GatewayRoute, request: Request, user: AuthUser) -> Response:
    tenant = str(user.tenant_id)
    base = (os.getenv(gw.url_env) or gw.default_url).rstrip("/")
    url = f"{base}/api/v1/{gw.prefix}{route.path.format_map(_safe_path_params(request.path_params))}"

    # Whatever tenant the browser asked for is discarded: the caller's own tenant is always the one used.
    params = [(k, v) for k, v in request.query_params.multi_items() if k != "tenant_id"] + [("tenant_id", tenant)]

    json_body = None
    if request.method in _BODY_METHODS:
        raw = await request.body()
        if len(raw) > _MAX_BODY_BYTES:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="request body too large")
        if raw:
            try:
                json_body = json.loads(raw)
            except ValueError as exc:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="request body must be JSON") from exc
        if route.body_tenant:
            if json_body is None:
                json_body = {}
            if not isinstance(json_body, dict):
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="a JSON object is required")
            json_body["tenant_id"] = tenant

    headers: dict[str, str] = {}
    token = (os.getenv(gw.token_env) or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"  # the SERVICE's own token, never the caller's credentials

    try:
        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            resp = await client.request(request.method, url, params=params, json=json_body)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"{gw.name} service is not available") from exc

    # A 401/403 from the service means THIS gateway's credentials were refused, not that the user is logged out;
    # surfacing it as 401 would send the console into its sign-in flow. Service-side 5xx are not passed through verbatim.
    if resp.status_code in (401, 403) or resp.status_code >= 500:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"{gw.name} service error")
    if resp.status_code == 204 or not resp.content:
        return Response(status_code=resp.status_code)
    return Response(content=resp.content, status_code=resp.status_code, media_type=resp.headers.get("content-type", "application/json"))


def _register(gw: Gateway, route: GatewayRoute) -> None:
    async def endpoint(request: Request, current_user: AuthUser) -> Response:
        return await _forward(gw, route, request, current_user)

    slug = re.sub(r"\W+", "_", route.path).strip("_") or "root"
    endpoint.__name__ = f"{gw.name.replace('-', '_')}_{route.method.lower()}_{slug}"
    router.add_api_route(
        f"/{gw.prefix}{route.path}",
        endpoint,
        methods=[route.method],
        dependencies=[Depends(require_permission(route.permission))],
        tags=[gw.name],
        summary=f"{route.method} {gw.name}{route.path} (authenticated gateway to the {gw.name} service)",
    )


for _gw in GATEWAYS:
    for _route in _gw.routes:
        _register(_gw, _route)
