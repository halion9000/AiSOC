"""No route may expose a login/database object as a QUERY PARAMETER.

`current_user: Annotated[Any, require_permission(...)]` (note: no Depends) made
FastAPI treat `current_user` as an ordinary query parameter. The permission check
never ran, and the API-key create/update/revoke endpoints returned 422 for
everyone. This catches that whole class of mistake from the OpenAPI schema.
"""

from app.main import app

SUSPICIOUS = {"current_user", "user", "db", "session", "auth", "credentials", "tenant_db", "current_tenant"}


def test_no_route_takes_an_auth_or_db_object_as_a_query_parameter():
    bad = []
    for path, ops in app.openapi()["paths"].items():
        for method, op in ops.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            for prm in op.get("parameters", []):
                if prm.get("in") == "query" and prm.get("name") in SUSPICIOUS:
                    bad.append(f"{method.upper()} {path}  ?{prm['name']}")
    assert not bad, "dependency parameters that FastAPI treats as query params (missing Depends?):\n  " + "\n  ".join(bad)


def test_the_detector_would_catch_the_original_mistake():
    from typing import Annotated, Any

    from fastapi import APIRouter, FastAPI

    from app.api.v1.deps import require_permission

    broken = FastAPI()
    r = APIRouter()

    @r.post("/x")
    async def handler(current_user: Annotated[Any, require_permission("users:write")]):  # the original bug
        return {}

    broken.include_router(r)
    names = [p["name"] for p in broken.openapi()["paths"]["/x"]["post"]["parameters"]]
    assert "current_user" in names  # FastAPI really does expose it as a query parameter
