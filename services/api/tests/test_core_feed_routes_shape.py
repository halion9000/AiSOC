"""Every route CORE calls, whatever the data: how it takes its body, where it is listed, and what it refuses.

Routes are found from the app itself (not by reading source), so a new core-feed route is covered here the day it exists.
"""

import typing
from pathlib import Path

import pytest
from app.core.route_introspect import walk_routes
from app.main import app
from fastapi.routing import APIRoute
from pydantic import BaseModel, ValidationError
from pydantic.fields import FieldInfo

REPO = Path(__file__).resolve().parents[3]


def core_feed_routes() -> list[tuple[str, APIRoute]]:
    return sorted(((path, r) for path, r in walk_routes(app.routes) if "/core-feed/" in path and "POST" in r.methods), key=lambda pr: pr[0])


def body_model(route: APIRoute) -> type[BaseModel] | None:
    field = route.body_field
    model = field.field_info.annotation if field is not None else None
    return model if isinstance(model, type) and issubclass(model, BaseModel) else None


ROUTES = core_feed_routes()
IDS = [path.split("/core-feed/{tenant_token}/")[1] for path, _r in ROUTES]


def test_the_core_feed_routes_were_found():
    assert len(ROUTES) >= 20, IDS
    assert "actions/claim" in IDS and "m365-checks" in IDS


# Models that accept an empty body on purpose (everything in them is optional or defaulted); every other route's model must refuse it.
ACCEPTS_EMPTY_BODY: dict[str, str] = {}


@pytest.mark.parametrize("route", ROUTES, ids=IDS)
def test_an_empty_or_wrong_shaped_body_is_a_validation_error_never_a_crash(route):
    path, route = route
    model = body_model(route)
    if model is None:
        pytest.skip("this route takes no body")
    route_id = path.split("/core-feed/{tenant_token}/")[1]
    for wrong in ({}, [], "text", 7, None, {"vendor": 5, "items": "no", "sources": "no", "scripts": "no", "checks": "no"}):
        if wrong == {} and route_id in ACCEPTS_EMPTY_BODY:
            continue
        with pytest.raises(ValidationError):
            model.model_validate(wrong)


def list_fields(model: type[BaseModel]) -> list[tuple[str, FieldInfo]]:
    return [
        (n, f)
        for n, f in model.model_fields.items()
        if typing.get_origin(f.annotation) is list
        or (
            typing.get_origin(f.annotation) in (typing.Union, getattr(__import__("types"), "UnionType", None))
            and any(typing.get_origin(a) is list for a in typing.get_args(f.annotation))
        )
    ]


@pytest.mark.parametrize("route", ROUTES, ids=IDS)
def test_every_list_a_route_accepts_has_a_size_limit(route):
    _path, route = route
    model = body_model(route)
    if model is None:
        pytest.skip("this route takes no body")
    unbounded = [n for n, f in list_fields(model) if not any(getattr(m, "max_length", None) for m in f.metadata)]
    assert not unbounded, f"{model.__name__}: no size limit on {unbounded}"


def test_every_core_feed_route_is_in_the_documents_of_public_routes_and_in_the_openapi_file():
    import test_anonymous_access_sweep as sweep  # noqa: PLC0415

    public = {p for (_m, p) in sweep.PUBLIC}
    openapi = (REPO / "docs" / "openapi.yaml").read_text(encoding="utf-8")
    for path, _r in ROUTES:
        assert path in public, f"{path} is not in the anonymous-access sweep's list of public routes (with its reason)"
        assert f"  {path}:" in openapi, f"{path} is not in docs/openapi.yaml (run scripts/export_openapi.py)"
