"""Route wiring the endpoint tests cannot see, because they call the functions directly."""

from app.api.v1.endpoints.devices import router


def _index(path: str, method: str) -> int:
    for i, r in enumerate(router.routes):
        if getattr(r, "path", None) == path and method in getattr(r, "methods", set()):
            return i
    raise AssertionError(f"{method} {path} is not a route")


def test_the_duplicates_list_is_matched_before_the_device_id_route_would_swallow_it():
    assert _index("/devices/duplicates", "GET") < _index("/devices/{device_id}", "GET")


def test_dismiss_and_merge_are_posts_that_exist():
    _index("/devices/duplicates/dismiss", "POST")
    _index("/devices/duplicates/merge", "POST")
