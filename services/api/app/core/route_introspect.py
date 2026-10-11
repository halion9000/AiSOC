"""Which permissions does a route require, and which routes does the application have? Shared by the permission tests and by the capability
reference generator
(app/scripts/export_capabilities.py), so there is one definition of both."""

from collections.abc import Iterator

from fastapi.routing import APIRoute


def required_permissions(route: APIRoute) -> list[str]:
    """The permission names a route's dependency tree asks for (every `require_permission("x:y")` in it), in the order found."""
    found: list[str] = []

    def walk(dep):
        for d in dep.dependencies:
            if "require_permission" in getattr(d.call, "__qualname__", ""):
                for cell in d.call.__closure__ or ():
                    if isinstance(cell.cell_contents, str) and ":" in cell.cell_contents:
                        found.append(cell.cell_contents)
            walk(d)

    walk(route.dependant)
    return found


SIGNED_IN_DEPENDENCIES = ("get_current_user", "require_signed_in_session")


def access_kind(route: APIRoute) -> str:
    """How a route is protected, as far as its DEPENDENCIES show: `permission` (it asks for a named permission), `signed-in` (it needs a
    signed-in caller but declares no permission) or `open`
    (no sign-in dependency at all: login itself, health checks, public listings, webhooks that check their own secret). A check made INSIDE
    the handler is not visible here."""
    if required_permissions(route):
        return "permission"
    names: list[str] = []

    def walk(dep):
        for d in dep.dependencies:
            names.append(getattr(d.call, "__qualname__", "") or getattr(d.call, "__name__", ""))
            walk(d)

    walk(route.dependant)
    return "signed-in" if any(marker in name for name in names for marker in SIGNED_IN_DEPENDENCIES) else "open"


def walk_routes(routes, prefix: str = "") -> Iterator[tuple[str, APIRoute]]:
    """Every APIRoute of the application with its full path, descending into included routers (their prefix is carried in
    `include_context`)."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield prefix + route.path, route
        elif hasattr(route, "original_router"):
            context = getattr(route, "include_context", None)
            yield from walk_routes(route.original_router.routes, prefix + (getattr(context, "prefix", "") or ""))
