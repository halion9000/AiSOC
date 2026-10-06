"""Shared helper: which permission(s) does a route's dependency tree require?"""
from fastapi.routing import APIRoute


def required_permissions(route: APIRoute) -> list[str]:
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
