"""Shared helper: which permission(s) does a route's dependency tree require? (The definition moved to app/core/route_introspect.py; this keeps the tests' import working.)"""
from app.core.route_introspect import required_permissions, walk_routes  # noqa: F401
