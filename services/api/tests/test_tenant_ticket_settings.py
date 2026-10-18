"""The HaloPSA status a resolved incident moves its ticket to: a default, an organization's own choice, tidied, and sent with a resolve request."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import alert_vendor_actions as av
from app.api.v1.endpoints import tenant_ticket_settings as ts
from fastapi import HTTPException
from pydantic import ValidationError

TENANT = uuid.uuid4()


def test_the_default_is_tech_update_and_an_own_choice_is_tidied():
    assert ts.close_status_of({}) == "Tech Update"
    assert ts.close_status_of(None) == "Tech Update"
    assert ts.close_status_of({"ticket_close_status": "  Waiting   on Customer "}) == "Waiting on Customer"
    assert ts.stored_close_status({"ticket_close_status": 5}) is None
    assert ts.stored_close_status({"ticket_close_status": "x" * 61}) is None
    assert ts.stored_close_status({"ticket_close_status": "   "}) is None


def test_the_request_model_refuses_an_empty_or_too_long_name():
    with pytest.raises(ValidationError):
        ts.SetTicketSettings(close_status="")
    with pytest.raises(ValidationError):
        ts.SetTicketSettings(close_status="x" * 61)


def _db(settings):
    db = MagicMock()
    tenant = SimpleNamespace(settings=settings, updated_at=None)
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=tenant)))
    db.commit = AsyncMock()
    db.tenant = tenant
    return db


def _user():
    return SimpleNamespace(tenant_id=TENANT)


@pytest.mark.asyncio
async def test_reading_says_whether_it_is_the_default():
    assert (await ts.get_ticket_settings(_user(), _db({}))).is_default is True
    own = await ts.get_ticket_settings(_user(), _db({"ticket_close_status": "Closed"}))
    assert (own.close_status, own.is_default) == ("Closed", False)


@pytest.mark.asyncio
async def test_setting_keeps_the_rest_of_the_organizations_settings_and_clearing_goes_back_to_the_default():
    db = _db({"auto_close_threshold": 0.9})
    out = await ts.set_ticket_settings(ts.SetTicketSettings(close_status="  Closed "), _user(), db)
    assert (out.close_status, out.is_default) == ("Closed", False)
    assert db.tenant.settings == {"auto_close_threshold": 0.9, "ticket_close_status": "Closed"}
    db.commit.assert_awaited()
    cleared = await ts.clear_ticket_settings(_user(), db)
    assert (cleared.close_status, cleared.is_default) == ("Tech Update", True)
    assert db.tenant.settings == {"auto_close_threshold": 0.9}


@pytest.mark.asyncio
async def test_the_status_reaches_a_resolve_request_and_only_a_resolve():
    async def with_settings(settings):
        db = MagicMock()
        db.get = AsyncMock(return_value=SimpleNamespace(settings=settings))
        return await av.ticket_status_param(db, TENANT, "resolve")

    assert await with_settings({"ticket_close_status": "Closed"}) == {"ticket_status": "Closed"}
    assert await with_settings({}) == {"ticket_status": "Tech Update"}
    db = MagicMock()
    db.get = AsyncMock(return_value=SimpleNamespace(settings={"ticket_close_status": "Closed"}))
    assert await av.ticket_status_param(db, TENANT, "approve") == {}
    assert await av.ticket_status_param(db, TENANT, "reject") == {}


@pytest.mark.asyncio
async def test_a_problem_reading_the_setting_falls_back_to_the_default_and_never_blocks_the_resolve():
    broken = MagicMock()
    broken.get = AsyncMock(side_effect=RuntimeError("db down"))
    assert await av.ticket_status_param(broken, TENANT, "resolve") == {"ticket_status": "Tech Update"}


def test_the_routes_need_the_settings_permissions():
    from fastapi.routing import APIRoute
    from route_introspect import required_permissions

    routes = {(m, r.path): r for r in ts.router.routes if isinstance(r, APIRoute) for m in r.methods}
    assert set(required_permissions(routes[("GET", "/tenant-settings/tickets")])) == {"settings:read"}
    assert set(required_permissions(routes[("PUT", "/tenant-settings/tickets")])) == {"settings:write"}
    assert set(required_permissions(routes[("DELETE", "/tenant-settings/tickets")])) == {"settings:write"}
