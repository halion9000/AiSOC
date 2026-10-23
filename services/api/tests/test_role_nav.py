"""A role can hide sections and pages of the console; a person sees a page when any of their roles shows it."""

import uuid

import pytest
from app.api.v1.endpoints.auth import UserMeResponse
from app.api.v1.endpoints.rbac import RoleIn, RoleOut, RoleUpdate
from app.models.rbac import Role
from app.services.role_nav import MAX_ENTRIES, clean_hidden_nav, hidden_for_roles, valid_entry
from fastapi import HTTPException


def test_sections_and_page_addresses_are_accepted():
    assert valid_entry("section:Automation")
    assert valid_entry("section:Client Security")
    assert valid_entry("section:Threat Operations")
    assert valid_entry("/settings/mfa")
    assert valid_entry("/detection/vendor-detections")


@pytest.mark.parametrize("bad", ["", "Automation", "section:", "section:<script>", "https://evil.example/x", "//evil.example", "/a b", "/x?y=1", "../etc", "section:" + "a" * 80, "/" + "a" * 130])
def test_anything_else_is_refused(bad):
    assert not valid_entry(bad)
    with pytest.raises(HTTPException) as e:
        clean_hidden_nav([bad])
    assert e.value.status_code == 422


def test_entries_are_trimmed_and_repeats_dropped_in_order():
    assert clean_hidden_nav([" /settings/mfa ", "section:Automation", "/settings/mfa"]) == ["/settings/mfa", "section:Automation"]
    assert clean_hidden_nav(None) == []
    assert clean_hidden_nav([]) == []


def test_too_many_entries_are_refused():
    with pytest.raises(HTTPException):
        clean_hidden_nav([f"/page-{i}" for i in range(MAX_ENTRIES + 1)])


def test_a_person_sees_a_page_when_any_of_their_roles_shows_it():
    a = ["section:Automation", "/settings/mfa"]
    b = ["section:Automation", "/hunt"]
    assert hidden_for_roles([a, b]) == ["section:Automation"]
    assert hidden_for_roles([a]) == ["/settings/mfa", "section:Automation"]
    assert hidden_for_roles([a, []]) == []


def test_no_assigned_roles_hides_nothing():
    assert hidden_for_roles([]) == []


def test_the_role_carries_hidden_nav_through_every_schema():
    assert RoleIn(name="x").hidden_nav == []
    assert RoleUpdate().hidden_nav is None
    out = RoleOut(id=uuid.uuid4(), tenant_id=uuid.uuid4(), name="n", description=None, is_system=False, hidden_nav=["/hunt"])
    assert out.hidden_nav == ["/hunt"]
    assert UserMeResponse(id=uuid.uuid4(), tenant_id=uuid.uuid4(), account_name="a", username="a", role="r", is_active=True).hidden_nav == []


def test_the_table_has_the_column_with_an_empty_default():
    col = Role.__table__.c.hidden_nav
    assert not col.nullable
    assert col.server_default is not None
