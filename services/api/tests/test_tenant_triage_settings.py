"""A tenant's own auto-close confidence: stored in tenants.settings, merged not replaced, range-checked."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import tenant_triage_settings as t
from fastapi import HTTPException
from pydantic import ValidationError


class _Result:
    def __init__(self, tenant):
        self._t = tenant

    def scalar_one_or_none(self):
        return self._t


class _Db:
    def __init__(self, tenant):
        self.tenant, self.commits = tenant, 0

    async def execute(self, *_a, **_k):
        return _Result(self.tenant)

    async def commit(self):
        self.commits += 1


def user():
    return SimpleNamespace(tenant_id=uuid.uuid4())


@pytest.mark.parametrize("raw,expected", [(0.9, 0.9), ("0.7", 0.7), (None, None), ("x", None), (0.4, None), (1.5, None), (True, None)])
def test_a_stored_value_is_read_only_when_it_is_a_number_in_range(raw, expected):
    assert t.stored_threshold({"auto_close_threshold": raw}) == expected


def test_no_settings_or_the_wrong_type_is_the_platform_value():
    assert t.stored_threshold(None) is None and t.stored_threshold("junk") is None and t.stored_threshold({}) is None


@pytest.mark.parametrize("value", [0.49, 0.0, 1.01, -1, 2])
def test_a_value_outside_half_to_one_is_refused_before_anything_is_stored(value):
    with pytest.raises(ValidationError):
        t.SetAutoClose(threshold=value)


@pytest.mark.asyncio
async def test_setting_it_changes_one_key_and_leaves_the_rest_of_the_tenants_settings(monkeypatch):
    tenant = SimpleNamespace(settings={"devices": {"master_vendor": "addigy"}, "kpi_bar": {"x": 1}}, updated_at=None)
    db = _Db(tenant)
    out = await t.set_auto_close(t.SetAutoClose(threshold=0.93), user(), db)
    assert out.threshold == 0.93
    assert tenant.settings == {"devices": {"master_vendor": "addigy"}, "kpi_bar": {"x": 1}, "auto_close_threshold": 0.93}
    assert db.commits == 1 and tenant.updated_at is not None


@pytest.mark.asyncio
async def test_clearing_it_removes_only_that_key_and_is_safe_when_there_was_none():
    tenant = SimpleNamespace(settings={"devices": {"a": 1}, "auto_close_threshold": 0.9}, updated_at=None)
    out = await t.clear_auto_close(user(), _Db(tenant))
    assert out.threshold is None and tenant.settings == {"devices": {"a": 1}}
    again = SimpleNamespace(settings=None, updated_at=None)
    assert (await t.clear_auto_close(user(), _Db(again))).threshold is None and again.settings == {}


@pytest.mark.asyncio
async def test_reading_reports_the_tenants_own_value_or_none():
    assert (await t.get_auto_close(user(), _Db(SimpleNamespace(settings={"auto_close_threshold": 0.88})))).threshold == 0.88
    assert (await t.get_auto_close(user(), _Db(SimpleNamespace(settings={})))).threshold is None


@pytest.mark.asyncio
async def test_an_unknown_tenant_is_a_404():
    with pytest.raises(HTTPException) as exc:
        await t.get_auto_close(user(), _Db(None))
    assert exc.value.status_code == 404


def test_the_agents_and_this_endpoint_agree_on_the_key_and_range():
    """The two services are separate apps (both called `app`), so this reads the agents' source: the setting name and the 0.5..1.0 range must match."""
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parents[2] / "agents" / "app" / "agents" / "auto_triage_agent.py").read_text(encoding="utf-8")
    assert f"settings ->> '{t.KEY}'" in src
    assert float(re.search(r"TENANT_THRESHOLD_MIN\s*=\s*([0-9.]+)", src).group(1)) == t.MIN_THRESHOLD
    assert float(re.search(r"TENANT_THRESHOLD_MAX\s*=\s*([0-9.]+)", src).group(1)) == t.MAX_THRESHOLD
