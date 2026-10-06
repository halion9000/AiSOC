"""FIM events and summary: tenant scoping, filters, paging, and the fields the console reads.

The service had no tests for these endpoints, and the console expects fields they did not return
(`node_key` and `since` filters, `active_nodes`), which is part of how the mismatch went unnoticed.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models.fim_event import FimEvent

AUTH = {"Authorization": "Bearer test-api-token"}
T0 = datetime(2026, 10, 1, 12, 0, 0)  # naive: SQLite stores no timezone


def _event(tenant="acme", node="node-a", host="web-1", path="/etc/passwd", action="UPDATED", minutes=0, **extra):
    return FimEvent(tenant_id=tenant, node_key=node, hostname=host, target_path=path, action=action, event_time=T0 + timedelta(minutes=minutes), **extra)


@pytest.fixture
async def seeded(db_session):
    db_session.add_all([
        _event(path="/etc/passwd", action="UPDATED", minutes=0, node="node-a", host="web-1"),
        _event(path="/etc/passwd", action="UPDATED", minutes=10, node="node-a", host="web-1"),
        _event(path="/etc/shadow", action="CREATED", minutes=20, node="node-b", host="db-1"),
        _event(path="/var/log/app.log", action="DELETED", minutes=30, node="node-b", host="db-1"),
        _event(path="/etc/hosts", action="ATTRIBUTES_MODIFIED", minutes=40, node="node-c", host="web-2"),
        _event(tenant="other", path="/etc/secret-of-another-tenant", action="CREATED", minutes=50, node="node-z", host="x"),
    ])
    await db_session.commit()


async def _events(client, **params):
    r = await client.get("/api/v1/osquery/fim/events", params={"tenant_id": "acme", **params}, headers=AUTH)
    assert r.status_code == 200, r.text
    return r.json()


async def _summary(client, **params):
    r = await client.get("/api/v1/osquery/fim/summary", params={"tenant_id": "acme", **params}, headers=AUTH)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_events_are_scoped_to_the_tenant(client, seeded):
    page = await _events(client)
    assert page["total"] == 5
    assert all(e["tenant_id"] == "acme" for e in page["items"])
    assert not any("another-tenant" in e["target_path"] for e in page["items"])
    other = await _events(client, tenant_id="other")
    assert other["total"] == 1 and other["items"][0]["target_path"] == "/etc/secret-of-another-tenant"


@pytest.mark.asyncio
async def test_a_tenant_with_no_events_gets_an_empty_page_not_an_error(client, seeded):
    page = await _events(client, tenant_id="nobody")
    assert (page["total"], page["items"]) == (0, [])
    s = await _summary(client, tenant_id="nobody")
    assert (s["total_events"], s["by_action"], s["top_paths"], s["active_nodes"]) == (0, [], [], 0)


@pytest.mark.asyncio
async def test_newest_first(client, seeded):
    times = [e["event_time"] for e in (await _events(client))["items"]]
    assert times == sorted(times, reverse=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("params,expected_paths", [
    ({"action": "created"}, {"/etc/shadow"}),                       # case-insensitive
    ({"action": "UPDATED"}, {"/etc/passwd"}),
    ({"path_prefix": "/etc/"}, {"/etc/passwd", "/etc/shadow", "/etc/hosts"}),
    ({"hostname": "db-1"}, {"/etc/shadow", "/var/log/app.log"}),
    ({"node_key": "node-b"}, {"/etc/shadow", "/var/log/app.log"}),
    ({"node_key": "node-c"}, {"/etc/hosts"}),
    ({"node_key": "node-z"}, set()),                                # another tenant's node: invisible here
    ({"action": "UPDATED", "node_key": "node-b"}, set()),           # filters combine (AND)
])
async def test_filters(client, seeded, params, expected_paths):
    page = await _events(client, **params)
    assert {e["target_path"] for e in page["items"]} == expected_paths
    assert page["total"] == len(page["items"])


@pytest.mark.asyncio
async def test_since_is_inclusive_and_cuts_off_older_events(client, seeded):
    cutoff = (T0 + timedelta(minutes=20)).isoformat()
    page = await _events(client, since=cutoff)
    assert {e["target_path"] for e in page["items"]} == {"/etc/shadow", "/var/log/app.log", "/etc/hosts"}
    assert (await _events(client, since=(T0 + timedelta(hours=5)).isoformat()))["total"] == 0


@pytest.mark.asyncio
async def test_paging(client, seeded):
    first = await _events(client, limit=2, offset=0)
    second = await _events(client, limit=2, offset=2)
    third = await _events(client, limit=2, offset=4)
    ids = [e["id"] for p in (first, second, third) for e in p["items"]]
    assert len(ids) == 5 and len(set(ids)) == 5, "pages must not overlap or skip"
    assert (first["total"], first["limit"], first["offset"]) == (5, 2, 0)
    assert len(third["items"]) == 1


@pytest.mark.asyncio
async def test_a_total_counts_the_filter_not_just_the_page(client, seeded):
    page = await _events(client, path_prefix="/etc/", limit=1)
    # passwd (2 events) + shadow + hosts = 4 rows match the filter; only 1 is on this page
    assert page["total"] == 4 and len(page["items"]) == 1


@pytest.mark.asyncio
async def test_summary_counts(client, seeded):
    s = await _summary(client)
    assert s["total_events"] == 5
    assert {a["action"]: a["count"] for a in s["by_action"]} == {"UPDATED": 2, "CREATED": 1, "DELETED": 1, "ATTRIBUTES_MODIFIED": 1}
    assert s["by_action"][0] == {"action": "UPDATED", "count": 2}, "most frequent first"
    assert s["top_paths"][0] == {"target_path": "/etc/passwd", "count": 2}
    assert s["active_nodes"] == 3, "node-a, node-b and node-c; node-z belongs to another tenant"
    assert s["tenant_id"] == "acme"


@pytest.mark.asyncio
async def test_summary_since_narrows_every_figure_including_active_nodes(client, seeded):
    s = await _summary(client, since=(T0 + timedelta(minutes=25)).isoformat())
    assert s["total_events"] == 2
    assert {a["action"] for a in s["by_action"]} == {"DELETED", "ATTRIBUTES_MODIFIED"}
    assert {p["target_path"] for p in s["top_paths"]} == {"/var/log/app.log", "/etc/hosts"}
    assert s["active_nodes"] == 2


@pytest.mark.asyncio
async def test_summary_top_paths_is_capped_at_ten(client, db_session):
    db_session.add_all([_event(path=f"/tmp/file-{i}", minutes=i) for i in range(15)])
    await db_session.commit()
    assert len((await _summary(client))["top_paths"]) == 10


@pytest.mark.asyncio
async def test_a_bad_since_is_a_422_not_a_500(client, seeded):
    r = await client.get("/api/v1/osquery/fim/events", params={"tenant_id": "acme", "since": "yesterday-ish"}, headers=AUTH)
    assert r.status_code == 422
    r = await client.get("/api/v1/osquery/fim/summary", params={"tenant_id": "acme", "since": "nope"}, headers=AUTH)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_tenant_id_is_required(client, seeded):
    assert (await client.get("/api/v1/osquery/fim/events", headers=AUTH)).status_code == 422
    assert (await client.get("/api/v1/osquery/fim/summary", headers=AUTH)).status_code == 422
