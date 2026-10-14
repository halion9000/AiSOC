"""Add a client and map vendor clients to tenants: what is created, linked, refused, and who may do it."""

import uuid
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import inbox_core_feed as cf
from app.api.v1.endpoints import mssp_clients as mc
from app.models.client_alias import ClientAlias
from app.models.tenant import Tenant
from app.services import client_mapping as cm
from fastapi import HTTPException

PARENT = uuid.uuid4()
USER = NS(tenant_id=PARENT, user_id=uuid.uuid4())


class _Result:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self.rows)

    def scalar_one_or_none(self):
        return self.rows[0] if self.rows else None

    def scalar_one(self):
        return self.rows[0]


def _db(*results, get=None):
    """A session whose successive execute() calls return the given row lists; ``get`` maps tenant id -> Tenant for db.get."""
    db = MagicMock()
    queue = list(results)
    db.added = []
    db.execute = AsyncMock(side_effect=lambda *a, **k: _Result(queue.pop(0)))
    db.add = lambda o: db.added.append(o)
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.get = AsyncMock(side_effect=lambda model, key: (get or {}).get(key))
    return db


def _tenant(name, parent=PARENT):
    return Tenant(id=uuid.uuid4(), name=name, slug=name.lower(), parent_tenant_id=parent)


def _alias(name, child=None, ignored=False):
    return ClientAlias(
        id=uuid.uuid4(), tenant_id=PARENT, vendor="petra", vendor_client_id=name, vendor_client_name=name,
        normalized_name=name.lower(), child_tenant_id=child, ignored=ignored, match_source="suggested",
    )  # fmt: skip


# ---- slugs -----------------------------------------------------------------------------------------------------------------------------------------------


def test_two_clients_with_the_same_name_get_different_slugs():
    a, b = cm.make_slug("Acme Dental, LLC"), cm.make_slug("Acme Dental, LLC")
    assert a != b
    assert a.startswith("acme-dental-llc-")
    assert cm.make_slug("!!!").startswith("client-")


# ---- what CORE sends -------------------------------------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_new_client_that_exactly_matches_one_tenant_is_linked_and_anything_less_waits():
    acme = _tenant("Acme Dental")
    db = _db([acme], [])  # candidates, existing aliases
    created, linked = await cm.upsert_clients(
        db, PARENT, "petra", [cm.IncomingClient("1", "ACME DENTAL, LLC"), cm.IncomingClient("2", "Totally Different Co")]
    )
    assert (created, linked) == (2, 1)
    by_id = {a.vendor_client_id: a for a in db.added}
    assert by_id["1"].child_tenant_id == acme.id
    assert by_id["2"].child_tenant_id is None


@pytest.mark.asyncio
async def test_two_tenants_with_the_same_name_are_not_guessed_between():
    db = _db([_tenant("Acme Dental"), _tenant("Acme Dental LLC")], [])
    _, linked = await cm.upsert_clients(db, PARENT, "petra", [cm.IncomingClient("1", "Acme Dental")])
    assert linked == 0


@pytest.mark.asyncio
async def test_a_known_client_keeps_what_a_person_decided_and_only_its_name_is_refreshed():
    chosen = uuid.uuid4()
    known = _alias("Old Name", child=chosen, ignored=False)
    known.vendor_client_id = "7"
    known.match_source = "manual"
    db = _db([_tenant("Elsewhere")], [known])
    created, _ = await cm.upsert_clients(db, PARENT, "petra", [cm.IncomingClient("7", "New Name")])
    assert created == 0 and db.added == []
    assert known.vendor_client_name == "New Name"
    assert known.child_tenant_id == chosen and known.match_source == "manual"


@pytest.mark.asyncio
async def test_the_clients_route_stores_them_under_the_token_tenant(monkeypatch):
    monkeypatch.setattr(cf, "_verify_core_feed_token", AsyncMock(return_value=PARENT))
    monkeypatch.setattr(cf, "adopt_tenant", AsyncMock())
    db = _db([], [])
    out = await cf.report_core_feed_clients("tok", cf.ClientsReport(vendor="petra", clients=[cf.ClientItem(id="1", name=" Zed ")]), db)
    assert (out.new, out.linked) == (1, 0)
    assert db.added[0].tenant_id == PARENT and db.added[0].vendor_client_name == "Zed"
    db.commit.assert_awaited()


# ---- add a client ----------------------------------------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_client_creates_a_child_of_the_callers_tenant(monkeypatch):
    monkeypatch.setattr(mc, "emit_audit", AsyncMock())
    parent = Tenant(id=PARENT, name="Live Oak", slug="live-oak", mssp_role=None)
    db = _db([0], get={PARENT: parent})
    out = await mc.create_client(mc.NewClient(name="  Acme Dental  "), MagicMock(), USER, db)
    child = db.added[0]
    assert out.name == "Acme Dental" and child.parent_tenant_id == PARENT and child.mssp_role == "child"
    assert parent.mssp_role == "parent"


@pytest.mark.asyncio
async def test_add_client_refuses_a_duplicate_name_and_a_blank_one():
    with pytest.raises(HTTPException) as dup:
        await mc.create_client(mc.NewClient(name="Acme"), MagicMock(), USER, _db([1]))
    assert dup.value.status_code == 409
    with pytest.raises(HTTPException) as blank:
        await mc.create_client(mc.NewClient(name="   "), MagicMock(), USER, _db())
    assert blank.value.status_code == 422


# ---- mapping ---------------------------------------------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mapping_to_an_existing_client_is_manual_and_sticks(monkeypatch):
    monkeypatch.setattr(mc, "emit_audit", AsyncMock())
    child, alias = _tenant("Acme"), _alias("ACME Inc")
    db = _db([alias], get={child.id: child})
    out = await mc.map_client(alias.id, mc.MapRequest(child_tenant_id=child.id), MagicMock(), USER, db)
    assert alias.child_tenant_id == child.id and alias.match_source == "manual" and out.child_tenant_name == "Acme"


@pytest.mark.asyncio
async def test_mapping_cannot_use_someone_elses_tenant(monkeypatch):
    monkeypatch.setattr(mc, "emit_audit", AsyncMock())
    stranger, alias = _tenant("Other MSP's client", parent=uuid.uuid4()), _alias("X")
    db = _db([alias], get={stranger.id: stranger})
    with pytest.raises(HTTPException) as e:
        await mc.map_client(alias.id, mc.MapRequest(child_tenant_id=stranger.id), MagicMock(), USER, db)
    assert e.value.status_code == 404 and alias.child_tenant_id is None


@pytest.mark.asyncio
async def test_map_with_a_new_name_creates_the_tenant_and_links_it(monkeypatch):
    monkeypatch.setattr(mc, "emit_audit", AsyncMock())
    alias = _alias("Brand New Client")
    db = _db([alias], [0], get={PARENT: Tenant(id=PARENT, name="P", slug="p")})
    out = await mc.map_client(alias.id, mc.MapRequest(new_tenant_name="Brand New Client"), MagicMock(), USER, db)
    assert (
        db.added[0].name == "Brand New Client" and alias.child_tenant_id == db.added[0].id and out.child_tenant_name == "Brand New Client"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [mc.MapRequest(), mc.MapRequest(child_tenant_id=uuid.uuid4(), new_tenant_name="Both")])
async def test_map_needs_exactly_one_of_existing_or_new(body):
    with pytest.raises(HTTPException) as e:
        await mc.map_client(uuid.uuid4(), body, MagicMock(), USER, _db())
    assert e.value.status_code == 422


@pytest.mark.asyncio
async def test_ignoring_clears_the_link_and_unignoring_keeps_it_clear():
    alias = _alias("Not mine", child=uuid.uuid4())
    await mc.ignore_client(alias.id, mc.IgnoreRequest(ignored=True), USER, _db([alias]))
    assert alias.ignored is True and alias.child_tenant_id is None
    await mc.ignore_client(alias.id, mc.IgnoreRequest(ignored=False), USER, _db([alias]))
    assert alias.ignored is False and alias.child_tenant_id is None


@pytest.mark.asyncio
async def test_unmap_returns_the_client_to_the_unmapped_list():
    alias = _alias("A", child=uuid.uuid4())
    await mc.unmap_client(alias.id, USER, _db([alias]))
    assert alias.child_tenant_id is None


@pytest.mark.asyncio
async def test_an_alias_of_another_tenant_is_404():
    with pytest.raises(HTTPException) as e:
        await mc.unmap_client(uuid.uuid4(), USER, _db([]))
    assert e.value.status_code == 404


@pytest.mark.asyncio
async def test_listing_shows_suggestions_only_for_unmapped_clients_and_counts_them():
    acme = _tenant("Acme Dental")
    mapped, open_one, ignored = _alias("Done", child=acme.id), _alias("Acme Dental Group"), _alias("Skip", ignored=True)
    out = await mc.list_clients(USER, _db([mapped, open_one, ignored], [acme], [acme]))
    by_name = {c.vendor_client_name: c for c in out.clients}
    assert out.unmapped == 1
    assert by_name["Done"].child_tenant_name == "Acme Dental" and by_name["Done"].suggestions == []
    assert [s.name for s in by_name["Acme Dental Group"].suggestions] == ["Acme Dental"]
    assert by_name["Skip"].suggestions == []


@pytest.mark.asyncio
async def test_hiding_a_client_marks_it_hidden_and_stops_suggesting_it():
    test_client = _tenant("Hal Test")
    cm.set_tenant_hidden(test_client, True)
    assert cm.tenant_hidden(test_client)
    mapped, open_one = _alias("Hal Test", child=test_client.id), _alias("Hal Test Two")
    out = await mc.list_clients(USER, _db([mapped, open_one], [test_client], [test_client]))
    by_name = {c.vendor_client_name: c for c in out.clients}
    assert by_name["Hal Test"].child_tenant_hidden is True and by_name["Hal Test"].child_tenant_name == "Hal Test"
    assert by_name["Hal Test Two"].suggestions == []  # a hidden test client is never offered as a match


@pytest.mark.asyncio
async def test_showing_a_hidden_client_clears_the_flag_and_keeps_other_settings():
    t = _tenant("Hal Test")
    t.settings = {"keep": 1}
    cm.set_tenant_hidden(t, True)
    db = _db([t])
    await mc.set_client_hidden(t.id, mc.HiddenRequest(hidden=False), MagicMock(), USER, db)
    assert not cm.tenant_hidden(t) and t.settings == {"keep": 1}
    db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_hiding_a_tenant_that_is_not_yours_is_404():
    with pytest.raises(HTTPException) as e:
        await mc.set_client_hidden(uuid.uuid4(), mc.HiddenRequest(hidden=True), MagicMock(), USER, _db([]))
    assert e.value.status_code == 404


# ---- who may -----------------------------------------------------------------------------------------------------------------------------------------------


def test_reading_needs_mssp_read_and_every_change_needs_mssp_manage():
    from fastapi.routing import APIRoute
    from route_introspect import required_permissions

    routes = {(m, r.path): r for r in mc.router.routes if isinstance(r, APIRoute) for m in r.methods}
    assert set(required_permissions(routes[("GET", "/mssp/clients")])) == {"mssp:read"}
    for method, path in [
        ("POST", "/mssp/clients/new"),
        ("POST", "/mssp/clients/{alias_id}/map"),
        ("POST", "/mssp/clients/{alias_id}/unmap"),
        ("POST", "/mssp/clients/{alias_id}/ignore"),
        ("PUT", "/mssp/tenants/{tenant_id}/hidden"),
    ]:
        assert set(required_permissions(routes[(method, path)])) == {"mssp:manage"}, path


# ---- import everything from one tool -------------------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_creates_tenants_links_name_matches_and_reuses_a_tenant_made_a_moment_ago():
    existing = _tenant("Acme Dental")
    a, b, c = _alias("ACME DENTAL, LLC"), _alias("Birch Law"), _alias("Birch Law Inc")  # the last two are one customer
    made = []

    async def make(name):
        t = _tenant(name)
        made.append(t)
        return t

    db = _db([existing], [a, b, c])  # candidates, pending aliases
    for alias, key in ((a, "acme dental"), (b, "birch law"), (c, "birch law")):
        alias.normalized_name = key
    created, linked = await cm.import_unmapped(db, PARENT, "petra", make)
    assert (created, linked) == (1, 2)
    assert [t.name for t in made] == ["Birch Law"]
    assert a.child_tenant_id == existing.id and b.child_tenant_id == made[0].id and c.child_tenant_id == made[0].id
    assert all(x.match_source == "manual" for x in (a, b, c))


@pytest.mark.asyncio
async def test_import_leaves_a_client_alone_when_two_tenants_share_its_name():
    a = _alias("Acme")
    a.normalized_name = "acme"
    made = []

    async def make(name):
        made.append(name)
        return _tenant(name)

    created, linked = await cm.import_unmapped(_db([_tenant("Acme"), _tenant("ACME")], [a]), PARENT, "petra", make)
    assert (created, linked) == (0, 0) and made == [] and a.child_tenant_id is None


@pytest.mark.asyncio
async def test_the_import_route_reports_the_counts_and_audits(monkeypatch):
    audit = AsyncMock()
    monkeypatch.setattr(mc, "emit_audit", audit)
    a = _alias("New Co")
    a.normalized_name = "new co"
    db = _db([], [a], [0], get={PARENT: Tenant(id=PARENT, name="P", slug="p")})
    out = await mc.import_clients(mc.ImportRequest(vendor="petra"), MagicMock(), USER, db)
    assert (out.created, out.linked) == (1, 0)
    assert audit.await_args.kwargs["action"] == "mssp:clients_imported"
    with pytest.raises(ValueError):
        mc.ImportRequest(vendor="Petra!")


def test_importing_needs_mssp_manage():
    from fastapi.routing import APIRoute
    from route_introspect import required_permissions

    routes = {(m, r.path): r for r in mc.router.routes if isinstance(r, APIRoute) for m in r.methods}
    assert set(required_permissions(routes[("POST", "/mssp/clients/import")])) == {"mssp:manage"}


# ---- choosing which tools add clients automatically ---------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_chosen_tools_are_remembered_on_the_parent_tenant_and_read_back_sorted():
    parent = Tenant(id=PARENT, name="P", slug="p", settings={"other": 1})
    db = _db(get={PARENT: parent})
    assert await cm.set_sync_vendors(db, PARENT, ["petra", "halopsa", "petra"]) == ["halopsa", "petra"]
    assert parent.settings == {"other": 1, "client_sync_vendors": ["halopsa", "petra"]}  # nothing else in the settings is lost
    assert await cm.sync_vendors(db, PARENT) == ["halopsa", "petra"]
    assert (
        await cm.sync_vendors(_db(get={PARENT: Tenant(id=PARENT, name="P", slug="p", settings={"client_sync_vendors": "junk"})}), PARENT)
        == []
    )
    assert await cm.sync_vendors(_db(), PARENT) == []


def _sync_db(parent, candidates=()):
    """A session that answers the three queries a sync makes: the tenants, the known aliases, and (after the aliases were added) the pending ones."""
    db = _db(get={PARENT: parent})

    async def execute(stmt, *a, **k):
        sql = str(stmt)
        if "FROM tenants" in sql:
            return _Result(list(candidates))
        if "child_tenant_id IS NULL" in sql:
            return _Result([x for x in db.added if isinstance(x, ClientAlias) and x.child_tenant_id is None])
        return _Result([])

    db.execute = AsyncMock(side_effect=execute)
    return db


@pytest.mark.asyncio
async def test_a_new_client_from_a_chosen_tool_becomes_a_tenant_and_one_from_another_tool_waits():
    parent = Tenant(id=PARENT, name="P", slug="p", settings={"client_sync_vendors": ["halopsa"]})
    db = _sync_db(parent)
    await cm.upsert_clients(db, PARENT, "halopsa", [cm.IncomingClient("1", "Acme Dental")])
    tenants = [o for o in db.added if isinstance(o, Tenant)]
    assert [t.name for t in tenants] == ["Acme Dental"] and tenants[0].parent_tenant_id == PARENT
    assert next(o for o in db.added if isinstance(o, ClientAlias)).child_tenant_id == tenants[0].id

    other = _sync_db(parent)
    await cm.upsert_clients(other, PARENT, "petra", [cm.IncomingClient("9", "Acme Dental")])
    assert [o for o in other.added if isinstance(o, Tenant)] == []
    assert next(o for o in other.added if isinstance(o, ClientAlias)).child_tenant_id is None


@pytest.mark.asyncio
async def test_choosing_a_tool_imports_what_is_already_waiting_but_a_tool_already_chosen_is_not_redone(monkeypatch):
    parent = Tenant(id=PARENT, name="P", slug="p", settings={"client_sync_vendors": ["halopsa"]})
    waiting = _alias("Waiting Co")
    waiting.normalized_name = "waiting co"
    db = _db([waiting], get={PARENT: parent})
    imported = []

    async def fake_import(db_, parent_id, vendor, make):
        imported.append(vendor)
        return 1, 0

    monkeypatch.setattr(mc, "import_unmapped", fake_import)
    out = await mc.set_client_sources(mc.SourcesRequest(vendors=["halopsa", "petra"]), USER, db)
    assert imported == ["petra"] and out.sync_vendors == ["halopsa", "petra"] and out.created == 1


def test_choosing_sources_needs_mssp_manage_and_a_bad_tool_name_is_refused():
    from fastapi.routing import APIRoute
    from route_introspect import required_permissions

    routes = {(m, r.path): r for r in mc.router.routes if isinstance(r, APIRoute) for m in r.methods}
    assert set(required_permissions(routes[("PUT", "/mssp/clients/sources")])) == {"mssp:manage"}
    with pytest.raises(ValueError):
        mc.SourcesRequest(vendors=["Petra!"])
