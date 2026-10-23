"""Every request CORE records is run through its real route on a REAL Postgres, as the application role with row-level security failing closed.

The recorded bodies are the ones CORE's own code builds (`tests/fixtures/core_feed/`, copied from the CORE repository). Two things are checked for all of them at once:
  * a token that is wrong, revoked, or minted for something else is refused with 401 by EVERY core-feed route, and nothing is written;
  * with a good token, EVERY recorded body is accepted by its route against the real database (a body the model takes but the database code chokes on fails here).
Then the routes whose effect matters most are checked for what they did: clients, tickets, device names, entities, closed incidents, scripts.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app); the database must be disposable and fully migrated.
"""

import json
import os
import uuid
from pathlib import Path

import pytest
from app.core.route_introspect import walk_routes
from app.main import app
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "core_feed"
PREFIX = "/core-feed/{tenant_token}/"
SIGNED_IN_ONLY_404 = {
    "actions/{action_id}/result",
    "vcio-proposals/{proposal_id}/result",
}  # they answer one claimed row; with none, 404 is the right answer


def recorded() -> dict[str, dict]:
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(FIXTURES.glob("*.json")) if p.stem != "generic-json"}


def routes() -> dict[str, object]:
    return {path.split(PREFIX)[1]: r for path, r in walk_routes(app.routes) if PREFIX in path and "POST" in r.methods}


ROUTES = routes()


def body_for(route, suffix):
    """The recorded body of a route, built into the route's own model (None for a route with no body)."""
    field = route.body_field
    if field is None:
        return None
    sample = next(r for r in recorded().values() if r["route"] == suffix)
    return field.field_info.annotation.model_validate(sample["body"])


@pytest.fixture
async def world(monkeypatch):
    tag = uuid.uuid4().hex[:10]
    w = {k: uuid.uuid4() for k in ("parent", "acme", "birch")}
    w["tag"] = tag
    w["good"] = f"aitnb_all_{tag}"
    w["bad"] = {"wrong": f"aitnb_nope_{tag}", "revoked": f"aitnb_rev_{tag}", "label": f"aitnb_lab_{tag}", "template": f"aitnb_tpl_{tag}"}
    owner = create_async_engine(PG_URL, poolclass=NullPool)
    app_engine = create_async_engine(APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}})
    ids = [w["parent"], w["acme"], w["birch"]]
    try:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            for key in ("parent", "acme", "birch"):
                parent = w["parent"] if key != "parent" else None
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                    {"i": w[key], "n": f"ar-{key}-{tag}", "s": f"ar-{key}-{tag}", "p": parent, "r": "child" if parent else "parent"},
                )
            for token, template, label, revoked in (
                (w["good"], "generic-json", "core-feed", False),
                (w["bad"]["revoked"], "generic-json", "core-feed", True),
                (w["bad"]["label"], "generic-json", "someone-elses", False),
                (w["bad"]["template"], "pagerduty", "core-feed", False),
            ):
                await conn.execute(
                    text(
                        f"insert into tenant_inbox_tokens (token, tenant_id, template_id, label, revoked_at) values (:k, :t, :tpl, :l, {'now()' if revoked else 'null'})"
                    ),
                    {"k": token, "t": w["parent"], "tpl": template, "l": label},
                )
            for uid in ("huntress:4821", "huntress:4822", "blumira:abc-006"):
                await conn.execute(
                    text(
                        "insert into alerts (id, tenant_id, title, severity, status, affected_hosts, raw_event, dedup_hash, created_at, event_time, first_seen, last_seen) "
                        "values (gen_random_uuid(), :t, 'Seeded', 'high', 'new', cast('[]' as jsonb), cast(:raw as jsonb), :d, now(), now(), now(), now())"
                    ),
                    {"t": w["acme"], "raw": json.dumps({"finding": {"uid": uid}}), "d": f"d-{tag}-{uid}"},
                )
        w["owner"], w["factory"] = owner, async_sessionmaker(app_engine, expire_on_commit=False)
        yield w
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            t = [str(x) for x in ids]
            for table in (
                "vendor_actions",
                "client_m365_checks",
                "client_vcio_reviews",
                "identity_secure_scores",
                "identity_mfa_users",
                "identity_events",
                "signin_events",
                "devices",
                "client_aliases",
                "connectors",
                "alerts",
                "tenant_inbox_tokens",
            ):
                if (await conn.execute(text("select to_regclass(:n)"), {"n": f"public.{table}"})).scalar_one() is not None:
                    await conn.execute(text(f"delete from {table} where tenant_id = any(cast(:t as uuid[]))"), {"t": t})
            await conn.execute(text("delete from tenants where id = any(cast(:t as uuid[])) and parent_tenant_id is not null"), {"t": t})
            await conn.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": t})
        await app_engine.dispose()
        await owner.dispose()


async def call(w, suffix, token, route=None):
    route = route or ROUTES[suffix]
    kwargs = {"tenant_token": token}
    if route.body_field is not None:
        kwargs["body"] = body_for(route, suffix)
    if "{action_id}" in suffix:
        kwargs["action_id"] = uuid.uuid4()
    if "{proposal_id}" in suffix:
        kwargs["proposal_id"] = uuid.uuid4()
    async with w["factory"]() as s:
        return await route.endpoint(db=s, **kwargs)


async def rows_written(w):
    async with w["owner"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        t = [str(w[k]) for k in ("parent", "acme", "birch")]
        out = {}
        for table in (
            "vendor_actions",
            "client_aliases",
            "devices",
            "client_m365_checks",
            "connectors",
            "identity_mfa_users",
            "signin_events",
            "identity_secure_scores",
        ):
            out[table] = (
                await conn.execute(text(f"select count(*) from {table} where tenant_id = any(cast(:t as uuid[]))"), {"t": t})
            ).scalar_one()
        return out


def test_every_core_feed_route_has_a_recording_to_run():
    assert len(ROUTES) >= 20
    have = {r["route"] for r in recorded().values()}
    assert set(ROUTES) <= have, f"routes with no recorded CORE request: {sorted(set(ROUTES) - have)}"


@pytest.mark.parametrize("kind", ["wrong", "revoked", "label", "template"])
async def test_every_core_feed_route_refuses_a_token_that_is_wrong_revoked_or_for_something_else_and_writes_nothing(world, kind):
    before = await rows_written(world)
    for suffix in ROUTES:
        with pytest.raises(HTTPException) as e:
            await call(world, suffix, world["bad"][kind])
        assert e.value.status_code == 401, suffix
    assert await rows_written(world) == before


@pytest.mark.parametrize("suffix", sorted(ROUTES))
async def test_every_recorded_core_request_is_accepted_by_its_route_on_a_real_database(world, suffix):
    try:
        out = await call(world, suffix, world["good"])
    except HTTPException as e:
        assert e.status_code == 404 and suffix in SIGNED_IN_ONLY_404, f"{suffix} answered {e.status_code}: {e.detail}"
        return
    assert out is not None


async def test_clients_are_added_once_and_a_client_someone_ignored_is_not_added_back(world):
    first = await call(world, "clients", world["good"])
    assert first.new == 2
    assert (await call(world, "clients", world["good"])).new == 0
    async with world["owner"].begin() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await conn.execute(
            text("update client_aliases set ignored = true where tenant_id = :t and vendor_client_id = '7'"), {"t": world["parent"]}
        )
    again = await call(world, "clients", world["good"])
    assert again.new == 0
    async with world["owner"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        assert (
            await conn.execute(
                text("select ignored from client_aliases where tenant_id = :t and vendor_client_id = '7'"), {"t": world["parent"]}
            )
        ).scalar_one() is True


async def alert_row(w, uid):
    async with w["owner"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        return (
            await conn.execute(
                text(
                    "select affected_hosts, enrichment_data, raw_event, status from alerts where tenant_id = :t and raw_event->'finding'->>'uid' = :u"
                ),
                {"t": w["acme"], "u": uid},
            )
        ).one()


async def test_tickets_names_and_entities_land_on_the_alert_that_holds_the_incident_and_only_there(world):
    assert (await call(world, "tickets", world["good"])).updated == 1
    ticket_alert = await alert_row(world, "huntress:4821")
    assert ticket_alert.enrichment_data["tickets"][0]["id"] == "553688"
    assert (await alert_row(world, "huntress:4822")).enrichment_data in (None, {}), "another incident is untouched"

    assert (await call(world, "device-names", world["good"])).updated == 1  # blumira:abc-006
    assert (await alert_row(world, "blumira:abc-006")).affected_hosts == ["SRV-FS01"]

    # entities: the first incident gets its host, user, address, link and links; another incident is untouched
    assert (await call(world, "entities", world["good"])).updated >= 5
    entity_alert = await alert_row(world, "huntress:4821")
    assert entity_alert.affected_hosts == ["PC-01"]
    assert entity_alert.raw_event["url"] == "https://acme.huntress.io/incidents/4821"
    assert entity_alert.raw_event["links"]["device_url"] == "https://acme.huntress.io/agents/9"
    assert (await alert_row(world, "huntress:4822")).affected_hosts == ["PC-02"]
    assert (await call(world, "entities", world["good"])).updated == 0, "a second report fills nothing already filled"


async def test_scripts_are_stored_on_the_owner_tenant(world):
    out = await call(world, "scripts", world["good"])
    assert out.stored == 2
    async with world["owner"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        settings = (await conn.execute(text("select settings from tenants where id = :t"), {"t": world["parent"]})).scalar_one()
    assert [s["name"] for s in settings["core_scripts"]] == ["Disk Space Scan", "Restart Spooler"]


async def test_a_closed_incident_resolves_only_the_new_alert_that_holds_it(world):
    out = await call(world, "closed", world["good"])
    assert out.resolved >= 1
    assert (await alert_row(world, "huntress:4821")).status in ("resolved", "closed")
    assert (await alert_row(world, "blumira:abc-006")).status == "new"


async def test_the_sync_buttons_are_handed_over_once(world):
    await call(world, "status", world["good"])  # makes the huntress connector row
    async with world["owner"].begin() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await conn.execute(
            text(
                "update connectors set connector_config = connector_config || cast(:c as jsonb) where tenant_id = :t and connector_config->>'vendor' = 'huntress'"
            ),
            {
                "c": json.dumps({"sync_requested_at": __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat()}),
                "t": world["parent"],
            },
        )
    first = await call(world, "sync-requests/claim", world["good"])
    assert first.vendors == ["huntress"]
    assert (await call(world, "sync-requests/claim", world["good"])).vendors == []
