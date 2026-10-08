"""The STIX/TAXII endpoints serve only what a tenant published, never invented indicators, never another tenant's, and what was published survives a restart.

/threatintel/stix/indicators, /bundles and /taxii/collections used to return module-level lists SEEDED with invented threat intelligence: five indicators ("Malicious IP - C2 Server ... associated with APT-42", a phishing domain,
an exfiltration URL, a BEC sender, and a "LockBit 3.0 ransomware" hash at confidence 95 that is in fact the SHA-256 of an EMPTY FILE, so anyone who loaded the feed into a blocklist would block every zero-byte file), one bundle of
three of them, and three TAXII collections that had no endpoints behind them. The same lists were shared by every tenant, and the publish routes appended to them, so one tenant's published indicators were visible to all the others.

Then they were per-tenant but still in process memory, so every API restart silently discarded published threat intelligence. Each published object is now stored as the JSON document that was published (table stix_objects,
migrations/053_stix_objects.sql). These tests run against a real file-backed SQLite database; every call gets its own session on a brand-new engine, so "published, then read back" is genuinely "published, then the process restarted".
"""
import asyncio
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1.endpoints import stix_taxii as stix
from app.db.database import Base
from app.models.stix_object import StixObject
from app.models.tenant import Tenant

INVENTED = [
    "198.51.100.47",
    "APT-42",
    "secure-login.example-phish.com",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # the SHA-256 of an empty file, labelled as LockBit
    "LockBit",
    "drop.evil-cdn.example",
    "cfo-urgent@spoofed-corp.example",
    "AiSOC Threat Feed",
    "Community IOCs",
]


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "stix.db"
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine, tables=[Tenant.__table__, StixObject.__table__])
    engine.dispose()
    return path


def run(db_path, fn):
    """Run `fn(session)` in its own session on a BRAND-NEW engine: each call is a separate request, and a new engine is a restarted process."""

    async def main():
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", poolclass=NullPool)
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                return await fn(session)
        finally:
            await engine.dispose()

    return asyncio.run(main())


def user():
    return SimpleNamespace(tenant_id=uuid.uuid4())


def list_indicators(db_path, u, label=None):
    return run(db_path, lambda s: stix.list_indicators(page=1, page_size=25, label=label, current_user=u, db=s))


def list_bundles(db_path, u):
    return run(db_path, lambda s: stix.list_bundles(current_user=u, db=s))


def publish_indicator(db_path, u, name="Real indicator", pattern="[ipv4-addr:value = '203.0.113.9']", **extra):
    body = stix.STIXIndicatorCreate(name=name, pattern=pattern, **extra)
    return run(db_path, lambda s: stix.create_indicator(body=body, push_to_misp=False, current_user=u, db=s))


def publish_bundle(db_path, u, objects=None):
    body = stix.STIXBundleCreate(objects=objects if objects is not None else [{"type": "indicator", "id": "indicator--x"}])
    return run(db_path, lambda s: stix.create_bundle(body=body, push_to_misp=False, current_user=u, db=s))


def stored_rows(db_path):
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with Session(engine) as s:
            return list(s.scalars(select(StixObject).order_by(StixObject.created_at)).all())
    finally:
        engine.dispose()


def test_a_new_tenant_has_no_indicators_bundles_or_collections(db_path):
    u = user()
    indicators = list_indicators(db_path, u)
    bundles = list_bundles(db_path, u)
    collections = asyncio.run(stix.list_taxii_collections())
    assert indicators.items == [] and indicators.total == 0
    assert bundles.items == [] and bundles.total == 0
    assert collections.items == [] and collections.total == 0
    shown = indicators.model_dump_json() + bundles.model_dump_json() + collections.model_dump_json()
    for value in INVENTED:
        assert value not in shown, f"invented threat intelligence is back: {value}"


def test_the_seeded_demo_data_and_the_in_memory_stores_no_longer_exist():
    for name in ("DEMO_INDICATORS", "DEMO_BUNDLES", "DEMO_TAXII_COLLECTIONS", "_INDICATORS", "_BUNDLES"):
        assert not hasattr(stix, name)


def test_a_tenant_sees_what_it_published_and_only_that(db_path):
    u = user()
    created = publish_indicator(db_path, u, name="Real C2 address")
    listed = list_indicators(db_path, u)
    assert listed.total == 1
    assert listed.items[0].id == created.id
    assert listed.items[0].name == "Real C2 address"
    assert listed.items[0].pattern == "[ipv4-addr:value = '203.0.113.9']"


def test_what_was_published_survives_a_restart(db_path):
    """The defect: published indicators and bundles lived in process memory and were lost on every API restart."""
    u = user()
    indicator = publish_indicator(db_path, u, name="Survives")
    bundle = publish_bundle(db_path, u)
    # every call above and below used its own brand-new engine: this is "the API was restarted in between"
    assert [i.id for i in list_indicators(db_path, u).items] == [indicator.id]
    assert [b.id for b in list_bundles(db_path, u).items] == [bundle.id]
    assert len(stored_rows(db_path)) == 2


def test_every_published_field_round_trips(db_path):
    u = user()
    created = publish_indicator(
        db_path, u, name="Full", description="A real description", indicator_types=["malicious-activity"], pattern_type="stix",
        valid_from="2026-10-01T00:00:00+00:00", valid_until="2026-12-31T00:00:00+00:00", confidence=77, labels=["c2", "apt"],
    )
    (back,) = list_indicators(db_path, u).items
    assert back.model_dump() == created.model_dump(exclude={"misp"})


def test_indicators_come_back_in_publish_order(db_path):
    u = user()
    names = ["first", "second", "third"]
    for n in names:
        publish_indicator(db_path, u, name=n)
    assert [i.name for i in list_indicators(db_path, u).items] == names


def test_the_rows_are_filed_under_the_publishing_tenant_with_the_right_kind(db_path):
    a = user()
    indicator = publish_indicator(db_path, a)
    bundle = publish_bundle(db_path, a)
    rows = {r.stix_id: r for r in stored_rows(db_path)}
    assert rows[indicator.id].kind == "indicator" and rows[indicator.id].tenant_id == a.tenant_id
    assert rows[bundle.id].kind == "bundle" and rows[bundle.id].tenant_id == a.tenant_id


def test_one_tenants_indicators_are_invisible_to_another(db_path):
    a, b = user(), user()
    publish_indicator(db_path, a, name="Tenant A's private indicator")
    assert list_indicators(db_path, a).total == 1
    assert list_indicators(db_path, b).items == [], "another tenant can see this tenant's indicators"
    publish_indicator(db_path, b, name="Tenant B's indicator")
    assert [i.name for i in list_indicators(db_path, a).items] == ["Tenant A's private indicator"]
    assert [i.name for i in list_indicators(db_path, b).items] == ["Tenant B's indicator"]


def test_one_tenants_bundles_are_invisible_to_another(db_path):
    a, b = user(), user()
    created = publish_bundle(db_path, a)
    assert [x.id for x in list_bundles(db_path, a).items] == [created.id]
    assert list_bundles(db_path, b).items == []


def test_indicators_and_bundles_are_not_mixed_up(db_path):
    u = user()
    publish_indicator(db_path, u)
    assert list_bundles(db_path, u).items == []
    publish_bundle(db_path, u)
    assert list_indicators(db_path, u).total == 1


def test_the_label_filter_applies_to_the_tenants_own_indicators(db_path):
    u = user()
    publish_indicator(db_path, u, name="Phish", labels=["phishing"])
    publish_indicator(db_path, u, name="C2", labels=["c2"])
    assert [i.name for i in list_indicators(db_path, u, label="phishing").items] == ["Phish"]
    assert list_indicators(db_path, u, label="nothing-has-this").items == []
    assert list_indicators(db_path, u).total == 2


def test_an_empty_bundle_is_still_refused_and_stores_nothing(db_path):
    with pytest.raises(HTTPException) as err:
        publish_bundle(db_path, user(), objects=[])
    assert err.value.status_code == 400
    assert stored_rows(db_path) == []


def test_the_same_stix_id_cannot_be_stored_twice_for_one_tenant(db_path):
    u = user()
    indicator = publish_indicator(db_path, u)

    async def duplicate(s):
        await stix._store(s, u, "indicator", indicator.id, {"id": indicator.id})

    with pytest.raises(IntegrityError):
        run(db_path, duplicate)
    assert len(stored_rows(db_path)) == 1
