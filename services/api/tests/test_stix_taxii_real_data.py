"""The STIX/TAXII endpoints serve only what a tenant itself published, never invented indicators, and never another tenant's.

/threatintel/stix/indicators, /bundles and /taxii/collections used to return module-level lists SEEDED with invented threat intelligence: five indicators ("Malicious IP - C2 Server ...
associated with APT-42", a phishing domain, an exfiltration URL, a BEC sender, and a "LockBit 3.0 ransomware" hash at confidence 95 that is in fact the SHA-256 of an EMPTY FILE, so
anyone who loaded the feed into a blocklist would block every zero-byte file), one bundle of three of them, and three TAXII collections that had no endpoints behind them. The same
lists were shared by every tenant, and the publish routes appended to them, so one tenant's published indicators were visible to all the others.

Now each tenant has its own (initially empty) store, and the collections list is empty because none is served. The store is in memory (lost on restart): that limitation is real and
is documented in the module, not hidden by sample data.
"""
import asyncio
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import stix_taxii as stix

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


def user():
    return SimpleNamespace(tenant_id=uuid.uuid4())


@pytest.fixture(autouse=True)
def clean_stores():
    stix._INDICATORS.clear()
    stix._BUNDLES.clear()
    yield
    stix._INDICATORS.clear()
    stix._BUNDLES.clear()


def list_indicators(u, label=None):
    return asyncio.run(stix.list_indicators(page=1, page_size=25, label=label, current_user=u))


def publish_indicator(u, name="Real indicator", pattern="[ipv4-addr:value = '203.0.113.9']", labels=None):
    body = stix.STIXIndicatorCreate(name=name, pattern=pattern, labels=labels or [])
    return asyncio.run(stix.create_indicator(body=body, push_to_misp=False, current_user=u))


def publish_bundle(u, objects=None):
    body = stix.STIXBundleCreate(objects=objects if objects is not None else [{"type": "indicator", "id": "indicator--x"}])
    return asyncio.run(stix.create_bundle(body=body, push_to_misp=False, current_user=u))


def test_a_new_tenant_has_no_indicators_bundles_or_collections():
    u = user()
    indicators = list_indicators(u)
    bundles = asyncio.run(stix.list_bundles(current_user=u))
    collections = asyncio.run(stix.list_taxii_collections())
    assert indicators.items == [] and indicators.total == 0
    assert bundles.items == [] and bundles.total == 0
    assert collections.items == [] and collections.total == 0
    shown = indicators.model_dump_json() + bundles.model_dump_json() + collections.model_dump_json()
    for value in INVENTED:
        assert value not in shown, f"invented threat intelligence is back: {value}"


def test_the_seeded_demo_data_no_longer_exists_in_the_module():
    for name in ("DEMO_INDICATORS", "DEMO_BUNDLES", "DEMO_TAXII_COLLECTIONS"):
        assert not hasattr(stix, name)


def test_a_tenant_sees_what_it_published_and_only_that():
    u = user()
    created = publish_indicator(u, name="Real C2 address", pattern="[ipv4-addr:value = '203.0.113.9']")
    listed = list_indicators(u)
    assert listed.total == 1
    assert listed.items[0].id == created.id
    assert listed.items[0].name == "Real C2 address"
    assert listed.items[0].pattern == "[ipv4-addr:value = '203.0.113.9']"


def test_one_tenants_indicators_are_invisible_to_another():
    a, b = user(), user()
    publish_indicator(a, name="Tenant A's private indicator")
    assert list_indicators(a).total == 1
    assert list_indicators(b).items == [], "another tenant can see this tenant's indicators"
    publish_indicator(b, name="Tenant B's indicator")
    assert [i.name for i in list_indicators(a).items] == ["Tenant A's private indicator"]
    assert [i.name for i in list_indicators(b).items] == ["Tenant B's indicator"]


def test_one_tenants_bundles_are_invisible_to_another():
    a, b = user(), user()
    created = publish_bundle(a)
    assert [x.id for x in asyncio.run(stix.list_bundles(current_user=a)).items] == [created.id]
    assert asyncio.run(stix.list_bundles(current_user=b)).items == []


def test_the_label_filter_applies_to_the_tenants_own_indicators():
    u = user()
    publish_indicator(u, name="Phish", labels=["phishing"])
    publish_indicator(u, name="C2", labels=["c2"])
    assert [i.name for i in list_indicators(u, label="phishing").items] == ["Phish"]
    assert list_indicators(u, label="nothing-has-this").items == []
    assert list_indicators(u).total == 2


def test_an_empty_bundle_is_still_refused():
    with pytest.raises(HTTPException) as err:
        publish_bundle(user(), objects=[])
    assert err.value.status_code == 400
