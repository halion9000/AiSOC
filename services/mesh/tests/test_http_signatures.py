"""The mesh's write routes accept only what the instance itself signed, opt-out included.

POST /v1/opt-out took only a public key and no signature, while every other write verified an Ed25519 signature. A public key is
not a secret (it accompanies every published sighting), so anyone could remove any instance from the mesh, after which its
sightings were rejected. It now needs a signature over crypto.opt_out_message(pubkey) by that instance's own key.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app import main as main_module
from app.crypto import generate_instance_key, ioc_hash, normalize_ioc, opt_out_message, sign
from app.hub import MeshHub
from fastapi.testclient import TestClient

NOW = datetime.now(UTC).isoformat()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main_module, "_hub", MeshHub())
    return TestClient(main_module.app, raise_server_exceptions=False)


def _publish(client, pub, priv, value="198.51.100.7"):
    h = ioc_hash("ip", normalize_ioc("ip", value))
    sighting = {"ioc_hash": h, "ioc_type": "ip", "severity": "high", "first_seen": NOW, "last_seen": NOW}
    from app.artifacts import IocSighting

    signature = sign(priv, IocSighting(**sighting).signing_bytes())
    return client.post("/v1/sightings", json={"instance_pubkey": pub, "signature": signature, "sighting": sighting})


def _opt_out(client, pub, signature):
    return client.post("/v1/opt-out", json={"instance_pubkey": pub, "signature": signature})


def test_an_instance_can_opt_itself_out_and_is_then_rejected(client):
    priv, pub = generate_instance_key()
    assert _publish(client, pub, priv).status_code == 200
    assert _opt_out(client, pub, sign(priv, opt_out_message(pub))).json() == {"opted_out": True}
    assert _publish(client, pub, priv).status_code == 403, "an opted-out instance must be rejected"


def test_nobody_else_can_opt_an_instance_out(client):
    """The attack: learn an instance's public key from anything it published, then remove it from the mesh."""
    victim_priv, victim_pub = generate_instance_key()
    attacker_priv, _ = generate_instance_key()
    assert _opt_out(client, victim_pub, sign(attacker_priv, opt_out_message(victim_pub))).status_code == 403
    assert _opt_out(client, victim_pub, sign(attacker_priv, b"anything")).status_code == 403
    assert _opt_out(client, victim_pub, "A" * 88).status_code == 403
    assert _opt_out(client, victim_pub, "x" * 8).status_code == 403
    assert _publish(client, victim_pub, victim_priv).status_code == 200, "the victim was removed from the mesh by a forged opt-out"


def test_a_signature_meant_for_something_else_is_not_an_opt_out(client):
    """The instance's own signature over a sighting (public once published) must not double as an opt-out."""
    priv, pub = generate_instance_key()
    from app.artifacts import IocSighting

    sighting = IocSighting(ioc_hash="a" * 64, ioc_type="ip", severity="high", first_seen=NOW, last_seen=NOW)
    assert _opt_out(client, pub, sign(priv, sighting.signing_bytes())).status_code == 403
    assert _opt_out(client, pub, sign(priv, b"aisoc-mesh-opt-out:v1:" + b"someone-else")).status_code == 403
    assert _publish(client, pub, priv).status_code == 200


def test_the_signature_is_required(client):
    _, pub = generate_instance_key()
    assert client.post("/v1/opt-out", json={"instance_pubkey": pub}).status_code == 422
    assert client.post("/v1/opt-out", json={"instance_pubkey": pub, "signature": ""}).status_code == 422


def test_the_message_is_bound_to_the_key_so_it_cannot_be_replayed_for_another(client):
    priv_a, pub_a = generate_instance_key()
    _, pub_b = generate_instance_key()
    assert _opt_out(client, pub_b, sign(priv_a, opt_out_message(pub_a))).status_code == 403
    assert opt_out_message(pub_a) != opt_out_message(pub_b)


def test_publishing_still_rejects_a_forged_signature_over_http(client):
    """Characterises the other writes (previously untested over HTTP): a signature by the wrong key is a 403."""
    priv, pub = generate_instance_key()
    other_priv, _ = generate_instance_key()
    h = ioc_hash("ip", normalize_ioc("ip", "203.0.113.5"))
    sighting = {"ioc_hash": h, "ioc_type": "ip", "severity": "high", "first_seen": NOW, "last_seen": NOW}
    from app.artifacts import IocSighting

    forged = sign(other_priv, IocSighting(**sighting).signing_bytes())
    assert client.post("/v1/sightings", json={"instance_pubkey": pub, "signature": forged, "sighting": sighting}).status_code == 403
