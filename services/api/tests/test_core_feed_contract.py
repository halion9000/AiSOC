"""What CORE really sends is accepted by the route's real request model.

CORE records the body each of its calls builds, with its own code, in `docs/contracts/core-feed/*.json` (CORE repository); `node scripts/sync-contracts.mjs` copies them to
`tests/fixtures/core_feed/` here. This test takes every file and checks it against the pydantic model of the route it is for, so a field CORE sends that the route refuses (the way
CORE's own vendor name was refused by the claim route) fails here instead of in a person's running system.

It also checks the two directories of routes agree: every file is for a route the API has, and every route the API has for CORE either has a file or is on the short list of
routes CORE does not call, with the reason.
"""

import json
import re
from pathlib import Path

import pytest
from app.api.v1.endpoints import client_review as cr
from app.api.v1.endpoints import devices as dev
from app.api.v1.endpoints import identities as idn
from app.api.v1.endpoints import identity as ident
from app.api.v1.endpoints import inbox_core_feed as feed
from app.api.v1.endpoints import signins as sig
from app.api.v1.endpoints import vcio_proposals as vp

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "core_feed"
ENDPOINTS = Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "endpoints"

# fixture name -> the request model of its route (None: the request has no body)
MODELS = {
    "clients": feed.ClientsReport,
    "closed": feed.ClosedReport,
    "device-names": feed.DevicesReport,
    "entities": feed.EntitiesReport,
    "scripts": feed.ScriptsReport,
    "status": feed.StatusReport,
    "sync-requests-claim": None,
    "devices": dev.DevicesReport,
    "tickets": feed.TicketsReport,
    "state": feed.StateReport,
    "actions-claim-huntress": feed.ClaimRequest,
    "actions-claim-blumira": feed.ClaimRequest,
    "actions-claim-fieldeffect": feed.ClaimRequest,
    "actions-claim-core": feed.ClaimRequest,
    "actions-result": feed.ActionResult,
    "signins": sig.SignInsReport,
    "directory-audits": ident.DirectoryAuditsReport,
    "mfa-users": ident.MfaUsersReport,
    "secure-scores": ident.SecureScoreReport,
    "vcio-reviews": cr.VcioReviewReport,
    "vcio-proposals-approved": None,
    "vcio-proposals-result": vp.ProposalResult,
    "m365-checks": cr.M365ChecksReport,
    "identities": idn.IdentitiesReport,
}

# Not a core-feed route: the alert push goes to the ingest service (`POST /v1/inbox/{token}`, the generic-json template). It is checked against the real template by
# `services/ingest/internal/inbox/core_feed_contract_test.go`; here only its shape is checked.
PUSH = "generic-json"

# core-feed routes the API has that CORE does not call (and why)
NOT_CALLED_BY_CORE: dict[str, str] = {}


def api_routes() -> set[str]:
    found: set[str] = set()
    for f in ENDPOINTS.glob("*.py"):
        found |= set(re.findall(r'@(?:ingest_)?router\.post\(\s*"(/core-feed/[^"]+)"', f.read_text(encoding="utf-8")))
    return found


def fixtures() -> dict[str, dict]:
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(FIXTURES.glob("*.json"))}


def path_of(route: str) -> str:
    return f"/core-feed/{{tenant_token}}/{route}"


def test_fixtures_were_found():
    assert len(fixtures()) >= 7, "run `node scripts/sync-contracts.mjs` in the CORE repository"


@pytest.mark.parametrize("name", sorted(fixtures()))
def test_what_core_sends_is_accepted_by_the_routes_request_model(name):
    recorded = fixtures()[name]
    if name == PUSH:
        assert isinstance(recorded["body"], list) and recorded["body"], "the push is a non-empty list of records"
        for record in recorded["body"]:
            assert {"source", "severity", "timestamp", "message", "finding"} <= set(
                record
            ), f"a pushed record lacks a field the template needs: {sorted(record)}"
            assert {"uid", "title"} <= set(record["finding"])
            assert (
                record["alert_id"] == record["finding"]["uid"] == record["id"]
            ), "the incident id is repeated at the top, where the template reads it"
        return
    assert name in MODELS, f"{name}: no request model is listed for this recorded request (add it to MODELS)"
    assert recorded["method"] == "POST"
    model = MODELS[name]
    if model is None:
        assert recorded["body"] is None, f"{name} has no request body on the route, but CORE sends one"
        return
    model.model_validate(recorded["body"])


@pytest.mark.parametrize("name", sorted(fixtures()))
def test_every_recorded_request_is_for_a_route_the_api_has(name):
    if name == PUSH:
        pytest.skip("the alert push is an ingest-service route; its Go test checks it")
    assert path_of(fixtures()[name]["route"]) in api_routes(), f"{name}: the API has no route {path_of(fixtures()[name]['route'])}"


def test_every_route_for_core_has_a_recorded_request_or_a_reason():
    covered = {path_of(f["route"]) for n, f in fixtures().items() if n != PUSH}
    missing = sorted(r for r in api_routes() if r not in covered and r not in NOT_CALLED_BY_CORE)
    assert not missing, f"core-feed routes with no recorded CORE request and no reason: {missing}"


def test_every_listed_model_has_its_recorded_request():
    assert sorted(set(MODELS) - set(fixtures())) == [], "a model is listed for a request CORE has not recorded"
    assert PUSH in fixtures()
