"""A forwarded alert goes to the client tenant its vendor client is mapped to, and to nobody else's."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.core.config import settings
from app.models.alert import FusionDecision
from app.services.alert_sink import PersistOutcome, PersistResult
from app.services.client_routing import client_key, route_to_client_tenant
from app.workers.consumer import _METRICS, FusionWorker

PARENT = uuid.UUID("00000000-0000-0000-0000-000000000001")
CHILD = uuid.UUID("00000000-0000-0000-0000-0000000000c1")


def _event(vendor: str, **context) -> dict:
    return {
        "class_uid": 2001,
        "category_uid": 2,
        "severity_id": 4,
        "message": "Something happened",
        "source": vendor,
        "finding": {"uid": f"{vendor}:1", "title": "t", "description": "d"},
        "unmapped": {"context": context},
        "metadata": {"uid": "e1", "product": {"name": "Generic JSON", "vendor_name": "Generic"}},
    }


# ---- which client a record names ---------------------------------------------------------------------------------------------------------------------------


def test_each_vendor_names_its_client_in_its_own_field():
    assert client_key(_event("huntress", organization_id=7)) == ("huntress", "7")
    assert client_key(_event("petra", petra_tenant_id="p-1")) == ("petra", "p-1")
    assert client_key(_event("ninjaone", organization_id="12")) == ("ninjaone", "12")
    assert client_key(_event("threatmate", threatmate_client_id="2")) == ("threatmate", "2")
    assert client_key(_event("addigy", addigy_client_id="pol-1")) == ("addigy", "pol-1")
    assert client_key(_event("blumira", blumira_account_id="b28773fc-8152-4169-9d21-b750f40a69e9")) == (
        "blumira",
        "b28773fc-8152-4169-9d21-b750f40a69e9",
    )
    assert client_key(_event("fieldeffect", fieldeffect_org_id="09a136cc-13f7-410e-9017-55fe3750c7b6")) == (
        "fieldeffect",
        "09a136cc-13f7-410e-9017-55fe3750c7b6",
    )


@pytest.mark.parametrize(
    "event",
    [
        _event("huntress"),
        _event("huntress", organization_id=None),
        _event("huntress", organization_id=""),
        _event("huntress", organization_id=True),
        _event("petra", organization_id=7),  # Petra's id is petra_tenant_id, not this
        _event("blumira", org_name="Acme"),  # no id to map on
        {"source": "huntress"},
        {"source": 5, "unmapped": "x"},
        None,
    ],
)
def test_a_record_that_names_no_client_has_no_key(event):
    assert client_key(event) is None


# ---- routing ----------------------------------------------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_mapped_client_routes_to_its_tenant_and_the_lookup_is_scoped_to_the_feed_owner():
    resolve = AsyncMock(return_value=CHILD)
    assert await route_to_client_tenant(PARENT, _event("huntress", organization_id=7), resolve) == CHILD
    resolve.assert_awaited_once_with(PARENT, "huntress", "7")


@pytest.mark.asyncio
async def test_unmapped_or_unnamed_stays_with_the_owner_and_a_failed_lookup_loses_nothing():
    assert await route_to_client_tenant(PARENT, _event("huntress", organization_id=7), AsyncMock(return_value=None)) == PARENT
    never = AsyncMock()
    assert await route_to_client_tenant(PARENT, _event("huntress"), never) == PARENT
    never.assert_not_awaited()
    assert (
        await route_to_client_tenant(PARENT, _event("huntress", organization_id=7), AsyncMock(side_effect=RuntimeError("db down")))
        == PARENT
    )


# ---- through the worker ---------------------------------------------------------------------------------------------------------------------------------


def _worker(child):
    engine = SimpleNamespace(
        process=AsyncMock(
            return_value=SimpleNamespace(id="f1", fusion_decision=FusionDecision.NEW_ALERT, model_dump=lambda mode="json": {"id": "f1"})
        )
    )
    sink = SimpleNamespace(
        child_tenant_for_client=AsyncMock(return_value=child), persist=AsyncMock(return_value=PersistResult(PersistOutcome.INSERTED, "r1"))
    )
    worker = FusionWorker(engine=engine, sink=sink)
    worker._producer = AsyncMock()  # noqa: SLF001
    return worker, engine, sink


def _message(event: dict) -> dict:
    return {"tenant_id": str(PARENT), "ocsf_event": {**event, "tenant_uid": str(PARENT)}}


@pytest.mark.asyncio
async def test_the_worker_stores_a_mapped_clients_alert_under_the_client_tenant():
    worker, engine, sink = _worker(CHILD)
    before = _METRICS["routed_to_client"]
    await worker._process_message(_message(_event("huntress", organization_id=7)), topic=settings.kafka_topic_raw_events)  # noqa: SLF001
    assert engine.process.await_args.args[0].tenant_id == CHILD
    sink.child_tenant_for_client.assert_awaited_once_with(PARENT, "huntress", "7")
    assert _METRICS["routed_to_client"] == before + 1


@pytest.mark.asyncio
async def test_the_worker_keeps_an_unmapped_clients_alert_with_the_feed_owner():
    worker, engine, _ = _worker(None)
    await worker._process_message(_message(_event("huntress", organization_id=7)), topic=settings.kafka_topic_raw_events)  # noqa: SLF001
    assert engine.process.await_args.args[0].tenant_id == PARENT
