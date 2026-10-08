"""A newly provisioned customer workspace starts EMPTY: demo data is something an operator asks for, never the default.

Promoting a waitlist entry in the admin UI sent `seed_demo: true`, the API's request model also defaulted to True, and so did the provisioner: a real customer's brand-new tenant was loaded with the demo
dataset (roughly 3,000 lines of invented incidents) and their first login showed fabricated alerts and cases. All three defaults are now off; an operator can still opt in explicitly.
"""
import inspect
import uuid
from typing import Any

from test_tenant_provision import _MockSession, _run, _waitlist_row  # the existing module's in-memory session helpers

from app.api.v1.endpoints import tenant_provision as endpoint
from app.models.tenant import Tenant
from app.services.tenant_provision import provision_from_waitlist


def _provision(**extra: Any):
    session = _MockSession()
    entry = _waitlist_row()
    session.waitlist[entry.id] = entry
    called: list[Tenant] = []

    async def seeder(_db: Any, tenant: Tenant) -> None:
        called.append(tenant)

    result = _run(provision_from_waitlist(session, waitlist_entry_id=entry.id, actor_email="ops@example.com", demo_seeder=seeder, **extra))  # type: ignore[arg-type]
    return result, called


def test_the_request_model_does_not_ask_for_demo_data_by_default():
    assert endpoint.TenantProvisionRequest(waitlist_entry_id=uuid.uuid4()).seed_demo is False


def test_the_provisioner_does_not_seed_unless_asked():
    assert inspect.signature(provision_from_waitlist).parameters["seed_demo"].default is False
    result, called = _provision()
    assert called == [], "demo data was loaded into a new tenant nobody asked it for"
    assert result.demo_seeded is False


def test_an_operator_can_still_opt_in_explicitly():
    result, called = _provision(seed_demo=True)
    assert result.demo_seeded is True
    assert len(called) == 1


def test_an_explicit_false_is_still_respected():
    result, called = _provision(seed_demo=False)
    assert called == [] and result.demo_seeded is False


def test_the_endpoint_hands_the_request_value_to_the_provisioner():
    # the request model's default flows straight through (no separate hard-coded True in the endpoint)
    source = inspect.getsource(endpoint)
    assert "seed_demo=payload.seed_demo" in source
    assert "seed_demo=True" not in source
