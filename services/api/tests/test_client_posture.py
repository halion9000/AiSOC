"""The device part of one client's posture (pure)."""

import uuid

from app.api.v1.endpoints import client_posture as ep


def test_devices_part_picks_the_clients_row_and_is_zero_for_a_client_without_devices():
    a, b = uuid.uuid4(), uuid.uuid4()
    rows = [ep.ClientRollup(client_id=a, client_name="A", devices=4, needs_attention=2, stale_agents=1, not_in_huntress=3, offline=1)]
    assert ep.devices_part(rows, a).model_dump() == {
        "devices": 4,
        "needs_attention": 2,
        "stale_agents": 1,
        "not_in_huntress": 3,
        "offline": 1,
    }
    assert ep.devices_part(rows, b).devices == 0


def test_posture_carries_the_tools_the_client_is_mapped_to():
    import uuid
    from datetime import UTC, datetime

    from app.api.v1.endpoints.client_posture import ClientPosture, PostureAlerts, PostureDevices, PostureTool

    base = {"client_id": uuid.uuid4(), "client_name": "Acme", "generated_at": datetime.now(UTC), "devices": PostureDevices(), "identity": None, "alerts": PostureAlerts(open=0, critical=0, high=0, without_ticket=0), "open_cases": 0}
    assert ClientPosture(**base).tools == []
    p = ClientPosture(**base, tools=[PostureTool(vendor="ninjaone", vendor_client_id="83", vendor_client_name="Acme")])
    assert (p.tools[0].vendor, p.tools[0].vendor_client_id) == ("ninjaone", "83")


# ---- the whole endpoint, with a client that has Datto SaaS (a 500 once: the SaaS read overwrote the alert counts) ------------------------------------------


def test_the_posture_of_a_client_in_datto_saas_still_reports_its_alert_counts_and_the_tools(monkeypatch):
    import asyncio
    import contextlib
    import uuid as _uuid
    from types import SimpleNamespace

    from app.api.v1.endpoints import client_posture as cp

    owner = _uuid.uuid4()

    async def scope(db, o, cid):
        return [owner], {}

    async def load(*a, **k):
        return []

    monkeypatch.setattr(cp, "_scope", scope)
    monkeypatch.setattr(cp, "_load_cached", load)
    monkeypatch.setattr(cp, "_master_of", lambda t: None)
    monkeypatch.setattr(cp, "acting_as_tenant", lambda db, tid: contextlib.nullcontext())

    class DB:
        async def get(self, model, key):
            return None

        async def execute(self, statement, params=None):
            text = str(statement)
            if "identity_mfa_users" in text:
                return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))
            if "client_aliases" in text:
                return SimpleNamespace(all=lambda: [("datto-saas", "494057", "Acme"), ("huntress", "5", "Acme")])
            if "client_m365_checks" in text:
                row = SimpleNamespace(checks=[{"key": "saas_backup_google", "status": "met", "evidence": "e"}])
                return SimpleNamespace(scalars=lambda: SimpleNamespace(first=lambda: row))
            if "FROM cases" in text:
                return SimpleNamespace(scalar_one=lambda: 4)
            return SimpleNamespace(one=lambda: (3, 1, 2, 5))

    out = asyncio.run(cp.client_posture(owner, SimpleNamespace(tenant_id=owner, user_id=_uuid.uuid4()), DB()))
    assert (out.alerts.open, out.alerts.critical, out.alerts.high, out.alerts.without_ticket) == (3, 1, 2, 5)
    assert out.open_cases == 4
    assert [(t.vendor, t.product) for t in out.tools] == [("datto-saas", "google"), ("huntress", None)]
