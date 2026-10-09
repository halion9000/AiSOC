"""The push gateway must never let a client choose WHOSE push subscription it is.

The gateway forwards the JSON body to the realtime service, and the realtime service takes the user from `body.user_id` BEFORE the verified `X-User-Id` header (its comment says "the API gateway is expected to validate it"). The gateway forwarded the body unchanged, so any signed-in user could post
`{"subscription": <their browser>, "user_id": "<someone else>"}` and receive that person's p0 alerts, agent approval requests and on-call handoffs. The identity fields now come from the verified session, whatever the client sent."""
import uuid

import pytest

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import push

TENANT, ME, VICTIM, OTHER_TENANT = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()


def me():
    return CurrentUser(user_id=ME, tenant_id=TENANT, role="viewer", email="me@example.test")


class FakeClient:
    sent: list = []

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, headers=None, json=None):
        FakeClient.sent.append({"method": method, "url": url, "headers": dict(headers or {}), "json": json})

        class R:
            status_code = 200
            content = b"{}"

            def json(self):
                return {"ok": True}

        return R()


@pytest.fixture(autouse=True)
def realtime(monkeypatch):
    FakeClient.sent = []
    monkeypatch.setattr(push.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(push.settings, "REALTIME_BASE_URL", "http://realtime:8080", raising=False)
    monkeypatch.setattr(push.settings, "REALTIME_INTERNAL_TOKEN", "internal-secret", raising=False)
    return FakeClient


SUBSCRIPTION = {"endpoint": "https://push.example.test/abc", "keys": {"p256dh": "k1", "auth": "k2"}}


@pytest.mark.asyncio
class TestIdentityComesFromTheVerifiedSession:
    async def test_subscribe_cannot_name_another_user(self, realtime):
        await push.subscribe(user=me(), body={"subscription": SUBSCRIPTION, "user_id": str(VICTIM)})
        assert realtime.sent[0]["json"]["user_id"] == str(ME)

    async def test_unsubscribe_cannot_name_another_user(self, realtime):
        await push.unsubscribe(user=me(), body={"endpoint": SUBSCRIPTION["endpoint"], "user_id": str(VICTIM)})
        assert realtime.sent[0]["json"]["user_id"] == str(ME)

    async def test_the_test_notification_cannot_target_another_user(self, realtime):
        await push.test_notify(user=me(), body={"user_id": str(VICTIM), "title": "hi"})
        assert realtime.sent[0]["json"]["user_id"] == str(ME)

    async def test_a_body_with_no_user_id_gets_the_callers(self, realtime):
        await push.subscribe(user=me(), body={"subscription": SUBSCRIPTION})
        assert realtime.sent[0]["json"]["user_id"] == str(ME)

    async def test_a_missing_test_body_still_carries_the_callers_identity(self, realtime):
        await push.test_notify(user=me(), body=None)
        assert realtime.sent[0]["json"] == {"user_id": str(ME)}

    @pytest.mark.parametrize("field", ["tenant_id", "tenantId", "userId", "user_ids", "tenant"])
    async def test_other_identity_shaped_fields_are_removed_before_forwarding(self, realtime, field):
        await push.subscribe(user=me(), body={"subscription": SUBSCRIPTION, field: str(OTHER_TENANT)})
        assert field not in realtime.sent[0]["json"]

    async def test_a_client_cannot_name_another_tenant_in_the_body(self, realtime):
        await push.subscribe(user=me(), body={"subscription": SUBSCRIPTION, "tenant_id": str(OTHER_TENANT)})
        assert str(OTHER_TENANT) not in str(realtime.sent[0]["json"])
        assert realtime.sent[0]["headers"]["X-Tenant-Id"] == str(TENANT)

    async def test_the_verified_identity_headers_are_still_sent(self, realtime):
        await push.subscribe(user=me(), body={"subscription": SUBSCRIPTION})
        h = realtime.sent[0]["headers"]
        assert h["X-Tenant-Id"] == str(TENANT) and h["X-User-Id"] == str(ME) and h["X-AiSOC-Internal-Token"] == "internal-secret"

    async def test_everything_else_in_the_body_is_forwarded_untouched(self, realtime):
        body = {"subscription": SUBSCRIPTION, "topics": ["p0_alert"], "user_agent": "UA/1.0", "user_id": str(VICTIM)}
        await push.subscribe(user=me(), body=body)
        sent = realtime.sent[0]["json"]
        assert sent["subscription"] == SUBSCRIPTION and sent["topics"] == ["p0_alert"] and sent["user_agent"] == "UA/1.0"

    async def test_the_callers_own_body_object_is_not_mutated(self, realtime):
        body = {"subscription": SUBSCRIPTION, "user_id": str(VICTIM)}
        await push.subscribe(user=me(), body=body)
        assert body["user_id"] == str(VICTIM)

    async def test_the_realtime_paths_and_methods_are_unchanged(self, realtime):
        await push.subscribe(user=me(), body={"subscription": SUBSCRIPTION})
        await push.unsubscribe(user=me(), body={"endpoint": "e"})
        await push.test_notify(user=me(), body=None)
        assert [(s["method"], s["url"]) for s in realtime.sent] == [
            ("POST", "http://realtime:8080/v1/push/subscribe"),
            ("POST", "http://realtime:8080/v1/push/unsubscribe"),
            ("POST", "http://realtime:8080/v1/push/test"),
        ]

    async def test_the_public_key_route_sends_no_identity(self, realtime):
        await push.get_public_key()
        assert realtime.sent[0]["json"] is None
        assert "X-User-Id" not in realtime.sent[0]["headers"] and "X-Tenant-Id" not in realtime.sent[0]["headers"]
