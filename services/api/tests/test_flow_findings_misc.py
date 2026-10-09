"""Defects found by running the real API against real Postgres with multi-step, two-tenant flows (see app/scripts/tenant_flows.py). Each of these crashed on every call and had no test.

 * CurrentUser had no `id`; fourteen call sites in eight modules read it, so reports, remediation, mssp, posture, insider threat, replay, sla and audit endpoints raised AttributeError (HTTP 500).
 * `:param::type` is not a bind parameter to SQLAlchemy's text(): the `::` after the name defeats its parser, so compliance evidence, knowledge-base ingest and phishing submit raised ArgumentError on every call.
 * IdentityNode.is_active was mapped String(10) while the annotation and the database column are boolean, so every node insert failed.
 * GET /assets/vulnerabilities was declared AFTER GET /assets/{asset_id}, which captured "vulnerabilities" as an id and answered 422: the endpoint was unreachable.
 * The playbooks proxy let a 2xx response with a non-JSON body escape as an unhandled JSONDecodeError.
"""
import re
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import Boolean, text
from sqlalchemy.exc import ArgumentError

from app.api.v1.deps import CurrentUser

APP = Path(__file__).resolve().parent.parent / "app"
MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"


class TestCurrentUserId:
    def user(self):
        return CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="admin", email="a@example.com")

    def test_id_is_the_user_id(self):
        u = self.user()
        assert u.id == u.user_id and isinstance(u.id, uuid.UUID)

    def test_it_is_read_only(self):
        with pytest.raises(AttributeError):
            self.user().id = uuid.uuid4()

    def test_it_follows_the_user_id(self):
        u = self.user()
        u.user_id = uuid.uuid4()
        assert u.id == u.user_id

    def test_the_sites_that_read_it_are_still_there(self):
        """If these are ever cleaned up to user_id the alias can go; until then it is what keeps them from crashing."""
        hits = [p.name for p in (APP / "api" / "v1" / "endpoints").glob("*.py") if re.search(r"\bcurrent_user\.id\b", p.read_text(encoding="utf-8", errors="replace"))]
        assert {"reports.py", "remediation.py", "mssp.py"} <= set(hits)


class TestBindParametersAndCasts:
    def test_sqlalchemy_does_not_see_a_bind_parameter_in_name_colon_colon_type(self):
        """The root cause, demonstrated: the glued form is silently not a parameter, so bindparams() on it raises."""
        with pytest.raises(ArgumentError, match="doesn't define a bound parameter named 'payload'"):
            text("SELECT :payload::jsonb").bindparams(payload="{}")

    def test_cast_is_a_parameter(self):
        assert text("SELECT CAST(:payload AS jsonb)").bindparams(payload="{}").compile().params == {"payload": "{}"}

    def test_no_source_file_glues_a_cast_to_a_named_bind_parameter(self):
        offenders = []
        for p in sorted(APP.rglob("*.py")):
            for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if re.search(r"(?<![:\w\\]):[a-z_]+::[a-z]", line) and not line.lstrip().startswith("#"):
                    offenders.append(f"{p.relative_to(APP)}:{n}: {line.strip()[:90]}")
        assert offenders == [], "use CAST(:name AS type), not :name::type, inside text():\n" + "\n".join(offenders)

    @pytest.mark.parametrize("module,needles", [
        ("knowledge_base.py", ["CAST(:tags AS text[])", "CAST(:kinds AS text[])"]),
        ("compliance.py", ["CAST(:payload AS jsonb)"]),
        ("phishing.py", ["CAST(:urls AS text[])", "CAST(:iocs AS jsonb)"]),
    ])
    def test_the_fixed_statements_use_cast(self, module, needles):
        src = (APP / "api" / "v1" / "endpoints" / module).read_text(encoding="utf-8")
        for needle in needles:
            assert needle in src, f"{module} lost {needle}"


class TestIdentityNodeIsActive:
    def test_the_orm_type_matches_the_annotation_and_the_database(self):
        from app.models.identity_graph import IdentityNode

        assert isinstance(IdentityNode.__table__.c.is_active.type, Boolean)

    def test_the_migration_creates_it_as_a_boolean(self):
        sql = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in sorted(MIGRATIONS.glob("*.sql")))
        m = re.search(r"CREATE TABLE(?: IF NOT EXISTS)? identity_nodes \((.*?)\n\)\s*;", sql, re.S | re.I)
        assert m and re.search(r"is_active\s+BOOLEAN", m.group(1), re.I)


@pytest.mark.asyncio
class TestPlaybooksProxy:
    @pytest.fixture
    def proxy(self, monkeypatch):
        from app.api.v1.endpoints import playbooks as pb

        monkeypatch.setattr(pb, "internal_service_headers", lambda: {})

        def respond(status=200, content=b"", raises=None):
            class FakeClient:
                def __init__(self, *a, **k):
                    pass

                async def __aenter__(self):
                    return self

                async def __aexit__(self, *a):
                    return False

                async def request(self, method, url, **kw):
                    if raises:
                        raise raises
                    return httpx.Response(status, content=content, request=httpx.Request(method, url))

            monkeypatch.setattr(pb.httpx, "AsyncClient", FakeClient)
            return pb._proxy

        return respond

    async def test_a_2xx_with_a_non_json_body_is_a_502_not_an_unhandled_500(self, proxy):
        with pytest.raises(HTTPException) as exc:
            await proxy(200, b"<html>gateway</html>")("POST", "")
        assert exc.value.status_code == 502 and exc.value.detail == "Agents service returned an invalid response"

    async def test_an_empty_2xx_body_is_the_same_502(self, proxy):
        with pytest.raises(HTTPException) as exc:
            await proxy(200, b"")("GET", "")
        assert exc.value.status_code == 502

    async def test_valid_json_is_returned(self, proxy):
        assert await proxy(200, b'{"ok": true}')("GET", "") == {"ok": True}

    async def test_a_204_is_none(self, proxy):
        assert await proxy(204)("DELETE", "/x") is None

    async def test_a_4xx_passes_the_upstream_explanation_through(self, proxy):
        with pytest.raises(HTTPException) as exc:
            await proxy(403, b'{"detail": "Shared library playbooks are read-only."}')("PUT", "/x")
        assert exc.value.status_code == 403 and exc.value.detail == "Shared library playbooks are read-only."

    async def test_a_4xx_with_an_unreadable_body_keeps_the_generic_detail(self, proxy):
        with pytest.raises(HTTPException) as exc:
            await proxy(404, b"not json")("GET", "/x")
        assert exc.value.status_code == 404 and exc.value.detail == "Upstream service error"

    async def test_a_5xx_stays_generic(self, proxy):
        with pytest.raises(HTTPException) as exc:
            await proxy(500, b'{"detail": "stack trace with internals"}')("GET", "/x")
        assert exc.value.status_code == 500 and exc.value.detail == "Upstream service error"

    async def test_a_connection_failure_is_a_503(self, proxy):
        with pytest.raises(HTTPException) as exc:
            await proxy(raises=httpx.ConnectError("refused"))("GET", "/x")
        assert exc.value.status_code == 503


METHODS = ("get", "post", "put", "patch", "delete")


def shadowed(paths: dict) -> list[tuple[list[str], str, str]]:
    """Paths (in registration order) that an EARLIER path with a {param} in the same position captures first, for a shared method."""
    order, found = list(paths), []
    for i, later in enumerate(order):
        lsegs = later.strip("/").split("/")
        lm = {m for m in paths[later] if m in METHODS}
        for earlier in order[:i]:
            esegs = earlier.strip("/").split("/")
            if len(esegs) != len(lsegs) or not all(a == b or (a.startswith("{") and a.endswith("}")) for a, b in zip(esegs, lsegs)):
                continue
            if not any(a.startswith("{") and not b.startswith("{") for a, b in zip(esegs, lsegs)):
                continue
            both = lm & {m for m in paths[earlier] if m in METHODS}
            if both:
                found.append((sorted(both), later, earlier))
    return found


class TestNoRouteIsShadowed:
    def test_the_detector_flags_a_literal_declared_after_a_parameter_route(self):
        spec = {"/a/{id}": {"get": {}}, "/a/vulnerabilities": {"get": {}}}
        assert shadowed(spec) == [(["get"], "/a/vulnerabilities", "/a/{id}")]

    def test_it_does_not_flag_the_correct_order(self):
        assert shadowed({"/a/vulnerabilities": {"get": {}}, "/a/{id}": {"get": {}}}) == []

    def test_it_only_flags_a_shared_method(self):
        assert shadowed({"/a/{id}": {"get": {}}, "/a/bulk": {"post": {}}}) == []

    def test_it_does_not_flag_different_lengths_or_prefixes(self):
        assert shadowed({"/a/{id}": {"get": {}}, "/a/x/y": {"get": {}}, "/b/z": {"get": {}}}) == []

    def test_the_real_api_has_no_shadowed_route(self):
        """GET /assets/vulnerabilities was unreachable for exactly this reason."""
        from app.main import app

        found = shadowed(app.openapi()["paths"])
        assert found == [], f"declare the literal path BEFORE the {{param}} path: {found}"

    def test_the_assets_vulnerabilities_route_comes_first(self):
        from app.main import app

        order = list(app.openapi()["paths"])
        assert order.index("/api/v1/assets/vulnerabilities") < order.index("/api/v1/assets/{asset_id}")


@pytest.mark.asyncio
class TestPlaybookRequestBodies:
    """create_playbook, update_playbook and run_playbook called `await request.json()` bare: an empty or malformed body was an unhandled JSONDecodeError (HTTP 500). Found by the write sweep sending POST /playbooks with no body."""

    @pytest.fixture
    def handlers(self, monkeypatch):
        from starlette.requests import Request

        from app.api.v1.endpoints import playbooks as pb

        calls = []

        async def fake_proxy(method, path, **kw):
            calls.append((method, path, kw))
            return {"proxied": True}

        monkeypatch.setattr(pb, "_proxy", fake_proxy)

        def request(body: bytes) -> Request:
            sent = {"done": False}

            async def receive():
                if sent["done"]:
                    return {"type": "http.disconnect"}
                sent["done"] = True
                return {"type": "http.request", "body": body, "more_body": False}

            return Request({"type": "http", "method": "POST", "headers": [], "path": "/"}, receive)

        user = SimpleNamespace(tenant_id=uuid.uuid4())
        return pb, calls, request, user

    CALLS = [("create_playbook", {}), ("update_playbook", {"playbook_id": "pb-1"}), ("run_playbook", {"playbook_id": "pb-1"}), ("clone_playbook", {"playbook_id": "pb-1"})]

    @pytest.mark.parametrize("name,kw", CALLS)
    async def test_a_valid_object_is_passed_through_unchanged(self, handlers, name, kw):
        pb, calls, request, user = handlers
        await getattr(pb, name)(request=request(b'{"a": 1, "b": [2]}'), user=user, **kw)
        assert calls[0][2]["json"] == {"a": 1, "b": [2]} and calls[0][2]["params"] == {"tenant_id": str(user.tenant_id)}

    @pytest.mark.parametrize("name,kw", CALLS)
    async def test_an_empty_body_is_an_empty_object_not_a_crash(self, handlers, name, kw):
        pb, calls, request, user = handlers
        await getattr(pb, name)(request=request(b""), user=user, **kw)
        assert calls[0][2]["json"] == {}

    @pytest.mark.parametrize("name,kw", CALLS)
    async def test_whitespace_only_counts_as_empty(self, handlers, name, kw):
        pb, calls, request, user = handlers
        await getattr(pb, name)(request=request(b"  \n "), user=user, **kw)
        assert calls[0][2]["json"] == {}

    @pytest.mark.parametrize("name,kw", [c for c in CALLS if c[0] != "clone_playbook"])
    async def test_malformed_json_is_a_400_and_never_reaches_the_agents_service(self, handlers, name, kw):
        pb, calls, request, user = handlers
        with pytest.raises(HTTPException) as exc:
            await getattr(pb, name)(request=request(b"{not json"), user=user, **kw)
        assert exc.value.status_code == 400 and exc.value.detail == "Request body must be valid JSON" and calls == []

    @pytest.mark.parametrize("name,kw", [c for c in CALLS if c[0] != "clone_playbook"])
    @pytest.mark.parametrize("body", [b"[1, 2]", b'"text"', b"42", b"null"])
    async def test_a_body_that_is_not_an_object_is_a_422_and_never_reaches_the_agents_service(self, handlers, name, kw, body):
        pb, calls, request, user = handlers
        with pytest.raises(HTTPException) as exc:
            await getattr(pb, name)(request=request(body), user=user, **kw)
        assert exc.value.status_code == 422 and calls == []

    @pytest.mark.parametrize("body", [b"{not json", b"[1]", b'"x"'])
    async def test_clone_keeps_its_lenient_behaviour_an_unreadable_body_is_no_body(self, handlers, body):
        pb, calls, request, user = handlers
        await pb.clone_playbook(playbook_id="pb-1", request=request(body), user=user)
        assert calls[0][2]["json"] == {}
