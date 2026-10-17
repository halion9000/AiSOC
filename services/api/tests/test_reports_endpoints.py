"""Report template / artefact / weekly-digest endpoints: tenant scoping, pending-on-generate, digest period and format handling.

NOT VERIFIED LIVE: the session is a fake (SQL is compiled, never executed) and the digest builder/renderers are stubbed.
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import reports as rp
from app.models.report import ReportArtefact, ReportTemplate
from fastapi import HTTPException
from pydantic import ValidationError

TENANT = uuid.uuid4()
OTHER = uuid.uuid4()
NOW = datetime(2026, 10, 1, tzinfo=UTC)


def run(coro):
    return asyncio.run(coro)


def user(tenant=TENANT):
    return SimpleNamespace(id=uuid.uuid4(), tenant_id=tenant)


def sql(statement) -> str:
    return str(statement.compile(compile_kwargs={"literal_binds": True})).replace("-", "")


class FakeDB:
    def __init__(self, got=None, rows=()):
        self.got = got
        self.rows = list(rows)
        self.added = []
        self.deleted = []
        self.executed = []
        self.commits = 0

    async def get(self, model, key):
        return self.got

    async def execute(self, statement):
        self.executed.append(statement)
        rows = self.rows
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))

    def add(self, obj):
        self.added.append(obj)

    async def delete(self, obj):
        self.deleted.append(obj)

    async def commit(self):
        self.commits += 1

    async def refresh(self, obj):
        return None


def template(tenant=TENANT):
    return ReportTemplate(id=uuid.uuid4(), tenant_id=tenant, name="Weekly", report_type="board_summary")


def artefact(tenant=TENANT):
    return ReportArtefact(id=uuid.uuid4(), tenant_id=tenant, report_type="board_summary", title="T")


def test_template_create_takes_its_tenant_from_the_caller_not_the_body():
    body = rp.TemplateCreate(name="Weekly", report_type="board_summary", recipients=["a@b.c"])
    assert "tenant_id" not in rp.TemplateCreate.model_fields
    db = FakeDB()
    caller = user()
    created = run(rp.create_template(body, db, caller))
    assert db.added == [created] and db.commits == 1
    assert created.tenant_id == TENANT
    assert created.created_by == caller.id
    assert created.recipients == ["a@b.c"]
    assert created.output_format == "pdf" and created.timezone == "UTC"


def test_template_create_requires_name_and_type():
    with pytest.raises(ValidationError):
        rp.TemplateCreate(name="x")  # type: ignore[call-arg]


def test_list_templates_is_scoped_to_the_callers_tenant():
    db = FakeDB(rows=[template()])
    out = run(rp.list_templates(db, user()))
    assert len(out) == 1
    text = sql(db.executed[0])
    assert str(TENANT).replace("-", "") in text
    assert str(OTHER).replace("-", "") not in text


def test_get_template_hides_another_tenants_template_as_404():
    with pytest.raises(HTTPException) as exc:
        run(rp.get_template(uuid.uuid4(), FakeDB(got=template(OTHER)), user()))
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException) as missing:
        run(rp.get_template(uuid.uuid4(), FakeDB(got=None), user()))
    assert missing.value.status_code == 404
    mine = template()
    assert run(rp.get_template(mine.id, FakeDB(got=mine), user())) is mine


def test_delete_template_deletes_only_the_callers_own():
    foreign = FakeDB(got=template(OTHER))
    with pytest.raises(HTTPException) as exc:
        run(rp.delete_template(uuid.uuid4(), foreign, user()))
    assert exc.value.status_code == 404
    assert foreign.deleted == [] and foreign.commits == 0
    mine = template()
    ok = FakeDB(got=mine)
    assert run(rp.delete_template(mine.id, ok, user())) is None
    assert ok.deleted == [mine] and ok.commits == 1


def test_list_artefacts_filters_by_tenant_type_status_and_pages():
    db = FakeDB(rows=[artefact()])
    run(rp.list_artefacts(report_type="board_summary", status_filter="done", limit=5, offset=10, db=db, current_user=user()))
    text = sql(db.executed[0])
    assert str(TENANT).replace("-", "") in text
    assert "board_summary" in text and "'done'" in text
    assert "LIMIT 5" in text and "OFFSET 10" in text
    assert "created_at DESC" in text


def test_list_artefacts_without_filters_adds_none():
    db = FakeDB()
    run(rp.list_artefacts(report_type=None, status_filter=None, limit=20, offset=0, db=db, current_user=user()))
    text = sql(db.executed[0])
    assert "report_type =" not in text and ".status =" not in text


def test_get_artefact_hides_another_tenants_as_404():
    with pytest.raises(HTTPException) as exc:
        run(rp.get_artefact(uuid.uuid4(), FakeDB(got=artefact(OTHER)), user()))
    assert exc.value.status_code == 404
    mine = artefact()
    assert run(rp.get_artefact(mine.id, FakeDB(got=mine), user())) is mine


def test_generate_queues_a_pending_artefact_owned_by_the_caller():
    caller = user()
    body = rp.GenerateRequest(title="Q3", period_start=NOW - timedelta(days=7), period_end=NOW, recipients=["ciso@example.test"])
    db = FakeDB()
    made = run(rp.generate_report(body, db, caller))
    assert db.added == [made] and db.commits == 1
    assert made.status == "pending"
    assert made.tenant_id == TENANT
    assert made.generated_by == str(caller.id)
    assert made.delivered_to == ["ciso@example.test"]
    assert (made.report_type, made.output_format) == ("board_summary", "pdf")


def test_generate_requires_a_period():
    with pytest.raises(ValidationError):
        rp.GenerateRequest(title="x")  # type: ignore[call-arg]


@pytest.fixture
def digest(monkeypatch):
    seen = {}
    fake = SimpleNamespace(period=SimpleNamespace(start=NOW))

    async def build(db, tenant_id, period_start=None, period_end=None):
        seen.update(tenant=tenant_id, start=period_start, end=period_end)
        return fake

    monkeypatch.setattr(rp, "build_weekly_digest", build)
    monkeypatch.setattr(rp, "render_digest_html", lambda d: "<html>digest</html>")
    seen["digest"] = fake
    return seen


def digest_call(fmt="json", start=None, end=None, caller=None):
    return run(rp.weekly_digest(fmt=fmt, period_start=start, period_end=end, db=FakeDB(), current_user=caller or user()))


def test_digest_json_is_the_built_digest_for_the_callers_tenant(digest):
    assert digest_call() is digest["digest"]
    assert digest["tenant"] == TENANT


def test_digest_rejects_an_empty_or_inverted_period_before_building(digest):
    for start, end in ((NOW, NOW), (NOW, NOW - timedelta(days=1))):
        with pytest.raises(HTTPException) as exc:
            digest_call(start=start, end=end)
        assert exc.value.status_code == 400
    assert "tenant" not in digest


def test_digest_with_only_one_bound_is_not_a_period_error(digest):
    assert digest_call(start=NOW) is digest["digest"]
    assert digest_call(end=NOW) is digest["digest"]


def test_digest_html_is_returned_as_html(digest):
    resp = digest_call("html")
    assert resp.media_type == "text/html"
    assert resp.body == b"<html>digest</html>"


def test_digest_pdf_is_an_attachment_named_for_the_period_start(monkeypatch, digest):
    monkeypatch.setattr(rp, "render_digest_pdf", lambda d: b"%PDF-1")
    resp = digest_call("pdf")
    assert resp.media_type == "application/pdf"
    assert resp.body == b"%PDF-1"
    assert resp.headers["content-disposition"] == 'attachment; filename="aisoc-digest-2026-10-01.pdf"'


def test_digest_pdf_is_503_when_weasyprint_is_missing(monkeypatch, digest):
    def boom(d):
        raise rp.WeasyPrintUnavailableError("no cairo")

    monkeypatch.setattr(rp, "render_digest_pdf", boom)
    with pytest.raises(HTTPException) as exc:
        digest_call("pdf")
    assert exc.value.status_code == 503
    assert "no cairo" in exc.value.detail


def test_digest_format_is_limited_to_json_html_pdf():
    param = next(p for p in __import__("inspect").signature(rp.weekly_digest).parameters.values() if p.name == "fmt")
    assert "json|html|pdf" in repr(param.default.metadata)
