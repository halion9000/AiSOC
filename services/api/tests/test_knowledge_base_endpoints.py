"""Knowledge base: retrieval/synthesis behavior, ingest chunking, and the delete-by-title rule.

Tenant isolation of every statement is covered in test_compliance_phishing_kb_tenant_isolation.py; this file covers behavior.
NOT VERIFIED LIVE: the session is a fake (SQL not executed, full-text search not run) and the LLM call is stubbed.
"""

import asyncio
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import knowledge_base as kb
from app.core.airgap import AirgapViolation
from fastapi import HTTPException

TENANT = uuid.uuid4()
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def run(coro):
    return asyncio.run(coro)


def user():
    return SimpleNamespace(tenant_id=TENANT, label="a@example.test")


def doc_row(title="Runbook", content="x" * 300, idx=0, total=1, rank=None, **over):
    row = dict(  # noqa: C408
        id=uuid.uuid4(),
        title=title,
        doc_kind="runbook",
        source_url=None,
        tags=None,
        chunk_index=idx,
        chunk_total=total,
        content=content,
        created_at=NOW,
        created_by="a",
    )
    if rank is not None:
        row["rank"] = rank
    row.update(over)
    return SimpleNamespace(**row)


class FakeDB:
    def __init__(self, rows=(), fail=False, first=None):
        self.rows = list(rows)
        self.fail = fail
        self.first = first
        self.statements = []
        self.commits = 0
        self.rollbacks = 0

    async def execute(self, statement):
        self.statements.append(statement)
        if self.fail:
            raise RuntimeError("db down")
        rows, first = self.rows, self.first
        return SimpleNamespace(fetchall=lambda: rows, fetchone=lambda: first if first is not None else (rows[0] if rows else None))

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


def text_of(statement):
    compiled = statement.compile()
    return (str(compiled) + " " + repr(compiled.params)).replace("-", "")


def hexid(value):
    return str(value).replace("-", "")


# --- helpers ---------------------------------------------------------------------------------------------------------------------


def test_doc_response_previews_only_the_first_200_characters_and_defaults_tags():
    out = kb._row_to_doc(doc_row(content="a" * 500))
    assert out.content_preview == "a" * 200 and out.tags == []


# --- _synthesise -----------------------------------------------------------------------------------------------------------------


class FakeHTTP:
    sent = {}
    status_ok = True

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None):
        FakeHTTP.sent = {"url": url, "headers": headers, "json": json}

        def raise_for_status():
            if not FakeHTTP.status_ok:
                raise RuntimeError("500")

        return SimpleNamespace(
            raise_for_status=raise_for_status, json=lambda: {"choices": [{"message": {"content": "  The answer [Runbook]  "}}]}
        )


@pytest.fixture
def llm(monkeypatch):
    for name in ("OPENAI_API_KEY", "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    FakeHTTP.sent, FakeHTTP.status_ok = {}, True
    monkeypatch.setattr(kb.httpx, "AsyncClient", FakeHTTP)
    monkeypatch.setattr(kb, "enforce_airgap_for_url", lambda url: None)
    return monkeypatch


def chunk(title="Runbook", idx=0, content="step one"):
    return kb.KBChunk(doc_id=uuid.uuid4(), title=title, chunk_index=idx, content=content)


def test_no_api_key_means_no_answer_and_no_network_call(llm):
    assert run(kb._synthesise("how?", [chunk()])) is None
    assert FakeHTTP.sent == {}


def test_synthesis_uses_the_configured_endpoint_and_model_and_labels_each_chunk(llm):
    llm.setenv("LLM_API_KEY", "k-1")
    llm.setenv("LLM_BASE_URL", "http://llm.internal/v1")
    llm.setenv("LLM_MODEL", "my-model")
    assert run(kb._synthesise("how do I isolate a host?", [chunk("A", 0, "alpha"), chunk("B", 3, "beta")])) == "The answer [Runbook]"
    sent = FakeHTTP.sent
    assert sent["url"] == "http://llm.internal/v1/chat/completions" and sent["headers"]["Authorization"] == "Bearer k-1"
    assert sent["json"]["model"] == "my-model"
    user_msg = sent["json"]["messages"][1]["content"]
    assert "[A] chunk 0:\nalpha" in user_msg and "[B] chunk 3:\nbeta" in user_msg and "QUESTION: how do I isolate a host?" in user_msg
    assert "ONLY" in sent["json"]["messages"][0]["content"], "the model must be told to answer only from the context"


def test_openai_key_is_preferred_and_the_default_endpoint_is_openai(llm):
    llm.setenv("OPENAI_API_KEY", "o-key")
    llm.setenv("LLM_API_KEY", "other")
    run(kb._synthesise("q?", [chunk()]))
    assert FakeHTTP.sent["headers"]["Authorization"] == "Bearer o-key"
    assert FakeHTTP.sent["url"] == "https://api.openai.com/v1/chat/completions"


def test_the_airgap_check_runs_before_any_request_and_its_error_propagates(llm):
    llm.setenv("LLM_API_KEY", "k")

    def refuse(url):
        raise AirgapViolation(url)

    llm.setattr(kb, "enforce_airgap_for_url", refuse)
    with pytest.raises(AirgapViolation):
        run(kb._synthesise("q?", [chunk()]))
    assert FakeHTTP.sent == {}


def test_an_llm_failure_degrades_to_no_answer(llm):
    llm.setenv("LLM_API_KEY", "k")
    FakeHTTP.status_ok = False
    assert run(kb._synthesise("q?", [chunk()])) is None


# --- POST /query -----------------------------------------------------------------------------------------------------------------


def stub_synth(monkeypatch, answer="synth", boom=None):
    calls = []

    async def fake(question, chunks):
        calls.append((question, chunks))
        if boom:
            raise boom
        return answer

    monkeypatch.setattr(kb, "_synthesise", fake)
    return calls


def test_query_returns_ranked_chunks_deduplicated_sources_and_a_synthesised_answer(monkeypatch):
    calls = stub_synth(monkeypatch)
    db = FakeDB([doc_row("A", rank=0.9), doc_row("B", rank=0.5), doc_row("A", idx=1, rank=0.2)])
    out = run(kb.query_kb(kb.QueryRequest(question="isolate host", top_k=3), db, user()))
    assert [c.score for c in out.chunks] == [0.9, 0.5, 0.2]
    assert out.sources == ["A", "B"] and out.answer == "synth" and len(calls) == 1
    sql = text_of(db.statements[0])
    assert hexid(TENANT) in sql and "'limit': 3" in sql and "doc_kind" not in sql.split("WHERE")[1].split("ORDER")[0]


def test_query_filters_by_document_kind_when_asked(monkeypatch):
    stub_synth(monkeypatch)
    db = FakeDB([doc_row(rank=1.0)])
    run(kb.query_kb(kb.QueryRequest(question="isolate host", doc_kinds=["policy", "sop"]), db, user()))
    assert "doc_kind = ANY" in text_of(db.statements[0])


def test_query_skips_the_llm_when_not_asked_or_when_nothing_matched(monkeypatch):
    calls = stub_synth(monkeypatch)
    out = run(kb.query_kb(kb.QueryRequest(question="isolate host", synthesise=False), FakeDB([doc_row(rank=1.0)]), user()))
    assert out.answer is None and len(out.chunks) == 1
    out = run(kb.query_kb(kb.QueryRequest(question="isolate host"), FakeDB([]), user()))
    assert out.answer is None and out.chunks == [] and out.sources == [] and calls == []


def test_an_airgapped_deployment_still_gets_the_retrieved_chunks(monkeypatch):
    stub_synth(monkeypatch, boom=AirgapViolation("blocked"))
    out = run(kb.query_kb(kb.QueryRequest(question="isolate host"), FakeDB([doc_row(rank=1.0)]), user()))
    assert out.answer is None and len(out.chunks) == 1


def test_query_database_failure_is_a_generic_503(monkeypatch):
    stub_synth(monkeypatch)
    with pytest.raises(HTTPException) as exc:
        run(kb.query_kb(kb.QueryRequest(question="isolate host"), FakeDB(fail=True), user()))
    assert exc.value.status_code == 503 and exc.value.detail == "Database error"


@pytest.mark.parametrize(
    "bad",
    [{"question": "ab"}, {"question": "abc", "top_k": 0}, {"question": "abc", "top_k": 21}, {"question": "abc", "doc_kinds": ["memo"]}],
)
def test_query_request_bounds(bad):
    with pytest.raises(Exception):  # noqa: B017  pydantic.ValidationError
        kb.QueryRequest(**bad)


# --- ingest ----------------------------------------------------------------------------------------------------------------------


class InsertDB(FakeDB):
    async def execute(self, statement):
        self.statements.append(statement)
        if self.fail:
            raise RuntimeError("db down")
        params = statement.compile().params
        row = SimpleNamespace(
            **{
                **dict(  # noqa: C408
                    id=params["id"],
                    title=params["title"],
                    doc_kind=params["kind"],
                    source_url=params["url"],
                    tags=params["tags"],
                    chunk_index=params["idx"],
                    chunk_total=params["total"],
                    content=params["content"],
                    created_at=params["now"],
                    created_by=params["user"],
                )
            }
        )
        return SimpleNamespace(fetchone=lambda: row)


def test_ingest_stores_every_chunk_for_the_callers_tenant_with_index_and_total():
    body = kb.IngestRequest(
        title="Isolation runbook", content="\n\n".join(f"Paragraph {i}. " + "word " * 120 for i in range(6)), tags=["edr"]
    )
    db = InsertDB()
    out = run(kb.ingest(body, db, user()))
    assert len(out) == len(db.statements) > 1 and db.commits == 1
    assert [d.chunk_index for d in out] == list(range(len(out))) and {d.chunk_total for d in out} == {len(out)}
    assert {d.title for d in out} == {"Isolation runbook"} and out[0].tags == ["edr"]
    assert all(s.compile().params["tenant_id"] == TENANT for s in db.statements)
    assert len({d.id for d in out}) == len(out)


def test_ingest_failure_rolls_back_and_hides_the_database_error():
    with pytest.raises(HTTPException) as exc:
        run(kb.ingest(kb.IngestRequest(title="Title", content="some real content here"), InsertDB(fail=True), user()))
    assert exc.value.status_code == 503 and exc.value.detail == "Database error"


@pytest.mark.parametrize(
    "bad",
    [
        {"title": "a", "content": "long enough content"},
        {"title": "ok", "content": "short"},
        {"title": "ok", "content": "long enough content", "doc_kind": "memo"},
    ],
)
def test_ingest_request_bounds(bad):
    with pytest.raises(Exception):  # noqa: B017  pydantic.ValidationError
        kb.IngestRequest(**bad)


# --- get / list / delete ---------------------------------------------------------------------------------------------------------


def test_get_404s_for_a_missing_document():
    with pytest.raises(HTTPException) as exc:
        run(kb.get_document(uuid.uuid4(), FakeDB(), user()))
    assert exc.value.status_code == 404


def test_list_shows_only_the_first_chunk_of_each_document_newest_first():
    db = FakeDB([doc_row()])
    run(kb.list_documents(db, user()))
    sql = text_of(db.statements[0])
    assert "chunk_index = 0" in sql and "ORDER BY created_at DESC" in sql and "LIMIT 200" in sql and hexid(TENANT) in sql


def test_delete_404s_when_missing_and_deletes_nothing():
    db = FakeDB()
    with pytest.raises(HTTPException) as exc:
        run(kb.delete_document(uuid.uuid4(), db, user()))
    assert exc.value.status_code == 404 and len(db.statements) == 1 and db.commits == 0


def test_delete_removes_every_chunk_sharing_the_title_within_the_tenant():
    """Documents are tied together by TITLE, not by an id: deleting one removes every chunk with that title in the tenant, so two
    different documents that happen to share a title are deleted together. Pinned so a future document-id column changes it on purpose."""
    db = FakeDB(first=SimpleNamespace(title="Runbook"))
    assert run(kb.delete_document(uuid.uuid4(), db, user())) is None
    sql = text_of(db.statements[1])
    assert (
        "DELETE FROM aisoc_kb_documents WHERE title = :title" in sql
        and "'title': 'Runbook'" in sql
        and hexid(TENANT) in sql
        and db.commits == 1
    )
