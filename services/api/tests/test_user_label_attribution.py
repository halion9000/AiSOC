"""Who did it, recorded as who it really was.

Three endpoints stored `str(user)`, the Python repr of the CurrentUser object ("<app.api.v1.deps.CurrentUser object at 0x...>"), where a person's identity belonged: the knowledge-base author, the phishing submitter and the compliance evidence REVIEWER. Beyond the meaningless value (and an in-process memory address in API output), the compliance review took the reviewer from the REQUEST BODY first,
so a caller could attribute their approval of audit evidence to anyone they named (shown on real Postgres: a review naming ceo@victim-company.example was stored as reviewed by them). The identity now comes from the authenticated user, always.
"""
import ast
import re
import uuid
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import compliance, knowledge_base, phishing

APP = Path(__file__).resolve().parent.parent / "app"
TENANT = uuid.uuid4()


def user(email="analyst@example.test"):
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="admin", email=email)


class RecordingDB:
    """Records every statement's bound parameters, then fails the statement: the endpoint turns that into a 503, but the parameters it tried to store are what is under test."""

    def __init__(self):
        self.params: list[dict] = []
        self.execute = AsyncMock(side_effect=self._execute)
        self.commit, self.rollback, self.flush = AsyncMock(), AsyncMock(), AsyncMock()

    async def _execute(self, stmt, params=None, *a, **k):
        try:
            bound = dict(stmt.compile().params)
        except Exception:  # noqa: BLE001
            bound = {}
        self.params.append({**bound, **(params or {})})
        raise RuntimeError("stop after recording")


class TestTheLabel:
    def test_it_is_the_email(self):
        assert user("a@example.test").label == "a@example.test"

    def test_it_falls_back_to_the_user_id_when_there_is_no_email(self):
        u = CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="admin", email="")
        assert u.label == str(u.user_id)

    def test_str_is_the_label_never_the_object_repr(self):
        u = user("a@example.test")
        assert str(u) == "a@example.test" and f"{u}" == "a@example.test"
        assert "object at 0x" not in str(u) and "CurrentUser" not in str(u)


@pytest.mark.asyncio
class TestTheEndpoints:
    async def test_the_compliance_reviewer_is_the_authenticated_user_not_whoever_the_body_names(self):
        db, u = RecordingDB(), user("real.reviewer@example.test")
        body = compliance.ReviewEvidenceRequest(decision="accepted", reviewer="ceo@victim-company.example")
        with pytest.raises(HTTPException):
            await compliance.review_evidence(evidence_id=uuid.uuid4(), body=body, db=db, user=u)
        assert db.params[0]["reviewer"] == "real.reviewer@example.test"

    async def test_with_no_reviewer_named_it_is_still_the_user_and_not_an_object_repr(self):
        db, u = RecordingDB(), user("real.reviewer@example.test")
        with pytest.raises(HTTPException):
            await compliance.review_evidence(evidence_id=uuid.uuid4(), body=compliance.ReviewEvidenceRequest(decision="accepted"), db=db, user=u)
        assert db.params[0]["reviewer"] == "real.reviewer@example.test" and "object at" not in str(db.params[0]["reviewer"])

    async def test_the_phishing_submitter_is_the_authenticated_user(self):
        db, u = RecordingDB(), user("submitter@example.test")
        body = phishing.SubmitRequest.model_construct(artifact_kind="email", raw_content="x", sender="s@example.test", subject="s", recipients=[], message_id=None, metadata={})
        with pytest.raises(Exception):  # noqa: B017, PT011  (the recording DB fails the statement on purpose)
            await phishing.submit(body=body, db=db, user=u)
        assert any(p.get("by") == "submitter@example.test" for p in db.params), db.params

    async def test_the_knowledge_base_author_is_the_authenticated_user(self):
        db, u = RecordingDB(), user("author@example.test")
        body = knowledge_base.IngestRequest(title="a runbook", content="steps to follow")
        with pytest.raises(Exception):  # noqa: B017, PT011
            await knowledge_base.ingest(body=body, db=db, user=u)
        assert any(p.get("user") == "author@example.test" for p in db.params), db.params


class TestNoStringifiedPrincipalAnywhere:
    def test_nothing_in_the_app_stringifies_the_user_object(self):
        """str(user) / str(current_user) is the repr of the object, never a name. Use user.label."""
        bad = []
        for f in sorted(APP.rglob("*.py")):
            if "/scripts/" in str(f):
                continue
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "str" and len(n.args) == 1 and isinstance(n.args[0], ast.Name) and n.args[0].id in {"user", "current_user", "auth_user", "principal", "actor"}:
                    bad.append(f"{f.relative_to(APP)}:{n.lineno}")
        assert bad == [], "use .label (or an explicit field) instead:\n" + "\n".join(bad)


class TestMigration066:
    sql = (APP.parent / "migrations" / "066_clean_user_object_repr.sql").read_text(encoding="utf-8")

    def norm(self) -> str:
        return " ".join(re.sub(r"--[^\n]*", "", self.sql).split())

    def test_it_is_transactional_and_follows_065(self):
        names = sorted(p.name for p in (APP.parent / "migrations").glob("*.sql"))
        assert self.sql.count("BEGIN;") == 1 and self.sql.count("COMMIT;") == 1
        assert names.index("066_clean_user_object_repr.sql") == names.index("065_backfill_alert_case_id.sql") + 1

    @pytest.mark.parametrize("table,col", [("aisoc_kb_documents", "created_by"), ("aisoc_phishing_submissions", "submitted_by"), ("aisoc_compliance_evidence", "reviewed_by")])
    def test_it_clears_exactly_the_polluted_values_in_each_table(self, table, col):
        assert f"UPDATE {table} SET {col} = 'unknown' WHERE {col} LIKE '<app.api.v1.deps.CurrentUser object at 0x%';" in self.norm()

    def test_it_touches_nothing_else(self):
        assert self.norm().count("UPDATE ") == 3 and "DELETE" not in self.norm().upper() and "DROP" not in self.norm().upper()
