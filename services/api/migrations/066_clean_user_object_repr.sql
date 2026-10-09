-- Migration 066: clear the text "<app.api.v1.deps.CurrentUser object at 0x...>" that three endpoints stored where a person's identity belonged.
--
-- aisoc_kb_documents.created_by (POST /kb/ingest), aisoc_phishing_submissions.submitted_by (POST /phishing/submit) and aisoc_compliance_evidence.reviewed_by (POST /compliance/evidence/{id}/review, when the request named no reviewer) were written with str(user), the Python repr of the
-- user object. Who the author / submitter / reviewer really was cannot be recovered from that, so the garbage is replaced by an explicit 'unknown' rather than left to be shown as if it were a name (it also exposed an in-process memory address through the API). Rows with a real value are untouched; idempotent.

BEGIN;

UPDATE aisoc_kb_documents SET created_by = 'unknown' WHERE created_by LIKE '<app.api.v1.deps.CurrentUser object at 0x%';
UPDATE aisoc_phishing_submissions SET submitted_by = 'unknown' WHERE submitted_by LIKE '<app.api.v1.deps.CurrentUser object at 0x%';
UPDATE aisoc_compliance_evidence SET reviewed_by = 'unknown' WHERE reviewed_by LIKE '<app.api.v1.deps.CurrentUser object at 0x%';

COMMIT;
