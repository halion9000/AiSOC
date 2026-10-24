-- Migration 102: answers a person types into the client review, and notes on any question.
--
-- client_review_answers: one row per client and question. `section` is readiness, tech or m365; `key` is the question's key (the question text for the Microsoft 365 list). A row can carry a status, an
-- answer (technology questions) and a note: any of them. A status or answer REPLACES what A.C.O.R.N worked out for that question (the page keeps showing what it worked out, marked as replaced); a row
-- with only a note changes no answer. Deleting the row goes back to the automatic answer.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS client_review_answers (
    tenant_id  UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    section    VARCHAR(12)  NOT NULL CHECK (section IN ('readiness', 'tech', 'm365')),
    key        VARCHAR(400) NOT NULL,
    status     VARCHAR(20),
    answer     VARCHAR(300),
    note       TEXT,
    updated_by UUID,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, section, key)
);

ALTER TABLE client_review_answers ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON client_review_answers;
CREATE POLICY tenant_isolation ON client_review_answers
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
