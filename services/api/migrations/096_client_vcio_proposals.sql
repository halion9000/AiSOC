-- Migration 096: what AiSOC suggests adding to a client's vCIO Toolbox, and what a person decided about it.
--
-- client_vcio_proposals: ONE row per client, source and check key. AiSOC works out suggestions from the data it holds (multi-factor, tool coverage, Secure Score...) and stores each as `suggested`.
-- A person approves or rejects it on the client review page; CORE then creates an approved one at vCIO Toolbox with its own key and reports back (`sent` or `failed`). Nothing leaves AiSOC without
-- that approval. A suggestion whose condition has gone away while nobody acted on it becomes `cleared`.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS client_vcio_proposals (
    id             UUID         PRIMARY KEY,
    tenant_id      UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    source         VARCHAR(40)  NOT NULL DEFAULT 'vciotoolbox',
    key            VARCHAR(80)  NOT NULL,
    kind           VARCHAR(20)  NOT NULL DEFAULT 'recommendation',
    name           VARCHAR(200) NOT NULL,
    description    TEXT         NOT NULL DEFAULT '',
    priority       VARCHAR(10)  NOT NULL DEFAULT 'Medium',
    evidence       TEXT         NOT NULL DEFAULT '',
    status         VARCHAR(12)  NOT NULL DEFAULT 'suggested',
    decided_by     UUID,
    decided_at     TIMESTAMPTZ,
    sent_at        TIMESTAMPTZ,
    vendor_id      VARCHAR(80),
    result_message TEXT,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT client_vcio_proposals_status_check CHECK (status IN ('suggested', 'approved', 'rejected', 'sent', 'failed', 'cleared')),
    CONSTRAINT client_vcio_proposals_kind_check CHECK (kind IN ('recommendation', 'risk')),
    CONSTRAINT client_vcio_proposals_unique UNIQUE (tenant_id, source, key)
);

CREATE INDEX IF NOT EXISTS client_vcio_proposals_status_idx ON client_vcio_proposals (tenant_id, status);

ALTER TABLE client_vcio_proposals ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON client_vcio_proposals;
CREATE POLICY tenant_isolation ON client_vcio_proposals
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
