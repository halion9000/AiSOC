-- Migration 101: the people (e-mail identities) each connected tool knows, for the Identities page.
--
-- identity_sources: one row per person per tool per client, replaced by each report CORE sends (Datto SaaS Protection seats, Dropsuite mailboxes, Huntress SAT learners, HaloPSA users...). Microsoft 365 people
-- are not copied here: they are read from identity_mfa_users, which CIPP already fills. A person is the same e-mail address (lower case) in the same client; the page puts all of a person's rows together.
-- `refreshed_at` is how fresh a row is: a row not refreshed for a few days is no longer shown (the person left that tool).
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS identity_sources (
    tenant_id    UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    vendor       VARCHAR(40)  NOT NULL,
    external_id  VARCHAR(200) NOT NULL,
    email        VARCHAR(320) NOT NULL,
    display_name VARCHAR(255),
    enabled      BOOLEAN,
    kind         VARCHAR(20)  NOT NULL DEFAULT 'user',
    details      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    refreshed_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, vendor, external_id)
);

CREATE INDEX IF NOT EXISTS idx_identity_sources_email ON identity_sources (tenant_id, email);

ALTER TABLE identity_sources ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON identity_sources;
CREATE POLICY tenant_isolation ON identity_sources
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
