-- Migration 091: sign-in events collected from a tenant's identity provider (CIPP, for Microsoft 365).
--
-- CORE reads each customer tenant's sign-in log through CIPP every hour and posts the new sign-ins. Each is stored here once (a second post of the same sign-in changes nothing), scored by
-- the UEBA service for how unusual it is for that person, and kept for 45 days so the next sign-in can be compared with what the person normally does (new country, new address).
--
-- This only COLLECTS and SCORES. Nothing here raises an alert.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS signin_events (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    source         VARCHAR(40) NOT NULL,
    source_id      VARCHAR(200) NOT NULL,
    user_principal VARCHAR(320) NOT NULL,
    display_name   VARCHAR(255),
    ip_address     VARCHAR(64),
    country        VARCHAR(16),
    city           VARCHAR(120),
    app            VARCHAR(160),
    client_app     VARCHAR(100),
    success        BOOLEAN     NOT NULL,
    error_code     INTEGER,
    interactive    BOOLEAN     NOT NULL DEFAULT TRUE,
    mfa            BOOLEAN,
    risk           VARCHAR(20),
    conditional_access VARCHAR(40),
    occurred_at    TIMESTAMPTZ NOT NULL,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    scored_at      TIMESTAMPTZ,
    anomaly_score  DOUBLE PRECISION,
    CONSTRAINT uq_signin_events_source UNIQUE (tenant_id, source, source_id)
);

CREATE INDEX IF NOT EXISTS ix_signin_events_tenant_time ON signin_events (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_signin_events_user ON signin_events (tenant_id, user_principal, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_signin_events_unscored ON signin_events (tenant_id, occurred_at) WHERE scored_at IS NULL;

ALTER TABLE signin_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON signin_events;
CREATE POLICY tenant_isolation ON signin_events
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
