-- Migration 093: identity changes and multi-factor status collected through CIPP.
--
-- directory_audit_events: the Microsoft 365 directory audit log's identity-related entries (a role added, a password reset, a security method registered, an app consented to, ...), read for
-- every tenant (they need no premium licence), stored once, scored by the UEBA service for how unusual the actor's behaviour is, and kept for 45 days. COLLECT AND SCORE ONLY: no alert.
--
-- identity_mfa_users: each person's multi-factor state, replaced whole by each daily snapshot, so the page can say who has no second factor.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS directory_audit_events (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    source        VARCHAR(40)  NOT NULL,
    source_id     VARCHAR(200) NOT NULL,
    actor         VARCHAR(320) NOT NULL,
    actor_is_app  BOOLEAN      NOT NULL DEFAULT FALSE,
    actor_ip      VARCHAR(64),
    activity      VARCHAR(200) NOT NULL,
    category      VARCHAR(60)  NOT NULL,
    service       VARCHAR(80),
    success       BOOLEAN      NOT NULL DEFAULT TRUE,
    reason        VARCHAR(200),
    target        VARCHAR(320),
    target_type   VARCHAR(40),
    sensitivity   SMALLINT     NOT NULL DEFAULT 1,
    occurred_at   TIMESTAMPTZ  NOT NULL,
    received_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    scored_at     TIMESTAMPTZ,
    anomaly_score DOUBLE PRECISION,
    CONSTRAINT uq_directory_audit_events_source UNIQUE (tenant_id, source, source_id)
);

CREATE INDEX IF NOT EXISTS ix_directory_audit_events_tenant_time ON directory_audit_events (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_directory_audit_events_unscored ON directory_audit_events (tenant_id, occurred_at) WHERE scored_at IS NULL;

CREATE TABLE IF NOT EXISTS identity_mfa_users (
    tenant_id         UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    source            VARCHAR(40)  NOT NULL,
    user_id           VARCHAR(100) NOT NULL,
    upn               VARCHAR(320) NOT NULL,
    display_name      VARCHAR(255),
    enabled           BOOLEAN      NOT NULL DEFAULT TRUE,
    user_type         VARCHAR(20),
    admin             BOOLEAN      NOT NULL DEFAULT FALSE,
    licensed          BOOLEAN      NOT NULL DEFAULT FALSE,
    registered        BOOLEAN      NOT NULL DEFAULT FALSE,
    capable           BOOLEAN      NOT NULL DEFAULT FALSE,
    per_user          VARCHAR(20),
    ca_enforced       BOOLEAN      NOT NULL DEFAULT FALSE,
    security_defaults BOOLEAN      NOT NULL DEFAULT FALSE,
    methods           VARCHAR(400),
    snapshot_id       UUID         NOT NULL,
    refreshed_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source, user_id)
);

CREATE INDEX IF NOT EXISTS ix_identity_mfa_users_upn ON identity_mfa_users (tenant_id, upn);

ALTER TABLE directory_audit_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON directory_audit_events;
CREATE POLICY tenant_isolation ON directory_audit_events
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

ALTER TABLE identity_mfa_users ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON identity_mfa_users;
CREATE POLICY tenant_isolation ON identity_mfa_users
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
