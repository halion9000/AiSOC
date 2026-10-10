-- Migration 073: emailing alerts to PLATFORM administrators (optional, off by default).
--
-- WHAT. A single platform-wide setting (who gets the email, from what severity, on or off) and a log of which alerts have been emailed. Recipients are platform operators, not tenant users: tenants never see or configure this, and it has no
-- per-tenant data of its own. Microsoft credentials and the sender mailbox are NOT here: they come from the environment (ALERT_EMAIL_GRAPH_*), so a database dump never holds the secret.
--
-- WHY A POLLING LOG AND NOT A HOOK. Alerts have two writers: the API's POST /alerts/submit, and the fusion service, which writes fused alerts STRAIGHT INTO POSTGRES without calling the API. A hook in the API would miss the production path.
-- The worker therefore looks for alerts that are at or above the severity, newer than the moment the feature was switched on, and not yet in alert_email_log; the primary key on alert_id makes "emailed" a fact the database enforces.
--
-- The settings row is a singleton (id = 1). No tenant_id column and no row-level security: nothing here belongs to a tenant, and only the platform-administrator endpoints read it.
--
-- Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS platform_alert_email_settings (
    id                   SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled              BOOLEAN     NOT NULL DEFAULT false,
    enabled_since        TIMESTAMPTZ,
    min_severity         VARCHAR(20) NOT NULL DEFAULT 'high' CHECK (min_severity IN ('info', 'low', 'medium', 'high', 'critical')),
    recipients           JSONB       NOT NULL DEFAULT '[]'::jsonb,
    updated_by_label     TEXT,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_sent_at         TIMESTAMPTZ,
    last_error           TEXT,
    last_error_at        TIMESTAMPTZ,
    consecutive_failures INTEGER     NOT NULL DEFAULT 0
);

INSERT INTO platform_alert_email_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS alert_email_log (
    alert_id        UUID         PRIMARY KEY,
    alert_tenant_id UUID         NOT NULL,
    severity        VARCHAR(20)  NOT NULL,
    title           VARCHAR(500) NOT NULL,
    batch_id        UUID         NOT NULL,
    recipient_count INTEGER      NOT NULL,
    sent_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_alert_email_log_sent_at ON alert_email_log (sent_at DESC);

COMMIT;
