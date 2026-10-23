-- Migration 099: a role can hide parts of the console.
--
-- `hidden_nav` lists what people in the role do not see in the sidebar: a whole section ("section:Automation") or one page (its address, "/settings/mfa"). It is a view setting; what a person may DO is still
-- decided by the role's permissions, which the server enforces. The default is an empty list, so every existing role keeps showing everything.
--
-- Idempotent.

BEGIN;

ALTER TABLE roles ADD COLUMN IF NOT EXISTS hidden_nav JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMIT;
