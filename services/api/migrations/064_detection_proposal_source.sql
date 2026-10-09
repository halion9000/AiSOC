-- Migration 064: detection_rule_proposals.source (where a proposal came from).
--
-- Three writers INSERT a `source` into detection_rule_proposals and the column never existed:
--   * the hunt scheduler's detection bridge ('hunt-finding'),
--   * POST /detection-loop/suggest ('detection-loop'),
--   * POST /rule-tuning/auto-suggest ('auto-tuner').
-- Every one of those INSERTs failed with `column "source" ... does not exist`. The suggestion endpoint swallowed it behind a savepoint (the draft was returned but no proposal was ever created), the auto-tuner returned HTTP 500, and the hunt scheduler's failure
-- (no savepoint) aborted the whole transaction, so the case it had just opened was rolled back with it: on a real Postgres no scheduled hunt could keep a case.
--
-- Additive and nullable: existing proposals (created by hand or from natural language) keep NULL, meaning "no recorded source".

BEGIN;

ALTER TABLE detection_rule_proposals ADD COLUMN IF NOT EXISTS source VARCHAR(50);

COMMENT ON COLUMN detection_rule_proposals.source IS 'Origin of the proposal, e.g. hunt-finding, detection-loop, auto-tuner. NULL = not recorded.';

COMMIT;
