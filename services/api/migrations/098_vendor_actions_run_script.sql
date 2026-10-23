-- Migration 098: let the vendor-actions queue carry the "run_script" action.
--
-- Migration 084 limited `action` to approve, reject and resolve (the Huntress incident actions). The Run script button (and the bulk version) queue a row with action 'run_script' for CORE; against a
-- database built from 084 alone that insert fails the check and the button answers with an error. This widens the check to include it. Nothing else about the table changes.
--
-- Idempotent: the old constraint is dropped if present and the new one is added in its place.

BEGIN;

ALTER TABLE vendor_actions DROP CONSTRAINT IF EXISTS vendor_actions_action_check;
ALTER TABLE vendor_actions ADD CONSTRAINT vendor_actions_action_check CHECK (action IN ('approve', 'reject', 'resolve', 'run_script'));

COMMIT;
