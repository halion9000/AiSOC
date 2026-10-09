-- Migration 065: backfill alerts.case_id from the case side (aisoc_cases.alert_ids).
--
-- The alert <-> case link was recorded only on the case, so alerts.case_id was NULL for every live alert (only the demo seed script set it). Four readers of the column were therefore inert: the alert queue's case_id, the SLA metrics' case count, the narrative projection and the
-- rail's case pivot. The cases API now keeps the column in step with every new link; this fills in the links that already exist.
--
-- An alert can be in several cases but has a single case_id: the EARLIEST-opened case wins (the same "first claim keeps it" rule the API applies going forward). Only alerts of the SAME tenant as the case are touched, so a cross-tenant citation that predates the ownership checks is
-- never turned into a link. Rows that already have a case_id are left alone, so re-running changes nothing.

BEGIN;

UPDATE alerts a
SET case_id = first_case.case_id
FROM (
    SELECT DISTINCT ON (x.alert_id, x.tenant_id) x.alert_id, x.tenant_id, x.case_id
    FROM (
        SELECT unnest(alert_ids) AS alert_id, tenant_id, id AS case_id, opened_at
        FROM aisoc_cases
    ) x
    ORDER BY x.alert_id, x.tenant_id, x.opened_at ASC, x.case_id
) first_case
WHERE a.id = first_case.alert_id
  AND a.tenant_id = first_case.tenant_id
  AND a.case_id IS NULL;

COMMIT;
