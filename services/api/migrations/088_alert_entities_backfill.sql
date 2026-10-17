-- Migration 088: fill alerts.affected_hosts / affected_users / affected_ips for rows the fusion service saved before it wrote those columns.
--
-- Fusion used to record an alert's host and user only in the generic ``entities`` column and its addresses only in ``iocs``; the alert rail, entity pivots and device
-- views read the affected_* columns, so those alerts showed no entities. Only rows whose column is still empty are touched, nothing already filled is changed, and
-- a row whose source column is not a list is skipped. Idempotent.

BEGIN;

UPDATE alerts a
SET affected_hosts = h.vals
FROM (
    SELECT id, jsonb_agg(DISTINCT e ->> 'value') AS vals
    FROM alerts, jsonb_array_elements(entities) e
    WHERE jsonb_typeof(entities) = 'array' AND e ->> 'type' = 'host' AND COALESCE(e ->> 'value', '') <> ''
    GROUP BY id
) h
WHERE a.id = h.id AND a.affected_hosts = '[]'::jsonb;

UPDATE alerts a
SET affected_users = u.vals
FROM (
    SELECT id, jsonb_agg(DISTINCT e ->> 'value') AS vals
    FROM alerts, jsonb_array_elements(entities) e
    WHERE jsonb_typeof(entities) = 'array' AND e ->> 'type' = 'user' AND COALESCE(e ->> 'value', '') <> ''
    GROUP BY id
) u
WHERE a.id = u.id AND a.affected_users = '[]'::jsonb;

UPDATE alerts a
SET affected_ips = i.vals
FROM (
    SELECT id, jsonb_agg(DISTINCT e ->> 'value') AS vals
    FROM alerts, jsonb_array_elements(iocs) e
    WHERE jsonb_typeof(iocs) = 'array' AND e ->> 'type' = 'ip' AND COALESCE(e ->> 'value', '') <> ''
    GROUP BY id
) i
WHERE a.id = i.id AND a.affected_ips = '[]'::jsonb;

COMMIT;
