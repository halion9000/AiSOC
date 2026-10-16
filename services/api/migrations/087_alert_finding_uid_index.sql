-- Migration 087: index the vendor incident id CORE puts on every alert it forwards.
--
-- CORE's state, closed and linked-ticket reports each look an alert up by ``raw_event->'finding'->>'uid'`` ("huntress:123"), once per incident and once per client in scope.
-- With no index on that expression every lookup read the whole alerts table, so a report with a few hundred incidents ran past CORE's 30 second limit ("AiSOC didn't answer").
-- The expression must match the one the queries use. Idempotent.

BEGIN;

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_finding_uid ON alerts (tenant_id, ((raw_event -> 'finding') ->> 'uid'));

COMMIT;
