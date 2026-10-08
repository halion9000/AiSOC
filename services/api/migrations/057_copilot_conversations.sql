-- Migration 057: persist copilot conversation history, scoped to (tenant, owner, conversation).
--
-- POST /api/v1/copilot/chat kept history in a module-level dict keyed by the CLIENT-SUPPLIED conversationId alone. Consequences:
--   * a restart silently dropped every conversation's context while the chat UI still showed the earlier messages, so the model answered without context the user believed it had;
--   * the key held no tenant and no user: anyone who had another tenant's conversationId got that conversation's history fed to the model (and could write into it);
--   * the 500-conversation LRU was GLOBAL, so one busy tenant silently evicted other tenants' conversations.
-- History now lives here, and the primary key is (tenant_id, owner_key, conversation_id): the same id used by two tenants (or two users) is two unrelated conversations, so an id from elsewhere can neither
-- read nor write someone else's history, and there is no way to tell whether another tenant's id exists.
--
--   owner_key  - the user's id (or 'service' for a principal with no user id).
--   messages   - the last turns as [{"role": "human"|"ai", "content": "..."}]; trimmed by the API. Only successful turns are stored (a fallback apology would poison later context).

BEGIN;

CREATE TABLE IF NOT EXISTS copilot_conversations (
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_key        VARCHAR(64) NOT NULL,
    conversation_id  VARCHAR(100) NOT NULL,
    messages         JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, owner_key, conversation_id)
);

CREATE INDEX IF NOT EXISTS copilot_conversations_owner_recent_idx ON copilot_conversations (tenant_id, owner_key, updated_at DESC);

ALTER TABLE copilot_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE copilot_conversations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS copilot_conversations_tenant_isolation ON copilot_conversations;
CREATE POLICY copilot_conversations_tenant_isolation ON copilot_conversations
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
