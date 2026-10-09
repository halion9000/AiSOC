-- Migration 070: an email address is one account, whatever its letter case.
--
-- WHAT WAS WRONG. users.email is UNIQUE, but case-sensitively: `Alice@x.com` and `alice@x.com` could both exist as separate accounts. Login matched the exact text, and the check that stops one organisation from claiming another
-- organisation's address could be bypassed by changing a letter's case. The application now compares and stores addresses lower-cased (app/core/emails.py); this makes the database refuse a case-variant too.
--
-- THE INDEX. A UNIQUE index on lower(email). Existing rows are NOT rewritten (their stored text may be relied on, and lookups compare lower(email) anyway).
--
-- IF TWO ACCOUNTS ALREADY DIFFER ONLY IN CASE the index cannot be built, and this migration will not guess which to keep: it builds nothing and prints a WARNING naming how many. Find them with
--     SELECT lower(email), array_agg(email), array_agg(tenant_id) FROM users GROUP BY 1 HAVING count(*) > 1;
-- merge or rename the extras, then run:   CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower ON users (lower(email));
-- (The migration runner records this file as applied, so it will not run again by itself.) Until then the application still compares case-insensitively and picks one account deterministically (an exact-case match, else the oldest).
--
-- Idempotent.

DO $$
DECLARE
    dup integer;
BEGIN
    SELECT count(*) INTO dup FROM (SELECT 1 FROM users GROUP BY lower(email) HAVING count(*) > 1) d;
    IF dup > 0 THEN
        RAISE WARNING 'users: % email address(es) exist in more than one letter case, so the unique index on lower(email) was NOT created. Find them: SELECT lower(email), array_agg(email), array_agg(tenant_id) FROM users GROUP BY 1 HAVING count(*) > 1; then merge or rename the extras and run: CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower ON users (lower(email));', dup;
    ELSE
        CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower ON users (lower(email));
    END IF;
END
$$;
