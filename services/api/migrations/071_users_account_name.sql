-- Migration 071: an account name, so that signing in no longer depends on an email address.
--
-- WHY. Login was by email, which is unique platform-wide, but nothing checks that an address is real or sends mail to it, so it was only ever a label with the cost of an identifier. A person now signs in with an ACCOUNT NAME: 3 to 32 characters,
-- lower-case letters, digits, '.', '_', '-', no '@' (so anything with an '@' is recognisably an email), unique across the platform and compared case-insensitively. Email becomes optional contact information (the column is made nullable; it is still unique, and
-- still accepted at sign-in, while LOGIN_ALLOW_EMAIL is on, so nobody is locked out by the change).
--
-- BACKFILL. Every existing user is given a name, deterministically and without collisions, oldest account first: the current `username` if it is already a valid name, otherwise the part of the email before the '@' with anything not allowed turned into '-'
-- (at least 3 characters: 'user' if nothing is left). If the name is taken, '-2', '-3', ... is added (so a second 'admin' becomes 'admin-2'). Nobody's name is therefore unique-by-luck: people whose name changed from what they expect can see it with
-- GET /auth/me, or an operator with SELECT account_name, email FROM users.
--
-- THE CONSTRAINTS. NOT NULL; a CHECK that the name has the allowed shape; a UNIQUE index on lower(account_name).
--
-- Idempotent (the backfill only touches users without a name).

BEGIN;

ALTER TABLE users ADD COLUMN IF NOT EXISTS account_name VARCHAR(32);

DO $$
DECLARE
    r record;
    base text;
    cand text;
    n integer;
    suffix text;
BEGIN
    FOR r IN SELECT id, username, email FROM users WHERE account_name IS NULL ORDER BY created_at, id LOOP
        base := lower(btrim(coalesce(r.username, '')));
        IF base !~ '^[a-z0-9][a-z0-9._-]{1,30}[a-z0-9]$' THEN
            base := lower(split_part(coalesce(r.email, ''), '@', 1));
            base := regexp_replace(base, '[^a-z0-9._-]+', '-', 'g');
            base := regexp_replace(base, '^[^a-z0-9]+|[^a-z0-9]+$', '', 'g');
            base := regexp_replace(left(base, 32), '[^a-z0-9]+$', '');
        END IF;
        IF length(base) < 3 THEN
            base := 'user';
        END IF;
        cand := base;
        n := 1;
        WHILE EXISTS (SELECT 1 FROM users WHERE lower(account_name) = cand) LOOP
            n := n + 1;
            suffix := '-' || n::text;
            cand := regexp_replace(left(base, 32 - length(suffix)), '[^a-z0-9]+$', '') || suffix;
        END LOOP;
        UPDATE users SET account_name = cand WHERE id = r.id;
    END LOOP;
END
$$;

ALTER TABLE users ALTER COLUMN account_name SET NOT NULL;
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_users_account_name_format') THEN
        ALTER TABLE users ADD CONSTRAINT ck_users_account_name_format CHECK (account_name ~ '^[a-z0-9][a-z0-9._-]{1,30}[a-z0-9]$');
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_account_name_lower ON users (lower(account_name));

COMMIT;
