-- Migration 069: a record of failed sign-ins, so that guessing a password is no longer free.
--
-- WHAT WAS WRONG. POST /auth/login had no rate limit and no lockout: a password could be guessed as fast as the server would answer, for as long as the attacker liked. (Until the login-timing fix an attacker could also learn which
-- addresses were worth guessing; now they cannot, so the lock must not bring that back: see app/services/login_throttle.py.)
--
-- THE TABLE. One row per FAILED attempt: the address as typed (lower-cased and trimmed, whether or not such an account exists, so a made-up address is locked exactly like a real one), the client address, and when. Login counts the recent rows for the
-- address and for the client address; too many in the window refuses further attempts for the rest of the window. A successful sign-in clears the address's rows; old rows are purged as new ones arrive.
-- There is no tenant column and no row-level security: a sign-in happens before anyone's tenant is known.
--
-- Idempotent. Existing deployments start with an empty table.

BEGIN;

CREATE TABLE IF NOT EXISTS login_failures (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email_key  VARCHAR(320) NOT NULL,
    client_ip  VARCHAR(64),
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_login_failures_email_created ON login_failures (email_key, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_login_failures_ip_created ON login_failures (client_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_login_failures_created ON login_failures (created_at);

COMMIT;
