-- Migration 067: the original primary administrator becomes a platform_admin.
--
-- Platform-level permissions (managing the shared plugin registry, onboarding tenants, searching across tenants) are no longer covered by the "*" wildcard that the `admin` role holds: they must be granted explicitly, and only the platform_admin role carries them.
-- Without this migration an existing deployment would have NO holder of those permissions after the upgrade (every administrator is an `admin`), so plugin management and tenant onboarding would be locked out.
--
-- WHO: the earliest-created ACTIVE user whose role is `admin`, and only when no platform_admin exists yet (so this is idempotent and never overrides a deliberate choice). ACTIVE matters: bootstrap_production disables the seeded default admin (admin@aisoc.local, public
-- password hash) and creates the real administrator, so the earliest `admin` row in a bootstrapped deployment is a disabled account that must not be the one promoted.
-- Nobody gains power they did not already have in practice: `admin` held "*". Everyone else stays `admin`, which keeps every tenant-level permission.
-- AFTER DEPLOYING: check who it chose and adjust if the primary administrator is someone else:
--     python -m app.scripts.platform_admin list
--     python -m app.scripts.platform_admin grant --email <person>      (and revoke from the wrong one)

BEGIN;

UPDATE users
SET role = 'platform_admin'
WHERE id = (
    SELECT id
    FROM users
    WHERE role = 'admin' AND is_active IS NOT FALSE
    ORDER BY created_at ASC NULLS LAST, id ASC
    LIMIT 1
)
AND NOT EXISTS (SELECT 1 FROM users WHERE role = 'platform_admin');

COMMIT;
