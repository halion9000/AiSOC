# Roles and platform permissions

AiSOC separates what a person may do **inside their own tenant** from what acts on **the whole platform** (every tenant).

## The roles

| Role | What it is |
| --- | --- |
| `platform_admin` | The operator of the platform. Everything an `admin` has, **plus** the platform permissions below. |
| `admin` | A tenant's own administrator. Every tenant-level permission (the `*` wildcard) but **no platform permission**. |
| `tenant_admin` | What a newly provisioned tenant's first administrator receives. A fixed list of tenant-level permissions. |
| `soc_lead`, `soc_analyst`, `threat_hunter`, `viewer`, `api_service` | Narrower tenant-level roles. |

## Platform permissions

These act on every tenant, so neither the `*` wildcard nor a resource wildcard such as `plugins:*` grants them. A principal holds one only if it is **named exactly**: in a role (only `platform_admin` lists them), in an API key's scopes, or in a database role.

| Permission | What it allows |
| --- | --- |
| `plugins:admin` | Enable, disable, reload, unload and discover plugins in the shared plugin registry, and approve or reject community plugin submissions. (Installing a community plugin into your own tenant needs only `settings:write`.) |
| `mssp:onboard` | Onboard a new tenant. |
| `platform:cross_tenant_query` | Search across tenants (reserved for the cross-tenant search feature). |

## Who holds platform power by default

The **original primary administrator**, and nobody else:

* a new install: `bootstrap_production` creates the primary administrator as `platform_admin`;
* an existing install: migration `067` promotes the earliest-created **active** `admin` user, and only if no `platform_admin` exists yet (it skips a disabled account, such as the seeded `admin@aisoc.local` that bootstrap disables, and never overrides a deliberate choice).

Everyone else stays as they were. Nobody gains power they did not already have in practice, because `admin` used to hold `*`.

## Giving it to someone, or taking it away

From the command line, with database access:

```bash
python -m app.scripts.platform_admin list
python -m app.scripts.platform_admin grant  --name hal.liveoak            # the account name they sign in with (or --email person@example.com)
python -m app.scripts.platform_admin revoke --name hal.liveoak [--to-role tenant_admin] [--force]
```

Revoking the **last active** `platform_admin` is refused unless you pass `--force`, because nobody could then administer the platform.

From inside the product, an existing `platform_admin` can set a user's role to `platform_admin` with `PATCH /api/v1/tenants/me/users/{id}` (users of their own tenant).

## Rules the API enforces

* **Nobody can grant more power than they hold.** A role can be assigned only if the assigner holds every permission in it; an API key can carry only scopes its creator holds (a wildcard key needs a wildcard; a platform scope needs that exact permission, and a wildcard key never carries platform permissions); a database role can contain, and be assigned with, only permissions the caller holds.
* **Nobody changes their own role**, and nobody edits a user whose role grants more than their own.
* An unknown role name is refused.

## After you upgrade: checklist

1. Apply migrations through `067` (the API does this on start).
2. Run `python -m app.scripts.platform_admin list` and confirm the right person holds platform power. If migration 067 chose someone else, `grant` the right person and `revoke` the other.
3. A person's session reflects a role change on their next request.
4. Until step 2 is right, plugin management and tenant onboarding are unavailable to everyone but the listed platform administrators.

### Check for past abuse

Before this release, any user holding `users:write` (including a `tenant_admin`, and any API key with that scope) could create a `platform_admin` or `admin` user, or promote themselves, and could mint API keys with scopes they did not hold. Review who holds the powerful roles and whether you recognise each of them:

```sql
SELECT email, role, tenant_id, created_at FROM users WHERE role IN ('platform_admin', 'admin') ORDER BY created_at;
SELECT name, user_id, scopes, created_at FROM api_keys WHERE scopes ?| ARRAY['*', 'plugins:admin'] ORDER BY created_at;
```
