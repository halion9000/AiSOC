# Email addresses

## One address, one account, whatever its letter case

`Alice@Example.com` and `alice@example.com` are the same mailbox for every mail system. Here they used to be two accounts: `users.email` was UNIQUE only case-sensitively, login matched the exact text, and the check that stops one organisation claiming another's address could be bypassed by changing a letter's case.

Now:

* Addresses are **compared** by `normalize_email` (trimmed, lower-cased) through one helper, `find_user_by_email` (`app/services/user_lookup.py`), which compares `lower(email)`. Sign-in, passkey sign-in, user creation, the tenant provisioner and the bootstrap script all use it; a test fails the build if code compares `User.email ==` directly.
* New accounts are **stored lower-cased**.
* **Existing rows are not rewritten.** A legacy account stored as `Alice@x.com` still signs in as `alice@x.com`, `ALICE@X.COM` and `Alice@x.com`.
* Migration `070_users_email_lower_unique.sql` adds a unique index on `lower(email)`, so the database refuses a case-variant too.
* The failed-sign-in lock counts by the same rule (`Alice@x` and `alice@x` share one count).

### If two accounts already differ only in case

The index cannot be built, and the migration **will not guess which account to keep**: it builds nothing and prints a WARNING with the exact queries. Find them:

```sql
SELECT lower(email), array_agg(email), array_agg(tenant_id) FROM users GROUP BY 1 HAVING count(*) > 1;
```

Merge or rename the extras, then run `CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower ON users (lower(email));` (the migration runner records the file as applied, so it will not run again by itself). Until then nothing breaks: the application still compares case-insensitively and picks one account deterministically, an exact-case match first, otherwise the oldest.

## What is NOT checked: that an address is real

Nothing verifies that an email address exists or belongs to the person it was typed for, and the application does not send email. An administrator can type a typo, or someone else's address, and the account is created. Consequences: no account recovery by email, and no way to know an address is mistyped until the person cannot sign in.

What already exists and could be built on: `users.is_verified`, and the tenant provisioner already creates an **inactive** first admin with a placeholder password (`!invite-pending`) for an invitation flow that has not been built. The proper fix is an invitation: creating a user sends a link, and the account is activated, with the password chosen, only when the link is used. That also removes the last remaining way to learn whether an address is registered (a refusal differs from a success). It needs email delivery to be configured, so it is not part of this change.

## Verified

Unit tests against a real database (lower-case, legacy mixed-case, inactive and other-tenant accounts, and a legacy case pair), and on real Postgres: the index is built on a clean database and the database refuses a case-variant; a database that already holds a pair gets the warning, nothing is rewritten, and sign-in still works for every spelling; as the non-superuser role, a case-variant from another tenant is refused (the bypass is closed). The passkey, provisioner and bootstrap paths are covered by source-level checks rather than by behavioural tests.
