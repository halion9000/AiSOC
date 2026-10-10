# Account names

A person signs in with an **account name**, not an email address.

## Why

Login was by email, unique platform-wide. But nothing checks that an address is real, and the application sends no email, so an email only ever behaved as a label while carrying the cost of an identifier: typos and someone else's address were accepted, and there was no way to recover an account by email. An account name asks for nothing that has to be verified or delivered.

## The rule

An account name is **3 to 32 characters**: lower-case letters, digits, `.`, `_` and `-`, starting and ending with a letter or digit, and **no `@`** (so anything with an `@` is recognisably an email). It is **unique across the whole platform** and compared case-insensitively (`Hal.LiveOak` and `hal.liveoak` are one name; names are stored lower-cased). The database enforces the shape (a `CHECK`) and the uniqueness (a unique index on `lower(account_name)`).

Because names are platform-wide, only one tenant can own `admin`. Use a convention that includes the organisation, for example `hal.liveoak`.

## What changed

* **Sign-in** takes an account name. The JSON key `email` is still accepted (so existing clients keep working), as are `account_name`, `username` and `identifier`. Passkey sign-in takes the same.
* **Email is optional contact information.** An account need not have one; it is not verified and not needed to sign in. It is still unique when present.
* **Existing people can still sign in with their email** while `LOGIN_ALLOW_EMAIL` is on (the default), so nobody is locked out when this arrives. Turn it off once people know their account name. A name never contains `@`, so the two cannot be confused.
* **Tokens** carry `account_name`, and the `email` claim is now a *label for "who"*: the email if the account has one, otherwise the account name. Audit, rule tuning and the rest read that label, so a person with no email still appears by name.
* **Creating a user** (`POST /tenants/me/users`) takes `account_name` (validated; a taken name is `409 That account name is already taken`, a bad one is `422` with the rule) and an optional `email`. A client that does not send an `account_name` still works: one is made from the `username` (or the email) and numbered if taken (`dave-brown`, `dave-brown-2`). Because a name is not private, "taken" is said plainly; an **email** that belongs to another organisation is still refused without saying so.
* **The failed-sign-in lock** counts by the name as typed, so `Alice` and `alice` share one count (see `login-throttling.md`).

## Existing accounts: migration 071

Every existing user is given a name, deterministically and without collisions, **oldest account first**: their current `username` if it is already a valid name; otherwise the part of their email before the `@`, with anything not allowed turned into `-` (at least 3 characters, `user` if nothing is left). If the name is taken, `-2`, `-3`, … is added, so a second `admin` becomes `admin-2`. The migration rewrites nothing else.

So **some people's name will differ from what they expect**. They can see it at `GET /auth/me`, on **Settings → Profile** ("Account name"), or an operator can run `SELECT account_name, email FROM users`. Checked on real Postgres against awkward data (duplicate usernames across tenants, usernames that are emails, too short, spaces, non-ASCII, uppercase, empty, very long and colliding long names): every name valid, unique, identical across two independent runs; the database refuses a bad shape and a duplicate; re-running changes nothing.

## Not done yet

* **`platform_admin` now takes `--name`** (or `--email`; exactly one), so it can target an account that has no email, and it reports the account name in every result. `login_lockout` takes any string (`--email alice` works for an account name too).
* **Email is still unique while `LOGIN_ALLOW_EMAIL` is on** (an email sign-in must be unambiguous), so an optional email can still hit "this address cannot be used". That goes away when email sign-in is retired.
* **The web console has no user-creation form** (users are created through the API); nothing to change there, but a form that asks for an account name is a natural addition.
* **Granting a person access to specific tenants, or to all of them, at read-only or full level** exists: see `viewing-another-tenant.md`. The console shows the level in the tenant switcher and banner; a Settings screen for managing grants is not built yet.
* **The audit table's column is still called `actor_email`**; it now holds the label described above.
* Names are guessable (`admin`); the failed-sign-in lock and the identical refusals are what cover that.
