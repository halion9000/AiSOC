# Sign-in lockout

`POST /api/v1/auth/login` used to have no rate limit and no lockout: a password could be guessed as fast as the server answered, for as long as the attacker liked. Failed sign-ins are now counted, and too many lock further attempts out.

## The rule

After **5 failed attempts for one address**, or **20 failed attempts from one client address**, within **15 minutes**, further attempts are refused with `429 Too Many Requests` and a `Retry-After` header until the oldest of those failures leaves the window. The text is always: *Too many failed sign-in attempts. Try again in about N minutes.*

* While locked, **even the correct password is refused** (otherwise the lock would only slow a guesser down by one request). A locked attempt does no password hashing and is not counted, so hammering a locked address does not extend the lock.
* A **successful** sign-in clears that address's failures. It does not clear the client address's, so one client still cannot try many addresses.
* The address is counted **as typed, trimmed and lower-cased**: `Alice@x` and `alice@x` share one count.
* Old failures are deleted as new ones arrive.

| Setting | Default | Meaning |
| --- | --- | --- |
| `LOGIN_MAX_FAILURES_PER_ACCOUNT` | 5 | failures for one address in the window |
| `LOGIN_MAX_FAILURES_PER_IP` | 20 | failures from one client address in the window |
| `LOGIN_FAILURE_WINDOW_MINUTES` | 15 | the window |

Each must be at least 1 (a smaller value is rejected at startup, so the lock cannot be configured into locking everyone or no one).

## It does not bring back the email enumeration

Login used to answer a registered address and an unknown one at very different speeds, so anyone could list which addresses are registered (fixed in `5c06f3f2`). A lock that treated real and made-up addresses differently would reopen that, so:

* a **made-up address locks after the same five attempts** as a real one (the count is by address typed, whether or not an account exists), and an inactive account likewise;
* every locked case gets **the same status and the same sentence**, which names no reason (not "account", "locked" or "exists");
* with failures being recorded, a registered address and a made-up one still answer in indistinguishable time (measured over HTTP, interleaved: 291.0 ms vs 292.2 ms as the superuser, 290.0 ms vs 289.9 ms as the restricted role).

## The trade-off you are accepting

Anyone who can send five wrong passwords for an address can **lock that person out for up to 15 minutes**. The lock ends by itself, and an operator can end it at once (below). The alternative, locking only an (address, client) pair, would let one attacker with many client addresses keep guessing; a higher per-address limit helps neither case much. If your users are routinely locked out by someone else, raise `LOGIN_MAX_FAILURES_PER_ACCOUNT` rather than disabling the lock.

The client-address limit is shared by everyone behind one address (an office behind NAT). 20 failures in 15 minutes is generous for that, but if a whole site is locked together, that is the cause.

## Behind a proxy or load balancer

The client address comes from the same resolver as the audit log: `X-Forwarded-For` is **ignored** unless `AISOC_TRUSTED_PROXIES` lists your proxies. This is deliberate (otherwise an attacker could dodge the per-client limit by forging the header). If you run behind a load balancer and do not set it, every request appears to come from the balancer, and the client limit (20 per 15 minutes) would apply to **all users together**. Set `AISOC_TRUSTED_PROXIES` to your proxy ranges.

## Operating it

```bash
python -m app.scripts.login_lockout list                     # who is locked now, and how long is left
python -m app.scripts.login_lockout clear --email person@example.com
python -m app.scripts.login_lockout clear --ip 203.0.113.7
python -m app.scripts.login_lockout clear --all
```

`clear` deletes the recorded failures (so the count restarts); it does not enable a disabled account and changes no password. Reaching the limit is logged once, at WARNING, with a hash of the address (never the address) and the client address.

## Deploying

Apply migration `069_login_failures.sql` (it runs with the others at startup). The counts live in the database (`login_failures`), so they hold across workers and restarts; an error reading them is **not** swallowed, because a store that cannot be read must not silently turn the lock off. A deployment that has not run the migration fails sign-in loudly rather than running without the lock.

## What this does not cover

* **Distributed guessing**: an attacker with many client addresses is limited per address (5 per 15 minutes, about 480 a day for one account) but not stopped. A strong password policy and MFA are the real answer; passkeys already exist.
* **Other credentials**: passkey sign-in (no password to guess), API keys (long random secrets) and refresh tokens are not counted here.
* **The console**: the sign-in page shows the server's sentence; it does not count down or disable the button.

## Verified

Unit tests against a real database and the real router, and over HTTP against real Postgres as the superuser and as the non-superuser role: the lock, a made-up address locking identically, the correct password refused while locked, failures committed despite the 401, the lock surviving a server restart, the operator tool, and the timing comparison above.
