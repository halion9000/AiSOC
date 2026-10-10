# Emailing alerts to platform administrators

An **optional** feature: new alerts at or above a severity are emailed to a short list of **platform administrators** (the people who run AiSOC, not a tenant's own users), sent through Microsoft Graph from one shared mailbox. It is **off by default** and does nothing until three things are all true: the worker is enabled in the deployment, the Microsoft credentials are set, and a platform administrator has switched the setting on with at least one recipient.

> **What has and has not been verified.** Everything here was tested against a mock Graph and, end to end, against a stand-in Graph server over real HTTP on real Postgres, with the restricted database role. It has **not** been run against a real Microsoft 365 tenant. The setup steps for Entra and Exchange below are from general knowledge of Microsoft Graph and should be checked against Microsoft's current documentation; use **"send a test email"** (below) as the first real check.

## Who is it for, and who can change it

* Recipients are plain email addresses chosen by a platform administrator (a distribution list works). Tenants never see, configure or receive these emails. The emails carry **other tenants' alert titles**, so changing the recipients needs `platform:cross_tenant_query`, the permission only the `platform_admin` role holds (a wildcard does not cover it). A tenant's own administrators get 403 on every route.
* Every change is written to the audit log (before, after, who) in the **same transaction** as the change; a successful test email is audited too.

## How alerts are found

Alerts have **two writers**: `POST /alerts/submit` in the API, and the fusion service, which inserts fused alerts **straight into Postgres** without calling the API (the production path). So the feature does not hook the API; a background worker asks the database, each cycle (60 s), for alerts that are

1. at or above the chosen minimum severity (default **high**: high and critical),
2. **created after the feature was switched on** (switching on never mails a backlog; switching off and on restarts that clock),
3. no more than **24 hours** old (a long outage cannot dump a day-old pile on anyone), and
4. not yet in `alert_email_log` (the primary key on `alert_id` is what makes "already sent" a fact the database enforces).

The worker runs in the API process like the other background jobs, one copy across replicas (`scheduler_lock`), and only if `ALERT_EMAIL_WORKER_ENABLED=true`.

## What an email looks like

One message per cycle, listing up to **20** alerts, most severe first: tenant name, title, severity, rule, source, time, and a link to the console (`CONSOLE_PUBLIC_BASE_URL` + `/alerts/<id>`). More than 20 waiting? The rest follow in the next cycle's message ("N more alerts are waiting"), so an alert storm is at most one email per minute. Plain text only.

Alert text comes from monitored systems, so from attackers. Every alert-derived field is stripped of control, line-break, bidirectional-override and zero-width characters, collapsed to one line, length-limited, and has its links **defanged** (`http://` becomes `hxxp://`); the description and raw events are never included, and the only link is the console's own address plus the alert's UUID.

## Setting it up

1. **Entra app registration** (Microsoft Entra admin center): register an application; under *API permissions* add **Microsoft Graph → Application permissions → `Mail.Send`** and grant admin consent; create a **client secret** (note its expiry: when it expires, sending stops and the setting shows a token error until you replace it).
2. **Limit the app to one mailbox.** `Mail.Send` as an *application* permission lets the app send as **any mailbox in the tenant** unless you restrict it. Create a dedicated sender mailbox (for example `alerts@yourmsp.example`) and restrict the app to it with an Exchange Online application access policy or its newer replacement, RBAC for Applications. Do not skip this.
3. **Set the environment** on the API (secrets belong in your secret store, not in the repository; the API never returns them and the database never holds them):

   | Variable | Meaning |
   | --- | --- |
   | `ALERT_EMAIL_WORKER_ENABLED` | `true` to start the worker (default `false`) |
   | `ALERT_EMAIL_GRAPH_TENANT_ID` | the Entra directory (tenant) id |
   | `ALERT_EMAIL_GRAPH_CLIENT_ID` | the app registration's client id |
   | `ALERT_EMAIL_GRAPH_CLIENT_SECRET` | the client secret |
   | `ALERT_EMAIL_SENDER` | the sender mailbox address |
   | `CONSOLE_PUBLIC_BASE_URL` | the console's public address, for links (optional) |
   | `ALERT_EMAIL_POLL_INTERVAL_SECONDS` (60), `ALERT_EMAIL_MAX_ALERTS_PER_EMAIL` (20), `ALERT_EMAIL_MAX_ALERT_AGE_HOURS` (24), `ALERT_EMAIL_LOG_RETENTION_DAYS` (90) | tuning |
   | `ALERT_EMAIL_GRAPH_BASE_URL`, `ALERT_EMAIL_AUTHORITY` | for sovereign clouds or a test stand-in (defaults: commercial Microsoft cloud) |

4. **Choose recipients and send a test.** As a platform administrator:

   ```
   PUT  /api/v1/platform/alert-email        {"recipients": ["ops@yourmsp.example"], "min_severity": "high"}
   POST /api/v1/platform/alert-email/test   (sends one real message now; at most one every 10 seconds)
   PUT  /api/v1/platform/alert-email        {"enabled": true}
   ```

   or from a shell with database access: `python -m app.scripts.alert_email set --recipients ops@yourmsp.example --min-severity high`, `... test`, `... set --enable`. `GET /api/v1/platform/alert-email` (or `... status`) shows the setting, which environment variables are missing **by name**, warnings (for example "on, but the worker is switched off"), and the last error. `GET .../log` lists what has been emailed.

## When something is wrong

Failures are about the whole message (credentials, permission, throttling, network), so **only sent alerts are recorded**: everything unsent stays eligible, the (secret-scrubbed) error is stored on the setting where `GET` shows it, and the worker waits longer between attempts (up to 16 times the interval) until a cycle succeeds. Fixing the problem makes the backlog flow out, within the 24-hour age limit. A token refusal usually means a wrong or expired secret or tenant/client id; `403` / `ErrorAccessDenied` usually means the `Mail.Send` consent or the mailbox restriction; `429` and `5xx` are retried by themselves.

## Guarantees and limits

* **At-least-once.** If the process dies between Microsoft accepting a message and the log being written, the next cycle repeats it: a duplicate email is better than a lost alert. If two copies of the worker ever run at once (the lock fails open when Redis is down), the alerts they did not both log are still recorded, not re-sent.
* **Latency** is up to one poll interval (default 60 s) after an alert is stored.
* **Not built:** per-tenant recipients or tenant-admin notification (by design: platform administrators only), digests or quiet hours, HTML, attachments, escalation, replies. Alerts older than the age limit are never mailed.
* `alerts.created_at` is nullable in the schema; an alert a writer stored with an explicit NULL would never be mailed (fusion leaves it to the column default, `now()`).
* The Microsoft credentials are never in the database, never returned by the API, never logged; every error text is scrubbed of the secret and the access token.
