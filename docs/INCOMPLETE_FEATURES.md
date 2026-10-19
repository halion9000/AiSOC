# Features that are not finished (reviewed 2026-10-17, updated 2026-10-18)

Each entry says what is missing, how it fails today (every one fails closed or says so; none invents data), and what finishing it takes.

## Finished since the first review
- **Compliance evidence collection** (`POST /compliance/evidence/collect`) records platform-derived evidence (accounts, monitoring coverage, incident handling) as pending items; the framework pages are real; DORA has controls.
- **EASM page** lists assets and drift and can start a scan.
- **Attack Graph**: `GET /api/v1/graph` did not exist, so the page always said "unavailable". It now returns a graph built from recent alerts (entities, ATT&CK techniques, who was seen with what).
- **Threat intel indicators** open to show what is known, the alerts they were seen on, a provider lookup and a VirusTotal link.
- **Cases**: a case can skip forward (new to in progress) and a refused change shows the API's reason.
- **Per-connector push URLs** (`ait_` tokens from "Reveal push URL") resolve in ingest; they used to answer 404.
- **Alert retention** can be switched on (`RETENTION_ALERTS_DAYS`, default 0 = never).
- **Huntress incidents** carry a device name (looked up from the Huntress agent), so they create host entities.
- **Entity promotion** can open a case (`AISOC_RBA_OPEN_CASE`, default off); a tenant can set its own **auto-close confidence** (Settings > Auto-close); **Kafka triage** can be limited per tenant (`AISOC_BUDGET_MAX_LLM_RUNS`, default no limit); stored **Huntress alerts** get a device name for open incidents through `POST /core-feed/{token}/device-names` (closed ones stay as they are).
- **Entities page** can be ordered by "Heating up" (points picked up in the last four hours) and shows New / Rising badges.
- **EQL sequences** (`sequence by host with maxspan=5m [process where ...] [network where ...]`) are matched in order across events, per `by` value and within the span; events without a readable time are an error, not a guess.
- **KQL rules** honour `and` / `or` / `not` and parentheses (they used to match on the first condition alone); **EQL** handles single-event conditions and refuses `sequence` rules instead of approximating them.
- **Devices**: Huntress agents (protection state, check-in age, Defender, tamper protection), Blumira agent devices (for a client whose licence includes the agent) and ThreatMate open-finding counts and pending restarts are now device sources. The Devices page has "Not in Huntress" and a "Needs attention" filter. ThreatMate devices are flagged when they have a critical finding, a known-exploited CVE and an upgrade ready.
- **Honeytoken links** work: opening one raises an alert (locally by default; see below for the other types).
- **Platform health** reports whether the database enforces row-level security and whether UEBA has consumed any event.

## Not finished
| Area | Today | To finish |
|---|---|---|
| **Simulated actions** | An action with no vendor credentials is rehearsed. The actions service now stores and returns `simulated: true` on its record (it used to drop the flag). Nothing in the console, the case timeline or the audit log reads action records yet: agents and the API do not call the actions service's `/actions`, so there is no page to label. | When playbooks start submitting actions, write the outcome (with `simulated`) to the case timeline and audit log and label it on the case page. |
| **Graph extractors** | Sources without their own extractor (CrowdStrike, Sentinel, Splunk, Cloudflare, PagerDuty and others) use the generic one: fewer nodes, no detail. | Write the per-source extractors listed in `services/ingest/internal/graph/extractor.go`. |
| **SentinelOne** | Kill-by-PID and run-script raise NotImplementedError by design (the vendor has no such API); playbooks must choose CrowdStrike. | None on AiSOC's side. |
| **Honeytokens: types other than links** | A **link** (and a **document carrying a beacon link**) now alerts when opened (the visit is recorded and a high-severity alert is raised in the token's tenant, one per token per hour): it points at `GET /api/v1/canary/<token id>` on `HONEYTOKEN_CANARY_BASE_URL` (default `http://localhost:3000`, this machine's console). Every other type (AWS key, database login, e-mail, DNS name, API key, custom) is a decoy value and the page says "Decoy only": nothing watches for it. | AWS key: CloudTrail wired to AiSOC. DNS: a name server you run. E-mail: a mailbox AiSOC can read. Logins: that system's logs. For a link planted where other machines will find it, set `HONEYTOKEN_CANARY_BASE_URL` to an address they can reach (LAN or public). |
| **UEBA** | Healthy and now fed: CORE reads each Microsoft 365 tenant's sign-in log through CIPP every hour and posts it (`POST /inbox/core-feed/{token}/signins`); AiSOC stores each sign-in once (45 days), turns it into features (hour, failed, no MFA, non-interactive, risk, new country, new address) and has the UEBA service score it. **Scoring only: no alert is raised from an anomaly yet.** Only tenants with Entra ID P1 or better have a sign-in log (about half of 125 on the live CIPP). | **Alerting (pending, decided 2026-10-19):** turn a high anomaly score into an alert, after a few days of scores have been looked at. Also: Okta and Google Workspace sign-ins, and a per-person view of the scores. |
| **Blumira entities** | Blumira's finding record has no host, user or IP, but its evidence does (a sign-in's user and client address, an endpoint detection's machine). CORE now reads the evidence of each new finding (up to 150 per run) and sends them, so findings create entities: about 4 in 10 findings name a user and a third an address (measured on a live estate); findings with no such field (some Google Workspace and operational alerts) still make alerts only. | Findings beyond the per-run limit on a first sync go without; nothing else to do on AiSOC's side. |
| **ATT&CK semantic search** | Embedding model is configurable (`AISOC_EMBEDDING_MODEL`), degrades with one warning; the gateway has no embedding model. | Add an embedding route to the gateway (provider/key decision), or set the variable to `off`. |
| **Effective permissions, non-AWS providers** | The console says the resolver is not wired to a live snapshot store. | Snapshot stores for Azure/GCP/Okta; each provider's collector. |
| **Community plugin install** | 501: only the package SHA-256 is stored. | Decide package storage and signing, or keep plugins admin-installed and remove the button. |
| **SAML / OIDC** | 501 until `SAML_IDP_SSO_URL` / `OIDC_ISSUER` + client id are configured (fails closed on purpose). | Configuration, needs an IdP. |
| **Slack approvals** | The Slack bot sends no verified approver identity, so `AISOC_ACTIONS_REQUIRE_PRINCIPAL` stays off. | Map Slack user to AiSOC user, send it as the approver, then turn the setting on. |
| **Evidence collection coverage** | Only controls the platform's own data can show are collected. | Attestation / policy-document upload for the rest. |
