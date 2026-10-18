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
- **Platform health** reports whether the database enforces row-level security and whether UEBA has consumed any event.

## Not finished
| Area | Today | To finish |
|---|---|---|
| **Honeytokens** | The service makes decoy values (fake AWS key, URL, DB credential, e-mail, DNS name, file, API key) and records a trigger only when something POSTs `/api/v1/honeytokens/webhook/trigger` with the token id. That endpoint is deliberately not proxied by the API gateway (it is reachable only on the honeytokens service port, bound to 127.0.0.1), the generated URL, DNS and e-mail values use `example.com` names that AiSOC does not control, and a fake AWS key is known to no AWS account. So planting a token produces no alert by itself. | A canary the token can really call: a public, unauthenticated GET route on the API that records the visit (IP, user agent) and fires the alert, URL tokens pointing at it through a configured `HONEYTOKEN_CANARY_BASE_URL` (the address your planting location can reach), and honest guidance for the types that cannot be detected without outside infrastructure (AWS keys need CloudTrail, DNS needs a name server you run). Needs your decision on the public address. |
| **UEBA** | Healthy, and now reports `events_consumed`; it consumes no events because nothing publishes to `security.events`. | Connect a behavioural source (Entra/Okta/M365 sign-in logs) and bridge normalised logon events to the topic. |
| **Blumira entities** | Blumira findings carry an account and a country but no host, user or IP (checked against its API), so they make alerts and no entities. | Nothing to do on AiSOC's side; parsing free text for names would be guesswork. |
| **ATT&CK semantic search** | Embedding model is configurable (`AISOC_EMBEDDING_MODEL`), degrades with one warning; the gateway has no embedding model. | Add an embedding route to the gateway (provider/key decision), or set the variable to `off`. |
| **Hunt search** | The console's hunt search works (it searches the alerts AiSOC holds, through the API). The separate agents-service route `POST /api/v1/hunt/search` still answers 501 and nothing calls it. | Remove the dead route, or give it the lake. |
| **Effective permissions, non-AWS providers** | The console says the resolver is not wired to a live snapshot store. | Snapshot stores for Azure/GCP/Okta; each provider's collector. |
| **Community plugin install** | 501: only the package SHA-256 is stored. | Decide package storage and signing, or keep plugins admin-installed and remove the button. |
| **SAML / OIDC** | 501 until `SAML_IDP_SSO_URL` / `OIDC_ISSUER` + client id are configured (fails closed on purpose). | Configuration, needs an IdP. |
| **Slack approvals** | The Slack bot sends no verified approver identity, so `AISOC_ACTIONS_REQUIRE_PRINCIPAL` stays off. | Map Slack user to AiSOC user, send it as the approver, then turn the setting on. |
| **Evidence collection coverage** | Only controls the platform's own data can show are collected. | Attestation / policy-document upload for the rest. |
| **Entities page** | Ranked queue works; no "changed since yesterday" ordering. | Store the previous score snapshot and sort by delta. |
