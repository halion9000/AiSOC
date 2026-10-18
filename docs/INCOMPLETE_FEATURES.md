# Features that are not finished (reviewed 2026-10-17)

Each entry says what is missing, how it fails today (every one fails closed or says so; none invents data), and what finishing it takes.

## Finished in this review
- **Compliance evidence collection** (`POST /compliance/evidence/collect`): it answered `queued` and queued nothing. It now records platform-derived evidence (accounts, monitoring coverage, incident handling) as pending items. The framework pages replace the "not available" placeholders.
- **EASM page**: now lists assets and drift and can start a scan; scan no longer needs the console to know its tenant id.

## Not finished
| Area | Today | To finish |
|---|---|---|
| **UEBA** | Service is healthy but consumes no events: no behavioural source (sign-in / logon events) feeds its topic. | Connect a source (Entra/Okta/M365 sign-in logs) and bridge normalised logon events to the UEBA topic. Needs a connected source to verify. |
| **ATT&CK semantic search** | Embedding model is configurable (`AISOC_EMBEDDING_MODEL`) and degrades with one warning; the gateway has no embedding model behind it. | Add an embedding route to the LiteLLM gateway (provider/key decision), or set the variable to `off`. |
| **Hunt search** (`agents` `POST /api/v1/hunt/search`) | Answers 501: not connected to an event store. | Route it to the data lake (the API's lake SQL / the saved-hunt executor already query it) with the service token. |
| **Effective permissions, non-AWS providers** | Console says the resolver is not wired to a live snapshot store. | Snapshot stores for Azure/GCP/Okta; each provider's collector. |
| **Community plugin install** | 501: only the package SHA-256 is stored, not the package. | Decide package storage and signing, then store and install; or keep plugins admin-installed and remove the button. |
| **SAML / OIDC** | 501 until `SAML_IDP_SSO_URL` / `OIDC_ISSUER` + client id are configured (fails closed on purpose). | Configuration, not code; needs an IdP. |
| **Slack approvals** | The Slack bot sends no verified approver identity, so `AISOC_ACTIONS_REQUIRE_PRINCIPAL` stays off. | Map Slack user to AiSOC user, send it as the approver, then turn the setting on. |
| **DORA framework** | Listed on the Compliance page but has no control list. | Add its controls to `FRAMEWORKS` in `compliance.py`. |
| **Per-tenant auto-close threshold** | One global `AISOC_AUTO_CLOSE_THRESHOLD`. | A tenant setting (table + admin UI) read by the triage agent. |
| **Evidence collection coverage** | Only controls the platform's own data can show are collected. | Attestation / policy-document upload for the rest (CC1.1, CC8.1, training controls). |
| **Entities page** | Ranked queue works; no "changed since yesterday" ordering. | Store the previous score snapshot and sort by delta. |
