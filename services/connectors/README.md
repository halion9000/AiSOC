# AiSOC Connectors Service

A Python/FastAPI service that polls external security sources on a schedule,
normalises raw events into OCSF, and forwards them to the ingest pipeline.

---

## Highlights

- **Click-and-connect** — add a source via the UI wizard; credentials are
  encrypted at rest with Fernet (`CredentialVault`) before they leave the
  API service.
- **Registry-based discovery** — drop a `BaseConnector` subclass into
  `app/connectors/` and register it in `__init__.py`. No other wiring needed.
- **APScheduler polling** — one in-process job per enabled connector
  instance, 5-min default cadence, configurable per-instance.
- **Federated search** — translate a single query into SPL, KQL, and ES|QL
  and fan out to connected SIEMs.
- **Four-tier severity** — vendor-native ladders collapse into
  `info | low | medium | high` in every connector's `normalize()` method.

---

## Supported connectors

| Connector              | Category | Source                       |
|------------------------|----------|------------------------------|
| AWS Security Hub       | cloud    | SecurityHub findings         |
| Azure Activity         | cloud    | Azure Resource Graph API     |
| Azure Defender         | cloud    | Microsoft Defender for Cloud |
| Azure Entra            | iam      | Microsoft Entra ID (AAD)     |
| Cloudflare             | cloud    | Cloudflare security events   |
| CrowdStrike            | edr      | CrowdStrike Falcon           |
| Elastic                | siem     | Elasticsearch / Elastic SIEM |
| GCP Cloud Audit        | cloud    | Google Cloud Logging API     |
| GCP SCC                | cloud    | Security Command Center      |
| GitHub                 | vcs      | GitHub Audit Log API         |
| Google Workspace       | saas     | Google Reports API           |
| M365 Audit             | saas     | Office 365 Management API    |
| Microsoft Sentinel     | siem     | Azure Log Analytics          |
| Okta                   | iam      | Okta System Log API          |
| Splunk                 | siem     | Splunk REST API              |
| Tailscale              | network  | Tailscale audit log API      |

---

## Quick start

```bash
# From the repo root
cp .env.example .env          # set AISOC_CREDENTIAL_KEY, DATABASE_URL, etc.
pnpm docker:dev               # bring up Postgres, Redis, Kafka, etc.

# Run the service
cd services/connectors
python -m uvicorn app.main:app --reload --port 8003
```

Disable the polling scheduler in tests:

```bash
AISOC_CONNECTORS_DISABLE_SCHEDULER=1 pytest
```

---

## Outbound request guard (SSRF)

Connectors call hosts that come from the tenant's own configuration (a Jira or Splunk `base_url`, an Okta domain, ...), and `POST /api/v1/connectors/test` forwards that configuration here, so the service refuses destinations that are never legitimate. Every `httpx` client the service creates, **including each hop of a redirect**, is checked:

* refused: a non-http(s) scheme, loopback, link-local (this contains the cloud metadata address `169.254.169.254`), the unspecified address, multicast, reserved ranges, and the metadata addresses outside link-local (`fd00:ec2::254`, `100.100.100.200`); a hostname is refused if **any** address it resolves to is refused;
* allowed: private ranges (RFC1918, unique-local), because on-prem integrations live there; names that do not resolve (the request fails by itself).

| Variable | Effect |
| --- | --- |
| `CONNECTORS_EGRESS_ALLOW_HOSTS` | Comma-separated hostnames or IPs that are always allowed. |
| `CONNECTORS_EGRESS_ALLOW_LOOPBACK=1` | Allow loopback, for local development where the platform's services are on `localhost`. Metadata addresses stay blocked. |
| `CONNECTORS_EGRESS_GUARD=0` | Turn the guard off. |

The host of `INGEST_SERVICE_URL` (this service's own peer) is always allowed. Limits: resolve-then-connect leaves a DNS-rebinding window, so this narrows the surface but is not a network egress firewall; a network policy denying the metadata address from this service remains the stronger control. A blocked request surfaces as an `httpx.RequestError`, so connectors' existing network-error handling reports it.

## Writing a new connector

1. Create `app/connectors/<name>.py` and subclass `BaseConnector`.
2. Implement `schema()`, `test_connection()`, `poll()`, and `normalize()`.
3. Add your class to `_CONNECTOR_CLASSES` in `app/connectors/__init__.py`.
4. Add a marketplace manifest at `plugins/<connector-id>/plugin.yaml`.
5. Add a docs walkthrough at `apps/docs/docs/connectors/<connector-id>.md`.
6. Run `pnpm marketplace:sync` and `pytest`.

See `CONTRIBUTING.md` in the repo root for the full checklist.

---

## Tests

```bash
cd services/connectors
python -m pytest tests/ -v
```

Current suite covers schema contracts, polling, normalisation,
federated query translation, and credential decryption.
