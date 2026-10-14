# What AiSOC needs from each tool, and how clients get matched

Status: working plan (2026-10-13). "Live" = CORE already forwards it. Everything else is a candidate, ordered by value.

## Path of the data
CORE holds the vendor credentials, polls every 5 minutes, and posts normalized records to AiSOC's push inbox (generic-json, class 2001). Status per source goes to `/api/v1/inbox/core-feed/{token}/status` and shows on the Connectors page.

## Per AiSOC area: which tool feeds it

| AiSOC area | Needs | From | State |
|---|---|---|---|
| Alerts, Queue, Dashboard | Detections/incidents with severity, time, client | Huntress incident reports, Blumira findings, Petra incidents | Live (Blumira unverified on a real account) |
| Cases, Investigate | Related events per user/host, ticket context | Huntress agent_id, Petra user UPN, Halo PSA tickets | Partly (Halo via MCP, not forwarded) |
| Identity (graph, timeline, insider threat) | Sign-ins, risky users, MFA state, account enabled | Microsoft 365/Entra (sign-in + risk), Petra (compromised UPNs), LastPass/Keeper (vault events) | Petra live; Microsoft not yet |
| Hunt, Explore | Raw events in the lake | Everything above, plus Meraki/UniFi/Auvik network logs | Blocked: ClickHouse lake unreachable from aisoc-api |
| UEBA | Per-user baselines | Microsoft sign-ins, Petra failed-attacks (/v1/failed-attacks, per tenant, by country and user) | Not started |
| EASM | External assets, exposure | ThreatMate, Field Effect, DNSFilter (domains/categories) | Not started |
| FIM | File integrity | Huntress/NinjaOne agents (AiSOC uses osquery itself) | N/A for now |
| Coverage advisor | Which log sources exist per client | Connector inventory per client | Needs client mapping first |
| Detection rules, Noise tuning | Source field names, false-positive feedback | Per-vendor field maps | Per source as added |
| Honeytokens, Purple team | Triggers/alerts | AiSOC's own | None needed |
| Threat intel | Indicators | Huntress indicator_types, DNSFilter blocks | Not started |
| Assets (inventory) | Devices and owners | NinjaOne, Addigy, Huntress agents, Auvik, Meraki/UniFi, Datto | Not started |
| Compliance, Reports, SLA | Per-client counts and posture | Petra posture reports, Liongard/ITGlue/Hudu docs, NinjaOne patch state | Not started |
| Copilot / Cipher | All of the above, scoped to one client | The feed + client mapping | Works on what is live |
| MSSP (children, metrics, cross-tenant incidents) | One AiSOC tenant per client | Client list from Petra `/v1/tenants`, Halo clients, NinjaOne organizations, Huntress organizations | Needs the work below |

## Sources to add next (only where official docs confirm the call)
1. Microsoft 365 / Entra sign-in and risk detections (Graph) - highest identity value.
2. NinjaOne alerts and device inventory.
3. Petra `/v1/failed-attacks` (per tenant) for UEBA/trends; `/v1/tenants` as the client import source.
4. Auvik alerts, DNSFilter threat blocks, Field Effect, Datto SaaS, Meraki/UniFi events.
Each needs its own adapter + tests in `hud/src/aisoc-feed.ts`.

## Client import and mapping (design)
Problem: the same customer is "Acme Dental, LLC" in Petra, "Acme Dental" in Huntress, "ACME" in NinjaOne. Events must land under one AiSOC tenant.

Reading taken: "map section" = a Clients mapping screen under MSSP. If you meant another place, say so.

Data model (new table `client_aliases`): `(id, parent_tenant_id, child_tenant_id, vendor, vendor_client_id, vendor_client_name, normalized_name, match_source[auto|manual], created_at)`, unique on `(parent_tenant_id, vendor, vendor_client_id)`.

Flow:
1. Import: pick a source (Petra tenants first; later Huntress organizations, NinjaOne organizations, Halo clients) and choose which clients to create as MSSP child tenants. Nothing is created without confirmation.
2. Suggest: for each vendor client not yet mapped, propose a child tenant by normalized name (lowercase, strip punctuation and suffixes like LLC/Inc/Co, collapse whitespace) with a score; exact normalized match is auto-suggested, near matches ranked.
3. Override: the person accepts, picks a different tenant, or marks "ignore". Manual choices are never overwritten by suggestions.
4. Route: CORE forwards `context.client_name` (and vendor ids) already; AiSOC resolves the alias to a tenant, and unmapped clients go to a visible "Unmapped" bucket instead of being dropped.

Out of scope until you confirm: auto-creating tenants without review; per-client inbox tokens.
