/**
 * The user guide's text, shown on the Guide page. Keep it in step with docs/USER_GUIDE.md (the same text, for people who read it in the repository).
 * Written in the small markdown subset that src/lib/guide-markdown.ts reads: headings, paragraphs, lists, tables, rules, bold, italics and code.
 */
export const USER_GUIDE = `# AiSOC and CORE: how to use them

A working guide for the people who run the SOC day to day. It covers what each page does, where to click, and what to expect. It is written from the code as of **2026-10-19**.

**Reading the status notes.** Features marked **(new)** were added in October 2026 and have been tested against test data and a scratch database, but **not yet checked on the live stack**. Where something only collects data and does not alert, the guide says so. Section 14 lists what is not finished.

---

## 1. How the pieces fit

- **CORE** is the desktop app. It holds the credentials for your tools (Huntress, Blumira, Petra, NinjaOne, ThreatMate, Addigy, HaloPSA, CIPP and so on). AiSOC never stores those keys for the CORE-fed tools.
- **AiSOC** is the SOC console (a web app running in Docker, opened inside CORE). It stores alerts, devices, cases and scores, and shows them.
- **The loop.** Every 5 minutes CORE reads each connected tool and sends new alerts to AiSOC. Every hour it also sends each tool's client list and devices. A few jobs run in the background (sign-ins and identity changes from CIPP). CORE always opens the connection; nothing calls into CORE.
- **Clients.** You are the parent organization; each customer is a *client* (a child tenant). Alerts and devices are filed under the client they belong to. Anything that cannot be matched to a client waits, it is never thrown away.
- **Cipher** is CORE's AiSOC expert agent. It knows how all of this works and can explain a page or a symptom. It describes what the console shows; it does not click for you.

## 2. Getting around

The left sidebar groups the console:

| Area | Pages |
|---|---|
| Work | Dashboard, SOC Insights, **Alerts**, **Devices**, Investigation Queue, **Cases**, Hunt, Explore |
| Detection | Detection Rules, Detection Catalog, Vendor Detections, MITRE Coverage, Detection Tuning, Shifts |
| Intelligence | Threat Intel, Attack Graph, AI Copilot, Investigation Chat, Coverage Advisor, EASM |
| Client Security | **Client Posture**, **Multi-Factor**, **Secure Score**, **Sign-in Scores**, **Client Cleanup**, **Platform Health** |
| Response and testing | Playbooks, Marketplace, File Integrity, Honeytokens, Purple Team |
| Admin | Get started, **Connectors**, Roles & Permissions, Compliance, **MSSP Dashboard**, Team Analytics, SLA Tracking, Executive Digest, Cost Dashboard, Audit Log, **Settings** |

\`Ctrl+K\` opens a command palette that jumps to the main pages.

**Settings** has tabs (Profile, Notifications, Appearance, Deployment & AI, Audit log, About, and others) and a **More settings** list with **Auto-close** and **Tickets**. The client pages (Client Posture, Multi-Factor, Sign-in Scores, Client Cleanup, Platform Health) have their own **Client Security** section in the left sidebar.

## 3. Connecting tools in CORE

Open the **Connections** list in CORE.

- Tools are split into two sections, **connected** and **not connected**, each in alphabetical order, each with the tool's logo (a lettered badge where no logo exists).
- To connect a tool, open it and fill in its fields (API key, client id and secret, and so on). A tool counts as connected only when **all** its required fields are saved.
- A tool that is not connected is skipped silently; it never produces a card or an error in AiSOC.

Things worth knowing per tool:

- **Huntress.** One key reads incidents, **ITDR escalations** and **signals** (Managed ITDR, Footholds, Process Insights). Approving, rejecting or resolving a remediation from AiSOC needs a *user-based key with write permission*; the default read-only key is refused (403). Huntress's SIEM has no public API, so no SIEM alerts can come from it.
- **Blumira.** Findings arrive with a summary and the analysis text. Findings with a user or address create entities; some operational ones do not.
- **Petra.** Read only. Petra has no write API, so nothing can be actioned in Petra from AiSOC.
- **HaloPSA.** Needs its client id, secret and subdomain in CORE; without them tickets are not linked and the Halo card says so.
- **CIPP (new).** Connected through an Entra app (client id and secret) plus the CIPP address. Feeds clients, sign-ins and identity data (sections 9 and 10).
- **DNSFilter and AutoElevate (new).** Each provides its clients (to map) and its devices (they show with their logo on the Devices page). AutoElevate's API does not say which users own a computer, so machine names are the only evidence it gives.
- **ConnectWise Control (ScreenConnect).** If the account uses two-factor, add the **TOTP secret** in its settings; CORE then sends the one-time code itself.
- **ThreatMate, Addigy, NinjaOne, Field Effect.** Alerts and devices as described in sections 5 and 8.

On each tool's card in AiSOC (**Connectors**, named "<Tool> (via CORE)"):

- **Test** reports what CORE last said. It does not call the tool. It fails if CORE never reported, or has been silent for 15 minutes.
- **Sync** asks CORE to run that tool now; CORE picks the request up within about 15 seconds.
- The card shows only the latest message; the connection log keeps history. "Alerts are flowing, but ..." means alerts arrived and a side job (devices, clients, ticket links) failed.

## 4. Mapping clients (MSSP Dashboard > Client mapping)

Each tool has its own list of customers. Mapping says which of **your** clients each one is.

**What happens automatically**

1. **Name match.** A tool client whose name matches exactly one of your clients (ignoring words like LLC, Inc and punctuation) is linked for you.
2. **Machines in common (new).** While a tool client is unmapped, AiSOC remembers the machine names it reports. If most of them are already machines under one of your clients, that client is *suggested* (at least 3 shared machines and 40% of its machines; 2 and 70% for a small client). The suggestion says why, for example "5 of its 6 devices are already under this client".
3. **Auto-link (new).** A tool client is linked **without asking** only when *every* one of its non-generic machine names is already under one client, there are at least three, and no other client has any of them. Generic names are ignored: stock words (mac, server, user, desktop, laptop, pc, admin...), a stock word with a short number (server2, pc-01), the "Johns-MacBook-Pro" pattern, and anything under four characters. Windows random names (DESKTOP-4F8K2QH) *do* count because they are unique. Anything you mapped, unmapped or ignored is never touched.

**What you do**

- **Unmapped** lists what is waiting. Each row has a dropdown (suggestions first, then all clients, then "Add ... as a new client"), **Map**, and **Ignore**.
- **Suggest mappings for <tool>** pre-fills the best match for every row of that tool. **Approve all checked (N)** maps all ticked rows at once; **Select all shown** ticks them. **Ignore all checked (N)** moves every ticked row to the Ignored list (after a confirmation; each can be restored there), whether or not it has a client chosen.
- **Import all N from <tool>** creates a new client for every unmapped customer of that tool.
- **Mapped** lists links, each with **Unmap**. **Ignored** lists customers you do not manage, each with **Restore**.
- **Add clients automatically from** tick the tool that is your master client list; its clients become clients, others are mapped to them.
- **Move existing alerts to their clients** files alerts that arrived before a mapping existed. New alerts go to the right client automatically.
- Tabs along the top filter by tool; the number badge is how many are unmapped.

**Duplicates and merging**

- **Possible duplicates** shows near-identical client names. **Keep this one** merges the others into it; **Not a duplicate** remembers your answer.
- **Merge two clients** lets you pick one to keep and one to merge into it (**Merge**). The merge is logged and can be undone.
- A client you no longer want can be **Hidden** (MSSP Dashboard table, **Hide**/**Show**), **archived** (renamed "<name> (archived)", hidden, its tool clients sent back to Unmapped, nothing deleted), or removed. Removal is refused for a client with cases, connectors, worked alerts or audit records; archive it instead.
- **Remove all client tenants** (type REMOVE to confirm) starts over; **Archive instead (deletes nothing)** is the safe version.
- **Client cleanup (new).** **Client Security > Client Cleanup** lists visible clients that hold nothing (no devices, alerts, cases or mapped tool clients), each with an **Archive** button (it asks first). Nothing is deleted; Show hidden brings an archived client back.

## 5. Alerts

**Alerts** opens on **Open all** (every alert that is not resolved, closed or a false positive). The **Alerts / Entities** switch at the top changes the view; Alerts is the default.

**The list**

- Top tiles: Total, Critical, High, Unresolved and **No Halo ticket**. Click *No Halo ticket* to list open alerts with no ticket linked to any Halo ticket.
- A search box ("Search alerts, devices or clients"), plus severity, status, source and client filters.
- Click a row to see its summary in the panel on the right. Ctrl, Shift or middle-click opens the full alert.
- **Group repeats (new).** The *Group repeats* box in the filter bar shows one row for each group of repeat alerts: the same rule (or title) about the same machines and users. The row is the newest alert of the group and carries a **×N** badge saying how many there are. Different machines or users with the same rule stay separate. The tiles at the top still count every alert; the setting is remembered. Tested against the alert list; **not yet seen on live data.**
- **Link one ticket to several alerts (new).** Tick the boxes beside alerts; a bar appears with a ticket number field and **Link ticket**. It links that Halo ticket to every ticked alert (a leading # is dropped). If some fail, the rest stay linked and the ticks stay so you can retry. Ticks only count for the current page.

**The alert page**

- **Where and who:** company, device and user, with links into Huntress, NinjaOne or ThreatMate when CORE sent the portal link; the address; a **Source alert** link.
- **Click the device name** to open the Devices page already filtered to that machine.
- **Halo tickets:** linked tickets are clickable. **Add by number** links one by hand; **Remove** removes one you added. A ticket CORE linked that HaloPSA no longer has (it was deleted or merged since, so it reads *Not found in HaloPSA*) can be removed too; a ticket CORE matched that HaloPSA still has cannot, CORE would report it again.
- **Related alerts:** other alerts on the same device or user in the last 30 days.
- **Run script** (top right of an alert that names a machine) offers the NinjaOne scripts CORE's owner switched on (Settings > Manage NinjaOne scripts). Pick the script and the HaloPSA ticket for the result: a ticket the alert already has, another ticket number, or **Open a new ticket** (needs the client linked to a Halo client in Client mapping). AiSOC opens a case for the alert first if it has none. CORE then runs the script on the machine and puts the output, unchanged, on the ticket as a private note and on the case as a comment. A script marked **Run at once when asked from AiSOC** in CORE starts within about 15 seconds; any other waits for your approval card in CORE. A low-disk alert pre-selects the disk-space script when exactly one script is about disk space. The alert page lists each run under **Script runs** with how it went, and the case gets a system comment saying it was asked. Built and tested end to end in pieces; **not yet run against a live NinjaOne, and opening a new Halo ticket has not been tried against a live Halo.**
- **Refresh status** (top right of an alert from Huntress, Blumira or Field Effect) asks CORE to re-read that one tool now, instead of waiting for its next run, so the alert's status catches up with the tool's. Other tools are not re-read. A small "status checked 4 min ago" line under it shows when CORE last reported this incident's state (Huntress). The alert updates by itself within about a minute; it needs a write key and CORE must be running. Not yet tried against a live tool.
- **Huntress alerts:** the remediation plan with **Approve**, **Reject** and **Resolve** (needs a write key, see section 3). Resolving can leave a private note on each linked Halo ticket and change its **status**; it never closes the ticket.
- **Huntress ITDR escalations and signals** appear as alerts. They have no approve or resolve buttons.
- **Blumira** alerts carry the finding's summary and the analysis text.

**What AiSOC can change in other tools (and what it cannot).**
- **Huntress incident reports:** **Approve**, **Reject** and **Resolve** the remediation plan from the alert page. Resolve needs every remediation approved first. AiSOC queues the request and CORE does it at Huntress with its own write key (CORE collects requests every 15 seconds). Each action leaves a **private note** on the incident's HaloPSA ticket(s), and **Resolve** also moves the ticket to your chosen status (set in **Settings > Tickets**, default Tech Updated). It never closes a ticket. The private note has been confirmed on a test ticket; a live approve, reject or resolve, and the status change, have **not** been run yet.
- **Huntress ITDR escalations and signals:** read only. A signal's alert names the incident Huntress bundled it into and that incident's Halo ticket, and is resolved in AiSOC when that incident closes.
- **Blumira:** **Resolve** only, with a reason (Valid, False Positive, No Action Needed or Risk Accepted). Nothing is written to Halo.
- **Field Effect:** **Resolve** only. Nothing is written to Halo.
- **Petra, NinjaOne, ThreatMate, Addigy, DNSFilter, AutoElevate, CIPP:** read only from AiSOC.
- **HaloPSA:** AiSOC itself never writes to Halo. Only CORE does (the Huntress note and status above). **Add by number** records a link inside AiSOC and changes nothing in Halo.

**Statuses.** New alerts start as \`new\`. A vendor closing its own incident only closes the alert in AiSOC if nobody had touched it yet, and never reopens one. An analyst's decision is never overridden.

**Duplicates.** One vendor incident is one alert, even if CORE re-sends it; a repeat just updates "last seen".

## 6. Entities

**Alerts > Entities** ranks users, hosts, addresses and domains by risk. Each alert adds points to what it names (critical 40, high 20, medium 8, low 3, info 1). Scores halve every 4 hours. At **80** an entity is *promoted*. Entities expire after 24 hours without new alerts, so there are fewer entities than alerts. A dash means unknown, not zero. Sort by **Highest score** or **Heating up** (points in the last four hours); **New** and **Rising** badges mark movement. Alerts with no host, user or address (some Blumira findings) create no entity.

## 7. Cases

- **Act now board (new).** Above the status tiles, one sentence says how many cases are open and how many have no owner ("12 open cases, 8 with no owner. Start with Ransomware Attempt."), and three cards show the first cases to work: most severe first, then ones nobody owns, then the oldest. It is shown on the **Open** and **All** tiles and reads the cases loaded on the page.
- **Devices panel (new).** A case's left column lists the machines its alerts are about, each with **Open in NinjaOne** / **Open in Huntress** buttons to that machine in the tool, and **In Devices** to its page here. A tool appears only when AiSOC holds a link for it: NinjaOne from the device record, Huntress from the alert. Other tools (ConnectWise Control, HaloPSA assets) are not linked yet. The case description is also laid out with headings and tables now, and a linked alert opens that alert. Built and tested; not yet seen on a live case.
- **My organization / All clients (new).** An organization with clients has a switch above the tiles. **All clients** lists this organization's cases and every client's together, each client's case showing its client name, and the tiles count all of them. A **Client** picker narrows it to one. Opening a client's case works like opening its alerts. The choice is remembered in this browser. (Cases opened for client alerts live under that client, which is why "My organization" shows far fewer.)
- Opens on **Open** (new and triaged). The tiles are **Open, In Progress, Resolved, Closed** and **All Cases**, last; the numbers come from the whole caseload, not one page.
- The list loads up to 500 cases, newest first, and tells you when it is cut short. (It used to show only 50, which is why the numbers never moved.)
- Status only moves forward: new, triaged, investigating, contained, resolved, closed. Steps can be skipped; going back is refused with the reason.
- CORE opens a case automatically for each new alert from its tools (limited per run); an analyst can open one by hand.

## 8. Devices

One row per machine, combined from every tool that reports it (matched on serial number, then name). Tools: NinjaOne, Addigy, Huntress, Blumira agents, ThreatMate, and **DNSFilter and AutoElevate (new)**. Phones and tablets never count as "missing" from ThreatMate, Huntress or Ninja.

**Tiles and filters**

- Client and tool pickers, search (name, serial, client or any IP address).
- **Not in master**, **Missing from Huntress / ThreatMate / Addigy** (Addigy only for Macs), **Offline 7+ days**, **With open alerts**, **Needs attention**, **Stale agents**, **Hidden until online**.
- **Needs attention** means: Huntress Defender, firewall or tamper protection unhealthy; an agent silent for 14 days while another tool says the machine is online; ThreatMate pending restart; or a ThreatMate critical finding with a known-exploited CVE and an upgrade ready.
- **The page remembers your filters (new)** in this browser (client, tool, missing-from, attention, stale, offline, has alerts). Search and the hidden list are not remembered.

**Per row.** Click a row to expand it: each feeding tool and the name it uses, specs, what needs attention, and **Show alerts (N open)**, which lists the alerts that name this device.

**Offline devices.**
- A device offline can be **Hidden until online**; it is left out of every count until any tool sees it online again. The **Hidden until online** tile lists them, each with **Show again**.
- A device offline **10 days or more** stays in the list and the offline count, but is left out of attention, stale agents, not-in-tool and open-alert numbers and the client summary, and the page says how many.

**Client summary table.** Above the list, per client: devices, needing attention, stale agents, not in Huntress, offline. Worst first.

**Export CSV.** Exports the filtered list (client, device, serial, OS, tools, last online, needs attention, open alerts). Cells that start with \`=\`, \`+\`, \`-\` or \`@\` get a leading apostrophe so spreadsheets do not run them as formulas.

**Merged automatically (new).** Devices in one client are merged without asking when they are plainly one machine seen by different tools. A name can be held by several records at once (one per tool not yet matched, up to six), and they are folded into the one that holds the most tools, each only when: the name is not a stock one (server, MacBook-Pro...), no tool reports both, no two different serial numbers, and operating systems that do not disagree. A name on more than six devices is left alone. Each merge is logged under **Recent merges** with **Undo**, and an undone merge is never redone. The merged device keeps every tool's feed. Anything less certain stays in Possible duplicates.

**A tool that has gone quiet (new).** A tool's badge on a device gets a **red line through it** when that tool has not seen the device for 10 days or more (hover for how long). When every tool that reports a check-in time is that quiet, the device **hides itself** (it is counted under Hidden and says "no tool has seen it for 10+ days") and comes back by itself as soon as one tool sees it again. A tool that gives no time (ThreatMate) cannot keep a device on the list, and a device any tool says is online right now is never hidden.

**Not in ScreenConnect / Not in Field Effect (new).** Two more coverage tiles, shown only once that tool feeds devices into AiSOC. Not in ScreenConnect leaves out iOS and macOS devices; Not in Field Effect leaves out phones and tablets. AiSOC cannot tell Field Effect EDR from MDR coverage, so any Field Effect record counts as covered. CORE now sends both: ScreenConnect's machines (by name, with whether each is connected and when it last reported; its companies are mapped to clients like any other tool's) and Field Effect's endpoints (name, serial, OS, online and last seen). ScreenConnect's login needs the **ManageSessionGroups** permission. Read live against your instances; **not yet seen on the Devices page**, and the ScreenConnect companies need mapping on the Clients page before their machines land under the right client.

**Duplicates.** Possible duplicates (same name, no serial proving they differ) can be compared and **Merged**. **Recent merges** (last 14 days) each have **Undo**, which brings the removed device back with its feeds. **Dismiss** remembers they are different machines.

## 9. Identity (all new, from CIPP through CORE)

CORE reads each Microsoft 365 tenant through CIPP in the background.

**Sign-ins (hourly).** Only tenants with Entra ID P1 or better have a sign-in log (about half). Each sign-in is stored once for 45 days and scored by the behaviour service on: hour of day, failed, no MFA, non-interactive, Microsoft risk, new country, new address. **Scoring only: no alert is raised.**

**Identity changes (hourly).** The directory audit log works for *every* tenant, whatever the licence. Role and group changes, password resets, security-method registration, app consent and license changes are stored and scored by who did them. Device, provisioning and read-only noise is dropped. Scoring only.

**Multi-Factor (daily).** Per person: registered, and whether anything requires it.

**Client Security > Multi-Factor**
- Per client: people, covered %, **Registered, not required**, **No Multi-Factor**, **Administrators without**.
- A **Search clients** box narrows the table, and clients are listed A to Z.
- Click a number to see the people (administrators first, marked). A link from Client Posture opens straight to one client's list.
- The filter **Only clients with administrators that have no Multi-Factor** narrows the table.
- Counts cover enabled, licensed member accounts (shared mailboxes, guests and disabled accounts are left out).

**Secure Score (daily).** The score Microsoft gives each tenant's Microsoft 365 setup (current points out of the maximum), with up to 90 days of daily points, Microsoft's average across all tenants, and the controls still missing the most points. Read through CIPP; read-only, nothing is changed in a tenant. **New; built and tested, not yet seen on live data.**

**Reports > Client Review (new).** Pick a client to see, on one printable page: a **cyber-insurance readiness** checklist (each answer **Met**, **Partly**, **Not met** or **Not known**, with the numbers behind it), **tool coverage** (how many of the client's computers each tool reports, with phones and tablets never counted against a tool that has no agent for them), Multi-Factor and Microsoft Secure Score, and the last 30 days of alerts and cases. **Print or save as PDF** makes a copy for a client review or a questionnaire.
- The checklist covers Multi-Factor for everyone and for administrators, endpoint detection, management, web filtering, privilege control, agents checking in, known-exploited vulnerabilities and the Microsoft Secure Score. Backups, e-mail filtering, awareness training and a written incident plan are always **Not known**: AiSOC does not collect them yet.
- Thresholds: endpoint detection and management need 95% of computers to be Met (80% Partly); Multi-Factor needs 95% of people (80% Partly) and **no** administrator without it; the Secure Score needs 60% (40% Partly).
- **From vCIO Toolbox (new).** When vCIO Toolbox is connected in CORE and its customers are mapped to clients on the MSSP page (**vCIO Toolbox** tab), the review also shows that client's recommendations (how many are pending, adopted and declined, and the pending ones that matter most: high priority first, then the earliest due) and its risks with their scores. CORE reads this once a day. vCIO Toolbox's API does not give the IT-review answers themselves (the Engineer and CIO review text), so those are not shown. **Not yet seen on live data.**
- It is evidence from the connected tools, not a certification, and a missing tool shows as **Not known**, never as a guess. **New; built and tested, not yet seen on live data.**

**Client Security > Secure Score**
- Per client: the score as a bar with its percentage and points, the **30 days** change (+ or -), a small **Trend** line, Microsoft's average for comparison (amber when the client is below it), and the people count.
- **Order by** lowest score first (the default), biggest 30-day drop first, or client name; **Search clients** narrows the table. The line above it says how many clients have fallen in 30 days.
- Click a client's name to see the controls that would add the most points: the points, Microsoft's title for the control, its user impact and cost, and what the tenant has now.
- A client appears after CORE's next daily CIPP read, once its CIPP tenant is mapped to a client on the MSSP page.

**Client Security > Sign-in Scores**
- The sign-ins the behaviour service flagged as unusual for that person, across clients, with person, client, when, where, address, app, result, "no MFA" and risk. Pick **Last day / 7 days / 30 days**. The service keeps a score only for the ones it flags, and flags little while it is still learning each person's pattern, so an empty list early on is normal.
- Below it, **Identity changes**: the directory changes flagged as unusual for whoever made them (who did what to whom).
- Higher scores are more unusual. This page is for judging whether the scores are useful before alerting is switched on.

CIPP tenants appear under Client mapping like every other tool; data for an unmapped tenant waits until it is mapped.

## 10. Client posture (new)

**Client Security > Client Posture.** Pick a client to see, side by side: devices (total, needing attention, stale agents, not in Huntress, offline), Multi-Factor coverage, open alerts (total, critical, high, **open with no ticket**) and open cases. **Print** produces a page for a client review. **Every number is a link** to the list behind it, already filtered to that client: devices needing attention (Devices page), people with no Multi-Factor (Multi-Factor page), critical alerts or open alerts with no ticket (Alerts page), open cases (Cases page). A client with no CIPP data says "No Multi-Factor data yet".

## 11. Platform health

**Client Security > Platform Health** refreshes every 15 seconds.

- Whether each internal service answers.
- **Needs-attention list (new):** database migrations shipped with the API but not applied (rebuild or restart), disk 85% or more full, device feeds with nothing for 3+ hours, sign-ins stored but none scored (check the behaviour service token). Services that are down and a silent CORE keep their own notes.
- **CORE silent** warning after 15 minutes without a report. While it is silent no new alerts, devices or links arrive.
- Database connection use and the busiest point in the last hour; per-tool device feed freshness; and how many sign-ins were collected and scored in the last 24 hours.
- A warning when the database does not enforce row-level security (the stack connects as a database superuser by default).

## 12. Tickets and auto-close

- **Settings > Tickets:** the HaloPSA **status** a resolved incident moves its ticket to (default **Tech Updated**). It only updates the status; it never closes a ticket. The private-note part has been confirmed on a test ticket; the status change has **not** yet been run on a live ticket.
- **Settings > Auto-close:** how sure AI triage must be (default 0.85) before it closes an alert itself. A tenant can set its own.

## 13. Everything else, briefly

- **Hunt:** searches the alerts AiSOC holds (plain words, "quoted phrases", \`field:value\` for severity, status, source, host, user, ip, tag, title, client; a leading minus negates). It is not KQL or SPL and searches no raw event store. Saved hunts can run on a schedule (off by default).
- **Detection Rules:** Sigma, KQL and EQL. KQL honours and, or, not and parentheses. EQL supports \`sequence by <field> with maxspan=<N>m [...] [...]\`. The rule editor can **test** a rule against pasted sample events.
- **Threat Intel:** indicators open to show what is known, the alerts they were seen on, a provider lookup (only when you press the button) and a VirusTotal link. Indicators pulled out of alerts are not confirmed malicious.
- **Attack Graph:** hosts, users, addresses and ATT&CK techniques from the last 30 days of alerts.
- **EASM:** external attack-surface scans. Needs Shodan or Censys keys, or the active scan switched on with IP targets, otherwise a scan finds nothing to record.
- **Honeytokens:** only a link or a document carrying a beacon link can alert; every other type is "Decoy only" and nothing watches it.
- **Compliance:** evidence items with a tamper-evident hash chain; controls that need a policy document stay "missing" rather than invented.
- **Approvals and actions:** risky actions (isolate host, disable user, reset password...) always wait for a person.
- **Backups:** \`./scripts/local-backup.sh\` (database and Qdrant); it does not back up ClickHouse, Redis, Neo4j, OpenSearch or your \`.env\` secrets. Keep the credential key safe separately.

## 14. What is not finished, and what has not been checked live

**Not live-checked yet (built and tested on test data):** the Halo status change, ConnectWise Control TOTP, DNSFilter and AutoElevate clients and devices in the running app, Huntress escalations and signals, the CIPP sign-in and identity jobs and their scoring end to end, device auto-link on real clients, the Multi-factor, Sign-in scores, Client posture and cleanup pages, bulk ticket linking, the Devices filter memory, the Platform health needs-attention list, and the connector logos in a packaged installer.

**Scoring only, no alerts yet:** sign-in anomalies and identity changes. Turning a high score into an alert is waiting until a few days of real scores have been reviewed.

**Known gaps:** UEBA only scores what CORE feeds it; Okta and Google Workspace sign-ins are not collected; Slack approvals carry no verified approver; SAML and OIDC are off until configured; community plugin install is not available; alerts are never purged unless retention is set; the database role is a superuser, so row-level security is not enforced by default; the embedding model for ATT&CK semantic search is not set up; Petra and Huntress SIEM cannot be actioned or read through any API.

## 15. When something looks wrong

| Symptom | Look at |
|---|---|
| No new alerts | Platform health: is CORE silent? Is CORE running and able to reach AiSOC? |
| A tool's card is red or yellow | Open its card, read the latest message, press **Sync**, then **Test** |
| A client's devices or alerts are missing | Client mapping: is it still Unmapped? |
| Tickets not linking | Is HaloPSA connected in CORE? The card message says which part failed |
| Cases or counts look frozen | Reload; counts come from the whole caseload now |
| A page says a migration is pending | Rebuild or restart the AiSOC API |
| Sign-ins stored but not scored | Platform health list; check the behaviour service token in the API's environment |
| "N sign-ins are waiting to be scored" | Normal for a while after a restart: they are scored a hundred at a time. If it is not falling, ask Cipher to check the behaviour service log |
| Sign-in scores page is empty | Normal early on: it lists only sign-ins the service flags, and it flags little until it has learned each person |
| No Huntress ITDR alerts | They are read back 30 days when CORE starts; check the Huntress card for a warning |
| Not sure what a page means | Ask Cipher |

---

*Source of truth: the code and \`docs/INCOMPLETE_FEATURES.md\`. Cipher's notes in CORE (\`agents/cipher/knowledge\`) carry the same detail with file references.*
`;
