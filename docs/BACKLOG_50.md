# Improvement backlog (written 2026-10-18)

Status as of this file: **Done** = built, tested, pushed. **Ready** = safe to build, not started. **Needs Hal** = a decision, credential or live system is required.

## Devices
1. Search by IP address — Done
2. "Last online" counts Huntress check-ins — Done
3. CSV export of the filtered list (formula-safe cells) — Done
4. Per-client rollup table — Done (earlier)
5. Stale-agent card and filter — Done (earlier)
6. Merge undo — Done (earlier)
7. Per-device "Open in <tool>" links on the device row — Ready
8. Saved filters ("my attention list") per user — Ready
9. Device detail drawer with each tool's raw fields side by side — Ready
10. Weekly digest of newly stale/needing-attention devices per client — Ready
11. Retention of old merge-log rows (older than the undo window) — Ready

## Alerts
12. Company/device/user/ticket context on the alert page — Done
13. Manual ticket link — Done
14. Related alerts — Done
15. Clickable tool links — Done
16. Bulk "link ticket to these alerts" — Ready
17. Alert page: "same device, other tools" timeline — Ready
18. Copy-as-ticket-text button (summary for pasting into Halo) — Ready
19. Mute a noisy rule for one client for N days — Ready

## Platform health / operations
20. Pool usage history — Done
21. Device feed freshness — Done
22. Slow-request logging — Done
23. CORE-silent warning — Done
24. Smoke script — Done
25. Container import check — Done
26. Health page: last 24 h of pool peaks as a small chart — Ready
27. Warn when the API's migration table is behind the files on disk — Ready
28. Warn when a connector's last sync failed for more than a day — Ready
29. Daily self-check job that posts the smoke result to the health page — Ready

## Detections
30. KQL and/or/not — Done
31. EQL sequences — Done
32. Rule test bench: paste events, see which rules match — Ready
33. Rule hit counts per week on the rule list — Ready
34. Sigma import for a single rule — Ready

## CORE / Cipher
35. Device sources: Huntress, Blumira, ThreatMate — Done
36. Drift check (AiSOC build behind GitHub) — Done
37. Scrubbed rolling log — Done
38. Cipher knowledge: devices, alert context, health — Done (aisoc-09-devices-and-alert-context)
39. Cipher tool for related alerts — Ready
40. Cipher tool for the device rollup — Ready
41. Cipher skill: weekly client posture email draft — Ready
42. CORE: retry a failed feed upload with backoff and show the count in diagnostics — Ready

## Needs Hal
43. Database role that is not superuser (so row-level security is enforced)
44. OS credential store for connector secrets
45. Embedding model route for ATT&CK search
46. Slack user to AiSOC user mapping (then require a verified approver)
47. UEBA source (Entra/Okta/M365 sign-in logs)
48. Petra actions via Microsoft Graph (Petra's API has none)
49. One real test of the Halo private note and status change on a reversible ticket
50. Windows CI job: run it once from the Actions tab and read what fails

---

# 100 more ideas (added 2026-10-18)

All **Ready** unless marked; none has been started. Where a vendor API is involved, check what the API offers before building.

## Devices
51. Per-device 'Open in <tool>' links - Ready
52. Saved filters per user - Ready
53. Detail drawer with raw fields per tool - Ready
54. Weekly stale/attention digest - Ready
55. Prune merge-log rows past the undo window - Ready
56. Flag devices with two different serials under one name - Ready
57. Flag OS versions past end of support - Ready
58. Show last logged-in user when a tool reports it - Ready
59. Group devices by site/location - Ready
60. Show disk-encryption state when a tool reports it - Ready
61. Tag devices (server, kiosk, loaner) and filter by tag - Ready
62. Ignore list for devices that are expected to be offline - Ready
63. Device age by first-seen date - Ready
64. Hide retired devices after N days offline - Ready
65. Bulk dismiss of duplicate pairs from one client - Ready
66. Rollup trend: this week versus last week per client - Ready
67. Export the rollup as CSV - Ready
68. Print-friendly client posture page - Ready
69. Link a device to its Halo asset - Ready
70. Show open vulnerabilities count per device from ThreatMate - Ready

## Alerts
71. Bulk link a ticket to selected alerts - Ready
72. Same-device timeline across tools - Ready
73. Copy-as-ticket-text button - Ready
74. Mute a rule for one client for N days - Ready
75. Show how often this rule fired for this client - Ready
76. Suggest 'close as false positive' when a user did the same 3 times - Ready
77. Alert age badge for anything open over 7 days - Ready
78. Group alerts by device on the list - Ready
79. Keyboard shortcuts for next/previous alert - Ready
80. Remember the last filter on the alert list - Ready
81. Show the vendor's own severity next to AiSOC's - Ready
82. Add a note without changing status - Ready
83. Assign an alert to a person - Ready
84. Due-date reminders for assigned alerts - Ready
85. Link two alerts as the same incident by hand - Ready
86. Show matching threat-intel indicators on the alert - Ready
87. Show geo of the sign-in address - Ready
88. Mark a user 'travelling' to quiet impossible-travel alerts - Ready
89. Show the Halo ticket's current status on the alert - Ready
90. Warn when a linked Halo ticket was closed but the alert is open - Ready

## Operations
91. Pool peaks chart for 24 hours - Ready
92. Warn when migrations on disk are ahead of the database - Ready
93. Warn when a connector failed for over a day - Ready
94. Daily self-check posting the smoke result - Ready
95. Disk space warning for the Postgres volume - Ready
96. Redis memory warning - Ready
97. Kafka lag on the health page - Ready
98. Show API version and build commit on the health page - Ready
99. Show time since each service last restarted - Ready
100. Alert on repeated container restarts - Ready
101. Backup age on the health page - Ready
102. Log rotation check for the API - Ready
103. Rate of 5xx per hour on the health page - Ready
104. Show the slowest endpoints of the last hour - Ready
105. Startup self-test that lists any missing environment variable - Ready
106. One-command rebuild-and-verify script - Ready
107. Compose file check for services without health checks - Ready
108. Dump of diagnostics for a support request with secrets removed - Ready
109. Warn when the credential key is the default - Ready
110. Document the restore procedure with a tested example - Ready

## Detections
111. Rule test bench - Ready
112. Weekly hit counts per rule - Ready
113. Single-rule Sigma import - Ready
114. Show rules that never fired in 90 days - Ready
115. Show rules that fire over 100 times a day - Ready
116. Per-client rule overrides - Ready
117. Rule change history - Ready
118. Dry-run a new rule over the last 7 days - Ready
119. Suppress a rule when a maintenance window is open - Ready
120. Maintenance windows per client - Ready
121. ATT&CK coverage by client - Ready
122. Export rules as a file - Ready
123. Rule owner field - Ready
124. Tag rules by data source - Ready
125. Warn when a rule references a field no source provides - Ready
126. EQL: support 'until' clauses - Ready
127. EQL: support wildcards in values - Ready
128. KQL: support 'in' lists - Ready
129. KQL: case-insensitive operators - Ready
130. Rule syntax check in the editor as you type - Ready

## CORE and Cipher
131. Cipher tool for related alerts - Ready
132. Cipher tool for the device rollup - Ready
133. Weekly client posture email draft skill - Ready
134. Feed upload retry with backoff - Ready
135. Diagnostics: show feed queue depth - Ready
136. Diagnostics: last successful upload per vendor - Ready
137. Cipher: explain why a device needs attention in plain words - Ready
138. Cipher: draft the Halo note for a resolved alert - Ready
139. Cipher: compare two clients' posture - Ready
140. Cipher: summarize last week's alerts per client - Ready
141. Cipher skill: onboarding checklist for a new client - Ready
142. Cipher skill: offboarding checklist - Ready
143. CORE: notify when the feed has been silent 15 minutes - Ready
144. CORE: show the AiSOC drift line on the main screen - Ready
145. CORE: one-click open of the AiSOC console for a device - Ready
146. CORE: sync-now button per vendor - Ready
147. CORE: show which vendors have API keys expiring - Ready
148. CORE: backup of its settings file - Ready
149. CORE: export the main log with one click - Ready
150. CORE: self-test button that runs the smoke script - Ready
