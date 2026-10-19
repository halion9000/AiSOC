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
