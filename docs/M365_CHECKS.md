# Microsoft 365 suggested answers: what each one reads

Client Review shows the vCIO Toolbox review template's 99 Microsoft 365 questions with a suggested answer where A.C.O.R.N can give one. CORE reads the settings below through CIPP once a day for every client (read-only: HTTP GETs, plus Exchange `Get-` cmdlets that CIPP takes as a POST to `ListExoRequest`; CORE refuses to send any other cmdlet) and posts the results to `POST /api/v1/inbox/core-feed/{token}/m365-checks`. A.C.O.R.N stores them per client (`client_m365_checks`, migration 097) and maps each result to its template question. Four more answers come from the multi-factor list A.C.O.R.N already holds. A question with no answer says **Needs a person**; nothing is guessed, and nothing is sent to vCIO Toolbox.

Keep this table in step with `CHECK_QUESTIONS` in `services/api/app/services/m365_review.py` (a test fails when a check is missing here) and with CORE's `hud/src/aisoc-m365-checks.ts`.

| Check key | Template question (start of) | Where it is read |
|---|---|---|
| `ga_count` | between two and four global admins | CIPP `ListRoles` (people in the Global Administrator role) |
| `password_expiry` | Password expiration policy | Graph `domains` (default domain's password validity) |
| `shared_mailbox_signin` | sign-in to shared mailboxes is blocked | CIPP `ListSharedMailboxAccountEnabled` |
| `safe_attachments` | Safe Attachments policy is enabled | CIPP `ListSafeAttachmentsFilters` |
| `anti_phishing` | an anti-phishing policy has been created | CIPP `ListAntiPhishingFilters` |
| `safe_links` | Safe Links for Office Applications | CIPP `ListSafeLinksPolicy` |
| `common_attachments` | Common Attachment Types Filter | CIPP `ListMalwareFilters` |
| `conn_ip_allow` | connection filter IP allow list | CIPP `ListConnectionFilter` |
| `conn_safe_list` | connection filter safe list | CIPP `ListConnectionFilter` |
| `spf`, `dkim`, `dmarc` | SPF / DKIM / DMARC for Exchange domains | CIPP `ListDomainAnalyser` (only domains that receive mail in Microsoft 365) |
| `user_consent` | user consent to apps | Graph `policies/authorizationPolicy` |
| `legacy_auth_ca` | Conditional Access to block legacy authentication | CIPP `ListConditionalAccessPolicies` |
| `device_code_ca` | device code sign-in flow is blocked | CIPP `ListConditionalAccessPolicies` |
| `user_risk_ca`, `signin_risk_ca` | Identity Protection user risk / sign-in risk policies | `ListConditionalAccessPolicies` (full policy text) |
| `managed_device_ca` | a managed device is required for authentication | `ListConditionalAccessPolicies` (full policy text) |
| `admin_signin_frequency` | Sign-in frequency ... Administrative users | `ListConditionalAccessPolicies` (full policy text) |
| `create_tenants` | restrict non-admin users from creating tenants | Graph `policies/authorizationPolicy` |
| `create_security_groups` | users cannot create security groups | Graph `policies/authorizationPolicy` |
| `guest_access` | guest user access is restricted | Graph `policies/authorizationPolicy` |
| `admin_consent_workflow` | the admin consent workflow is enabled | Graph `policies/adminConsentRequestPolicy` |
| `sharepoint_modern_auth` | modern authentication for SharePoint | CIPP `ListSharepointSettings` |
| `sharepoint_external_sharing` | external content sharing is restricted | CIPP `ListSharepointSettings` |
| `audit_disabled` | `AuditDisabled` is `False` | Exchange `Get-OrganizationConfig` |
| `customer_lockbox` | customer lockbox | Exchange `Get-OrganizationConfig` |
| `mailtips` | MailTips are enabled | Exchange `Get-OrganizationConfig` |
| `exo_modern_auth` | modern authentication for Exchange Online | Exchange `Get-OrganizationConfig` |
| `smtp_auth_disabled` | SMTP AUTH is disabled | Exchange `Get-TransportConfig` |
| `owa_storage_providers` | additional storage providers ... Outlook on the web | Exchange `Get-OwaMailboxPolicy` |
| `bookings_restricted` | shared bookings pages | Exchange `Get-OwaMailboxPolicy` |
| `external_sender_tag` | email from external senders is identified | Exchange `Get-ExternalInOutlook` |
| `malware_admin_notify` | notifications for internal users sending malware | Exchange `Get-MalwareFilterPolicy` |
| `authenticator_fatigue` | Microsoft Authenticator ... MFA fatigue | Graph `authenticationMethodsPolicy` |
| `weak_auth_methods` | weak authentication methods are disabled | Graph `authenticationMethodsPolicy` |
| `system_preferred_mfa` | system-preferred multifactor authentication | Graph `authenticationMethodsPolicy` |
| `banned_passwords` | custom banned passwords lists | Graph `settings` (Password Rule Settings) |
| `onprem_password_protection` | password protection ... on-prem Active Directory | Graph `settings` and `organization` |
| `password_hash_sync` | password hash sync for hybrid deployments | Graph `organization` |
| `device_quota` | maximum number of devices per user | Graph `policies/deviceRegistrationPolicy` |
| `laps` | Local Administrator Password Solution | Graph `policies/deviceRegistrationPolicy` |
| `ga_local_admin` | the GA role is not added as a local administrator | Graph `policies/deviceRegistrationPolicy` |
| `local_admin_join` | local administrator assignment is limited | Graph `policies/deviceRegistrationPolicy` |
| `guest_dynamic_group` | a dynamic group for guest users | Graph `groups` (dynamic groups whose rule names guests) |
| `cloud_only_admins` | Administrative accounts are cloud-only | `ListRoles` then Graph `users/{id}` for each administrator (at most 25) |
| `inbound_allowed_domains` | inbound anti-spam policies do not contain allowed domains | Exchange `Get-HostedContentFilterPolicy` |
| `outbound_spam_notify` | Spam Policies are set to notify administrators | Exchange `Get-HostedOutboundSpamFilterPolicy` |
| `mail_forwarding_blocked` | all forms of mail forwarding are blocked | `Get-HostedOutboundSpamFilterPolicy` and `ListTransportRules` |
| `audit_bypass` | `AuditBypassEnabled` is not enabled | Exchange `Get-MailboxAuditBypassAssociation` |
| `safe_attachments_collab` | Safe Attachments for SharePoint, OneDrive, and Teams | Exchange `Get-AtpPolicyForO365` |
| `outlook_addins` | users installing Outlook add-ins is not allowed | Exchange `Get-RoleAssignmentPolicy` |
| `transport_whitelist` | mail transport rules do not whitelist domains | CIPP `ListTransportRules` |
| `unified_audit_log` | Microsoft 365 audit log search is Enabled | Exchange `Get-AdminAuditLogConfig` |
| `zap_teams` | Zero-hour auto purge for Microsoft Teams | Exchange `Get-TeamsProtectionPolicy` |
| `calendar_external_sharing` | External sharing of calendars | Exchange `Get-SharingPolicy` |
| `admin_license_footprint` | administrative accounts use licenses with a reduced application footprint | `ListLicenses` and each administrator's licences |

From the multi-factor list (no CIPP read needed): multifactor authentication for administrative roles, for all users, per-user MFA disabled, and all member users MFA capable.

## What CORE posts
`POST /api/v1/inbox/core-feed/{token}/m365-checks`, with a body like `docs/api/m365-checks-example.json` (a test checks that file against the real request model). A repeat replaces the client's last list.

## What a pass costs CIPP
Each client takes 33 reads (the table above) plus one lookup per administrator (at most 25), made six at a time and at most four clients at once, and only once a day per client (a failed or empty pass counts as done, so an unreachable client is not hammered every hour). For about 118 clients that is roughly 3,900 reads plus the administrator lookups per day. CORE's tests pin the 33 (`hud/src/aisoc-m365-reads.test.ts`), the six-at-once and four-clients limits, and the once-a-day rule.

## Known gaps
- **Not readable through CIPP**: Purview DLP and sensitivity labels, every Teams policy, most SharePoint link and guest settings, some admin-centre settings. These stay "Needs a person".
- **Waiting on CIPP permissions**: Privileged Identity Management approval rules and access reviews. CIPP's app needs `RoleManagementPolicy.Read.Directory` and `AccessReview.Read.All` before those reads can work.
- **A person has to judge**: emergency access accounts and their monitoring, priority account protection.
