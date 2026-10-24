"""Suggested answers to the Microsoft 365 questions of the vCIO Toolbox review template (the CIS-style list, per admin centre).

The questions are the template's own, word for word. An answer comes from one of two places: a baseline check CORE read through CIPP and reported (``client_m365_checks``), or the multi-factor
list A.C.O.R.N already holds. A question neither can answer is ``needs_person``: it is never guessed. Nothing is sent to vCIO Toolbox. Pure functions, so every rule is testable without a database.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.services.mfa_registration import has_second_factor, registration_known, required_of

# (group, the template's question), in the template's order. Generated from the vCIO Toolbox review template's M365 sheet; the wording is the template's own.
QUESTIONS: tuple[tuple[str, str], ...] = (
    ("M365 Admin Center", "Ensure that between two and four global admins are designated"),
    ("M365 Admin Center", "Ensure the `Password expiration policy` is set to `Set passwords to never expire (recommended)`"),
    ("M365 Admin Center", "Ensure `Idle session timeout` is set to `3 hours (or less)` for unmanaged devices"),
    ("M365 Admin Center", "Ensure `External sharing` of calendars is not available"),
    ("M365 Admin Center", "Ensure the customer lockbox feature is enabled"),
    ("M365 Admin Center", "Ensure `third-party storage services` are restricted in `Microsoft 365 on the web`"),
    ("M365 Admin Center", "Ensure Administrative accounts are cloud-only"),
    ("M365 Admin Center", "Ensure two emergency access accounts have been defined"),
    ("M365 Admin Center", "Ensure administrative accounts use licenses with a reduced application footprint"),
    ("M365 Admin Center", "Ensure sign-in to shared mailboxes is blocked"),
    ("M365 Admin Center", "Ensure 'User owned apps and services' is restricted"),
    ("M365 Admin Center", "Ensure internal phishing protection for Forms is enabled"),
    ("M365 Admin Center", "Ensure shared bookings paged are restricted to select users"),
    ("M365 Defender", "Ensure Safe Attachments policy is enabled"),
    ("M365 Defender", "Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled"),
    ("M365 Defender", "Ensure Exchange Online Spam Policies are set to notify administrators"),
    ("M365 Defender", "Ensure that an anti-phishing policy has been created"),
    ("M365 Defender", "Ensure Safe Links for Office Applications is Enabled"),
    ("M365 Defender", "Ensure the Common Attachment Types Filter is enabled"),
    ("M365 Defender", "Ensure the connection filter IP allow list is not used"),
    ("M365 Defender", "Ensure the connection filter safe list is off"),
    ("M365 Defender", "Ensure inbound anti-spam policies do not contain allowed domains"),
    ("M365 Defender", "Ensure outbound anti-spam message limits are in place"),
    ("M365 Defender", "Ensure Zero-hour auto purge for Microsoft Teams is on"),
    ("M365 Defender", "Ensure notifications for internal users sending malware is Enabled"),
    ("M365 Defender", "Ensure that SPF records are published for all Exchange Domains"),
    ("M365 Defender", "Ensure that DKIM is enabled for all Exchange Online Domains"),
    ("M365 Defender", "Ensure DMARC Records for all Exchange Online domains are published"),
    ("M365 Defender", "Ensure emergency access account activity is monitored"),
    ("M365 Defender", "Ensure Priority account protection is enabled and configured"),
    ("M365 Defender", "Ensure Priority accounts have 'Strict protection' presets applied"),
    ("Microsoft Purview", "Ensure Microsoft 365 audit log search is Enabled"),
    ("Microsoft Purview", "Ensure DLP policies are enabled"),
    ("Microsoft Purview", "Ensure DLP policies are enabled for Microsoft Teams"),
    ("Microsoft Purview", "Ensure Information Protection sensitivity label policies are published"),
    ("Microsoft Entra admin center", "Ensure user consent to apps accessing company data on their behalf is not allowed"),
    ("Microsoft Entra admin center", "Ensure multifactor authentication is enabled for all users in administrative roles"),
    ("Microsoft Entra admin center", "Ensure multifactor authentication is enabled for all users"),
    ("Microsoft Entra admin center", "Enable Conditional Access policies to block legacy authentication"),
    ("Microsoft Entra admin center", "Enable Identity Protection user risk policies"),
    ("Microsoft Entra admin center", "Enable Identity Protection sign-in risk policies"),
    ("Microsoft Entra admin center", "Ensure `Self service password reset enabled` is set to `All`"),
    ("Microsoft Entra admin center", "Ensure 'Per-user MFA' is disabled"),
    ("Microsoft Entra admin center", "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'"),
    ("Microsoft Entra admin center", "Ensure access to the Entra admin center is restricted"),
    ("Microsoft Entra admin center", "Ensure a dynamic group for guest users is created"),
    ("Microsoft Entra admin center", "Ensure users cannot create security groups"),
    ("Microsoft Entra admin center", "Ensure the maximum number of devices per user is limited"),
    ("Microsoft Entra admin center", "Ensure the GA role is not added as a local administrator during Entra join"),
    ("Microsoft Entra admin center", "Ensure local administrator assignment is limited during Entra join"),
    ("Microsoft Entra admin center", "Ensure Local Administrator Password Solution is enabled"),
    ("Microsoft Entra admin center", "Ensure the admin consent workflow is enabled"),
    ("Microsoft Entra admin center", "Ensure that guest user access is restricted"),
    ("Microsoft Entra admin center", "Ensure that password hash sync is enabled for hybrid deployments"),
    (
        "Microsoft Entra admin center",
        "Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users",
    ),
    ("Microsoft Entra admin center", "Ensure a managed device is required for authentication"),
    ("Microsoft Entra admin center", "Ensure a managed device is required to register security information"),
    ("Microsoft Entra admin center", "Ensure sign-in frequency for Intune Enrollment is set to 'Every time'"),
    ("Microsoft Entra admin center", "Ensure the device code sign-in flow is blocked"),
    ("Microsoft Entra admin center", "Ensure Microsoft Authenticator is configured to protect against MFA fatigue"),
    ("Microsoft Entra admin center", "Ensure custom banned passwords lists are used"),
    ("Microsoft Entra admin center", "Ensure password protection is enabled for on-prem Active Directory"),
    ("Microsoft Entra admin center", "Ensure all member users are 'MFA capable'"),
    ("Microsoft Entra admin center", "Ensure weak authentication methods are disabled"),
    ("Microsoft Entra admin center", "Ensure system-preferred multifactor authentication is enabled"),
    ("Microsoft Entra admin center", "Ensure 'Access reviews' for Guest Users are configured"),
    ("Microsoft Entra admin center", "Ensure 'Access reviews' for privileged roles are configured"),
    ("Microsoft Entra admin center", "Ensure approval is required for Global Administrator role activation"),
    ("Microsoft Entra admin center", "Ensure approval is required for Privileged Role"),
    ("Exchange admin center", "Ensure `AuditDisabled` organizationally is set to `False`"),
    ("Exchange admin center", "Ensure all forms of mail forwarding are blocked and/or disabled"),
    ("Exchange admin center", "Ensure modern authentication for Exchange Online is enabled"),
    ("Exchange admin center", "Ensure MailTips are enabled for end users"),
    ("Exchange admin center", "Ensure users installing Outlook add-ins is not allowed"),
    ("Exchange admin center", "Ensure additional storage providers are restricted in Outlook on the web"),
    ("Exchange admin center", "Ensure mailbox audit actions are configured"),
    ("Exchange admin center", "Ensure 'AuditBypassEnabled' is not enabled on mailboxes"),
    ("Exchange admin center", "Ensure mail transport rules do not whitelist specific domains"),
    ("Exchange admin center", "Ensure email from external senders is identified"),
    ("Exchange admin center", "Ensure SMTP AUTH is disabled"),
    ("SharePoint admin center", "Ensure modern authentication for SharePoint applications is required"),
    ("SharePoint admin center", "Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled"),
    ("SharePoint admin center", "Ensure external content sharing is restricted"),
    ("SharePoint admin center", "Ensure link sharing is restricted in SharePoint and OneDrive"),
    ("SharePoint admin center", "Ensure guest access to a site or OneDrive will expire automatically"),
    ("SharePoint admin center", "Ensure reauthentication with verification code is restricted"),
    ("SharePoint admin center", "Ensure the SharePoint default sharing link permission is set"),
    ("Microsoft Teams admin center", "Ensure anonymous users and dial-in callers can`t start a meeting"),
    ("Microsoft Teams admin center", "Ensure users dialing in can`t bypass the lobby"),
    ("Microsoft Teams admin center", "Ensure anonymous users can`t join a meeting"),
    ("Microsoft Teams admin center", "Ensure external participants can`t give or request control"),
    ("Microsoft Teams admin center", "Ensure only organizers and co-organizers can present"),
    ("Microsoft Teams admin center", "Ensure users can't send emails to a channel email address"),
    ("Microsoft Teams admin center", "Ensure communication with unmanaged Teams users is disabled"),
    ("Microsoft Teams admin center", "Ensure external Teams users cannot initiate conversations"),
    ("Microsoft Teams admin center", "Ensure the organization cannot communicate with accounts in trial Teams tenants"),
    ("Microsoft Teams admin center", "Ensure app permission policies are configured"),
    ("Microsoft Teams admin center", "Ensure only people in my org can bypass the lobby"),
    ("Microsoft Teams admin center", "Ensure users can report security concerns in Teams"),
)


# CORE's check key -> the template question it answers (matched by the start of the question; each must match exactly one, which a test pins).
CHECK_QUESTIONS: dict[str, str] = {
    "ga_count": "Ensure that between two and four global admins",
    "password_expiry": "Ensure the `Password expiration policy`",
    "shared_mailbox_signin": "Ensure sign-in to shared mailboxes is blocked",
    "safe_attachments": "Ensure Safe Attachments policy is enabled",
    "anti_phishing": "Ensure that an anti-phishing policy has been created",
    "safe_links": "Ensure Safe Links for Office Applications is Enabled",
    "common_attachments": "Ensure the Common Attachment Types Filter is enabled",
    "conn_ip_allow": "Ensure the connection filter IP allow list is not used",
    "conn_safe_list": "Ensure the connection filter safe list is off",
    "spf": "Ensure that SPF records are published",
    "dkim": "Ensure that DKIM is enabled",
    "dmarc": "Ensure DMARC Records",
    "user_consent": "Ensure user consent to apps accessing company data",
    "legacy_auth_ca": "Enable Conditional Access policies to block legacy authentication",
    "device_code_ca": "Ensure the device code sign-in flow is blocked",
    "create_tenants": "Ensure 'Restrict non-admin users from creating tenants'",
    "create_security_groups": "Ensure users cannot create security groups",
    "guest_access": "Ensure that guest user access is restricted",
    "admin_consent_workflow": "Ensure the admin consent workflow is enabled",
    "sharepoint_modern_auth": "Ensure modern authentication for SharePoint applications is required",
    "audit_disabled": "Ensure `AuditDisabled` organizationally is set to `False`",
    "customer_lockbox": "Ensure the customer lockbox feature is enabled",
    "mailtips": "Ensure MailTips are enabled for end users",
    "exo_modern_auth": "Ensure modern authentication for Exchange Online is enabled",
    "smtp_auth_disabled": "Ensure SMTP AUTH is disabled",
    "owa_storage_providers": "Ensure additional storage providers are restricted in Outlook on the web",
    "external_sender_tag": "Ensure email from external senders is identified",
    "malware_admin_notify": "Ensure notifications for internal users sending malware is Enabled",
    "user_risk_ca": "Enable Identity Protection user risk policies",
    "signin_risk_ca": "Enable Identity Protection sign-in risk policies",
    "managed_device_ca": "Ensure a managed device is required for authentication",
    "register_security_info_ca": "Ensure a managed device is required to register security information",
    "intune_enrollment_frequency_ca": "Ensure sign-in frequency for Intune Enrollment is set to 'Every time'",
    "idle_session_timeout": "Ensure `Idle session timeout` is set to `3 hours (or less)` for unmanaged devices",
    "outbound_limits": "Ensure outbound anti-spam message limits are in place",
    "admin_signin_frequency": "Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users",
    "sharepoint_external_sharing": "Ensure external content sharing is restricted",
    "authenticator_fatigue": "Ensure Microsoft Authenticator is configured to protect against MFA fatigue",
    "weak_auth_methods": "Ensure weak authentication methods are disabled",
    "system_preferred_mfa": "Ensure system-preferred multifactor authentication is enabled",
    "banned_passwords": "Ensure custom banned passwords lists are used",
    "onprem_password_protection": "Ensure password protection is enabled for on-prem Active Directory",
    "password_hash_sync": "Ensure that password hash sync is enabled for hybrid deployments",
    "device_quota": "Ensure the maximum number of devices per user is limited",
    "laps": "Ensure Local Administrator Password Solution is enabled",
    "ga_local_admin": "Ensure the GA role is not added as a local administrator during Entra join",
    "local_admin_join": "Ensure local administrator assignment is limited during Entra join",
    "guest_dynamic_group": "Ensure a dynamic group for guest users is created",
    "cloud_only_admins": "Ensure Administrative accounts are cloud-only",
    "inbound_allowed_domains": "Ensure inbound anti-spam policies do not contain allowed domains",
    "outbound_spam_notify": "Ensure Exchange Online Spam Policies are set to notify administrators",
    "mail_forwarding_blocked": "Ensure all forms of mail forwarding are blocked and/or disabled",
    "audit_bypass": "Ensure 'AuditBypassEnabled' is not enabled on mailboxes",
    "safe_attachments_collab": "Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled",
    "outlook_addins": "Ensure users installing Outlook add-ins is not allowed",
    "transport_whitelist": "Ensure mail transport rules do not whitelist specific domains",
    "unified_audit_log": "Ensure Microsoft 365 audit log search is Enabled",
    "zap_teams": "Ensure Zero-hour auto purge for Microsoft Teams is on",
    "calendar_external_sharing": "Ensure `External sharing` of calendars is not available",
    "bookings_restricted": "Ensure shared bookings paged are restricted to select users",
    "admin_license_footprint": "Ensure administrative accounts use licenses with a reduced application footprint",
}

# Questions answered from the multi-factor list A.C.O.R.N already holds.
MFA_QUESTIONS = {
    "admins": "Ensure multifactor authentication is enabled for all users in administrative roles",
    "everyone": "Ensure multifactor authentication is enabled for all users",
    "per_user": "Ensure 'Per-user MFA' is disabled",
    "capable": "Ensure all member users are 'MFA capable'",
}

_STATUSES = {"met", "partly", "not_met"}


class M365Answer(BaseModel):
    group: str
    question: str
    # met / partly / not_met from a check; needs_person when A.C.O.R.N has nothing that answers it.
    status: str
    evidence: str = ""
    # A person's typed answer or note (see review_overrides). ``manual``: the status or answer was typed, replacing what A.C.O.R.N worked out, which is kept in ``auto_*``.
    manual: bool = False
    note: str | None = None
    auto_status: str | None = None
    updated_at: datetime | None = None


def question_for(prefix: str) -> str:
    """The template question equal to ``prefix``, or else the one that starts with it."""
    found = [q for _, q in QUESTIONS if q == prefix] or [q for _, q in QUESTIONS if q.startswith(prefix)]
    if len(found) != 1:
        raise ValueError(f"{prefix!r} matches {len(found)} template questions")
    return found[0]


def _band(percent: float, met: float, partly: float) -> str:
    return "met" if percent >= met else "partly" if percent >= partly else "not_met"


def from_mfa(users: list[Any]) -> dict[str, tuple[str, str]]:
    """Answers the multi-factor list can give, by MFA_QUESTIONS key: (status, evidence). ``users`` are IdentityMfaUser rows (anything with the same fields)."""
    if not users:
        return {}
    out: dict[str, tuple[str, str]] = {}
    people = len(users)
    known = registration_known(users)
    covered = sum(1 for u in users if has_second_factor(u, known) and required_of(u))
    note = "" if known else " (Microsoft doesn't report who has registered, so this is who is required to.)"
    out["everyone"] = (_band(100 * covered / people, 95, 80), f"{covered} of {people} people have Multi-Factor required and set up.{note}")
    admins = [u for u in users if u.admin]
    bare = [u for u in admins if not (has_second_factor(u, known) and required_of(u))]
    if admins:
        out["admins"] = (
            "met" if not bare else "not_met",
            "Every administrator has Multi-Factor." if not bare else f"{len(bare)} of {len(admins)} administrators have no Multi-Factor.",
        )
    per_user = sum(1 for u in users if u.per_user in ("enabled", "enforced"))
    out["per_user"] = (
        "met" if per_user == 0 else "not_met",
        "No one is set up with per-user Multi-Factor."
        if per_user == 0
        else f"{per_user} people still use per-user Multi-Factor (Microsoft recommends Conditional Access instead).",
    )
    members = [u for u in users if (u.user_type or "").lower() == "member" and u.enabled]
    if members:
        incapable = sum(1 for u in members if not u.capable)
        out["capable"] = (
            _band(100 * (len(members) - incapable) / len(members), 100, 90),
            "Every member can use Multi-Factor."
            if incapable == 0
            else f"{incapable} of {len(members)} members are not able to use Multi-Factor.",
        )
    return out


def m365_answers(checks: list[dict[str, Any]], mfa_users: list[Any]) -> list[M365Answer]:
    """One answer per template question, in the template's order."""
    by_question: dict[str, tuple[str, str]] = {}
    for c in checks:
        key, status = c.get("key"), c.get("status")
        if key in CHECK_QUESTIONS and status in _STATUSES:
            by_question[question_for(CHECK_QUESTIONS[key])] = (str(status), str(c.get("evidence") or "")[:300])
    for key, answer in from_mfa(mfa_users).items():
        by_question.setdefault(question_for(MFA_QUESTIONS[key]), answer)
    out: list[M365Answer] = []
    for group, question in QUESTIONS:
        status, evidence = by_question.get(question, ("needs_person", ""))
        out.append(M365Answer(group=group, question=question, status=status, evidence=evidence))
    return out
