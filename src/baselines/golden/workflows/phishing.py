"""Phishing golden workflow — deterministic tool sequence.

Maps the pre-Verdict phishing-playbook nodes to concrete tool calls.
Skipped nodes (no registry equivalent):

  - AUTH_CHECK (SPF/DKIM/DMARC parsing — not in our email schema)
  - SENDER_DOMAIN_OSINT, URL_OSINT (no OSINT / WHOIS lookup)
  - URL_SANDBOX, ATTACH_SANDBOX (no sandbox / detonation service)
  - URL_SIMILARITY (no phishing-detection / brand-similarity tool)
  - BODY_ANALYSIS (deliberately skipped: no LLM during execution)
  - SIMILAR_INCIDENTS (no ITSM / SOAR ticket history)
"""
from __future__ import annotations

from baselines.golden.context import ExecutionContext
from baselines.golden.steps import WorkflowStep


def _user_lookup(ctx: ExecutionContext) -> list[dict]:
    if not ctx.email:
        return []
    return [{"user_ref": ctx.email}]


def _delivery_status(ctx: ExecutionContext) -> list[dict]:
    """Phase 1: emails to the user — delivery status, sender, attachments."""
    if not ctx.email:
        return []
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [
        {
            "recipient": ctx.email,
            "time_start": start,
            "time_end": end,
            "limit": 100,
        }
    ]


def _sender_summary(ctx: ExecutionContext) -> list[dict]:
    senders = ctx.collect_external_senders(from_functions=("defender_search_emails",))
    return [{"sender": s} for s in senders]


def _phishing_indicators(ctx: ExecutionContext) -> list[dict]:
    """Per external sender domain — historical phishing volume."""
    senders = ctx.collect_external_senders(from_functions=("defender_search_emails",))
    domains = sorted({s.rsplit("@", 1)[-1] for s in senders if "@" in s})
    start, end = ctx.time_window(days_back=30, days_forward=1)
    return [
        {"sender_domain": d, "time_start": start, "time_end": end}
        for d in domains
    ]


def _campaign_by_sender(ctx: ExecutionContext) -> list[dict]:
    """Phase 3 CAMPAIGN_SEARCH: same sender across all recipients."""
    senders = ctx.collect_external_senders(from_functions=("defender_search_emails",))
    start, end = ctx.time_window(days_back=7, days_forward=1)
    return [
        {"sender": s, "time_start": start, "time_end": end, "limit": 100}
        for s in senders
    ]


def _sender_email_ti(ctx: ExecutionContext) -> list[dict]:
    senders = ctx.collect_external_senders(from_functions=("defender_search_emails",))
    return [{"email": s} for s in senders]


def _sender_domain_ti(ctx: ExecutionContext) -> list[dict]:
    senders = ctx.collect_external_senders(from_functions=("defender_search_emails",))
    domains = sorted({s.rsplit("@", 1)[-1] for s in senders if "@" in s})
    return [{"domain": d} for d in domains]


def _url_ti(ctx: ExecutionContext) -> list[dict]:
    urls = ctx.collect_urls(from_functions=("defender_search_emails",))
    return [{"url": u} for u in urls]


def _url_domain_ti(ctx: ExecutionContext) -> list[dict]:
    """URL_CATEGORY — TI on the URL's domain (covers categorization signal)."""
    urls = ctx.collect_urls(from_functions=("defender_search_emails",))
    domains: set[str] = set()
    for u in urls:
        try:
            host = u.split("://", 1)[1].split("/", 1)[0].lower()
            if host:
                domains.add(host)
        except IndexError:
            continue
    return [{"domain": d} for d in sorted(domains)]


def _attachment_hash_ti(ctx: ExecutionContext) -> list[dict]:
    hashes = ctx.collect_hashes(
        from_functions=(
            "defender_search_emails",
            "defender_get_email_attachments",
        ),
    )
    return [{"file_hash": h} for h in hashes]


def _attachment_filename_ti(ctx: ExecutionContext) -> list[dict]:
    names = ctx.collect_filenames()
    return [{"filename": n} for n in names]


def _email_attachments(ctx: ExecutionContext) -> list[dict]:
    """Pull attachment details per external sender."""
    senders = ctx.collect_external_senders(from_functions=("defender_search_emails",))
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [
        {"sender": s, "time_start": start, "time_end": end}
        for s in senders
    ]


def _signin_logs(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end, "limit": 100}]


def _audit_log(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end, "limit": 100}]


def _mfa_activity(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end}]


def _process_tree(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end}]


def _device_events(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end}]


def _post_click_ip_ti(ctx: ExecutionContext) -> list[dict]:
    """Phase 2/3 — TI per IP seen in sign-ins (post-click attacker session)."""
    ips = ctx.collect_ips(from_functions=("entra_sign_in_logs",))
    return [{"ip_address": ip} for ip in ips]


def _user_dashboard(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end}]


STEPS: list[WorkflowStep] = [
    WorkflowStep(
        label="RECIPIENT_CONTEXT",
        function="entra_lookup_user",
        build_argsets=_user_lookup,
        covers=("EXTRACT_RECIPIENT",),
        description="Phase 1: directory profile of the recipient (high-value target?).",
    ),
    WorkflowStep(
        label="DELIVERY_STATUS",
        function="defender_search_emails",
        build_argsets=_delivery_status,
        covers=(
            "EXTRACT_ALERT",
            "DELIVERY_STATUS",
            "USER_ACTIONS",
            "CLICK_INVESTIGATION",
        ),
        description="Phase 1: full inbound-email record (sender, URL, attachments, click).",
    ),
    WorkflowStep(
        label="SENDER_PROFILE",
        function="defender_get_sender_summary",
        build_argsets=_sender_summary,
        covers=("SENDER_DOMAIN_HISTORY",),
        description="Phase 2: per-sender messaging profile / history.",
    ),
    WorkflowStep(
        label="SENDER_DOMAIN_PHISHING_HISTORY",
        function="defender_find_phishing_indicators",
        build_argsets=_phishing_indicators,
        covers=("SENDER_DOMAIN_HISTORY", "SENDER_IP_HISTORY"),
        description="Phase 2: prior phishing volume from the sender's domain.",
    ),
    WorkflowStep(
        label="EMAIL_TI_SENDER",
        function="ti_lookup_email_address",
        build_argsets=_sender_email_ti,
        covers=("SENDER_IP_REP",),
        description="Phase 2: TI per external sender address.",
    ),
    WorkflowStep(
        label="DOMAIN_TI_SENDER",
        function="ti_lookup_domain",
        build_argsets=_sender_domain_ti,
        covers=("SENDER_DOMAIN_REP",),
        description="Phase 2: TI per sender domain.",
    ),
    WorkflowStep(
        label="URL_TI",
        function="ti_lookup_url",
        build_argsets=_url_ti,
        covers=("URL_REP",),
        description="Phase 2: TI per URL embedded in inbound emails.",
    ),
    WorkflowStep(
        label="URL_DOMAIN_TI",
        function="ti_lookup_domain",
        build_argsets=_url_domain_ti,
        covers=("URL_CATEGORY",),
        description="Phase 2: TI on each URL's domain (categorization signal).",
    ),
    WorkflowStep(
        label="EMAIL_ATTACHMENTS",
        function="defender_get_email_attachments",
        build_argsets=_email_attachments,
        covers=("ATTACH_HASH_REP",),
        description="Phase 2: per-sender attachment listing.",
    ),
    WorkflowStep(
        label="ATTACH_HASH_TI",
        function="ti_lookup_hash",
        build_argsets=_attachment_hash_ti,
        covers=("ATTACH_HASH_REP",),
        description="Phase 2: TI per attachment hash.",
    ),
    WorkflowStep(
        label="ATTACH_FILENAME_TI",
        function="ti_lookup_filename",
        build_argsets=_attachment_filename_ti,
        covers=("ATTACH_HASH_REP",),
        description="Phase 2: TI per attachment filename (lure-name match).",
    ),
    WorkflowStep(
        label="CAMPAIGN_BY_SENDER",
        function="defender_search_emails",
        build_argsets=_campaign_by_sender,
        covers=("CAMPAIGN_SEARCH", "SENT_TO_ORG"),
        description="Phase 3: same sender across all recipients (blast radius).",
    ),
    WorkflowStep(
        label="SIGNIN_LOGS",
        function="entra_sign_in_logs",
        build_argsets=_signin_logs,
        covers=("SIGNIN_CHECK",),
        description="Phase 3: post-click sign-in anomalies.",
    ),
    WorkflowStep(
        label="AUDIT_LOG",
        function="entra_user_audit_log",
        build_argsets=_audit_log,
        covers=("SIGNIN_CHECK",),
        description="Phase 3: persistence (forwarding rules, OAuth, delegates).",
    ),
    WorkflowStep(
        label="MFA_ACTIVITY",
        function="entra_mfa_activity",
        build_argsets=_mfa_activity,
        covers=("SIGNIN_CHECK",),
        description="Phase 3: new-MFA registrations, unusual approvals.",
    ),
    WorkflowStep(
        label="POST_CLICK_IP_TI",
        function="ti_lookup_ip",
        build_argsets=_post_click_ip_ti,
        covers=("SIGNIN_CHECK",),
        description="Phase 3: TI per sign-in IP (foreign / known-bad?).",
    ),
    WorkflowStep(
        label="ENDPOINT_PROCESSES",
        function="cs_get_process_tree",
        build_argsets=_process_tree,
        covers=("ENDPOINT_CHECK",),
        description="Phase 3: process tree on recipient's endpoint.",
    ),
    WorkflowStep(
        label="ENDPOINT_DEVICE_EVENTS",
        function="cs_get_device_events",
        build_argsets=_device_events,
        covers=("ENDPOINT_CHECK",),
        description="Phase 3: device events post-click.",
    ),
    WorkflowStep(
        label="USER_DASHBOARD",
        function="splunk_search_dashboard",
        build_argsets=_user_dashboard,
        covers=("ENDPOINT_CHECK",),
        description="Phase 3: SIEM dashboard for the recipient.",
    ),
]
