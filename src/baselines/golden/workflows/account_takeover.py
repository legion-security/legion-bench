"""AccountTakeover golden workflow — deterministic tool sequence.

Maps the pre-Verdict mermaid nodes (Phases 1-3) to concrete tool calls
in our SOC tool registry. Nodes that have no equivalent capability
(IP_OSINT, BREACH_CHECK, HISTORICAL_INCIDENTS) are skipped. Multiple
nodes that collapse to the same tool are issued as a single call (the
four IP-enrichment nodes — IP_REP / IP_GEO / IP_VPN / IP_TI_FEED —
collapse to one ``ti_lookup_ip`` per distinct external IP).
"""
from __future__ import annotations

from baselines.golden.context import ExecutionContext
from baselines.golden.steps import WorkflowStep


def _user_lookup(ctx: ExecutionContext) -> list[dict]:
    if not ctx.email:
        return []
    return [{"user_ref": ctx.email}]


def _signin_logs(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end, "limit": 200}]


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


def _user_groups(ctx: ExecutionContext) -> list[dict]:
    if not ctx.email:
        return []
    return [{"user_ref": ctx.email}]


def _risky_users(ctx: ExecutionContext) -> list[dict]:
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [{"time_start": start, "time_end": end}]


def _ip_ti_lookups(ctx: ExecutionContext) -> list[dict]:
    ips = ctx.collect_ips(from_functions=("entra_sign_in_logs",))
    return [{"ip_address": ip} for ip in ips]


def _ip_org_history(ctx: ExecutionContext) -> list[dict]:
    """SIEM query: who else signed in from these IPs?"""
    ips = ctx.collect_ips(from_functions=("entra_sign_in_logs",))
    if not ips:
        return []
    quoted = ", ".join(f"'{ip}'" for ip in ips)
    query = (
        "SELECT employee_id, ip, geo, COUNT(*) AS attempts, "
        "MIN(ts) AS first_seen, MAX(ts) AS last_seen "
        f"FROM login_events WHERE ip IN ({quoted}) "
        "GROUP BY employee_id, ip ORDER BY attempts DESC"
    )
    return [{"query": query, "limit": 200}]


def _user_dashboard(ctx: ExecutionContext) -> list[dict]:
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


def _process_tree(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end}]


def _network_for_ips(ctx: ExecutionContext) -> list[dict]:
    """For each external IP from sign-in logs, check if it touched our network."""
    ips = ctx.collect_ips(from_functions=("entra_sign_in_logs",))
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [{"ip": ip, "time_start": start, "time_end": end} for ip in ips]


def _phishing_correlation(ctx: ExecutionContext) -> list[dict]:
    if not ctx.email:
        return []
    start, end = ctx.time_window(days_back=2, days_forward=1)
    return [
        {
            "recipient": ctx.email,
            "time_start": start,
            "time_end": end,
            "limit": 50,
        }
    ]


STEPS: list[WorkflowStep] = [
    WorkflowStep(
        label="USER_CONTEXT",
        function="entra_lookup_user",
        build_argsets=_user_lookup,
        covers=("USER_CONTEXT",),
        description="Phase 1: identity-provider profile of the alerted user.",
    ),
    WorkflowStep(
        label="USER_GROUPS",
        function="entra_get_user_groups",
        build_argsets=_user_groups,
        covers=("USER_CONTEXT",),
        description="Phase 1: privilege level via group memberships.",
    ),
    WorkflowStep(
        label="SIGNIN_LOGS",
        function="entra_sign_in_logs",
        build_argsets=_signin_logs,
        covers=("SIGNIN_CONTEXT", "SIGNIN_LOGS", "USER_IP_HISTORY"),
        description="Phase 1+2+3: full sign-in history around the alert.",
    ),
    WorkflowStep(
        label="AUDIT_LOGS",
        function="entra_user_audit_log",
        build_argsets=_audit_log,
        covers=("AUDIT_LOGS",),
        description="Phase 2: account changes (password, MFA, delegate, rules).",
    ),
    WorkflowStep(
        label="MFA_ACTIVITY",
        function="entra_mfa_activity",
        build_argsets=_mfa_activity,
        covers=("SIGNIN_CONTEXT",),
        description="Phase 1/2: MFA pushes / approvals / denials.",
    ),
    WorkflowStep(
        label="RISK_DETECTIONS",
        function="entra_risky_users",
        build_argsets=_risky_users,
        covers=("RISK_DETECTIONS",),
        description="Phase 2: Identity Protection risk detections in window.",
    ),
    WorkflowStep(
        label="IP_TI",
        function="ti_lookup_ip",
        build_argsets=_ip_ti_lookups,
        covers=("IP_REP", "IP_GEO", "IP_VPN", "IP_TI_FEED"),
        description="Phase 2: TI lookup per distinct external IP from sign-ins.",
    ),
    WorkflowStep(
        label="IP_ORG_HISTORY",
        function="splunk_run_query",
        build_argsets=_ip_org_history,
        covers=("IP_ORG_HISTORY",),
        description="Phase 3: who else in the org signed in from these IPs.",
    ),
    WorkflowStep(
        label="ADV_HUNTING_SIGNIN",
        function="splunk_search_dashboard",
        build_argsets=_user_dashboard,
        covers=("ADV_HUNTING_SIGNIN",),
        description="Phase 3: comprehensive recent-activity dashboard for the user.",
    ),
    WorkflowStep(
        label="ENDPOINT_DEVICE_EVENTS",
        function="cs_get_device_events",
        build_argsets=_device_events,
        covers=("ENDPOINT_SIGNALS",),
        description="Phase 3: USB / install / device events for the user.",
    ),
    WorkflowStep(
        label="ENDPOINT_PROCESSES",
        function="cs_get_process_tree",
        build_argsets=_process_tree,
        covers=("ENDPOINT_SIGNALS",),
        description="Phase 3: process tree on the user's endpoint.",
    ),
    WorkflowStep(
        label="NETWORK_IPS",
        function="cs_search_network_events",
        build_argsets=_network_for_ips,
        covers=("ENDPOINT_SIGNALS",),
        description="Phase 3: did the suspicious IPs touch the user's endpoint?",
    ),
    WorkflowStep(
        label="PHISHING_CORRELATION",
        function="defender_search_emails",
        build_argsets=_phishing_correlation,
        covers=("PHISHING_CORRELATION",),
        description="Phase 3: emails to the user — phishing root-cause check.",
    ),
]
