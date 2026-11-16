"""DLP golden workflow — deterministic tool sequence.

Maps the pre-Decision phases of the DLP playbook (PHASE1, PHASE2A-D) to
concrete tool calls. Nodes without a registry equivalent are skipped:

  - TRUSTED 3RD PARTY (no GRC tool)
  - DESTINATION REP via OSINT (no web search; partly covered by TI)
  - FILE ANALYSIS / encryption check (no DLP file-content tool;
    file-event metadata is the closest substitute via SIEM)
  - CASB cloud sharing scope (no CASB tool; cnapp covers cloud
    resource activity instead)

The DLP playbook's "Background Analytics" / "DLP HISTORY" node is
served by ``purview_get_dlp_alerts`` (90-day window).
"""
from __future__ import annotations

from baselines.golden.context import ExecutionContext
from baselines.golden.steps import WorkflowStep


def _user_lookup(ctx: ExecutionContext) -> list[dict]:
    if not ctx.email:
        return []
    return [{"user_ref": ctx.email}]


def _user_groups(ctx: ExecutionContext) -> list[dict]:
    if not ctx.email:
        return []
    return [{"user_ref": ctx.email}]


def _user_access_review(ctx: ExecutionContext) -> list[dict]:
    if not ctx.email:
        return []
    return [{"user_ref": ctx.email}]


def _dlp_alerts_history(ctx: ExecutionContext) -> list[dict]:
    """90-day DLP history for repeat-offender / pattern detection."""
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=90, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end, "limit": 100}]


def _irm_alerts(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=90, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end, "limit": 100}]


def _file_events_query(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=7, days_forward=1)
    # Inline the time filter so run_query's auto-injector skips it and we
    # keep ORDER BY at the end.
    where = [f"employee_id = '{eid}'"]
    if start:
        where.append(f"ts >= '{start}'")
    if end:
        where.append(f"ts <= '{end}'")
    query = (
        "SELECT id, ts, action, path, system, destination, size_bytes, count, "
        "label, category, description, shared_with, owner_role "
        f"FROM file_events WHERE {' AND '.join(where)} "
        "ORDER BY ts DESC"
    )
    return [{"query": query, "limit": 200}]


def _email_outbound_query(ctx: ExecutionContext) -> list[dict]:
    """Outbound email exfil: the user emailing data externally."""
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=7, days_forward=1)
    where = [f"employee_id = '{eid}'", "direction = 'sent'", "external = 1"]
    if start:
        where.append(f"ts >= '{start}'")
    if end:
        where.append(f"ts <= '{end}'")
    query = (
        "SELECT id, ts, sender, recipients, subject, content, external, "
        "attachment_types, attachments, contains_url "
        f"FROM email_events WHERE {' AND '.join(where)} "
        "ORDER BY ts DESC"
    )
    return [{"query": query, "limit": 100}]


def _print_events_query(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=7, days_forward=1)
    where = [f"employee_id = '{eid}'"]
    if start:
        where.append(f"ts >= '{start}'")
    if end:
        where.append(f"ts <= '{end}'")
    query = (
        "SELECT id, ts, printer_name, document_name, pages, copies, status "
        f"FROM print_events WHERE {' AND '.join(where)} "
        "ORDER BY ts DESC"
    )
    return [{"query": query, "limit": 100}]


def _signin_logs(ctx: ExecutionContext) -> list[dict]:
    """Login / VPN / location signal — Phase 2C SECURITY EVENTS."""
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=7, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end, "limit": 100}]


def _user_dashboard(ctx: ExecutionContext) -> list[dict]:
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=7, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end}]


def _device_events(ctx: ExecutionContext) -> list[dict]:
    """Phase 2D ENDPOINT — USB whitelist, BYOD/corporate device check."""
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=7, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end}]


def _app_events(ctx: ExecutionContext) -> list[dict]:
    """Phase 2D CLOUD/COLLAB — SharePoint / OneDrive / Slack share actions."""
    eid = ctx.employee_id
    if not eid:
        return []
    start, end = ctx.time_window(days_back=7, days_forward=1)
    return [{"employee_id": eid, "time_start": start, "time_end": end, "limit": 200}]


def _domain_ti(ctx: ExecutionContext) -> list[dict]:
    """Phase 2B URL/IP REP — TI per destination domain from file/email events."""
    domains = ctx.collect_domains(
        from_functions=("splunk_run_query",),
    )
    return [{"domain": d} for d in domains]


def _ip_ti(ctx: ExecutionContext) -> list[dict]:
    ips = ctx.collect_ips(
        from_functions=("entra_sign_in_logs", "splunk_run_query"),
    )
    return [{"ip_address": ip} for ip in ips]


def _email_ti(ctx: ExecutionContext) -> list[dict]:
    """For outbound exfil, lookup external recipient / personal-email reputation."""
    addresses: set[str] = set()
    for r in ctx.calls_for("splunk_run_query"):
        if r.error or not isinstance(r.result, list):
            continue
        for row in r.result:
            if not isinstance(row, dict):
                continue
            recipients = row.get("recipients") or row.get("destination")
            if isinstance(recipients, str):
                for part in recipients.replace(";", ",").split(","):
                    part = part.strip().strip("<>").lower()
                    if "@" in part:
                        addresses.add(part)
    own = ctx.email.rsplit("@", 1)[-1].lower() if ctx.email else None
    return [
        {"email": addr}
        for addr in sorted(addresses)
        if not (own and addr.endswith("@" + own))
    ]


STEPS: list[WorkflowStep] = [
    WorkflowStep(
        label="USER_CONTEXT",
        function="entra_lookup_user",
        build_argsets=_user_lookup,
        covers=("USER",),
        description="Phase 2A: directory profile of the user.",
    ),
    WorkflowStep(
        label="USER_GROUPS",
        function="entra_get_user_groups",
        build_argsets=_user_groups,
        covers=("USER",),
        description="Phase 2A: group memberships / access level.",
    ),
    WorkflowStep(
        label="DLP_HISTORY",
        function="purview_get_dlp_alerts",
        build_argsets=_dlp_alerts_history,
        covers=("HISTORY",),
        description="Phase 2A: 90-day DLP history (repeat-offender check).",
    ),
    WorkflowStep(
        label="IRM_ALERTS",
        function="purview_get_irm_alerts",
        build_argsets=_irm_alerts,
        covers=("RISK",),
        description="Phase 2A: Insider Risk Management signals (leaver, bulk download).",
    ),
    WorkflowStep(
        label="USER_ACCESS_REVIEW",
        function="entra_user_access_review",
        build_argsets=_user_access_review,
        covers=("USER", "RISK"),
        description="Phase 2A: comprehensive access review (recent admin changes).",
    ),
    WorkflowStep(
        label="FILE_EVENTS",
        function="splunk_run_query",
        build_argsets=_file_events_query,
        covers=("FILE", "EVENTS"),
        description="Phase 2C: file-event timeline (download / share / upload).",
    ),
    WorkflowStep(
        label="EMAIL_OUTBOUND",
        function="splunk_run_query",
        build_argsets=_email_outbound_query,
        covers=("FILE", "EVENTS"),
        description="Phase 2B/C: outbound external emails from the user.",
    ),
    WorkflowStep(
        label="PRINT_EVENTS",
        function="splunk_run_query",
        build_argsets=_print_events_query,
        covers=("ENDPOINT",),
        description="Phase 2D: print activity (DLP exfil channel).",
    ),
    WorkflowStep(
        label="SIGNIN_LOGS",
        function="entra_sign_in_logs",
        build_argsets=_signin_logs,
        covers=("EVENTS",),
        description="Phase 2C: login / VPN / location around the alert.",
    ),
    WorkflowStep(
        label="USER_DASHBOARD",
        function="splunk_search_dashboard",
        build_argsets=_user_dashboard,
        covers=("EVENTS",),
        description="Phase 2C: SIEM activity dashboard.",
    ),
    WorkflowStep(
        label="DEVICE_EVENTS",
        function="cs_get_device_events",
        build_argsets=_device_events,
        covers=("ENDPOINT",),
        description="Phase 2D: USB / install / removable-media events.",
    ),
    WorkflowStep(
        label="APP_EVENTS",
        function="splunk_search_app_events",
        build_argsets=_app_events,
        covers=("CLOUD",),
        description="Phase 2D: SharePoint / OneDrive / app share actions.",
    ),
    WorkflowStep(
        label="DOMAIN_TI",
        function="ti_lookup_domain",
        build_argsets=_domain_ti,
        covers=("DOMAIN", "URL"),
        description="Phase 2B: TI per destination domain (gmail/yahoo/competitor flags).",
    ),
    WorkflowStep(
        label="IP_TI",
        function="ti_lookup_ip",
        build_argsets=_ip_ti,
        covers=("URL",),
        description="Phase 2B: TI per IP from sign-ins / events.",
    ),
    WorkflowStep(
        label="EMAIL_TI",
        function="ti_lookup_email_address",
        build_argsets=_email_ti,
        covers=("DOMAIN",),
        description="Phase 2B: TI per external recipient address from outbound mail.",
    ),
]
