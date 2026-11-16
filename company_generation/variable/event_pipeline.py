"""
Event generation pipeline that orchestrates correlated and independent event generation.

This module provides a unified pipeline for generating all event types:
1. First, generate correlated event scenarios (linked events across types)
2. Then, generate independent random events to fill in activity
3. Finally, sort all events by timestamp for each employee

Usage:
    from company_generation.variable.event_pipeline import generate_all_events

    stats = generate_all_events(company, seed=1337)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .event_correlations import generate_correlated_events
from .login_events import generate_login_event_logs
from .email_events import generate_email_event_logs
from .file_events import generate_file_event_logs, FileWorldState
from .file_correlations import fulfill_share_reads
from .admin_actions import generate_random_admin_actions
from .app_events import generate_app_event_logs
from .process_events import generate_process_event_logs
from .device_events import generate_device_event_logs
from .network_events import generate_network_event_logs
from .temporal_model import get_window
from .episodic_bursts import generate_burst_schedule, inject_burst_emails, annotate_employees_with_bursts
from .cloud_events import generate_cloud_event_logs
from .mfa_events import generate_mfa_event_logs
from .confounders import plan_confounders, inject_confounders


Person = Dict[str, Any]
Company = Dict[str, Any]


def _select_people_container(company: Company) -> Tuple[List[Person], str]:
    """Select the appropriate people container (employees or workers)."""
    employees = company.get("employees")
    if isinstance(employees, list) and employees:
        return employees, "employee"
    workers = company.get("workers")
    if isinstance(workers, list) and workers:
        return workers, "worker"
    return [], "employee"


def _sort_events_by_timestamp(company: Company) -> Dict[str, int]:
    """
    Sort all event lists by timestamp for each employee.

    This ensures events appear in chronological order after merging
    correlated and independent events.

    Args:
        company: Company data dict with employees/workers

    Returns:
        Statistics about sorting operations
    """
    stats = {
        "employees_processed": 0,
        "event_lists_sorted": 0,
    }

    people, _ = _select_people_container(company)

    event_types = ["logins", "email_events", "file_events", "admin_actions", "user_actions", "app_events", "process_events", "mfa_events", "device_events", "cloud_events"]

    for person in people:
        recent_activity = person.get("recent_activity")
        if not isinstance(recent_activity, dict):
            continue

        sorted_any = False
        for event_type in event_types:
            events = recent_activity.get(event_type)
            if not isinstance(events, list) or not events:
                continue

            # Check if all events have timestamps
            if all(isinstance(e, dict) and "ts" in e for e in events):
                try:
                    events.sort(key=lambda e: e.get("ts", ""))
                    recent_activity[event_type] = events
                    stats["event_lists_sorted"] += 1
                    sorted_any = True
                except Exception:
                    pass  # Skip if sorting fails

        if sorted_any:
            stats["employees_processed"] += 1

    # Sort network events at the subnet level
    for subnet in (company.get("network") or {}).get("subnets", []):
        events = subnet.get("events")
        if not isinstance(events, list) or not events:
            continue
        if all(isinstance(e, dict) and "ts" in e for e in events):
            try:
                events.sort(key=lambda e: e.get("ts", ""))
                subnet["events"] = events
                stats["event_lists_sorted"] += 1
            except Exception:
                pass

    return stats


def generate_all_events(
    company: Company,
    *,
    seed: int = 1337,
    # Correlation settings
    scenarios_per_employee: float = 0.3,
    # Login settings
    login_events_multiplier: float = 1.0,
    # Email settings
    email_events_multiplier: float = 1.0,
    max_attachments_per_email: int = 2,
    # File event settings
    file_events_multiplier: float = 1.0,
    max_shares_per_file: int = 3,
    # Admin action settings
    admin_actions_multiplier: float = 1.0,
    # App event settings
    app_events_multiplier: float = 1.0,
    # Process event settings
    process_events_multiplier: float = 1.0,  # scales baseline (2.0 = 2x events)
    # Device event settings
    device_events_multiplier: float = 1.0,
    # Network event settings
    network_events_multiplier: float = 1.0,
    # Cloud event settings
    cloud_events_multiplier: float = 1.0,
    # Difficulty scaling
    confounder_rate_scale: float = 1.0,
    baseline_std_scale: float = 1.0,
    # Control flags
    generate_correlations: bool = True,
    generate_logins: bool = True,
    generate_emails: bool = True,
    generate_file_events: bool = True,
    generate_admin_actions: bool = True,
    generate_app_events: bool = True,
    generate_process_events: bool = True,
    generate_device_events: bool = True,
    generate_network_events: bool = True,
    generate_cloud_events: bool = True,
    replace_existing: bool = True,
    # Temporal model configuration
    generation_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generate all event logs with proper correlations.

    This function orchestrates the complete event generation pipeline:
    1. Generate correlated event scenarios FIRST (if enabled)
    2. Generate independent random events for each type
    3. Sort all events by timestamp for each employee

    All event count parameters are **multipliers** of the per-person baseline
    rate (1.0 = normal, 2.0 = double, 0.5 = half).  The baseline comes from
    each person's ``behavior_baselines`` or from hardcoded role-tier defaults.

    Args:
        company: Company data dict to modify in-place
        seed: Base seed for deterministic generation (each generator uses seed+offset)
        scenarios_per_employee: Fraction of employees to assign correlation scenarios
        login_events_multiplier: Multiplier for baseline login event rate
        email_events_multiplier: Multiplier for baseline email event rate
        max_attachments_per_email: Maximum attachments per email
        file_events_multiplier: Multiplier for baseline file event rate
        max_shares_per_file: Maximum shares per file event
        admin_actions_multiplier: Multiplier for baseline admin action rate
        app_events_multiplier: Multiplier for baseline app event rate
        process_events_multiplier: Multiplier for baseline process event rate
        device_events_multiplier: Multiplier for baseline device event rate
        network_events_multiplier: Multiplier for baseline network event rate
        generate_correlations: Whether to generate correlated scenarios
        generate_logins: Whether to generate random login events
        generate_emails: Whether to generate random email events
        generate_file_events: Whether to generate random file events
        generate_admin_actions: Whether to generate random admin actions
        generate_app_events: Whether to generate random app events
        generate_process_events: Whether to generate process events
        generate_device_events: Whether to generate device events
        generate_network_events: Whether to generate network events
        replace_existing: If True, replace existing events; if False, append

    Returns:
        Comprehensive statistics dict with counts from each generation phase

    Example:
        >>> company = load_company_json("company.json")
        >>> stats = generate_all_events(company, seed=42, scenarios_per_employee=0.4)
        >>> print(f"Generated {stats['total_events']} events")
        >>> print(f"Correlated scenarios: {stats['correlations']['scenarios_generated']}")
    """
    # Resolve generation_config: explicit param > company data > empty
    gen_cfg = generation_config or company.get("_generation_config") or {}

    stats: Dict[str, Any] = {
        "correlations": {},
        "bursts": {},
        "logins": {},
        "emails": {},
        "file_events": {},
        "admin_actions": {},
        "app_events": {},
        "process_events": {},
        "device_events": {},
        "network_events": {},
        "cloud_events": {},
        "confounders": {},
        "sorting": {},
        "total_events": 0,
    }

    people, container_kind = _select_people_container(company)

    if not people:
        return stats

    # If replacing existing, clear all event lists first
    if replace_existing:
        for person in people:
            ra = person.setdefault("recent_activity", {})
            ra["logins"] = []
            ra["email_events"] = []
            ra["file_events"] = []
            ra["admin_actions"] = []
            ra["app_events"] = []
            ra["process_events"] = []
            ra["mfa_events"] = []
            ra["device_events"] = []
            ra["cloud_events"] = []
        # Clear network events at the subnet level
        for subnet in (company.get("network") or {}).get("subnets", []):
            subnet["events"] = []
        # Clear cloud events
        if company.get("cloud"):
            company["cloud"]["events"] = []

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1: Generate correlated event scenarios FIRST
    # ─────────────────────────────────────────────────────────────────────────
    if generate_correlations:
        correlation_stats = generate_correlated_events(
            company,
            seed=seed,
            scenarios_per_employee=scenarios_per_employee,
        )
        stats["correlations"] = correlation_stats
        stats["total_events"] += correlation_stats.get("events_generated", 0)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1b: Generate episodic burst schedule
    # ─────────────────────────────────────────────────────────────────────────
    burst_schedule = generate_burst_schedule(
        company,
        seed=seed,
        generation_config=gen_cfg,
    )
    stats["bursts"] = {
        "active_bursts": len(burst_schedule.bursts),
        "burst_names": [b.name for b in burst_schedule.bursts],
        "total_affected_employees": len(
            set().union(*(b.affected_employee_ids for b in burst_schedule.bursts))
        ) if burst_schedule.bursts else 0,
    }

    # Tag each employee with their burst involvement
    annotate_employees_with_bursts(company, burst_schedule)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1c: Inject burst-explaining email scenarios
    # ─────────────────────────────────────────────────────────────────────────
    burst_email_stats = inject_burst_emails(
        company,
        burst_schedule,
        seed=seed,
    )
    stats["bursts"]["email_scenarios"] = burst_email_stats
    stats["total_events"] += burst_email_stats.get("burst_emails_injected", 0)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2: Generate independent random events
    # ─────────────────────────────────────────────────────────────────────────

    # Pre-compute window bounds for burst scaling
    if gen_cfg:
        _window_start, _window_end = get_window(gen_cfg)
    else:
        from datetime import datetime, timedelta, timezone as tz
        _window_end = datetime.now(tz.utc)
        _window_start = _window_end - timedelta(days=30)

    # 2a. Login events (realistic IP clustering, Zipf app weights, role-conditioned counts)
    if generate_logins:
        login_stats = generate_login_event_logs(
            company,
            seed=seed + 1000,
            replace_existing=False,  # Don't replace — we already cleared if needed
            events_multiplier=login_events_multiplier,
            baseline_std_scale=baseline_std_scale,
            generation_config=gen_cfg,
            burst_schedule=burst_schedule,
            safe_mode=True,
        )
        stats["logins"] = login_stats
        stats["total_events"] += login_stats.get("events_added", 0)

    # 2a+. MFA events (derived from login events that used MFA methods)
    mfa_stats = generate_mfa_event_logs(
        company,
        seed=seed + 1500,
        replace_existing=False,
        generation_config=gen_cfg,
    )
    stats["mfa_events"] = mfa_stats
    stats["total_events"] += mfa_stats.get("events_added", 0)

    # 2b. Email events
    if generate_emails and email_events_multiplier > 0:
        email_stats = generate_email_event_logs(
            company,
            seed=seed + 2000,
            replace_existing=False,  # Don't replace - we already cleared if needed
            events_multiplier=email_events_multiplier,
            baseline_std_scale=baseline_std_scale,
            max_attachments_per_email=max_attachments_per_email,
            generation_config=gen_cfg,
        )
        stats["emails"] = email_stats
        stats["total_events"] += email_stats.get("events_added", 0)

    # 2c. File events (session-based with world state)
    file_world_state = FileWorldState()
    if generate_file_events and file_events_multiplier > 0:
        file_stats, file_world_state = generate_file_event_logs(
            company,
            seed=seed + 3000,
            max_shares_per_file=max_shares_per_file,
            replace_existing=False,  # Don't replace - we already cleared if needed
            events_multiplier=file_events_multiplier,
            baseline_std_scale=baseline_std_scale,
            generation_config=gen_cfg,
            burst_schedule=burst_schedule,
        )
        stats["file_events"] = file_stats
        stats["total_events"] += file_stats.get("events_added", 0)

    # 2c+. Fulfill share-read tasks from file event world state
    if file_world_state.pending_share_reads:
        share_read_stats = fulfill_share_reads(
            company,
            file_world_state,
            seed=seed + 3500,
        )
        stats["file_share_reads"] = share_read_stats
        stats["total_events"] += share_read_stats.get("reads_generated", 0)

    # 2d. Admin actions (safe_mode=True excludes actions that imply correlated events)
    if generate_admin_actions and admin_actions_multiplier > 0:
        admin_stats = generate_random_admin_actions(
            company,
            seed=seed + 4000,
            actions_multiplier=admin_actions_multiplier,
            replace_existing=False,  # Don't replace - we already cleared if needed
            safe_mode=True,  # Exclude unlock_account, reset_mfa, disable_account, etc.
            generation_config=gen_cfg,
        )
        stats["admin_actions"] = admin_stats
        stats["total_events"] += admin_stats.get("actions_added", 0)

    # 2e. App events (in-app activity based on person's authorised apps)
    if generate_app_events and app_events_multiplier > 0:
        app_stats = generate_app_event_logs(
            company,
            seed=seed + 5000,
            replace_existing=False,  # Don't replace - we already cleared if needed
            events_multiplier=app_events_multiplier,
            baseline_std_scale=baseline_std_scale,
            generation_config=gen_cfg,
        )
        stats["app_events"] = app_stats
        stats["total_events"] += app_stats.get("events_added", 0)

    # 2f. Process events (correlated with app/file events — must come after 2c/2e)
    if generate_process_events:
        process_stats = generate_process_event_logs(
            company,
            seed=seed + 6000,
            replace_existing=False,  # Don't replace - we already cleared if needed
            baseline_multiplier=process_events_multiplier,
            baseline_std_scale=baseline_std_scale,
            generation_config=gen_cfg,
            burst_schedule=burst_schedule,
        )
        stats["process_events"] = process_stats
        stats["total_events"] += process_stats.get("events_added", 0)

    # 2g. Device events (USB, bluetooth, software installs)
    if generate_device_events and device_events_multiplier > 0:
        device_stats = generate_device_event_logs(
            company,
            seed=seed + 7000,
            replace_existing=False,  # Don't replace - we already cleared if needed
            events_multiplier=device_events_multiplier,
            baseline_std_scale=baseline_std_scale,
            generation_config=gen_cfg,
        )
        stats["device_events"] = device_stats
        stats["total_events"] += device_stats.get("events_added", 0)

    # 2h. Network events (firewall/network logs)
    if generate_network_events and network_events_multiplier > 0:
        network_stats = generate_network_event_logs(
            company,
            seed=seed + 8000,
            replace_existing=False,  # Don't replace - we already cleared if needed
            events_multiplier=network_events_multiplier,
            baseline_std_scale=baseline_std_scale,
            generation_config=gen_cfg,
        )
        stats["network_events"] = network_stats
        stats["total_events"] += network_stats.get("events_added", 0)

    # 2j. Cloud events (cloud API audit logs per instance)
    if generate_cloud_events and cloud_events_multiplier > 0:
        cloud_event_stats = generate_cloud_event_logs(
            company,
            seed=seed + 9000,
            replace_existing=False,  # Don't replace - we already cleared if needed
            events_multiplier=cloud_events_multiplier,
            baseline_std_scale=baseline_std_scale,
            generation_config=gen_cfg,
        )
        stats["cloud_events"] = cloud_event_stats
        stats["total_events"] += cloud_event_stats.get("events_added", 0)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2i: Inject deceptive benign confounders
    # ─────────────────────────────────────────────────────────────────────────
    confounder_plans = plan_confounders(
        company,
        seed=seed,
        generation_config=gen_cfg,
        confounder_rate_scale=confounder_rate_scale,
    )
    confounder_stats = inject_confounders(
        company,
        confounder_plans,
        seed=seed,
    )
    stats["confounders"] = confounder_stats
    stats["total_events"] += confounder_stats.get("total_events_injected", 0)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3: Sort all events by timestamp
    # ─────────────────────────────────────────────────────────────────────────
    sort_stats = _sort_events_by_timestamp(company)
    stats["sorting"] = sort_stats

    return stats


def enrich_company_with_events(
    company: Company,
    *,
    seed: int = 1337,
    correlation_ratio: float = 0.3,
    activity_level: str = "normal",
    generation_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Enrich a company fixture with realistic event logs.

    This is a convenience wrapper around generate_all_events with
    preset configurations for different activity levels.

    Args:
        company: Company data dict to modify in-place
        seed: Base seed for deterministic generation
        correlation_ratio: Fraction of employees with correlated scenarios (0.0-1.0)
        activity_level: One of "minimal", "normal", "high"
            - minimal: 1-2 events per type per employee
            - normal: 3-8 events per type per employee (default)
            - high: 10-15 events per type per employee

    Returns:
        Statistics from event generation

    Example:
        >>> company = generate_company(cfg, baseline_date, scenario_id)
        >>> stats = enrich_company_with_events(company, activity_level="high")
    """
    # Preset configurations by activity level (all values are multipliers of baseline)
    presets = {
        "minimal": {
            "login_events_multiplier": 0.5,
            "email_events_multiplier": 0.3,
            "file_events_multiplier": 0.3,
            "admin_actions_multiplier": 0.3,
            "app_events_multiplier": 0.3,
            "process_events_multiplier": 0.5,
            "device_events_multiplier": 0.3,
            "network_events_multiplier": 0.3,
            "cloud_events_multiplier": 0.3,
        },
        "normal": {
            "login_events_multiplier": 1.0,
            "email_events_multiplier": 1.0,
            "file_events_multiplier": 1.0,
            "admin_actions_multiplier": 1.0,
            "app_events_multiplier": 1.0,
            "process_events_multiplier": 1.0,
            "device_events_multiplier": 1.0,
            "network_events_multiplier": 1.0,
            "cloud_events_multiplier": 1.0,
        },
        "high": {
            "login_events_multiplier": 2.5,
            "email_events_multiplier": 2.5,
            "file_events_multiplier": 2.5,
            "admin_actions_multiplier": 2.5,
            "app_events_multiplier": 2.5,
            "process_events_multiplier": 2.5,
            "device_events_multiplier": 2.5,
            "network_events_multiplier": 2.5,
            "cloud_events_multiplier": 2.5,
        },
    }

    config = presets.get(activity_level, presets["normal"])

    return generate_all_events(
        company,
        seed=seed,
        scenarios_per_employee=correlation_ratio,
        generation_config=generation_config,
        **config,
    )
