"""
Variable (time-varying) company generation API re-exports (local src versions).
"""
from .snapshot_generator import GenerationConfig as SnapshotGenerationConfig, generate_snapshots
from .user_activity import add_file_event_logs, add_login_log, add_random_login_logs, add_recent_activity_log, add_app_event_logs, add_network_event_logs, vary_count
from .file_events import generate_file_event_logs, FileWorldState
from .email_events import generate_email_event_logs
from .app_events import generate_app_event_logs
from .process_events import generate_process_event_logs
from .device_events import generate_device_event_logs
from .network_events import generate_network_event_logs
from .admin_actions import (
    add_to_group,
    remove_from_group,
    add_to_distribution_list,
    remove_from_distribution_list,
    add_role,
    remove_role,
    enable_mfa,
    disable_mfa,
    bypass_mfa,
    reset_mfa,
    revoke_token,
    disable_account,
    enable_account,
    unlock_account,
    register_device,
    remove_device,
    generate_random_admin_actions,
)
from .event_correlations import (
    generate_correlated_events,
    CORRELATION_SCENARIOS,
    delay,
    sample_delay,
)
from .event_pipeline import (
    generate_all_events,
    enrich_company_with_events,
)
from .email_scenario_engine import (
    generate_scenario_based_emails,
    generate_single_scenario,
    get_all_scenarios,
)
from .email_file_correlator import (
    correlate_email_file_events,
)
from .login_events import generate_login_event_logs
from .login_correlations import (
    generate_login_correlations,
    LOGIN_CORRELATION_SCENARIOS,
)
from .file_correlations import (
    generate_file_correlations,
    fulfill_share_reads,
)
from .admin_correlations import (
    generate_admin_correlations,
    ADMIN_CORRELATION_SCENARIOS,
)
from .temporal_model import (
    CircadianSampler,
    WeeklyCycleModulator,
    sample_timestamp,
    format_ts,
    resolve_event_count,
    resolve_person_temporal,
    get_window,
)
from .episodic_bursts import (
    BurstEvent,
    BurstSchedule,
    generate_burst_schedule,
    apply_burst_to_count,
    inject_burst_emails,
)
from .confounders import (
    ConfounderPlan,
    plan_confounders,
    inject_confounders,
)

__all__ = [
    "SnapshotGenerationConfig",
    "generate_snapshots",
    "add_login_log",
    "add_random_login_logs",
    "add_recent_activity_log",
    "add_file_event_logs",
    "add_app_event_logs",
    "generate_file_event_logs",
    "FileWorldState",
    "generate_email_event_logs",
    "generate_app_event_logs",
    "generate_process_event_logs",
    "generate_device_event_logs",
    "add_network_event_logs",
    "generate_network_event_logs",
    # Admin actions
    "add_to_group",
    "remove_from_group",
    "add_to_distribution_list",
    "remove_from_distribution_list",
    "add_role",
    "remove_role",
    "enable_mfa",
    "disable_mfa",
    "bypass_mfa",
    "reset_mfa",
    "revoke_token",
    "disable_account",
    "enable_account",
    "unlock_account",
    "register_device",
    "remove_device",
    "generate_random_admin_actions",
    # Event correlations
    "generate_correlated_events",
    "CORRELATION_SCENARIOS",
    "delay",
    "sample_delay",
    # Event pipeline
    "generate_all_events",
    "enrich_company_with_events",
    # Email scenarios
    "generate_scenario_based_emails",
    "generate_single_scenario",
    "get_all_scenarios",
    # Email-file correlation
    "correlate_email_file_events",
    # Login events
    "generate_login_event_logs",
    # Login correlations
    "generate_login_correlations",
    "LOGIN_CORRELATION_SCENARIOS",
    # File correlations
    "generate_file_correlations",
    "fulfill_share_reads",
    # Admin correlations
    "generate_admin_correlations",
    "ADMIN_CORRELATION_SCENARIOS",
    # Temporal model
    "CircadianSampler",
    "WeeklyCycleModulator",
    "sample_timestamp",
    "format_ts",
    "resolve_event_count",
    "resolve_person_temporal",
    "get_window",
    # Episodic bursts
    "BurstEvent",
    "BurstSchedule",
    "generate_burst_schedule",
    "apply_burst_to_count",
    "inject_burst_emails",
    # Confounders
    "ConfounderPlan",
    "plan_confounders",
    "inject_confounders",
]


