"""
Admin actions module for company data manipulation.

Each function performs both:
1. The actual modification to the company data structure
2. Logging the action to the employee's recent_activity.admin_actions
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .user_activity import _resolve_worker, add_recent_activity_log, vary_count
from .temporal_model import (
    format_ts,
    get_window,
    resolve_event_count,
    resolve_person_temporal,
    sample_timestamp,
)
from .episodic_bursts import BurstSchedule, apply_burst_to_count


# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------


def _now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _get_employee_email(company: Dict[str, Any], employee_id: str) -> str:
    """Get the primary email for an employee."""
    person = _resolve_worker(company, employee_id=employee_id)
    # Try 'email' field first (static fixtures), then 'emails' array
    email = person.get("email")
    if not email:
        emails = person.get("emails", [])
        email = emails[0] if emails else None
    if not email:
        raise ValueError(f"Employee {employee_id} has no email address")
    return email


def _find_group(company: Dict[str, Any], group_id: str) -> Optional[Dict[str, Any]]:
    """Find a group by ID."""
    groups = company.get("groups", [])
    for g in groups:
        if g.get("id") == group_id:
            return g
    return None


def _find_group_by_name(company: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    """Find a group by name."""
    groups = company.get("groups", [])
    for g in groups:
        if g.get("name") == name:
            return g
    return None


def _find_distribution_list(
    company: Dict[str, Any], address: str
) -> Optional[Dict[str, Any]]:
    """Find a distribution list mailbox by address."""
    mailboxes = company.get("mailboxes", [])
    for m in mailboxes:
        if m.get("is_distribution_list") and m.get("address") == address:
            return m
    return None


def _find_account_by_system(
    person: Dict[str, Any], system: str
) -> Optional[Dict[str, Any]]:
    """Find an account by system name within a person's accounts."""
    accounts = person.get("accounts", [])
    for acc in accounts:
        if acc.get("system") == system:
            return acc
    return None


def _find_device(company: Dict[str, Any], device_id: str) -> Optional[Dict[str, Any]]:
    """Find a device by ID."""
    devices = company.get("devices", [])
    for d in devices:
        if d.get("id") == device_id:
            return d
    return None


def _log_admin_action(
    company: Dict[str, Any],
    employee_id: str,
    action: str,
    system: str,
    approved_by: str,
    ts: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Log an admin action to the employee's recent_activity."""
    log_entry: Dict[str, Any] = {
        "ts": ts or _now_iso(),
        "system": system,
        "action": action,
        "approved_by": approved_by,
    }
    if details:
        log_entry["details"] = details
    return add_recent_activity_log(
        company,
        employee_id=employee_id,
        key="admin_actions",
        log=log_entry,
    )


# -----------------------------------------------------------------------------
# Group Management
# -----------------------------------------------------------------------------


def add_to_group(
    company: Dict[str, Any],
    *,
    employee_id: str,
    group_id: str,
    system: str = "okta",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Add an employee to a group and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee to add
        group_id: ID of the group to add the employee to
        system: System where the action is performed (okta, o365, github, etc.)
        approved_by: Who approved the action (change-mgmt, oncall, self)
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    group = _find_group(company, group_id)
    if not group:
        raise ValueError(f"Group '{group_id}' not found")

    # Add employee to group members if not already present
    members: List[str] = group.setdefault("members", [])
    if employee_id not in members:
        members.append(employee_id)

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="add_to_group",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"group_id": group_id, "group_name": group.get("name", group_id)},
    )


def remove_from_group(
    company: Dict[str, Any],
    *,
    employee_id: str,
    group_id: str,
    system: str = "okta",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Remove an employee from a group and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee to remove
        group_id: ID of the group to remove the employee from
        system: System where the action is performed
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    group = _find_group(company, group_id)
    if not group:
        raise ValueError(f"Group '{group_id}' not found")

    # Remove employee from group members
    members: List[str] = group.get("members", [])
    if employee_id in members:
        members.remove(employee_id)

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="remove_from_group",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"group_id": group_id, "group_name": group.get("name", group_id)},
    )


# -----------------------------------------------------------------------------
# Distribution List Management
# -----------------------------------------------------------------------------


def add_to_distribution_list(
    company: Dict[str, Any],
    *,
    employee_id: str,
    distribution_list: str,
    system: str = "o365",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Add an employee to a distribution list and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee to add
        distribution_list: Email address of the distribution list
        system: System where the action is performed
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    dl = _find_distribution_list(company, distribution_list)
    if not dl:
        raise ValueError(f"Distribution list '{distribution_list}' not found")

    # Get the employee's email
    employee_email = _get_employee_email(company, employee_id)

    # Add email to members if not already present
    members: List[str] = dl.setdefault("members", [])
    if employee_email not in members:
        members.append(employee_email)

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="add_to_distribution_list",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"distribution_list": distribution_list},
    )


def remove_from_distribution_list(
    company: Dict[str, Any],
    *,
    employee_id: str,
    distribution_list: str,
    system: str = "o365",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Remove an employee from a distribution list and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee to remove
        distribution_list: Email address of the distribution list
        system: System where the action is performed
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    dl = _find_distribution_list(company, distribution_list)
    if not dl:
        raise ValueError(f"Distribution list '{distribution_list}' not found")

    # Get the employee's email
    employee_email = _get_employee_email(company, employee_id)

    # Remove email from members
    members: List[str] = dl.get("members", [])
    if employee_email in members:
        members.remove(employee_email)

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="remove_from_distribution_list",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"distribution_list": distribution_list},
    )


# -----------------------------------------------------------------------------
# Role Management
# -----------------------------------------------------------------------------


def add_role(
    company: Dict[str, Any],
    *,
    employee_id: str,
    role: str,
    system: str = "okta",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Add a role to an employee's account and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee
        role: Role to add (e.g., 'admin', 'viewer')
        system: System where the role is added
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    person = _resolve_worker(company, employee_id=employee_id)
    accounts: List[Dict[str, Any]] = person.setdefault("accounts", [])

    # Find or create account for the system
    account = _find_account_by_system(person, system)
    if not account:
        # Create a new account for this system
        account = {"system": system, "username": person.get("email", employee_id), "roles": []}
        accounts.append(account)

    # Add role if not already present
    roles: List[str] = account.setdefault("roles", [])
    if role not in roles:
        roles.append(role)

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="add_role",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"role": role},
    )


def remove_role(
    company: Dict[str, Any],
    *,
    employee_id: str,
    role: str,
    system: str = "okta",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Remove a role from an employee's account and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee
        role: Role to remove
        system: System where the role is removed
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    person = _resolve_worker(company, employee_id=employee_id)
    account = _find_account_by_system(person, system)

    if account:
        roles: List[str] = account.get("roles", [])
        if role in roles:
            roles.remove(role)

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="remove_role",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"role": role},
    )


# -----------------------------------------------------------------------------
# MFA Management
# -----------------------------------------------------------------------------


def enable_mfa(
    company: Dict[str, Any],
    *,
    employee_id: str,
    system: str = "okta",
    methods: Optional[List[str]] = None,
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enable MFA for an employee's account and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee
        system: System where MFA is enabled
        methods: MFA methods to enable (e.g., ['push', 'totp'])
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    if methods is None:
        methods = ["push"]

    person = _resolve_worker(company, employee_id=employee_id)
    accounts: List[Dict[str, Any]] = person.setdefault("accounts", [])

    # Find or create account for the system
    account = _find_account_by_system(person, system)
    if not account:
        account = {"system": system, "username": person.get("email", employee_id)}
        accounts.append(account)

    # Enable MFA
    mfa = account.setdefault("mfa", {})
    mfa["enabled"] = True
    mfa["methods"] = methods

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="enable_mfa",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"methods": methods},
    )


def disable_mfa(
    company: Dict[str, Any],
    *,
    employee_id: str,
    system: str = "okta",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Disable MFA for an employee's account and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee
        system: System where MFA is disabled
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    person = _resolve_worker(company, employee_id=employee_id)
    account = _find_account_by_system(person, system)

    if account:
        mfa = account.get("mfa", {})
        mfa["enabled"] = False
        account["mfa"] = mfa

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="disable_mfa",
        system=system,
        approved_by=approved_by,
        ts=ts,
    )


def bypass_mfa(
    company: Dict[str, Any],
    *,
    employee_id: str,
    system: str = "okta",
    duration_hours: int = 24,
    approved_by: str = "oncall",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Log an MFA bypass action (temporary bypass, no permanent data change).

    Args:
        company: The company data structure
        employee_id: ID of the employee
        system: System where MFA is bypassed
        duration_hours: Duration of the bypass in hours
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    # Bypass is temporary - only log the action, no permanent change
    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="bypass_mfa",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"duration_hours": duration_hours},
    )


def reset_mfa(
    company: Dict[str, Any],
    *,
    employee_id: str,
    system: str = "okta",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Reset MFA methods for an employee's account and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee
        system: System where MFA is reset
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    person = _resolve_worker(company, employee_id=employee_id)
    account = _find_account_by_system(person, system)

    if account:
        mfa = account.setdefault("mfa", {})
        mfa["methods"] = []

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="reset_mfa",
        system=system,
        approved_by=approved_by,
        ts=ts,
    )


# -----------------------------------------------------------------------------
# Token Management
# -----------------------------------------------------------------------------


def revoke_token(
    company: Dict[str, Any],
    *,
    employee_id: str,
    system: str = "okta",
    token_type: str = "access_token",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Log a token revocation action (tokens are ephemeral, no permanent data change).

    Args:
        company: The company data structure
        employee_id: ID of the employee
        system: System where the token is revoked
        token_type: Type of token revoked (access_token, refresh_token, session)
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    # Token revocation is ephemeral - only log the action
    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="revoke_token",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"token_type": token_type},
    )


# -----------------------------------------------------------------------------
# Account Lifecycle Management
# -----------------------------------------------------------------------------


def disable_account(
    company: Dict[str, Any],
    *,
    employee_id: str,
    system: str = "okta",
    reason: str = "security",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Disable an employee's account and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee
        system: System where the account is disabled
        reason: Reason for disabling (security, termination, policy)
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    person = _resolve_worker(company, employee_id=employee_id)
    accounts: List[Dict[str, Any]] = person.setdefault("accounts", [])

    # Find or create account for the system
    account = _find_account_by_system(person, system)
    if not account:
        account = {"system": system, "username": person.get("email", employee_id)}
        accounts.append(account)

    # Set disabled flag
    account["disabled"] = True

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="disable_account",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"reason": reason},
    )


def enable_account(
    company: Dict[str, Any],
    *,
    employee_id: str,
    system: str = "okta",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enable an employee's account and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee
        system: System where the account is enabled
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    person = _resolve_worker(company, employee_id=employee_id)
    account = _find_account_by_system(person, system)

    if account and "disabled" in account:
        del account["disabled"]

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="enable_account",
        system=system,
        approved_by=approved_by,
        ts=ts,
    )


def unlock_account(
    company: Dict[str, Any],
    *,
    employee_id: str,
    system: str = "okta",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Log an account unlock action (unlock is ephemeral, no permanent data change).

    Args:
        company: The company data structure
        employee_id: ID of the employee
        system: System where the account is unlocked
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    # Unlock is ephemeral - only log the action
    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="unlock_account",
        system=system,
        approved_by=approved_by,
        ts=ts,
    )


# -----------------------------------------------------------------------------
# Device Management
# -----------------------------------------------------------------------------


def register_device(
    company: Dict[str, Any],
    *,
    employee_id: str,
    device_id: Optional[str] = None,
    hostname: str,
    os: str = "Windows",
    system: str = "endpoint_mgmt",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Register a new device for an employee and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee
        device_id: ID of the device (auto-generated if not provided)
        hostname: Hostname of the device
        os: Operating system of the device
        system: System where the device is registered
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    devices: List[Dict[str, Any]] = company.setdefault("devices", [])

    # Generate device ID if not provided
    if not device_id:
        device_id = f"dev_{uuid.uuid4().hex[:8]}"

    # Check if device already exists
    existing = _find_device(company, device_id)
    if existing:
        raise ValueError(f"Device '{device_id}' already exists")

    # Create new device
    new_device: Dict[str, Any] = {
        "id": device_id,
        "hostname": hostname,
        "os": os,
        "owner_user_id": employee_id,
    }
    devices.append(new_device)

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="register_device",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"device_id": device_id, "hostname": hostname, "os": os},
    )


def remove_device(
    company: Dict[str, Any],
    *,
    employee_id: str,
    device_id: str,
    system: str = "endpoint_mgmt",
    approved_by: str = "self",
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Remove a device from the company and log the action.

    Args:
        company: The company data structure
        employee_id: ID of the employee (for logging)
        device_id: ID of the device to remove
        system: System where the device is removed
        approved_by: Who approved the action
        ts: Timestamp of the action (defaults to now)

    Returns:
        The admin action log entry
    """
    devices: List[Dict[str, Any]] = company.get("devices", [])

    # Find and remove the device
    device = _find_device(company, device_id)
    hostname = device.get("hostname", "unknown") if device else "unknown"

    company["devices"] = [d for d in devices if d.get("id") != device_id]

    return _log_admin_action(
        company,
        employee_id=employee_id,
        action="remove_device",
        system=system,
        approved_by=approved_by,
        ts=ts,
        details={"device_id": device_id, "hostname": hostname},
    )


# -----------------------------------------------------------------------------
# Random Generation
# -----------------------------------------------------------------------------

# All available admin actions with their requirements
# Format: (action_name, system_choices, requires_target, target_type)
ADMIN_ACTIONS = [
    ("add_to_group", ["okta", "o365", "google"], True, "group"),
    ("remove_from_group", ["okta", "o365", "google"], True, "group"),
    ("add_to_distribution_list", ["o365", "google"], True, "distribution_list"),
    ("remove_from_distribution_list", ["o365", "google"], True, "distribution_list"),
    ("add_role", ["okta", "o365", "github", "aws", "gcp", "azure"], True, "role"),
    ("remove_role", ["okta", "o365", "github", "aws", "gcp", "azure"], True, "role"),
    ("enable_mfa", ["okta", "o365", "google"], False, None),
    ("disable_mfa", ["okta", "o365", "google"], False, None),
    ("bypass_mfa", ["okta", "o365", "google"], False, None),
    ("reset_mfa", ["okta", "o365", "google"], False, None),
    ("revoke_token", ["okta", "o365", "github", "slack"], False, None),
    ("disable_account", ["okta", "o365", "google"], False, None),
    ("enable_account", ["okta", "o365", "google"], False, None),
    ("unlock_account", ["okta", "o365", "google"], False, None),
    ("register_device", ["endpoint_mgmt", "okta"], False, None),
    ("remove_device", ["endpoint_mgmt", "okta"], True, "device"),
]

# Actions that imply correlated events (should be excluded in safe_mode):
# - unlock_account: implies prior account_locked login failure
# - reset_mfa: implies prior mfa_failed login failures
# - bypass_mfa: implies prior mfa_failed login failure
# - disable_account: implies no more logins should follow
# - enable_account: implies prior disable_account
# - revoke_token: implies suspicious activity and re-auth after
CORRELATION_TRIGGERING_ACTIONS = {
    "unlock_account",
    "reset_mfa",
    "bypass_mfa",
    "disable_account",
    "enable_account",
    "revoke_token",
}

# Safe actions that don't imply other events must exist
SAFE_ADMIN_ACTIONS = [
    action for action in ADMIN_ACTIONS
    if action[0] not in CORRELATION_TRIGGERING_ACTIONS
]

APPROVAL_SOURCES = ["self", "oncall", "change-mgmt", "security-team"]
ROLE_EXAMPLES = ["admin", "viewer", "editor", "owner", "contributor", "reader", "operator"]

# ---------------------------------------------------------------------------
# Natural distribution constants
# ---------------------------------------------------------------------------

# Relative frequency weights for each action (higher = more common)
ACTION_WEIGHTS: Dict[str, float] = {
    # High (routine)
    "add_to_group": 25,
    "add_to_distribution_list": 15,
    "remove_from_group": 12,
    "add_role": 10,
    "enable_mfa": 8,
    # Medium (periodic)
    "register_device": 6,
    "remove_role": 4,
    "unlock_account": 4,
    "reset_mfa": 3,
    "remove_device": 2.5,
    "revoke_token": 2,
    # Rare (privileged)
    "bypass_mfa": 1,
    "disable_mfa": 0.8,
    "disable_account": 0.5,
    "enable_account": 0.2,
    "remove_from_distribution_list": 5,
}

# Per-action approval source probabilities: {action: [self, oncall, change-mgmt, security-team]}
_APPROVAL_MATRIX: Dict[str, Tuple[float, ...]] = {
    "add_to_group":                 (0.40, 0.35, 0.20, 0.05),
    "remove_from_group":            (0.35, 0.30, 0.25, 0.10),
    "add_to_distribution_list":     (0.50, 0.30, 0.15, 0.05),
    "remove_from_distribution_list":(0.45, 0.30, 0.20, 0.05),
    "add_role":                     (0.15, 0.30, 0.40, 0.15),
    "remove_role":                  (0.20, 0.30, 0.35, 0.15),
    "enable_mfa":                   (0.70, 0.20, 0.05, 0.05),
    "disable_mfa":                  (0.05, 0.15, 0.20, 0.60),
    "bypass_mfa":                   (0.00, 0.40, 0.10, 0.50),
    "reset_mfa":                    (0.30, 0.45, 0.15, 0.10),
    "revoke_token":                 (0.10, 0.35, 0.15, 0.40),
    "disable_account":              (0.00, 0.10, 0.30, 0.60),
    "enable_account":               (0.05, 0.20, 0.45, 0.30),
    "unlock_account":               (0.35, 0.50, 0.10, 0.05),
    "register_device":              (0.60, 0.25, 0.10, 0.05),
    "remove_device":                (0.30, 0.30, 0.25, 0.15),
}

# System affinity: weight given to the primary IdP
_PRIMARY_IDP_WEIGHT = 0.70

# Actions that always use a fixed system regardless of IdP
_FIXED_SYSTEM_ACTIONS: Dict[str, str] = {
    "add_to_distribution_list": "o365",
    "remove_from_distribution_list": "o365",
    "register_device": "endpoint_mgmt",
    "remove_device": "endpoint_mgmt",
}

# Department classification sets (mirrors login_events.py)
_ADMIN_OPS_DEPARTMENTS = {"IT", "Security", "Infrastructure"}
_ADMIN_ENG_DEPARTMENTS = {"Engineering"}
_ADMIN_SALES_DEPARTMENTS = {"Sales"}
_ADMIN_CS_DEPARTMENTS = {"Customer Success"}
_ADMIN_GENERAL_DEPARTMENTS = {
    "Product", "Marketing", "HR", "Finance", "Legal", "Operations", "Data Science",
}

# Role-tiered admin event rates: (mean_events_per_day, std_dev)
_DEFAULT_ADMIN_RATES: Dict[str, Tuple[float, float]] = {
    "general_ic":       (0.03, 0.02),
    "general_senior":   (0.05, 0.03),
    "eng_ic":           (0.05, 0.03),
    "eng_senior":       (0.07, 0.03),
    "ops_ic":           (0.10, 0.05),
    "ops_senior":       (0.15, 0.07),
    "manager":          (0.08, 0.04),
    "executive":        (0.04, 0.02),
    "sales_ic":         (0.05, 0.03),
    "cs_ic":            (0.05, 0.03),
}


def _classify_admin_tier(person: Dict[str, Any]) -> str:
    """Classify a person into an admin-action rate tier based on department/title."""
    dept = person.get("department", "")
    title = (person.get("title") or "").lower()

    if dept == "Executive" or any(
        t in title for t in ("ceo", "cto", "cfo", "coo", "ciso", "vp ", "vice president", "chief")
    ):
        return "executive"

    if any(t in title for t in ("manager", "director", "head of", "lead")):
        return "manager"

    if dept in _ADMIN_OPS_DEPARTMENTS:
        if any(t in title for t in ("senior", "staff", "principal", "lead")):
            return "ops_senior"
        return "ops_ic"

    if dept in _ADMIN_ENG_DEPARTMENTS:
        if any(t in title for t in ("senior", "staff", "principal")):
            return "eng_senior"
        return "eng_ic"

    if dept in _ADMIN_SALES_DEPARTMENTS:
        return "sales_ic"

    if dept in _ADMIN_CS_DEPARTMENTS:
        return "cs_ic"

    if dept in _ADMIN_GENERAL_DEPARTMENTS:
        if any(t in title for t in ("senior", "staff", "principal")):
            return "general_senior"
        return "general_ic"

    return "general_ic"


def _resolve_admin_count(
    person: Dict[str, Any],
    rng: random.Random,
    scale_factor: float = 1.0,
    window_days: int = 30,
) -> int:
    """Resolve how many admin actions a person should generate.

    The baseline rate comes from (in priority order):
    1. behavior_baselines.admin_baseline.avg_events_per_day (per-employee YAML)
    2. _DEFAULT_ADMIN_RATES by role tier (code defaults)

    ``scale_factor`` is applied to the final count (e.g. 2.0 doubles the count).
    """
    # 1. Check per-employee baselines
    baselines = person.get("behavior_baselines") or {}
    bl = baselines.get("admin_baseline")
    if isinstance(bl, dict) and "avg_events_per_day" in bl:
        avg_spec = bl["avg_events_per_day"]
        if isinstance(avg_spec, dict):
            mean_per_day = float(avg_spec.get("mean", 0.03))
            std_per_day = float(avg_spec.get("std", 0.02))
        else:
            mean_per_day = float(avg_spec)
            std_per_day = mean_per_day * 0.5
        person_rate = max(0.0, rng.gauss(mean_per_day, std_per_day))
        count = person_rate * window_days
    else:
        # 2. Code defaults by role tier
        tier = _classify_admin_tier(person)
        mean_per_day, std_per_day = _DEFAULT_ADMIN_RATES.get(tier, (0.03, 0.02))
        person_rate = max(0.0, rng.gauss(mean_per_day, std_per_day))
        count = person_rate * window_days

    return max(0, round(count * scale_factor))


def _resolve_primary_idp(company: Dict[str, Any]) -> str:
    """Detect the company's primary IdP from company.company.apps or default to 'okta'."""
    company_info = company.get("company", {})
    apps = company_info.get("apps", [])
    for app in apps:
        if isinstance(app, dict) and app.get("type") == "idp":
            name = app.get("name", "").lower()
            if name:
                return name
    return "okta"


def _pick_system_for_action(
    action_name: str,
    valid_systems: List[str],
    primary_idp: str,
    rng: random.Random,
) -> str:
    """Pick a system for an action with IdP affinity and fixed overrides."""
    # Fixed-system actions always use one system
    if action_name in _FIXED_SYSTEM_ACTIONS:
        return _FIXED_SYSTEM_ACTIONS[action_name]

    if not valid_systems:
        return primary_idp

    # If primary IdP is in the valid list, bias toward it
    if primary_idp in valid_systems:
        if rng.random() < _PRIMARY_IDP_WEIGHT:
            return primary_idp
        # Pick from the rest
        others = [s for s in valid_systems if s != primary_idp]
        if others:
            return rng.choice(others)
        return primary_idp

    # Primary IdP not in valid list — uniform choice
    return rng.choice(valid_systems)


def _pick_approval_source(action_name: str, rng: random.Random) -> str:
    """Pick an approval source based on per-action probability matrix."""
    probs = _APPROVAL_MATRIX.get(action_name)
    if probs is None:
        return rng.choice(APPROVAL_SOURCES)
    return rng.choices(APPROVAL_SOURCES, weights=probs, k=1)[0]


def _pick_weighted_action(
    action_pool: List[Tuple[str, List[str], bool, Optional[str]]],
    rng: random.Random,
) -> Tuple[str, List[str], bool, Optional[str]]:
    """Pick an action from the pool using ACTION_WEIGHTS."""
    weights = [ACTION_WEIGHTS.get(a[0], 1.0) for a in action_pool]
    return rng.choices(action_pool, weights=weights, k=1)[0]


def _get_available_groups(company: Dict[str, Any]) -> List[str]:
    """Get list of available group IDs."""
    return [g["id"] for g in company.get("groups", []) if g.get("id")]


def _get_available_distribution_lists(company: Dict[str, Any]) -> List[str]:
    """Get list of available distribution list addresses."""
    return [
        m["address"]
        for m in company.get("mailboxes", [])
        if m.get("is_distribution_list") and m.get("address")
    ]


def _get_available_devices(company: Dict[str, Any], employee_id: str) -> List[str]:
    """Get list of device IDs owned by the employee."""
    return [
        d["id"]
        for d in company.get("devices", [])
        if d.get("owner_user_id") == employee_id and d.get("id")
    ]


def _get_all_employee_ids(company: Dict[str, Any]) -> List[str]:
    """Get list of all employee IDs."""
    employees = company.get("employees", [])
    if employees:
        return [e["id"] for e in employees if e.get("id")]
    workers = company.get("workers", [])
    return [w["id"] for w in workers if w.get("id")]


def generate_random_admin_actions(
    company: Dict[str, Any],
    *,
    seed: Optional[int] = None,
    actions_multiplier: float = 1.0,
    replace_existing: bool = False,
    safe_mode: bool = True,
    generation_config: Optional[Dict[str, Any]] = None,
    burst_schedule: Optional[BurstSchedule] = None,
) -> Dict[str, Any]:
    """
    Generate random admin actions for all employees.

    Uses natural distributions: role-tiered volume (most employees get 0 actions),
    weighted action selection (routine actions dominate), system affinity (primary
    IdP biased), and per-action approval source probabilities.

    Args:
        company: The company data structure to modify in-place
        seed: Random seed for reproducibility
        actions_multiplier: Multiplier for baseline admin action rate (1.0 = normal)
        replace_existing: If True, replace existing admin_actions; otherwise append
        safe_mode: If True, only generate "safe" actions that don't imply other
                   correlated events must exist (e.g., excludes unlock_account
                   which implies prior account_locked login). Set to False if
                   generating correlated scenarios separately.
        generation_config: Optional temporal/window config
        burst_schedule: Optional burst schedule for volume scaling

    Returns:
        Statistics about the generation
    """
    gen_cfg = generation_config or company.get("_generation_config") or {}
    rng = random.Random(seed)
    stats: Dict[str, Any] = {
        "employees_total": 0,
        "employees_with_actions": 0,
        "actions_added": 0,
        "action_types": {},
    }

    employee_ids = _get_all_employee_ids(company)
    stats["employees_total"] = len(employee_ids)

    available_groups = _get_available_groups(company)
    available_dls = _get_available_distribution_lists(company)

    # Detect company primary IdP once
    primary_idp = _resolve_primary_idp(company)

    # Pre-compute window for temporal model
    window_start = window_end = None
    window_days = 30
    if gen_cfg:
        window_start, window_end = get_window(gen_cfg)
        window_days = gen_cfg.get("temporal", {}).get("window_days", 30)

    for emp_id in employee_ids:
        try:
            person = _resolve_worker(company, employee_id=emp_id)
        except ValueError:
            continue

        if replace_existing:
            ra = person.get("recent_activity", {})
            if "admin_actions" in ra:
                ra["admin_actions"] = []

        # Role-tiered volume: use _resolve_admin_count for natural distribution
        target_count = _resolve_admin_count(person, rng, actions_multiplier, window_days)

        # If not replacing, subtract existing actions
        if not replace_existing:
            current_count = len(
                (person.get("recent_activity") or {}).get("admin_actions") or []
            )
            target_count = max(0, target_count - current_count)

        # Apply burst scaling
        if burst_schedule and burst_schedule.bursts and window_start and window_end:
            target_count = apply_burst_to_count(
                target_count, emp_id, "admin_actions",
                burst_schedule, rng, window_start, window_end,
            )

        if target_count <= 0:
            continue

        # Build temporal samplers for this person
        circadian = weekly = None
        if gen_cfg:
            circadian, weekly = resolve_person_temporal(person, gen_cfg)

        employee_added = 0
        available_devices = _get_available_devices(company, emp_id)

        for _ in range(target_count):
            action_pool = SAFE_ADMIN_ACTIONS if safe_mode else ADMIN_ACTIONS
            action_name, systems, requires_target, target_type = _pick_weighted_action(action_pool, rng)

            if target_type == "group" and not available_groups:
                continue
            if target_type == "distribution_list" and not available_dls:
                continue
            if target_type == "device" and not available_devices:
                continue

            # Temporal model: smooth circadian sampling
            if circadian and weekly and window_start and window_end:
                ts_dt = sample_timestamp(circadian, weekly, rng, window_start, window_end)
                ts = format_ts(ts_dt)
            else:
                days_back = rng.randint(0, 29)
                hours_offset = rng.randint(-10, 10)
                ts_dt = datetime.now(timezone.utc) - timedelta(days=days_back, hours=hours_offset)
                ts = ts_dt.isoformat().replace("+00:00", "Z")

            # System affinity: bias toward primary IdP with fixed overrides
            system = _pick_system_for_action(action_name, systems, primary_idp, rng)
            # Per-action approval source probabilities
            approved_by = _pick_approval_source(action_name, rng)

            try:
                if action_name == "add_to_group":
                    group_id = rng.choice(available_groups)
                    add_to_group(company, employee_id=emp_id, group_id=group_id, system=system, approved_by=approved_by, ts=ts)
                elif action_name == "remove_from_group":
                    group_id = rng.choice(available_groups)
                    remove_from_group(company, employee_id=emp_id, group_id=group_id, system=system, approved_by=approved_by, ts=ts)
                elif action_name == "add_to_distribution_list":
                    dl = rng.choice(available_dls)
                    add_to_distribution_list(company, employee_id=emp_id, distribution_list=dl, system=system, approved_by=approved_by, ts=ts)
                elif action_name == "remove_from_distribution_list":
                    dl = rng.choice(available_dls)
                    remove_from_distribution_list(company, employee_id=emp_id, distribution_list=dl, system=system, approved_by=approved_by, ts=ts)
                elif action_name == "add_role":
                    role = rng.choice(ROLE_EXAMPLES)
                    add_role(company, employee_id=emp_id, role=role, system=system, approved_by=approved_by, ts=ts)
                elif action_name == "remove_role":
                    role = rng.choice(ROLE_EXAMPLES)
                    remove_role(company, employee_id=emp_id, role=role, system=system, approved_by=approved_by, ts=ts)
                elif action_name == "enable_mfa":
                    methods = rng.sample(["push", "totp", "sms", "u2f"], k=rng.randint(1, 2))
                    enable_mfa(company, employee_id=emp_id, system=system, methods=methods, approved_by=approved_by, ts=ts)
                elif action_name == "disable_mfa":
                    disable_mfa(company, employee_id=emp_id, system=system, approved_by=approved_by, ts=ts)
                elif action_name == "bypass_mfa":
                    duration = rng.choice([4, 8, 24, 48])
                    bypass_mfa(company, employee_id=emp_id, system=system, duration_hours=duration, approved_by=approved_by, ts=ts)
                elif action_name == "reset_mfa":
                    reset_mfa(company, employee_id=emp_id, system=system, approved_by=approved_by, ts=ts)
                elif action_name == "revoke_token":
                    token_type = rng.choice(["access_token", "refresh_token", "session"])
                    revoke_token(company, employee_id=emp_id, system=system, token_type=token_type, approved_by=approved_by, ts=ts)
                elif action_name == "disable_account":
                    reason = rng.choice(["security", "termination", "policy", "investigation"])
                    disable_account(company, employee_id=emp_id, system=system, reason=reason, approved_by=approved_by, ts=ts)
                elif action_name == "enable_account":
                    enable_account(company, employee_id=emp_id, system=system, approved_by=approved_by, ts=ts)
                elif action_name == "unlock_account":
                    unlock_account(company, employee_id=emp_id, system=system, approved_by=approved_by, ts=ts)
                elif action_name == "register_device":
                    hostname = f"{person.get('display_name', 'USER').split()[0].upper()}-{rng.randint(1000, 9999)}"
                    os_choice = rng.choice(["Windows", "macOS", "Linux"])
                    register_device(company, employee_id=emp_id, hostname=hostname, os=os_choice, system=system, approved_by=approved_by, ts=ts)
                elif action_name == "remove_device":
                    device_id = rng.choice(available_devices)
                    remove_device(company, employee_id=emp_id, device_id=device_id, system=system, approved_by=approved_by, ts=ts)
                    available_devices.remove(device_id)  # Update available list

                employee_added += 1
                stats["actions_added"] += 1
                stats["action_types"][action_name] = stats["action_types"].get(action_name, 0) + 1

            except (ValueError, KeyError):
                # Skip if action fails (e.g., target not found)
                continue

        if employee_added > 0:
            stats["employees_with_actions"] += 1

    return stats

