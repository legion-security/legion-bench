"""
Event correlation module for generating linked event chains.

This module defines correlation scenarios that create connected events across
different event types (login, email, file, admin actions). Events within a
scenario share context (files, devices, participants) and have realistic
timing with variable delays sampled from normal distributions.

Usage:
    from company_generation.variable.event_correlations import generate_correlated_events

    stats = generate_correlated_events(company, seed=1337, scenarios_per_employee=0.3)
"""
from __future__ import annotations

import json
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .user_activity import (
    add_login_log,
    add_email_event_logs,
    add_file_event_logs,
    add_recent_activity_log,
    _resolve_worker,
    _collect_person_device_ids,
)
from .admin_actions import (
    unlock_account,
    reset_mfa,
    bypass_mfa,
    register_device,
    disable_account,
    revoke_token,
    add_to_group,
)


Person = Dict[str, Any]
Company = Dict[str, Any]

from .constants_loader import load_company_files as _load_company_files_by_id


# -----------------------------------------------------------------------------
# Delay Specification
# -----------------------------------------------------------------------------


@dataclass
class DelaySpec:
    """Specifies a delay sampled from a normal distribution."""
    mean: float          # Mean delay in minutes
    std: float           # Standard deviation in minutes
    min_value: float = 0  # Floor (no negative delays)
    max_value: Optional[float] = None  # Optional ceiling

    def sample(self, rng: random.Random) -> float:
        """Sample a delay value from the distribution."""
        value = rng.gauss(self.mean, self.std)
        value = max(self.min_value, value)
        if self.max_value is not None:
            value = min(self.max_value, value)
        return value


def delay(
    mean: float,
    std: float,
    min_value: float = 0,
    max_value: Optional[float] = None,
) -> Dict[str, Any]:
    """Helper to create delay specification in scenario definitions."""
    return {
        "mean": mean,
        "std": std,
        "min": min_value,
        "max": max_value,
    }


def sample_delay(delay_spec: Dict[str, Any], rng: random.Random) -> float:
    """
    Sample a delay value from the specification.

    Args:
        delay_spec: Dict with 'mean', 'std', optional 'min' and 'max'
        rng: Random number generator for reproducibility

    Returns:
        Sampled delay in minutes
    """
    mean = delay_spec["mean"]
    std = delay_spec["std"]
    min_val = delay_spec.get("min", 0)
    max_val = delay_spec.get("max")

    # Sample from normal distribution
    value = rng.gauss(mean, std)

    # Clamp to bounds
    value = max(min_val, value)
    if max_val is not None:
        value = min(max_val, value)

    return value


# -----------------------------------------------------------------------------
# Correlation Scenarios
# -----------------------------------------------------------------------------


CORRELATION_SCENARIOS: Dict[str, Dict[str, Any]] = {

    # ─────────────────────────────────────────────────────────────────────────
    # LOGIN FAILURE → ADMIN UNLOCK
    # ─────────────────────────────────────────────────────────────────────────
    "account_lockout_unlock": {
        "description": "Failed logins lead to account lock, then admin unlocks",
        "participants": ["victim"],
        "events": [
            {
                "type": "login",
                "delay": delay(mean=0, std=0),  # First event, no delay
                "data": {"success": False, "failure_reason": "invalid_password"}
            },
            {
                "type": "login",
                "delay": delay(mean=2, std=1, min_value=0.5),  # ~2 min, varies 0.5-4 min
                "data": {"success": False, "failure_reason": "invalid_password"}
            },
            {
                "type": "login",
                "delay": delay(mean=5, std=2, min_value=1),  # ~5 min after second attempt
                "data": {"success": False, "failure_reason": "account_locked"}
            },
            {
                "type": "admin_action",
                "delay": delay(mean=30, std=15, min_value=5, max_value=120),  # IT responds 5-120 min
                "data": {"action": "unlock_account", "system": "okta"}
            },
            {
                "type": "login",
                "delay": delay(mean=10, std=5, min_value=1),  # User tries again after unlock
                "data": {"success": True}
            },
        ]
    },

    # NOTE: file_shared_and_accessed is now handled by the session-based
    # file event generator (file_events.py) + world-state fulfillment
    # (file_correlations.py:fulfill_share_reads). Removed from here to
    # avoid duplicate share→read chains.

    # ─────────────────────────────────────────────────────────────────────────
    # MFA RESET FLOW
    # ─────────────────────────────────────────────────────────────────────────
    "mfa_failure_reset": {
        "description": "MFA failures lead to reset, then successful login",
        "participants": ["user"],
        "events": [
            {
                "type": "login",
                "delay": delay(mean=0, std=0),
                "data": {"success": False, "failure_reason": "mfa_failed"}
            },
            {
                "type": "login",
                "delay": delay(mean=3, std=1.5, min_value=0.5),  # Quick retry
                "data": {"success": False, "failure_reason": "mfa_failed"}
            },
            {
                "type": "admin_action",
                "delay": delay(mean=45, std=20, min_value=10, max_value=180),  # IT resets MFA
                "data": {"action": "reset_mfa", "system": "okta"}
            },
            {
                "type": "login",
                "delay": delay(mean=15, std=10, min_value=2),  # User re-enrolls and logs in
                "data": {"success": True, "method": "SSO+MFA"}
            },
        ]
    },

    # ─────────────────────────────────────────────────────────────────────────
    # NEW DEVICE REGISTRATION
    # ─────────────────────────────────────────────────────────────────────────
    "new_device_login": {
        "description": "Login from unknown device triggers registration",
        "participants": ["user"],
        "shared_context": ["device"],
        "events": [
            {
                "type": "login",
                "delay": delay(mean=0, std=0),
                "data": {
                    "success": True,
                    "known_device": False,
                    "use_context_device": True
                }
            },
            {
                "type": "admin_action",
                "delay": delay(mean=15, std=10, min_value=1, max_value=60),  # Auto or manual registration
                "data": {
                    "action": "register_device",
                    "use_context_device": True
                }
            },
            {
                "type": "login",
                "delay": delay(mean=1440, std=480, min_value=60, max_value=4320),  # Next login 1hr-3days
                "data": {
                    "success": True,
                    "known_device": True,
                    "use_context_device": True
                }
            },
        ]
    },

    # ─────────────────────────────────────────────────────────────────────────
    # GROUP ACCESS → FILE ACCESS
    # ─────────────────────────────────────────────────────────────────────────
    "group_membership_file_access": {
        "description": "Added to group, then accesses group-restricted files",
        "participants": ["user"],
        "shared_context": ["group"],
        "events": [
            {
                "type": "admin_action",
                "delay": delay(mean=0, std=0),
                "data": {"action": "add_to_group"}
            },
            {
                "type": "file_event",
                "delay": delay(mean=120, std=60, min_value=5, max_value=1440),  # Accesses within a day
                "data": {
                    "action": "read",
                    "file_matches_group": True
                }
            },
        ]
    },

    # ─────────────────────────────────────────────────────────────────────────
    # ACCOUNT DISABLE AFTER SUSPICIOUS ACTIVITY
    # ─────────────────────────────────────────────────────────────────────────
    "account_disabled_for_security": {
        "description": "Account disabled after suspicious activity detected",
        "participants": ["user"],
        "events": [
            {
                "type": "login",
                "delay": delay(mean=0, std=0),
                "data": {"success": True}
            },
            {
                "type": "file_event",
                "delay": delay(mean=5, std=3, min_value=1),
                "data": {"action": "read"}
            },
            {
                "type": "file_event",
                "delay": delay(mean=2, std=1, min_value=0.5),  # Rapid file access
                "data": {"action": "read"}
            },
            {
                "type": "admin_action",
                "delay": delay(mean=20, std=10, min_value=5, max_value=60),  # Security responds
                "data": {
                    "action": "disable_account",
                    "details": {"reason": "security"}
                }
            },
        ]
    },

    # ─────────────────────────────────────────────────────────────────────────
    # TOKEN REVOCATION AFTER SUSPICIOUS LOGIN
    # ─────────────────────────────────────────────────────────────────────────
    "suspicious_login_token_revoke": {
        "description": "Suspicious login triggers token revocation and re-auth",
        "participants": ["user"],
        "events": [
            {
                "type": "login",
                "delay": delay(mean=0, std=0),
                "data": {
                    "success": True,
                    "known_device": False  # Unusual device
                }
            },
            {
                "type": "admin_action",
                "delay": delay(mean=10, std=5, min_value=2, max_value=30),  # Quick security response
                "data": {
                    "action": "revoke_token",
                    "details": {"token_type": "access_token"}
                }
            },
            {
                "type": "login",
                "delay": delay(mean=5, std=3, min_value=1),  # User re-authenticates
                "data": {"success": True}
            },
        ]
    },

    # ─────────────────────────────────────────────────────────────────────────
    # MFA BYPASS FOR EMERGENCY ACCESS
    # ─────────────────────────────────────────────────────────────────────────
    "mfa_bypass_emergency": {
        "description": "User requests MFA bypass and logs in during bypass window",
        "participants": ["user"],
        "events": [
            {
                "type": "login",
                "delay": delay(mean=0, std=0),
                "data": {"success": False, "failure_reason": "mfa_failed"}
            },
            {
                "type": "admin_action",
                "delay": delay(mean=20, std=10, min_value=5, max_value=60),
                "data": {
                    "action": "bypass_mfa",
                    "details": {"duration_hours": 24}
                }
            },
            {
                "type": "login",
                "delay": delay(mean=5, std=3, min_value=1),
                "data": {"success": True, "method": "SSO"}  # No MFA required during bypass
            },
        ]
    },
}


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------


def _get_company_id(company: Company) -> str:
    """Extract company_id from the company dict."""
    return (company.get("company") or {}).get("id", "")


def _format_ts(dt: datetime) -> str:
    """Format datetime to ISO string."""
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _primary_email(person: Person) -> Optional[str]:
    """Get the primary email for a person."""
    if "email" in person and person["email"]:
        return person["email"]
    emails = person.get("emails") or []
    for value in emails:
        if value:
            return value
    return None


def _select_people_container(company: Company) -> Tuple[List[Person], str]:
    """Select the appropriate people container (employees or workers)."""
    employees = company.get("employees")
    if isinstance(employees, list) and employees:
        return employees, "employee"
    workers = company.get("workers")
    if isinstance(workers, list) and workers:
        return workers, "worker"
    return [], "employee"


def _event_target_kwargs(kind: str, person_id: str) -> Dict[str, Any]:
    """Get the appropriate kwargs for targeting a person."""
    if kind == "worker":
        return {"worker_id": person_id}
    return {"employee_id": person_id}


def _random_public_ip(rng: random.Random) -> str:
    """Generate a random public IP address."""
    while True:
        a, b, c, d = rng.randint(1, 223), rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254)
        if a in (10, 127, 169, 172, 192):
            continue
        if a == 100 and 64 <= b <= 127:
            continue
        if a == 198 and b in (18, 19):
            continue
        return f"{a}.{b}.{c}.{d}"


def _infer_system(path: str) -> str:
    """Infer storage system from file path."""
    suffix = Path(path).suffix.lower()
    if suffix in {".docx", ".pptx", ".ppt", ".xlsx", ".xls"}:
        return "microsoft_sharepoint"
    if suffix in {".pdf", ".txt", ".log"}:
        return "document_repository"
    if suffix in {".md"}:
        return "wiki"
    if path.startswith("drive://"):
        return "google_drive"
    return "fileshare"


# -----------------------------------------------------------------------------
# Context Resolution
# -----------------------------------------------------------------------------


def _resolve_participants(
    company: Company,
    primary_employee: Person,
    participant_keys: List[str],
    rng: random.Random,
) -> Dict[str, Person]:
    """
    Resolve participant placeholders to actual employees.

    Args:
        company: Company data
        primary_employee: The main employee for this scenario
        participant_keys: List of participant role names (e.g., ["sender", "recipient"])
        rng: Random number generator

    Returns:
        Dict mapping participant keys to Person objects
    """
    participants: Dict[str, Person] = {}
    people, _ = _select_people_container(company)

    # First participant is always the primary employee
    first_key = participant_keys[0] if participant_keys else "user"
    participants[first_key] = primary_employee

    # For additional participants, select from same department when possible
    primary_dept = (primary_employee.get("department") or "").strip().lower()
    primary_id = primary_employee.get("id")

    # Get potential participants (exclude primary)
    same_dept = [
        p for p in people
        if p.get("id") != primary_id
        and (p.get("department") or "").strip().lower() == primary_dept
        and _primary_email(p)
    ]
    other_dept = [
        p for p in people
        if p.get("id") != primary_id
        and (p.get("department") or "").strip().lower() != primary_dept
        and _primary_email(p)
    ]

    for key in participant_keys[1:]:
        # 80% chance to pick from same department
        pool = same_dept if same_dept and rng.random() < 0.8 else (other_dept or same_dept or people)
        if pool:
            selected = rng.choice(pool)
            participants[key] = selected
            # Remove from pools to avoid selecting same person twice
            if selected in same_dept:
                same_dept.remove(selected)
            if selected in other_dept:
                other_dept.remove(selected)

    return participants


def _resolve_shared_context(
    company: Company,
    primary_employee: Person,
    context_types: List[str],
    rng: random.Random,
) -> Dict[str, Any]:
    """
    Resolve shared context items (files, devices, groups) for the scenario.

    Args:
        company: Company data
        primary_employee: The main employee for this scenario
        context_types: List of context types needed (e.g., ["file", "device"])
        rng: Random number generator

    Returns:
        Dict with resolved context items
    """
    context: Dict[str, Any] = {}

    for ctx_type in context_types:
        if ctx_type == "file":
            # Select a file from company files
            files = _load_company_files_by_id(_get_company_id(company))
            if files:
                file_meta = rng.choice(files)
                context["file"] = {
                    "path": file_meta.get("path", "/shared/document.pdf"),
                    "filename": Path(file_meta.get("path", "document.pdf")).name,
                    "type": file_meta.get("type", "regular"),
                    "owner_role": file_meta.get("owner role"),
                    "created": file_meta.get("created"),
                    "content": file_meta.get("content"),
                }
            else:
                # Fallback file
                context["file"] = {
                    "path": "/shared/project_document.pdf",
                    "filename": "project_document.pdf",
                    "type": "regular",
                }

        elif ctx_type == "device":
            # Generate a new device context
            hostname = f"{primary_employee.get('display_name', 'USER').split()[0].upper()}-NEW-{rng.randint(1000, 9999)}"
            device_id = f"dev_{uuid.uuid4().hex[:8]}"
            os_choice = rng.choice(["Windows", "macOS", "Linux"])
            context["device"] = {
                "device_id": device_id,
                "hostname": hostname,
                "os": os_choice,
            }

        elif ctx_type == "group":
            # Select a group from company
            groups = company.get("groups", [])
            if groups:
                group = rng.choice(groups)
                context["group"] = {
                    "id": group.get("id"),
                    "name": group.get("name"),
                }

    return context


# -----------------------------------------------------------------------------
# Event Creation
# -----------------------------------------------------------------------------


def _create_login_event(
    company: Company,
    employee: Person,
    container_kind: str,
    timestamp: datetime,
    data: Dict[str, Any],
    context: Dict[str, Any],
    rng: random.Random,
) -> None:
    """Create and add a login event."""
    person_id = employee.get("id")
    device_ids = _collect_person_device_ids(company, employee)
    tz = (employee.get("locations") or {}).get("tz") if isinstance(employee.get("locations"), dict) else None
    tz = tz or employee.get("location") or "UTC"

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148",
    ]

    # Determine device
    use_context_device = data.get("use_context_device", False)
    if use_context_device and "device" in context:
        device_id = context["device"]["device_id"]
        known_device = data.get("known_device", False)
    else:
        known_device = data.get("known_device", True) and bool(device_ids)
        device_id = rng.choice(device_ids) if known_device and device_ids else "unknown"

    add_login_log(
        company,
        **_event_target_kwargs(container_kind, person_id),
        ip=_random_public_ip(rng),
        user_agent=rng.choice(user_agents),
        device_id=device_id,
        known_device=known_device,
        failure_reason=data.get("failure_reason"),
        ts=_format_ts(timestamp),
        method=data.get("method", "SSO+MFA"),
        success=data.get("success", True),
        geo=tz,
    )


def _create_email_event(
    company: Company,
    employee: Person,
    container_kind: str,
    timestamp: datetime,
    data: Dict[str, Any],
    context: Dict[str, Any],
    participants: Dict[str, Person],
    rng: random.Random,
) -> None:
    """Create and add an email event."""
    person_id = employee.get("id")
    person_email = _primary_email(employee)
    company_domain = company.get("company", {}).get("domain", "example.com")

    direction = data.get("direction", "sent")

    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "direction": direction,
        "external": False,
    }

    if direction == "sent":
        event["from"] = person_email
        # Find recipient from participants
        recipient_key = [k for k in participants if k != data.get("participant", "sender")]
        if recipient_key:
            recipient = participants[recipient_key[0]]
            event["to"] = [_primary_email(recipient) or f"colleague@{company_domain}"]
        else:
            event["to"] = [f"colleague@{company_domain}"]
        event["cc"] = []
        event["bcc"] = []
    else:
        # Find sender from participants
        sender_key = [k for k in participants if k != data.get("participant", "recipient")]
        if sender_key:
            sender = participants[sender_key[0]]
            event["from"] = _primary_email(sender) or f"colleague@{company_domain}"
        else:
            event["from"] = f"colleague@{company_domain}"
        event["to"] = [person_email]
        event["cc"] = []
        event["bcc"] = []

    # Generate subject/content
    subjects = [
        "Document for review",
        "File attachment",
        "Shared document",
        "Please review attached",
        "Information requested",
    ]
    event["subject"] = rng.choice(subjects)
    event["content"] = "Please see the attached document for your review."

    # Add attachment if context file exists and flag is set
    if data.get("attach_context_file") and "file" in context:
        file_ctx = context["file"]
        event["attachments"] = [{
            "filename": file_ctx["filename"],
            "url": f"https://mail.{company_domain}/attachments/{uuid.uuid4().hex[:12]}",
            "file_path": file_ctx["path"],
            "size_bytes": rng.randint(10000, 500000),
        }]
        event["attachment_types"] = [Path(file_ctx["filename"]).suffix.lstrip(".") or "pdf"]
    else:
        event["attachment_types"] = []

    add_email_event_logs(
        company,
        **_event_target_kwargs(container_kind, person_id),
        log=event,
    )


def _create_file_event(
    company: Company,
    employee: Person,
    container_kind: str,
    timestamp: datetime,
    data: Dict[str, Any],
    context: Dict[str, Any],
    participants: Dict[str, Person],
    rng: random.Random,
) -> None:
    """Create and add a file event."""
    person_id = employee.get("id")

    # Use context file if available
    if "file" in context:
        file_ctx = context["file"]
        path = file_ctx["path"]
        label = (file_ctx.get("type") or "regular").capitalize()
        owner_role = file_ctx.get("owner_role")
        file_created = file_ctx.get("created")
        description = file_ctx.get("content")
    else:
        # Fallback to random file
        files = _load_company_files_by_id(_get_company_id(company))
        if files:
            file_meta = rng.choice(files)
            path = file_meta.get("path", "/shared/document.pdf")
            label = (file_meta.get("type") or "regular").capitalize()
            owner_role = file_meta.get("owner role")
            file_created = file_meta.get("created")
            description = file_meta.get("content")
        else:
            path = "/shared/document.pdf"
            label = "Regular"
            owner_role = None
            file_created = None
            description = None

    action = data.get("action", "read")

    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "action": action,
        "path": path,
        "system": _infer_system(path),
        "label": label,
    }

    if owner_role:
        event["owner_role"] = owner_role
    if file_created:
        event["file_created"] = file_created
    if description:
        event["description"] = description

    # Handle share action
    if action == "share":
        share_with_key = data.get("share_with_participant")
        if share_with_key and share_with_key in participants:
            recipient = participants[share_with_key]
            event["shared_with"] = [_primary_email(recipient) or recipient.get("id")]
        else:
            # Share with random colleague
            event["shared_with"] = [f"colleague{rng.randint(1, 99)}@example.com"]

    add_file_event_logs(
        company,
        **_event_target_kwargs(container_kind, person_id),
        log=event,
    )


def _create_admin_action(
    company: Company,
    employee: Person,
    container_kind: str,
    timestamp: datetime,
    data: Dict[str, Any],
    context: Dict[str, Any],
    rng: random.Random,
) -> None:
    """Create and add an admin action event."""
    person_id = employee.get("id")
    action = data.get("action")
    system = data.get("system", "okta")
    ts = _format_ts(timestamp)
    approved_by = rng.choice(["self", "oncall", "change-mgmt", "security-team"])

    try:
        if action == "unlock_account":
            unlock_account(company, employee_id=person_id, system=system, approved_by=approved_by, ts=ts)

        elif action == "reset_mfa":
            reset_mfa(company, employee_id=person_id, system=system, approved_by=approved_by, ts=ts)

        elif action == "bypass_mfa":
            details = data.get("details", {})
            duration = details.get("duration_hours", 24)
            bypass_mfa(company, employee_id=person_id, system=system, duration_hours=duration, approved_by=approved_by, ts=ts)

        elif action == "register_device":
            if data.get("use_context_device") and "device" in context:
                device_ctx = context["device"]
                register_device(
                    company,
                    employee_id=person_id,
                    device_id=device_ctx["device_id"],
                    hostname=device_ctx["hostname"],
                    os=device_ctx["os"],
                    system=system,
                    approved_by=approved_by,
                    ts=ts,
                )
            else:
                hostname = f"{employee.get('display_name', 'USER').split()[0].upper()}-{rng.randint(1000, 9999)}"
                register_device(
                    company,
                    employee_id=person_id,
                    hostname=hostname,
                    os=rng.choice(["Windows", "macOS", "Linux"]),
                    system=system,
                    approved_by=approved_by,
                    ts=ts,
                )

        elif action == "disable_account":
            details = data.get("details", {})
            reason = details.get("reason", "security")
            disable_account(company, employee_id=person_id, system=system, reason=reason, approved_by=approved_by, ts=ts)

        elif action == "revoke_token":
            details = data.get("details", {})
            token_type = details.get("token_type", "access_token")
            revoke_token(company, employee_id=person_id, system=system, token_type=token_type, approved_by=approved_by, ts=ts)

        elif action == "add_to_group":
            if "group" in context:
                group_id = context["group"]["id"]
                add_to_group(company, employee_id=person_id, group_id=group_id, system=system, approved_by=approved_by, ts=ts)

        else:
            # Generic admin action logging
            log_entry: Dict[str, Any] = {
                "ts": ts,
                "system": system,
                "action": action,
                "approved_by": approved_by,
            }
            if "details" in data:
                log_entry["details"] = data["details"]
            add_recent_activity_log(
                company,
                **_event_target_kwargs(container_kind, person_id),
                key="admin_actions",
                log=log_entry,
            )
    except (ValueError, KeyError):
        # Skip if action fails (e.g., group not found)
        pass


# -----------------------------------------------------------------------------
# Main Generator
# -----------------------------------------------------------------------------


def generate_correlated_events(
    company: Company,
    *,
    seed: int = 1337,
    scenarios_per_employee: float = 0.3,
    days_back_range: Tuple[int, int] = (1, 25),
) -> Dict[str, Any]:
    """
    Generate correlated event chains with variable timing.

    This function creates linked event sequences where events share context
    (files, devices, participants) and have realistic timing based on
    normal distributions.

    Args:
        company: Company data dict to modify in-place
        seed: Base seed for deterministic generation
        scenarios_per_employee: Average number of scenarios per employee.
            Can be > 1.0 to assign multiple scenarios to some employees.
            E.g., 0.3 means ~30% of employees get one scenario on average,
            1.5 means each employee gets ~1.5 scenarios on average.
        days_back_range: Range of days back to start scenarios (min, max)

    Returns:
        Statistics dict with counts of generated scenarios and events
    """
    rng = random.Random(seed)
    stats: Dict[str, Any] = {
        "scenarios_generated": 0,
        "events_generated": 0,
        "by_scenario": {},
        "employees_with_scenarios": 0,
    }

    people, container_kind = _select_people_container(company)

    if not people:
        return stats

    # Select employees to receive correlated scenarios (same employee can be selected multiple times)
    scenario_count = int(len(people) * scenarios_per_employee)
    scenario_count = max(1, scenario_count)  # At least 1 scenario
    selected = rng.choices(people, k=scenario_count)

    scenario_names = list(CORRELATION_SCENARIOS.keys())
    employees_with_scenarios: set[str] = set()

    for employee in selected:
        employee_id = employee.get("id")
        if not employee_id:
            continue

        # Pick a random scenario
        scenario_name = rng.choice(scenario_names)
        scenario = CORRELATION_SCENARIOS[scenario_name]

        # Pick a base timestamp (random point in the date range)
        days_back = rng.randint(days_back_range[0], days_back_range[1])
        hour = rng.choice([8, 9, 10, 11, 14, 15, 16, 17])
        base_time = datetime.now(timezone.utc) - timedelta(days=days_back)
        base_time = base_time.replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59), microsecond=0)

        # Resolve participants
        participant_keys = scenario.get("participants", ["user"])
        participants = _resolve_participants(company, employee, participant_keys, rng)

        # Resolve shared context
        context_types = scenario.get("shared_context", [])
        context = _resolve_shared_context(company, employee, context_types, rng)

        # Generate events with sampled delays
        current_time = base_time
        events_in_scenario = 0

        for event_spec in scenario["events"]:
            # Sample the delay for this event
            delay_minutes = sample_delay(event_spec["delay"], rng)
            current_time = current_time + timedelta(minutes=delay_minutes)

            # Determine which participant this event belongs to
            participant_key = event_spec.get("participant", participant_keys[0])
            target_employee = participants.get(participant_key, employee)

            # Create the event based on type
            event_type = event_spec["type"]
            event_data = event_spec.get("data", {})

            try:
                if event_type == "login":
                    _create_login_event(
                        company, target_employee, container_kind,
                        current_time, event_data, context, rng
                    )
                elif event_type == "email":
                    _create_email_event(
                        company, target_employee, container_kind,
                        current_time, event_data, context, participants, rng
                    )
                elif event_type == "file_event":
                    _create_file_event(
                        company, target_employee, container_kind,
                        current_time, event_data, context, participants, rng
                    )
                elif event_type == "admin_action":
                    _create_admin_action(
                        company, target_employee, container_kind,
                        current_time, event_data, context, rng
                    )

                events_in_scenario += 1
                stats["events_generated"] += 1
            except Exception:
                # Skip event if creation fails
                continue

        if events_in_scenario > 0:
            stats["scenarios_generated"] += 1
            employees_with_scenarios.add(employee_id)
            stats["by_scenario"][scenario_name] = stats["by_scenario"].get(scenario_name, 0) + 1

    stats["employees_with_scenarios"] = len(employees_with_scenarios)
    return stats
