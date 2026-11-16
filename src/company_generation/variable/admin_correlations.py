"""
Admin action correlation scenarios that generate linked admin + file event chains.

This module generates correlated admin events such as:
- Added to group → user accesses group-related files

Usage:
    from company_generation.variable.admin_correlations import generate_admin_correlations

    stats = generate_admin_correlations(company, seed=1337, scenarios_per_employee=0.1)
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .user_activity import add_file_event_logs
from .admin_actions import add_to_group


Person = Dict[str, Any]
Company = Dict[str, Any]

from .constants_loader import load_company_files as _load_company_files_by_id


# -----------------------------------------------------------------------------
# Delay Specification
# -----------------------------------------------------------------------------


def delay(
    mean: float,
    std: float,
    min_value: float = 0,
    max_value: Optional[float] = None,
) -> Dict[str, Any]:
    """Helper to create delay specification."""
    return {
        "mean": mean,
        "std": std,
        "min": min_value,
        "max": max_value,
    }


def sample_delay(delay_spec: Dict[str, Any], rng: random.Random) -> float:
    """Sample a delay value from the specification."""
    mean = delay_spec["mean"]
    std = delay_spec["std"]
    min_val = delay_spec.get("min", 0)
    max_val = delay_spec.get("max")

    value = rng.gauss(mean, std)
    value = max(min_val, value)
    if max_val is not None:
        value = min(max_val, value)

    return value


# -----------------------------------------------------------------------------
# Correlation Scenarios
# -----------------------------------------------------------------------------

ADMIN_CORRELATION_SCENARIOS = {
    "group_membership_file_access": {
        "description": "User added to group, then accesses group-related files",
        "weight": 1.0,
    },
}


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------


def _get_company_id(company: Company) -> str:
    """Extract company_id from the company dict."""
    return (company.get("company") or {}).get("id", "")


def _select_people_container(company: Company) -> Tuple[List[Person], str]:
    """Select the appropriate people container (employees or workers)."""
    employees = company.get("employees")
    if isinstance(employees, list) and employees:
        return employees, "employee"
    workers = company.get("workers")
    if isinstance(workers, list) and workers:
        return workers, "worker"
    return [], "employee"


def _format_ts(dt: datetime) -> str:
    """Format datetime to ISO string."""
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


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


def _get_file_label(file_meta: Dict[str, Any]) -> str:
    """Get a label for the file."""
    file_type = file_meta.get("type", "regular")
    return file_type.capitalize() if file_type else "File"


# -----------------------------------------------------------------------------
# Scenario Implementations
# -----------------------------------------------------------------------------


def _generate_group_membership_file_access(
    company: Company,
    person: Person,
    container_kind: str,
    base_time: datetime,
    rng: random.Random,
) -> Dict[str, Any]:
    """
    Generate: user added to group → accesses files related to that group/department.
    """
    person_id = person.get("id")
    groups = company.get("groups", [])

    if not groups:
        return {"scenario": "group_membership_file_access", "events_added": 0}

    # Select a group to add the person to
    group = rng.choice(groups)
    group_id = group.get("id")
    group_name = group.get("name", "")

    events_added = 0
    current_time = base_time

    # Event 1: Admin adds user to group
    approved_by = rng.choice(["manager", "oncall", "access-team"])

    try:
        add_to_group(
            company,
            employee_id=person_id,
            group_id=group_id,
            system="okta",
            approved_by=approved_by,
            ts=_format_ts(current_time),
        )
        events_added += 1
    except (ValueError, KeyError):
        return {"scenario": "group_membership_file_access", "events_added": 0}

    # Event 2: User accesses files (5 min to 24 hours later, mean 2 hours)
    # Try to find files that match the group name or related keywords
    files = _load_company_files_by_id(_get_company_id(company))
    if not files:
        return {"scenario": "group_membership_file_access", "events_added": events_added}

    # Try to find a file that matches the group context
    group_name_lower = group_name.lower()
    matching_files = [
        f for f in files
        if group_name_lower in (f.get("path", "").lower())
        or group_name_lower in (f.get("content", "").lower())
    ]

    # Fall back to any file if no match
    if not matching_files:
        matching_files = files

    file_meta = rng.choice(matching_files)
    file_path = file_meta.get("path", "/shared/document.pdf")
    system = _infer_system(file_path)
    label = _get_file_label(file_meta)

    delay_minutes = sample_delay(delay(mean=120, std=60, min_value=5, max_value=1440), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)

    read_event: Dict[str, Any] = {
        "ts": _format_ts(current_time),
        "action": "read",
        "path": file_path,
        "system": system,
        "label": label,
    }

    if file_meta.get("content"):
        read_event["description"] = file_meta["content"]

    add_file_event_logs(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        log=read_event,
    )
    events_added += 1

    return {"scenario": "group_membership_file_access", "events_added": events_added}


# -----------------------------------------------------------------------------
# Main Generator
# -----------------------------------------------------------------------------


def generate_admin_correlations(
    company: Company,
    *,
    seed: int = 1337,
    scenarios_per_employee: float = 0.1,
    days_back_range: Tuple[int, int] = (1, 25),
) -> Dict[str, Any]:
    """
    Generate correlated admin action + file event chains.

    Each chain includes admin actions and subsequent file access events.

    Args:
        company: Company data dict to modify in-place
        seed: Base seed for deterministic generation
        scenarios_per_employee: Fraction of employees to assign scenarios (0.0-1.0)
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

    # Select employees to receive scenarios
    scenario_count = int(len(people) * scenarios_per_employee)
    scenario_count = max(1, min(scenario_count, len(people)))
    selected = rng.sample(people, scenario_count)

    for person in selected:
        person_id = person.get("id")
        if not person_id:
            continue

        # Pick a base timestamp
        days_back = rng.randint(days_back_range[0], days_back_range[1])
        hour = rng.choice([9, 10, 11, 14, 15, 16])
        base_time = datetime.now(timezone.utc) - timedelta(days=days_back)
        base_time = base_time.replace(
            hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59), microsecond=0
        )

        # Generate the scenario
        result = _generate_group_membership_file_access(
            company, person, container_kind, base_time, rng
        )

        if result.get("events_added", 0) > 0:
            stats["scenarios_generated"] += 1
            stats["events_generated"] += result["events_added"]
            stats["employees_with_scenarios"] += 1
            stats["by_scenario"]["group_membership_file_access"] = (
                stats["by_scenario"].get("group_membership_file_access", 0) + 1
            )

    return stats
