"""
Login correlation scenarios that generate linked login + admin action chains.

This module generates correlated login events such as:
- Failed logins → account locked → admin unlock → successful login
- MFA failures → admin reset → successful login
- Unknown device login → device registration → next login
- MFA failed → bypass granted → successful login

Usage:
    from company_generation.variable.login_correlations import generate_login_correlations

    stats = generate_login_correlations(company, seed=1337, scenarios_per_employee=0.2)
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .user_activity import add_login_log, _resolve_worker, _collect_person_device_ids
from .admin_actions import unlock_account, reset_mfa, bypass_mfa, register_device


Person = Dict[str, Any]
Company = Dict[str, Any]


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

LOGIN_CORRELATION_SCENARIOS = {
    "account_lockout_unlock": {
        "description": "Failed logins lead to account lock, then admin unlocks",
        "weight": 1.0,
    },
    "mfa_failure_reset": {
        "description": "MFA failures lead to reset, then successful login",
        "weight": 1.0,
    },
    "new_device_login": {
        "description": "Login from unknown device triggers registration",
        "weight": 1.5,
    },
    "mfa_bypass_emergency": {
        "description": "MFA failed, admin grants bypass, user logs in",
        "weight": 0.8,
    },
}


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------


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


def _random_user_agent(rng: random.Random) -> str:
    """Generate a random user agent string."""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    ]
    return rng.choice(user_agents)


def _get_person_timezone(person: Person) -> str:
    """Get timezone for a person."""
    locations = person.get("locations")
    if isinstance(locations, dict):
        tz = locations.get("tz")
        if tz:
            return tz
    return person.get("location") or "UTC"


# -----------------------------------------------------------------------------
# Scenario Implementations
# -----------------------------------------------------------------------------


def _generate_account_lockout_unlock(
    company: Company,
    person: Person,
    container_kind: str,
    base_time: datetime,
    rng: random.Random,
) -> Dict[str, Any]:
    """
    Generate: failed logins → account locked → admin unlock → successful login.
    """
    person_id = person.get("id")
    device_ids = _collect_person_device_ids(company, person)
    geo = _get_person_timezone(person)
    ip = _random_public_ip(rng)
    user_agent = _random_user_agent(rng)
    device_id = rng.choice(device_ids) if device_ids else "unknown"

    events_added = 0
    current_time = base_time

    # Event 1: First failed login (invalid password)
    add_login_log(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
        known_device=True,
        failure_reason="invalid_password",
        ts=_format_ts(current_time),
        method="SSO+MFA",
        success=False,
        geo=geo,
    )
    events_added += 1

    # Event 2: Second failed login (~2 min later)
    delay_minutes = sample_delay(delay(mean=2, std=1, min_value=0.5), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)
    add_login_log(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
        known_device=True,
        failure_reason="invalid_password",
        ts=_format_ts(current_time),
        method="SSO+MFA",
        success=False,
        geo=geo,
    )
    events_added += 1

    # Event 3: Third failed login - account locked (~5 min later)
    delay_minutes = sample_delay(delay(mean=5, std=2, min_value=1), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)
    add_login_log(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
        known_device=True,
        failure_reason="account_locked",
        ts=_format_ts(current_time),
        method="SSO+MFA",
        success=False,
        geo=geo,
    )
    events_added += 1

    # Event 4: Admin unlocks account (5-120 min later, mean 30 min)
    delay_minutes = sample_delay(delay(mean=30, std=15, min_value=5, max_value=120), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)
    approved_by = rng.choice(["oncall", "helpdesk", "security-team"])

    try:
        unlock_account(
            company,
            employee_id=person_id,
            system="okta",
            approved_by=approved_by,
            ts=_format_ts(current_time),
        )
        events_added += 1
    except (ValueError, KeyError):
        pass

    # Event 5: Successful login after unlock (~10 min later)
    delay_minutes = sample_delay(delay(mean=10, std=5, min_value=1), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)
    add_login_log(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
        known_device=True,
        failure_reason=None,
        ts=_format_ts(current_time),
        method="SSO+MFA",
        success=True,
        geo=geo,
    )
    events_added += 1

    return {"scenario": "account_lockout_unlock", "events_added": events_added}


def _generate_mfa_failure_reset(
    company: Company,
    person: Person,
    container_kind: str,
    base_time: datetime,
    rng: random.Random,
) -> Dict[str, Any]:
    """
    Generate: MFA failures → admin resets MFA → successful login.
    """
    person_id = person.get("id")
    device_ids = _collect_person_device_ids(company, person)
    geo = _get_person_timezone(person)
    ip = _random_public_ip(rng)
    user_agent = _random_user_agent(rng)
    device_id = rng.choice(device_ids) if device_ids else "unknown"

    events_added = 0
    current_time = base_time

    # Event 1: First MFA failure
    add_login_log(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
        known_device=True,
        failure_reason="mfa_failed",
        ts=_format_ts(current_time),
        method="SSO+MFA",
        success=False,
        geo=geo,
    )
    events_added += 1

    # Event 2: Second MFA failure (~3 min later)
    delay_minutes = sample_delay(delay(mean=3, std=1.5, min_value=0.5), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)
    add_login_log(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
        known_device=True,
        failure_reason="mfa_failed",
        ts=_format_ts(current_time),
        method="SSO+MFA",
        success=False,
        geo=geo,
    )
    events_added += 1

    # Event 3: Admin resets MFA (10-180 min later, mean 45 min)
    delay_minutes = sample_delay(delay(mean=45, std=20, min_value=10, max_value=180), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)
    approved_by = rng.choice(["oncall", "helpdesk", "security-team"])

    try:
        reset_mfa(
            company,
            employee_id=person_id,
            system="okta",
            approved_by=approved_by,
            ts=_format_ts(current_time),
        )
        events_added += 1
    except (ValueError, KeyError):
        pass

    # Event 4: Successful login after MFA reset (~15 min later)
    delay_minutes = sample_delay(delay(mean=15, std=10, min_value=2), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)
    add_login_log(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
        known_device=True,
        failure_reason=None,
        ts=_format_ts(current_time),
        method="SSO+MFA",
        success=True,
        geo=geo,
    )
    events_added += 1

    return {"scenario": "mfa_failure_reset", "events_added": events_added}


def _generate_new_device_login(
    company: Company,
    person: Person,
    container_kind: str,
    base_time: datetime,
    rng: random.Random,
) -> Dict[str, Any]:
    """
    Generate: login from unknown device → device registration → next login.
    """
    person_id = person.get("id")
    geo = _get_person_timezone(person)
    ip = _random_public_ip(rng)
    user_agent = _random_user_agent(rng)

    # Generate new device info
    first_name = (person.get("display_name") or "USER").split()[0].upper()
    new_device_id = f"dev_{uuid.uuid4().hex[:8]}"
    hostname = f"{first_name}-NEW-{rng.randint(1000, 9999)}"
    os_choice = rng.choice(["Windows", "macOS", "Linux"])

    events_added = 0
    current_time = base_time

    # Event 1: Login from unknown device (successful but flagged)
    add_login_log(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        ip=ip,
        user_agent=user_agent,
        device_id=new_device_id,
        known_device=False,
        failure_reason=None,
        ts=_format_ts(current_time),
        method="SSO+MFA",
        success=True,
        geo=geo,
    )
    events_added += 1

    # Event 2: Device registration (1-60 min later, mean 15 min)
    delay_minutes = sample_delay(delay(mean=15, std=10, min_value=1, max_value=60), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)
    approved_by = rng.choice(["self", "oncall", "helpdesk"])

    try:
        register_device(
            company,
            employee_id=person_id,
            device_id=new_device_id,
            hostname=hostname,
            os=os_choice,
            system="okta",
            approved_by=approved_by,
            ts=_format_ts(current_time),
        )
        events_added += 1
    except (ValueError, KeyError):
        pass

    # Event 3: Next login from now-registered device (1hr to 3 days later)
    delay_minutes = sample_delay(delay(mean=1440, std=480, min_value=60, max_value=4320), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)
    add_login_log(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        ip=ip,
        user_agent=user_agent,
        device_id=new_device_id,
        known_device=True,
        failure_reason=None,
        ts=_format_ts(current_time),
        method="SSO+MFA",
        success=True,
        geo=geo,
    )
    events_added += 1

    return {"scenario": "new_device_login", "events_added": events_added}


def _generate_mfa_bypass_emergency(
    company: Company,
    person: Person,
    container_kind: str,
    base_time: datetime,
    rng: random.Random,
) -> Dict[str, Any]:
    """
    Generate: MFA failed → admin grants bypass → successful login without MFA.
    """
    person_id = person.get("id")
    device_ids = _collect_person_device_ids(company, person)
    geo = _get_person_timezone(person)
    ip = _random_public_ip(rng)
    user_agent = _random_user_agent(rng)
    device_id = rng.choice(device_ids) if device_ids else "unknown"

    events_added = 0
    current_time = base_time

    # Event 1: MFA failure
    add_login_log(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
        known_device=True,
        failure_reason="mfa_failed",
        ts=_format_ts(current_time),
        method="SSO+MFA",
        success=False,
        geo=geo,
    )
    events_added += 1

    # Event 2: Admin grants MFA bypass (5-60 min later, mean 20 min)
    delay_minutes = sample_delay(delay(mean=20, std=10, min_value=5, max_value=60), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)
    approved_by = rng.choice(["oncall", "helpdesk", "security-team"])
    duration_hours = rng.choice([4, 8, 24])

    try:
        bypass_mfa(
            company,
            employee_id=person_id,
            system="okta",
            duration_hours=duration_hours,
            approved_by=approved_by,
            ts=_format_ts(current_time),
        )
        events_added += 1
    except (ValueError, KeyError):
        pass

    # Event 3: Successful login (SSO only, no MFA) (~5 min later)
    delay_minutes = sample_delay(delay(mean=5, std=3, min_value=1), rng)
    current_time = current_time + timedelta(minutes=delay_minutes)
    add_login_log(
        company,
        employee_id=person_id if container_kind == "employee" else None,
        worker_id=person_id if container_kind == "worker" else None,
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
        known_device=True,
        failure_reason=None,
        ts=_format_ts(current_time),
        method="SSO",  # No MFA during bypass
        success=True,
        geo=geo,
    )
    events_added += 1

    return {"scenario": "mfa_bypass_emergency", "events_added": events_added}


# -----------------------------------------------------------------------------
# Main Generator
# -----------------------------------------------------------------------------

SCENARIO_GENERATORS = {
    "account_lockout_unlock": _generate_account_lockout_unlock,
    "mfa_failure_reset": _generate_mfa_failure_reset,
    "new_device_login": _generate_new_device_login,
    "mfa_bypass_emergency": _generate_mfa_bypass_emergency,
}


def generate_login_correlations(
    company: Company,
    *,
    seed: int = 1337,
    scenarios_per_employee: float = 0.2,
    days_back_range: Tuple[int, int] = (1, 25),
    scenario_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Generate correlated login event chains.

    Each chain includes login events and related admin actions
    (unlock, MFA reset, device registration, etc.).

    Args:
        company: Company data dict to modify in-place
        seed: Base seed for deterministic generation
        scenarios_per_employee: Fraction of employees to assign scenarios (0.0-1.0)
        days_back_range: Range of days back to start scenarios (min, max)
        scenario_ids: Optional list of specific scenario IDs to use

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

    # Filter scenarios if specific IDs requested
    available_scenarios = list(LOGIN_CORRELATION_SCENARIOS.keys())
    if scenario_ids:
        available_scenarios = [s for s in available_scenarios if s in scenario_ids]

    if not available_scenarios:
        return stats

    # Build weights for scenario selection
    weights = [LOGIN_CORRELATION_SCENARIOS[s]["weight"] for s in available_scenarios]

    # Select employees to receive correlated scenarios
    scenario_count = int(len(people) * scenarios_per_employee)
    scenario_count = max(1, min(scenario_count, len(people)))
    selected = rng.sample(people, scenario_count)

    for person in selected:
        person_id = person.get("id")
        if not person_id:
            continue

        # Pick a random scenario (weighted)
        scenario_name = rng.choices(available_scenarios, weights=weights, k=1)[0]
        generator = SCENARIO_GENERATORS.get(scenario_name)

        if not generator:
            continue

        # Pick a base timestamp
        days_back = rng.randint(days_back_range[0], days_back_range[1])
        hour = rng.choice([8, 9, 10, 11, 14, 15, 16, 17])
        base_time = datetime.now(timezone.utc) - timedelta(days=days_back)
        base_time = base_time.replace(
            hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59), microsecond=0
        )

        # Generate the scenario
        result = generator(company, person, container_kind, base_time, rng)

        if result.get("events_added", 0) > 0:
            stats["scenarios_generated"] += 1
            stats["events_generated"] += result["events_added"]
            stats["employees_with_scenarios"] += 1
            stats["by_scenario"][scenario_name] = stats["by_scenario"].get(scenario_name, 0) + 1

    return stats
