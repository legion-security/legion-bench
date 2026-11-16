"""
Baseline MFA event generation for company fixtures.

Scans existing login events to find logins that used MFA methods
(SSO+MFA, Password+MFA) and generates corresponding push_sent +
push_approved MFA event pairs.  This provides a realistic MFA event
baseline so that attack-injected MFA events (e.g. push bombing)
don't stand out as the only MFA activity in the dataset.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .user_activity import add_mfa_event_logs
from .temporal_model import format_ts


Person = Dict[str, Any]
Company = Dict[str, Any]

# MFA methods in login events that imply a push/code challenge
_MFA_METHODS = {"SSO+MFA", "Password+MFA"}

# MFA device name templates
_MFA_DEVICE_NAMES = [
    "iPhone (Personal)",
    "Android Phone",
    "Okta Verify",
    "Authenticator App",
    "YubiKey",
]


def _select_people_container(company: Company) -> Tuple[List[Person], str]:
    employees = company.get("employees")
    if isinstance(employees, list) and employees:
        return employees, "employee"
    workers = company.get("workers")
    if isinstance(workers, list) and workers:
        return workers, "worker"
    return [], "employee"


def generate_mfa_event_logs(
    company: Company,
    *,
    seed: int = 1337,
    replace_existing: bool = False,
    generation_config: Optional[Dict[str, Any]] = None,
    sample_rate: float = 0.4,
) -> Dict[str, Any]:
    """Generate baseline MFA events derived from existing login events.

    For each employee, scan their login events for MFA-method logins and
    generate push_sent + push_approved pairs for a fraction of them
    (controlled by ``sample_rate``).

    Args:
        company: Company data dict (modified in-place).
        seed: Base seed for deterministic generation.
        replace_existing: If True, clear existing mfa_events first.
        generation_config: Not used directly but accepted for pipeline compat.
        sample_rate: Fraction of MFA logins to generate MFA events for (0-1).

    Returns:
        Statistics dict.
    """
    people, container_kind = _select_people_container(company)

    stats: Dict[str, Any] = {
        "employees_total": len(people),
        "employees_with_events": 0,
        "events_added": 0,
        "logins_scanned": 0,
    }

    if not people:
        return stats

    if replace_existing:
        for person in people:
            ra = person.setdefault("recent_activity", {})
            ra["mfa_events"] = []

    base_seed = seed or 0

    for idx, person in enumerate(people):
        person_id = person.get("id")
        if not person_id:
            continue

        rng = random.Random(base_seed * 1031 + idx)

        # Pick a stable MFA device name for this person
        device_name = rng.choice(_MFA_DEVICE_NAMES)

        ra = person.get("recent_activity") or {}
        logins = ra.get("logins") or []

        events_for_person = 0

        for login in logins:
            if not isinstance(login, dict):
                continue
            method = login.get("method", "")
            if method not in _MFA_METHODS:
                continue
            if not login.get("success", True):
                continue

            stats["logins_scanned"] += 1

            # Only generate MFA events for a sample of MFA logins
            if rng.random() > sample_rate:
                continue

            ts_str = login.get("ts", "")
            if not ts_str:
                continue

            # Parse the login timestamp and create MFA events slightly before it
            try:
                ts_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue

            # push_sent happens 5-30 seconds before the login
            push_offset = rng.randint(5, 30)
            push_ts = ts_dt - timedelta(seconds=push_offset)
            # push_approved happens 2-10 seconds after push_sent
            approve_offset = rng.randint(2, 10)
            approve_ts = push_ts + timedelta(seconds=approve_offset)

            ip = login.get("ip", "")
            app = login.get("app", "")

            id_kwargs: Dict[str, Any] = {}
            if container_kind == "employee":
                id_kwargs["employee_id"] = person_id
            else:
                id_kwargs["worker_id"] = person_id

            # push_sent
            add_mfa_event_logs(
                company,
                **id_kwargs,
                log={
                    "ts": format_ts(push_ts),
                    "action": "push_sent",
                    "method": "push",
                    "device_name": device_name,
                    "app": app or "Okta Verify",
                    "ip": ip,
                },
            )
            stats["events_added"] += 1
            events_for_person += 1

            # push_approved
            add_mfa_event_logs(
                company,
                **id_kwargs,
                log={
                    "ts": format_ts(approve_ts),
                    "action": "push_approved",
                    "method": "push",
                    "device_name": device_name,
                    "app": app or "Okta Verify",
                    "ip": ip,
                    "success": True,
                },
            )
            stats["events_added"] += 1
            events_for_person += 1

        if events_for_person > 0:
            stats["employees_with_events"] += 1

    return stats
