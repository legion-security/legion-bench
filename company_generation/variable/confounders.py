"""
Deceptive benign confounder injection for company event fixtures.

Generates realistic-looking anomalous events that mimic attack patterns but
are actually benign. These serve as confounders to test SOC analyst
discrimination ability.

Confounder types:
- late_night_work: Executive/senior staff working at unusual hours
- travel_login: Login from unusual geography (business travel)
- bulk_file_operation: Large batch file read/download (reporting, auditing)
- failed_login_cluster: Multiple failed logins followed by success (typo, password reset)

Confounders are defined in YAML generation_config.confounders and injected
after normal event generation but before timestamp sorting.
"""
from __future__ import annotations

import fnmatch
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .temporal_model import format_ts, get_window
from .user_activity import _collect_person_apps, _collect_person_device_ids, add_login_log

Person = Dict[str, Any]
Company = Dict[str, Any]


@dataclass
class ConfounderPlan:
    """A planned confounder for a specific employee."""

    confounder_type: str
    employee_id: str
    start: datetime
    end: datetime
    params: Dict[str, Any] = field(default_factory=dict)


def _match_role(title: str, patterns: List[str]) -> bool:
    """Check if a title matches any of the glob patterns."""
    for pattern in patterns:
        if pattern == "*":
            return True
        if fnmatch.fnmatch(title, pattern):
            return True
    return False


def _random_external_ip(rng: random.Random) -> str:
    """Generate a random public IP address."""
    while True:
        a = rng.randint(1, 223)
        b, c, d = rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254)
        if a in (10, 127, 169, 172, 192):
            continue
        return f"{a}.{b}.{c}.{d}"


_CONFOUNDER_UA_TEMPLATES = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


def _pick_ua(person_id: str, rng: random.Random) -> str:
    """Pick a stable user agent for a person (deterministic by person_id)."""
    idx = hash(f"ua:{person_id}") % len(_CONFOUNDER_UA_TEMPLATES)
    return _CONFOUNDER_UA_TEMPLATES[idx]


# Lightweight app action definitions used by confounders (subset of app_events.py's
# full catalog, enough to produce schema-conformant events).
_CONFOUNDER_APP_ACTIONS: Dict[str, List[Dict[str, str]]] = {
    "Slack": [
        {"action": "send_message", "usage": "write", "resource_type": "message", "description": "Sent a message in channel"},
        {"action": "view_channel", "usage": "read", "resource_type": "channel", "description": "Viewed channel messages"},
        {"action": "send_direct_message", "usage": "write", "resource_type": "direct_message", "description": "Sent a direct message"},
    ],
    "Jira": [
        {"action": "update_issue", "usage": "write", "resource_type": "issue", "description": "Updated an issue"},
        {"action": "view_board", "usage": "read", "resource_type": "board", "description": "Viewed project board"},
        {"action": "add_comment", "usage": "write", "resource_type": "comment", "description": "Added a comment to issue"},
    ],
    "Confluence": [
        {"action": "edit_page", "usage": "write", "resource_type": "document", "description": "Edited a Confluence page"},
        {"action": "view_page", "usage": "read", "resource_type": "document", "description": "Viewed a Confluence page"},
    ],
    "GitHub": [
        {"action": "push_code", "usage": "write", "resource_type": "pull_request", "description": "Pushed code to repository"},
        {"action": "view_pull_request", "usage": "read", "resource_type": "pull_request", "description": "Viewed a pull request"},
    ],
    "Outlook": [
        {"action": "send_email", "usage": "write", "resource_type": "message", "description": "Sent an email"},
        {"action": "read_email", "usage": "read", "resource_type": "message", "description": "Read an email"},
    ],
    "Google Workspace": [
        {"action": "edit_document", "usage": "write", "resource_type": "document", "description": "Edited a Google Doc"},
        {"action": "view_document", "usage": "read", "resource_type": "document", "description": "Viewed a Google Doc"},
    ],
}

_CONFOUNDER_DEFAULT_ACTIONS = [
    {"action": "page_view", "usage": "read", "resource_type": "resource", "description": "Viewed a page"},
    {"action": "data_export", "usage": "read", "resource_type": "resource", "description": "Exported data"},
]


def _pick_app_action(app_name: str, rng: random.Random) -> Dict[str, str]:
    """Pick a realistic action for an app, returning a dict with action/usage/resource_type/description/resource_name."""
    actions = _CONFOUNDER_APP_ACTIONS.get(app_name, _CONFOUNDER_DEFAULT_ACTIONS)
    action = rng.choice(actions)
    # Generate a resource name
    resource_name = f"{action['resource_type']}_{rng.randint(100, 9999)}"
    return {**action, "resource_name": resource_name}


def _transform_file_path(canonical: str, system: str, company: Company) -> str:
    """Transform a canonical path to a system-specific path (mirrors file_events._transform_path)."""
    # Extract company short name
    name = company.get("name", "company")
    short_name = name.lower().replace(" ", "").replace(",", "").replace(".", "")[:12]
    domain = company.get("domain", f"{short_name}.com")

    parts = canonical.strip("/").split("/")
    if len(parts) >= 3 and parts[0].lower() == "departments":
        dept = parts[1]
        rest = "/".join(parts[2:])
    elif len(parts) >= 2:
        dept = parts[0]
        rest = "/".join(parts[1:])
    else:
        dept = "General"
        rest = parts[-1] if parts else "file"

    dept_display = dept.replace("_", " ").title()

    if system == "microsoft_sharepoint":
        return f"https://{short_name}.sharepoint.com/sites/{dept_display}/Shared Documents/{rest}"
    elif system == "google_drive":
        return f"https://drive.google.com/corp/{dept_display}/{rest}"
    else:  # fileshare
        return f"\\\\fileserver01\\{dept_display}\\{rest.replace('/', chr(92))}"


def plan_confounders(
    company: Company,
    *,
    seed: int = 1337,
    generation_config: Optional[Dict[str, Any]] = None,
    confounder_rate_scale: float = 1.0,
) -> List[ConfounderPlan]:
    """Plan confounders for eligible employees.

    Reads confounder definitions from ``generation_config["confounders"]``,
    filters eligible employees by role glob patterns, and samples at the
    configured rate.

    Args:
        company: Company data dict
        seed: Random seed
        generation_config: Full generation config
        confounder_rate_scale: Multiplier applied to each confounder's rate
            (e.g. 2.0 doubles the probability of each confounder firing)

    Returns:
        List of ConfounderPlan objects
    """
    gen_cfg = generation_config or company.get("_generation_config") or {}
    conf_cfg = gen_cfg.get("confounders", {})

    if not conf_cfg.get("enabled", False):
        return []

    conf_types = conf_cfg.get("types", [])
    if not conf_types:
        return []

    window_start, window_end = get_window(gen_cfg)
    window_days = max(1, (window_end - window_start).days)

    people = company.get("employees") or company.get("workers") or []
    if not people:
        return []

    rng = random.Random(seed + 10000)
    plans: List[ConfounderPlan] = []

    max_per_employee = int(conf_cfg.get("max_per_employee", 3))
    employee_confounder_counts: Dict[str, int] = {}

    for conf_def in conf_types:
        name = conf_def.get("name", "unknown")
        rate = min(1.0, float(conf_def.get("rate", 0.0)) * confounder_rate_scale)
        eligible_roles = conf_def.get("eligible_roles", ["*"])
        effect = conf_def.get("effect", {})

        for person in people:
            person_id = person.get("id")
            if not person_id:
                continue

            # Enforce per-employee cap across all confounder types
            if employee_confounder_counts.get(person_id, 0) >= max_per_employee:
                continue

            title = person.get("title", "")
            if not _match_role(title, eligible_roles):
                continue

            # Late-night work needs apps the person is authorised to use
            if name == "late_night_work" and not _collect_person_apps(person):
                continue

            if rng.random() >= rate:
                continue

            # Sample a random time within the window for this confounder
            start_offset = rng.randint(0, max(0, window_days - 1))
            conf_start = window_start + timedelta(days=start_offset)
            conf_end = conf_start + timedelta(hours=rng.randint(1, 4))

            plans.append(ConfounderPlan(
                confounder_type=name,
                employee_id=person_id,
                start=conf_start,
                end=conf_end,
                params=dict(effect),
            ))
            employee_confounder_counts[person_id] = employee_confounder_counts.get(person_id, 0) + 1

    return plans


def inject_confounders(
    company: Company,
    plans: List[ConfounderPlan],
    *,
    seed: int = 1337,
) -> Dict[str, int]:
    """Inject confounder events into the company data.

    Args:
        company: Company data dict (modified in-place)
        plans: List of ConfounderPlan from plan_confounders()
        seed: Random seed

    Returns:
        Statistics dict with counts by confounder type
    """
    stats: Dict[str, int] = {
        "total_confounders": 0,
        "total_events_injected": 0,
        "late_night_work": 0,
        "travel_login": 0,
        "bulk_file_operation": 0,
        "failed_login_cluster": 0,
    }

    if not plans:
        return stats

    people = company.get("employees") or company.get("workers") or []
    people_by_id: Dict[str, Dict[str, Any]] = {}
    for p in people:
        pid = p.get("id")
        if pid:
            people_by_id[pid] = p

    rng = random.Random(seed + 10001)

    for plan in plans:
        person = people_by_id.get(plan.employee_id)
        if not person:
            continue

        if plan.confounder_type == "late_night_work":
            count = _inject_late_night_work(company, person, plan, rng)
        elif plan.confounder_type == "travel_login":
            count = _inject_travel_login(company, person, plan, rng)
        elif plan.confounder_type == "bulk_file_operation":
            count = _inject_bulk_file_operation(company, person, plan, rng)
        elif plan.confounder_type == "failed_login_cluster":
            count = _inject_failed_login_cluster(company, person, plan, rng)
        else:
            continue

        stats["total_confounders"] += 1
        stats["total_events_injected"] += count
        stats[plan.confounder_type] = stats.get(plan.confounder_type, 0) + 1

    return stats


def _inject_late_night_work(
    company: Company,
    person: Person,
    plan: ConfounderPlan,
    rng: random.Random,
) -> int:
    """Inject late-night login + app events for executive/senior staff."""
    effect = plan.params
    duration_spec = effect.get("duration_events", {"mean": 3, "std": 1})
    mean_events = float(duration_spec.get("mean", 3) if isinstance(duration_spec, dict) else duration_spec)
    std_events = float(duration_spec.get("std", 1) if isinstance(duration_spec, dict) else 0)
    num_events = max(1, min(4, round(rng.gauss(mean_events, std_events))))

    count = 0
    person_id = person["id"]

    # Get person's device info
    device_ids = _collect_person_device_ids(company, person)
    devices = company.get("devices") or []
    device_ip = None
    device_id = None
    for d in devices:
        if isinstance(d, dict) and d.get("id") in device_ids:
            device_ip = d.get("ip_address")
            device_id = d.get("id")
            break

    # Pick a user agent consistent with the person
    ua = _pick_ua(person_id, rng)

    # Only use apps the person is authorised for
    late_night_apps = _collect_person_apps(person)
    if not late_night_apps:
        return 0

    for i in range(num_events):
        # Late night: 22:00 - 03:00
        late_hour = rng.choice([22, 23, 0, 1, 2, 3])
        ts_dt = plan.start.replace(
            hour=late_hour,
            minute=rng.randint(0, 59),
            second=rng.randint(0, 59),
            microsecond=0,
            tzinfo=timezone.utc,
        )
        ts = format_ts(ts_dt)

        # Pick app first so login and app event are correlated
        app_name = rng.choice(late_night_apps)

        # Add a login event via canonical builder
        add_login_log(
            company,
            employee_id=person_id,
            ip=device_ip or f"10.1.{rng.randint(1,254)}.{rng.randint(1,254)}",
            user_agent=ua,
            device_id=device_id,
            method=rng.choice(["password", "sso", "certificate"]),
            ts=ts,
            app=app_name,
        )
        count += 1
        action_info = _pick_app_action(app_name, rng)
        app_event = {
            "ts": ts,
            "app": app_name,
            "action": action_info["action"],
            "usage": action_info["usage"],
            "success": True,
            "resource_type": action_info["resource_type"],
            "resource_id": f"res_{rng.randint(10000, 99999)}",
            "resource_name": action_info["resource_name"],
            "description": action_info["description"],
        }
        ra = person.setdefault("recent_activity", {})
        ra.setdefault("app_events", []).append(app_event)
        count += 1

    return count


def _inject_travel_login(
    company: Company,
    person: Person,
    plan: ConfounderPlan,
    rng: random.Random,
) -> int:
    """Replace existing logins during a travel window with foreign-location logins.

    Finds existing logins within plan.start..plan.end and rewrites their IP and
    geo to simulate business travel.  If no existing logins fall in the window,
    adds new ones as a fallback.
    """
    effect = plan.params
    unknown_device_prob = float(effect.get("unknown_device_probability", 0.6))

    person_id = person["id"]

    # Get a known device as fallback
    device_ids = _collect_person_device_ids(company, person)
    ua = _pick_ua(person_id, rng)

    foreign_cities = [
        "London, UK", "Tokyo, JP", "Singapore, SG", "Berlin, DE",
        "Sydney, AU", "Toronto, CA", "Mumbai, IN", "Paris, FR",
        "Seoul, KR", "Dubai, AE",
    ]

    foreign_ip = _random_external_ip(rng)
    city = rng.choice(foreign_cities)

    # Find existing logins in the travel window and replace them
    ra = person.get("recent_activity") or {}
    logins = ra.get("logins", [])
    start_iso = format_ts(plan.start)
    end_iso = format_ts(plan.end)
    replaced = 0

    for login in logins:
        ts = login.get("ts", "")
        if start_iso <= ts <= end_iso:
            login["ip"] = foreign_ip
            login["geo"] = city
            if rng.random() < unknown_device_prob:
                login["device_id"] = "unknown_device"
                login["known_device"] = False
            replaced += 1

    # If no existing logins were found in the window, add new ones as fallback
    if replaced == 0:
        duration_spec = effect.get("duration_events", {"mean": 2, "std": 1})
        mean_events = float(duration_spec.get("mean", 2) if isinstance(duration_spec, dict) else duration_spec)
        std_events = float(duration_spec.get("std", 1) if isinstance(duration_spec, dict) else 0)
        num_events = max(1, round(rng.gauss(mean_events, std_events)))

        for i in range(num_events):
            hour = rng.choice([8, 9, 10, 11, 14, 15, 16, 17])
            ts_dt = plan.start.replace(
                hour=hour,
                minute=rng.randint(0, 59),
                second=rng.randint(0, 59),
                microsecond=0,
                tzinfo=timezone.utc,
            )
            ts_str = format_ts(ts_dt)

            use_unknown = rng.random() < unknown_device_prob
            device_id = "unknown_device" if use_unknown else (list(device_ids)[0] if device_ids else None)

            add_login_log(
                company,
                employee_id=person_id,
                ip=foreign_ip,
                user_agent=ua,
                device_id=device_id,
                method=rng.choice(["password", "sso", "mfa"]),
                ts=ts_str,
                geo=city,
            )
            replaced += 1

    return replaced


def _inject_bulk_file_operation(
    company: Company,
    person: Person,
    plan: ConfounderPlan,
    rng: random.Random,
) -> int:
    """Inject a cluster of file read/download events (audit, reporting).

    Preferentially selects files that already exist in the company's file
    events pool across all employees.  Falls back to synthetic file generation
    when not enough existing files are available.
    """
    effect = plan.params
    mult_spec = effect.get("file_count_multiplier", {"mean": 5.0, "std": 1.5})
    mult_mean = float(mult_spec.get("mean", 5.0) if isinstance(mult_spec, dict) else mult_spec)
    mult_std = float(mult_spec.get("std", 1.5) if isinstance(mult_spec, dict) else 0)
    multiplier = max(2.0, rng.gauss(mult_mean, mult_std))

    num_files = max(3, round(multiplier * 3))
    count = 0

    base_hour = rng.choice([9, 10, 11, 14, 15, 16])

    # Collect existing files from all employees' file_events
    existing_files: List[Dict[str, Any]] = []
    people = company.get("employees") or company.get("workers") or []
    for p in people:
        for fe in (p.get("recent_activity") or {}).get("file_events", []):
            if isinstance(fe, dict) and fe.get("path"):
                existing_files.append(fe)

    # Also check the person's own file events
    person_files = (person.get("recent_activity") or {}).get("file_events", [])
    for fe in person_files:
        if isinstance(fe, dict) and fe.get("path"):
            existing_files.append(fe)

    # Deduplicate by path
    seen_paths: Set[str] = set()
    unique_files: List[Dict[str, Any]] = []
    for fe in existing_files:
        p = fe["path"]
        if p not in seen_paths:
            seen_paths.add(p)
            unique_files.append(fe)

    # Select files: prefer existing, fall back to synthetic
    selected_files = rng.sample(unique_files, min(num_files, len(unique_files))) if unique_files else []
    need_synthetic = num_files - len(selected_files)

    for i, source_file in enumerate(selected_files):
        minutes_offset = rng.randint(0, 30)
        ts_dt = plan.start.replace(
            hour=base_hour,
            minute=min(59, minutes_offset),
            second=rng.randint(0, 59),
            microsecond=0,
            tzinfo=timezone.utc,
        )
        ts = format_ts(ts_dt)

        file_event = {
            "ts": ts,
            "action": "read",
            "path": source_file["path"],
            "system": source_file.get("system", "fileshare"),
            "label": source_file.get("label", "Business"),
            "owner_role": source_file.get("owner_role"),
            "category": source_file.get("category", "Document"),
            "description": source_file.get("description", ""),
        }
        ra = person.setdefault("recent_activity", {})
        ra.setdefault("file_events", []).append(file_event)
        count += 1

    # Synthetic fallback for any remaining files needed
    if need_synthetic > 0:
        system = rng.choice(["microsoft_sharepoint", "google_drive", "fileshare"])
        bulk_categories = ["Report", "Spreadsheet", "Presentation", "Document"]
        bulk_departments = ["Finance", "Analytics", "Operations", "Compliance"]
        dept = rng.choice(bulk_departments)
        report_names = [
            "Q{q}_Revenue_Summary.xlsx", "Monthly_KPIs_{month}.xlsx",
            "Budget_Forecast_{year}.xlsx", "Expense_Report_{num}.pdf",
            "Audit_Findings_{year}.docx", "Headcount_Plan_{year}.xlsx",
            "Pipeline_Review_{month}.pptx", "Board_Deck_Q{q}.pptx",
            "Compliance_Checklist_{num}.pdf", "Vendor_Analysis_{num}.csv",
        ]
        for i in range(need_synthetic):
            minutes_offset = rng.randint(0, 30)
            ts_dt = plan.start.replace(
                hour=base_hour,
                minute=min(59, minutes_offset),
                second=rng.randint(0, 59),
                microsecond=0,
                tzinfo=timezone.utc,
            )
            ts = format_ts(ts_dt)

            template = rng.choice(report_names)
            filename = template.format(
                q=rng.randint(1, 4), month=rng.choice(["Jan", "Feb", "Mar", "Apr", "May", "Jun"]),
                year=rng.randint(2024, 2026), num=rng.randint(1000, 9999),
            )
            canonical_path = f"/departments/{dept.lower()}/{filename}"
            transformed_path = _transform_file_path(canonical_path, system, company)

            category = rng.choice(bulk_categories)
            file_event = {
                "ts": ts,
                "action": "read",
                "path": transformed_path,
                "system": system,
                "label": "Business",
                "owner_role": None,
                "category": category,
                "description": filename.rsplit(".", 1)[0].replace("_", " "),
            }
            ra = person.setdefault("recent_activity", {})
            ra.setdefault("file_events", []).append(file_event)
            count += 1

    return count


def _inject_failed_login_cluster(
    company: Company,
    person: Person,
    plan: ConfounderPlan,
    rng: random.Random,
) -> int:
    """Inject multiple failed logins followed by a success (typo/password reset)."""
    effect = plan.params
    fail_spec = effect.get("failure_count", {"mean": 4, "std": 2})
    fail_mean = float(fail_spec.get("mean", 4) if isinstance(fail_spec, dict) else fail_spec)
    fail_std = float(fail_spec.get("std", 2) if isinstance(fail_spec, dict) else 0)
    num_failures = max(2, min(6, round(rng.gauss(fail_mean, fail_std))))
    followed_by_success = effect.get("followed_by_success", True)

    count = 0
    person_id = person["id"]

    # Get device info
    device_ids = _collect_person_device_ids(company, person)
    devices = company.get("devices") or []
    device_ip = None
    device_id = None
    for d in devices:
        if isinstance(d, dict) and d.get("id") in device_ids:
            device_ip = d.get("ip_address")
            device_id = d.get("id")
            break

    ua = _pick_ua(person_id, rng)
    base_hour = rng.choice([7, 8, 9, 13, 14])
    base_minute = rng.randint(0, 50)
    ip = device_ip or f"10.1.{rng.randint(1,254)}.{rng.randint(1,254)}"

    failure_reasons = [
        "invalid_password", "invalid_password", "invalid_password",
        "account_locked", "expired_password",
    ]

    for i in range(num_failures):
        ts_dt = plan.start.replace(
            hour=base_hour,
            minute=min(59, base_minute + i),
            second=rng.randint(0, 59),
            microsecond=0,
            tzinfo=timezone.utc,
        )
        ts = format_ts(ts_dt)

        add_login_log(
            company,
            employee_id=person_id,
            ip=ip,
            user_agent=ua,
            device_id=device_id,
            method="password",
            failure_reason=rng.choice(failure_reasons),
            ts=ts,
        )
        count += 1

    # Followed by success
    if followed_by_success:
        ts_dt = plan.start.replace(
            hour=base_hour,
            minute=min(59, base_minute + num_failures + 1),
            second=rng.randint(0, 59),
            microsecond=0,
            tzinfo=timezone.utc,
        )
        ts = format_ts(ts_dt)

        add_login_log(
            company,
            employee_id=person_id,
            ip=ip,
            user_agent=ua,
            device_id=device_id,
            method="password",
            ts=ts,
        )
        count += 1

    return count
