"""
Email scenario engine for generating multi-participant email threads.

This engine applies pre-defined email scenarios to company data, filling
template slots with actual employee information and generating coherent
email threads that appear in all participants' activity logs.

Key features:
- Multi-participant support (not just 2-party conversations)
- Emails added to ALL participants' logs (sent/received as appropriate)
- Slot filling with actual employee names, files, and context
- Department-aware scenario selection
- Deterministic generation with seeded RNG
"""

from __future__ import annotations

import hashlib
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .email_scenarios import EmailScenario, EmailTemplate, ScenarioSlots
from .builtin_scenarios import BUILTIN_SCENARIOS, get_scenarios_for_department
from .constants_loader import load_company_files, load_email_scenarios
from .user_activity import add_email_event_logs

Person = Dict[str, Any]
Company = Dict[str, Any]


def _get_company_id(company: Company) -> str:
    """Extract company_id from the company dict."""
    return (company.get("company") or {}).get("id", "")


def get_all_scenarios(company_id: str = "") -> List[EmailScenario]:
    """Get all available scenarios (built-in + company-specific external)."""
    return BUILTIN_SCENARIOS + load_email_scenarios(company_id)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _primary_email(person: Person) -> Optional[str]:
    """Get the primary email for a person."""
    if "email" in person and person["email"]:
        return person["email"]
    emails = person.get("emails") or []
    for value in emails:
        if value:
            return value
    return None


def _person_name(person: Person) -> str:
    """Get the display name for a person."""
    return person.get("display_name") or person.get("name") or "Unknown"


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


def _event_target_kwargs(kind: str, person_id: str) -> Dict[str, Any]:
    """Get the appropriate kwargs for targeting a person."""
    if kind == "worker":
        return {"worker_id": person_id}
    return {"employee_id": person_id}


def _generate_attachment_url(file_path: str, company_domain: str) -> str:
    """Generate an attachment URL for a file."""
    attachment_id = hashlib.md5(file_path.encode()).hexdigest()[:12]
    return f"https://mail.{company_domain}/attachments/{attachment_id}"


def _generate_file_size(file_type: str, rng: random.Random) -> int:
    """Generate a realistic file size based on file type."""
    size_ranges = {
        "pdf": (50_000, 5_000_000),
        "docx": (20_000, 2_000_000),
        "xlsx": (30_000, 10_000_000),
        "pptx": (100_000, 50_000_000),
        "zip": (100_000, 100_000_000),
        "csv": (1_000, 50_000_000),
        "txt": (100, 500_000),
    }
    min_size, max_size = size_ranges.get(file_type.lower(), (10_000, 1_000_000))
    return rng.randint(min_size, max_size)


# =============================================================================
# SCENARIO SELECTION
# =============================================================================

def _select_scenario(
    scenarios: List[EmailScenario],
    department: str,
    has_manager: bool,
    num_colleagues: int,
    rng: random.Random,
) -> Optional[EmailScenario]:
    """Select a scenario that fits the constraints."""
    eligible = []
    weights = []

    for s in scenarios:
        # Check department constraint
        if s.departments and department not in s.departments:
            # Allow cross-department scenarios even if specific departments listed
            if not s.cross_department:
                continue

        # Check manager constraint
        if s.requires_manager and not has_manager:
            continue

        # Check participant count
        if s.num_participants > num_colleagues + 1:  # +1 for the person themselves
            continue

        if s.weight > 0:  # Skip weight=0 scenarios (burst-only)
            eligible.append(s)
            weights.append(s.weight)

    if not eligible:
        return None

    return rng.choices(eligible, weights=weights, k=1)[0]


# =============================================================================
# PARTICIPANT SELECTION
# =============================================================================

def _select_participants(
    scenario: EmailScenario,
    initiator: Person,
    department_members: Dict[str, List[Person]],
    cross_department_members: Dict[str, List[Person]],
    person_index: Dict[str, Person],
    rng: random.Random,
) -> List[Person]:
    """
    Select participants for a scenario.

    Returns a list of Person dicts in order:
    - Index 0: initiator (always the given person)
    - Index 1+: other participants based on scenario requirements

    Args:
        scenario: The email scenario to apply.
        initiator: The person initiating the scenario.
        department_members: Pre-computed ``{dept_key: [person, ...]}`` index.
        cross_department_members: Pre-computed ``{dept_key: [person NOT in dept, ...]}`` index.
        person_index: Pre-computed ``{id: person}`` lookup dict.
        rng: Seeded random instance.
    """
    participants = [initiator]
    initiator_id = initiator.get("id")
    initiator_dept = (initiator.get("department") or "").strip().lower()

    # Build candidate pools (cheap — just filtering the initiator out)
    same_dept = [
        p for p in department_members.get(initiator_dept, [])
        if p.get("id") != initiator_id
    ]
    other_dept = cross_department_members.get(initiator_dept, [])

    # Track used participants
    used_ids = {initiator_id}

    # Helper to pick from a pool
    def pick_from(pool: List[Person]) -> Optional[Person]:
        available = [p for p in pool if p.get("id") not in used_ids]
        if not available:
            return None
        selected = rng.choice(available)
        used_ids.add(selected.get("id"))
        return selected

    # If scenario requires manager, try to add them
    if scenario.requires_manager:
        manager_id = initiator.get("manager_id")
        manager = person_index.get(manager_id) if manager_id else None
        if manager:
            participants.append(manager)
            used_ids.add(manager_id)
        else:
            # Try to find someone with manager-ish title in same dept
            manager_candidates = [
                p for p in same_dept
                if p.get("id") not in used_ids
                and any(t in (p.get("title") or "").lower()
                       for t in ["manager", "director", "vp", "lead", "chief"])
            ]
            if manager_candidates:
                manager = rng.choice(manager_candidates)
                participants.append(manager)
                used_ids.add(manager.get("id"))

    # Fill remaining participant slots
    needed = scenario.num_participants - len(participants)

    for _ in range(needed):
        if scenario.same_department and not scenario.cross_department:
            # Prefer same department
            person = pick_from(same_dept)
            if not person:
                person = pick_from(other_dept)  # Fallback
        elif scenario.cross_department:
            # Prefer different department
            person = pick_from(other_dept)
            if not person:
                person = pick_from(same_dept)  # Fallback
        else:
            # Any department
            all_candidates = same_dept + other_dept
            person = pick_from(all_candidates)

        if person:
            participants.append(person)
        else:
            break  # No more available participants

    return participants


# =============================================================================
# FILE SELECTION
# =============================================================================

def _select_file_for_scenario(
    scenario: EmailScenario,
    department: str,
    files: List[Dict],
    rng: random.Random,
) -> Optional[Dict]:
    """Select an appropriate file for the scenario."""
    if not scenario.requires_file or not files:
        return None

    # Filter by file type if specified
    candidates = files
    if scenario.file_types:
        type_set = set(t.lower() for t in scenario.file_types)
        candidates = [
            f for f in files
            if Path(f.get("path", "")).suffix.lstrip(".").lower() in type_set
        ]

    if not candidates:
        candidates = files  # Fallback to all files

    # Prefer files from the department if specified
    if scenario.file_departments:
        dept_files = [
            f for f in candidates
            if any(d.lower() in (f.get("path") or "").lower()
                  for d in scenario.file_departments)
        ]
        if dept_files:
            candidates = dept_files
    else:
        # Default: prefer files mentioning the department
        dept_files = [
            f for f in candidates
            if department.lower() in (f.get("path") or "").lower()
        ]
        if dept_files:
            candidates = dept_files

    return rng.choice(candidates) if candidates else None


# =============================================================================
# SLOT FILLING
# =============================================================================

def _fill_slots(
    scenario: EmailScenario,
    participants: List[Person],
    file_meta: Optional[Dict],
    company: Company,
    rng: random.Random,
) -> ScenarioSlots:
    """Fill template slots with actual data."""
    slots = ScenarioSlots()

    # Company info
    company_info = company.get("company", {})
    slots.company_name = company_info.get("name", "Company")
    slots.company_domain = company_info.get("domain", "example.com")

    # Participant info
    for i, person in enumerate(participants):
        slots.participants.append({
            "name": _person_name(person),
            "email": _primary_email(person) or "",
            "department": person.get("department", ""),
            "title": person.get("title", ""),
        })

    # Role aliases
    for i, role in enumerate(scenario.participant_roles):
        if i < len(participants):
            slots.role_aliases[role] = i

    # File info
    if file_meta:
        slots.file_path = file_meta.get("path", "")
        slots.file_name = Path(slots.file_path).name
        slots.file_description = file_meta.get("content", "")
        slots.file_type = Path(slots.file_path).suffix.lstrip(".")
        slots.file_category = file_meta.get("type", "")

    # Department (from initiator)
    if participants:
        slots.department = participants[0].get("department", "")

    # Dynamic content with variety
    project_names = [
        "Phoenix", "Atlas", "Horizon", "Nova", "Apollo", "Mercury",
        "Zenith", "Compass", "Velocity", "Summit", "Catalyst", "Nexus",
    ]
    slots.project_name = rng.choice(project_names)

    deadlines = [
        "end of week", "next Monday", "EOD tomorrow", "Friday",
        "end of the month", "by close of business", "next sprint",
    ]
    slots.deadline = rng.choice(deadlines)

    quarters = ["Q1", "Q2", "Q3", "Q4"]
    slots.quarter = rng.choice(quarters)

    date_refs = [
        "today", "yesterday", "this morning", "last week",
        "earlier this month", "recently",
    ]
    slots.date_reference = rng.choice(date_refs)

    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    slots.meeting_day = rng.choice(days)

    times = ["10am", "2pm", "3pm", "11am", "4pm", "9:30am"]
    slots.meeting_time = rng.choice(times)

    return slots


# =============================================================================
# EMAIL GENERATION
# =============================================================================

def _generate_attachment(
    file_meta: Dict,
    company_domain: str,
    rng: random.Random,
) -> Dict[str, Any]:
    """Generate attachment object from file metadata."""
    path = file_meta.get("path", "")
    filename = Path(path).name
    file_type = Path(path).suffix.lstrip(".").lower()

    return {
        "filename": filename,
        "url": _generate_attachment_url(path, company_domain),
        "file_path": path,
        "size_bytes": _generate_file_size(file_type, rng),
    }


def _apply_scenario(
    company: Company,
    container_kind: str,
    scenario: EmailScenario,
    participants: List[Person],
    file_meta: Optional[Dict],
    base_timestamp: datetime,
    rng: random.Random,
) -> Dict[str, Any]:
    """
    Apply a scenario to generate email events for ALL participants.

    Each email in the scenario is added to every participant's activity log
    with the appropriate direction (sent/received).

    Returns statistics about the generated emails.
    """
    if len(participants) < 2:
        return {"emails_generated": 0, "skipped": "not_enough_participants"}

    company_info = company.get("company", {})
    company_domain = company_info.get("domain", "example.com")

    slots = _fill_slots(scenario, participants, file_meta, company, rng)

    stats = {
        "scenario_id": scenario.id,
        "emails_generated": 0,
        "participants": len(participants),
    }

    # Get original subject for "Re:" threading
    original_subject = None
    if scenario.emails:
        original_subject = slots.render(scenario.emails[0].subject_template)

    for email_template in scenario.emails:
        # Calculate timestamp
        ts_dt = base_timestamp + timedelta(hours=email_template.offset_hours)
        ts = _format_ts(ts_dt)

        # Determine sender
        sender_idx = email_template.sender_index
        if sender_idx >= len(participants):
            sender_idx = 0  # Fallback to initiator
        sender = participants[sender_idx]
        sender_email = _primary_email(sender) or ""

        # Determine recipients
        if email_template.recipient_indices:
            recipient_indices = [
                i for i in email_template.recipient_indices
                if i < len(participants) and i != sender_idx
            ]
        else:
            # All other participants
            recipient_indices = [
                i for i in range(len(participants)) if i != sender_idx
            ]

        to_emails = [
            _primary_email(participants[i])
            for i in recipient_indices
            if _primary_email(participants[i])
        ]

        # CC recipients
        cc_emails = []
        if email_template.cc_indices:
            cc_emails = [
                _primary_email(participants[i])
                for i in email_template.cc_indices
                if i < len(participants)
                and i != sender_idx
                and i not in recipient_indices
                and _primary_email(participants[i])
            ]

        # Render subject
        subject = slots.render(email_template.subject_template)
        if email_template.reply_to_previous and original_subject:
            if not subject.lower().startswith("re:"):
                subject = f"Re: {original_subject}"

        # Render body
        body = slots.render(email_template.body_template)

        # Build attachment if needed
        attachment = None
        attachment_types = []
        if email_template.include_attachment and file_meta:
            attachment = _generate_attachment(file_meta, company_domain, rng)
            attachment_types = [slots.file_type] if slots.file_type else []

        # Create email event for EACH participant
        for participant_idx, participant in enumerate(participants):
            participant_id = participant.get("id")
            if not participant_id:
                continue

            # Determine direction from this participant's perspective
            if participant_idx == sender_idx:
                direction = "sent"
                event_from = sender_email
                event_to = to_emails
            else:
                direction = "received"
                event_from = sender_email
                # From recipient's view, they're in the "to" list
                event_to = [_primary_email(participant)]

            event: Dict[str, Any] = {
                "ts": ts,
                "direction": direction,
                "external": False,
                "from": event_from,
                "to": event_to if direction == "sent" else to_emails,
                "cc": cc_emails,
                "bcc": [],
                "subject": subject,
                "content": body,
                "attachment_types": attachment_types,
                "scenario_id": scenario.id,
                "thread_id": f"{scenario.id}_{base_timestamp.timestamp():.0f}",
            }

            if attachment:
                event["attachments"] = [attachment]

            add_email_event_logs(
                company,
                **_event_target_kwargs(container_kind, participant_id),
                log=event,
            )

        stats["emails_generated"] += 1

    return stats


# =============================================================================
# MAIN GENERATION FUNCTION
# =============================================================================

def generate_scenario_based_emails(
    company: Company,
    *,
    seed: int = 1337,
    scenarios_per_person: int = 4,
    replace_existing: bool = True,
    scenario_ids: Optional[List[str]] = None,
    min_scenarios_guaranteed: int = 2,
) -> Dict[str, Any]:
    """
    Generate email events using pre-defined scenarios.

    Each person gets `scenarios_per_person` email threads applied.
    Emails appear in ALL participants' activity logs with correct
    sent/received direction.

    Optimized for large companies (1000+ employees) with:
    - Adaptive scenario selection that falls back to simpler scenarios
    - Higher attempt multiplier for better coverage
    - Guaranteed minimum scenarios per employee

    Args:
        company: Company data dict
        seed: Base seed for deterministic generation
        scenarios_per_person: Target number of email threads per person (default: 4)
        replace_existing: If True, clear existing email events first
        scenario_ids: Optional list of specific scenario IDs to use
        min_scenarios_guaranteed: Minimum scenarios each employee must receive.
            Uses fallback strategies (simpler scenarios) to ensure coverage.
            Set to 0 to disable guarantee. (default: 2)

    Returns:
        Statistics dict with generation details
    """
    people, container_kind = _select_people_container(company)
    if not people:
        return {"error": "No employees found", "success": False}

    # Get available scenarios
    company_id = _get_company_id(company)
    all_scenarios = get_all_scenarios(company_id)
    if scenario_ids:
        all_scenarios = [s for s in all_scenarios if s.id in scenario_ids]

    if not all_scenarios:
        return {"error": "No scenarios available", "success": False}

    files = load_company_files(company_id)

    # Build department index
    department_members: Dict[str, List[Person]] = defaultdict(list)
    for p in people:
        dept_key = (p.get("department") or "").strip().lower()
        if dept_key:
            department_members[dept_key].append(p)

    # Pre-compute cross-department pools (people NOT in a given dept) — O(N) per dept, done once
    cross_department_members: Dict[str, List[Person]] = {}
    for dept_key in department_members:
        cross_department_members[dept_key] = [
            p for other_key, members in department_members.items()
            if other_key != dept_key
            for p in members
        ]

    # Pre-compute person index for O(1) lookups (e.g. manager by id)
    person_index: Dict[str, Person] = {p["id"]: p for p in people if p.get("id")}

    stats: Dict[str, Any] = {
        "success": True,
        "employees_processed": 0,
        "employees_total": len(people),
        "scenarios_applied": 0,
        "total_emails_generated": 0,
        "scenarios_skipped": 0,
        "scenarios_available": len(all_scenarios),
        "scenarios_by_type": defaultdict(int),
        # Scalability metrics
        "employees_below_target": 0,
        "employees_below_minimum": 0,
        "fallback_scenarios_used": 0,
        "average_scenarios_per_employee": 0.0,
        "min_scenarios_per_employee": float('inf'),
        "max_scenarios_per_employee": 0,
    }

    base_seed = seed or 0

    # Clear existing events if requested
    if replace_existing:
        for person in people:
            ra = person.get("recent_activity", {})
            if "email_events" in ra:
                ra["email_events"] = []

    # Track which scenarios have been applied to each person
    # to avoid duplicate threads
    person_scenarios: Dict[str, set] = defaultdict(set)

    # Track scenarios applied per person for stats
    scenarios_per_person_count: Dict[str, int] = defaultdict(int)

    # Build fallback scenarios list (simpler scenarios for guaranteed minimum)
    # These are scenarios that don't require files and have minimal participants
    fallback_scenarios = [
        s for s in all_scenarios
        if not s.requires_file and s.num_participants <= 2
    ]
    if not fallback_scenarios:
        # If no simple scenarios, use any without file requirement
        fallback_scenarios = [s for s in all_scenarios if not s.requires_file]
    if not fallback_scenarios:
        fallback_scenarios = all_scenarios  # Last resort

    for idx, person in enumerate(people):
        person_id = person.get("id")
        if not person_id:
            continue

        department = person.get("department", "")
        has_manager = bool(person.get("manager_id"))

        # Get colleagues count for scenario selection
        dept_key = (department or "").strip().lower()
        num_colleagues = len(department_members.get(dept_key, [])) - 1

        # Person-specific RNG
        rng = random.Random(base_seed * 1009 + idx)

        # Get scenarios suitable for this department
        dept_scenarios = get_scenarios_for_department(department)
        if scenario_ids:
            dept_scenarios = [s for s in dept_scenarios if s.id in scenario_ids]

        if not dept_scenarios:
            dept_scenarios = all_scenarios  # Fallback

        scenarios_applied = 0
        attempts = 0
        # Increased multiplier from 3x to 5x for better coverage with large companies
        max_attempts = scenarios_per_person * 5

        # Phase 1: Try to apply department-appropriate scenarios
        while scenarios_applied < scenarios_per_person and attempts < max_attempts:
            attempts += 1

            # Select a scenario
            scenario = _select_scenario(
                dept_scenarios,
                department,
                has_manager,
                num_colleagues,
                rng,
            )

            if not scenario:
                continue

            # Skip if this person already has this scenario type
            if scenario.id in person_scenarios[person_id]:
                continue

            # Select participants
            participants = _select_participants(
                scenario,
                person,
                department_members,
                cross_department_members,
                person_index,
                rng,
            )

            if len(participants) < scenario.num_participants:
                stats["scenarios_skipped"] += 1
                continue

            # Select file if needed
            file_meta = _select_file_for_scenario(scenario, department, files, rng)
            if scenario.requires_file and not file_meta:
                stats["scenarios_skipped"] += 1
                continue

            # Generate base timestamp (within last 30 days)
            days_back = rng.randint(1, 29)
            hour = rng.randint(8, 17)
            minute = rng.randint(0, 59)
            base_ts = datetime.now(timezone.utc) - timedelta(days=days_back)
            base_ts = base_ts.replace(hour=hour, minute=minute, second=0, microsecond=0)

            # Apply the scenario
            result = _apply_scenario(
                company,
                container_kind,
                scenario,
                participants,
                file_meta,
                base_ts,
                rng,
            )

            if result.get("emails_generated", 0) > 0:
                scenarios_applied += 1
                stats["scenarios_applied"] += 1
                stats["total_emails_generated"] += result["emails_generated"]
                stats["scenarios_by_type"][scenario.id] += 1

                # Mark scenario as used for all participants
                for p in participants:
                    pid = p.get("id")
                    if pid:
                        person_scenarios[pid].add(scenario.id)

        # Phase 2: Fallback for guaranteed minimum coverage
        # If employee didn't reach minimum, try simpler fallback scenarios
        if scenarios_applied < min_scenarios_guaranteed and min_scenarios_guaranteed > 0:
            fallback_attempts = 0
            max_fallback_attempts = min_scenarios_guaranteed * 3

            while scenarios_applied < min_scenarios_guaranteed and fallback_attempts < max_fallback_attempts:
                fallback_attempts += 1

                # Try fallback scenarios (simpler, no file requirements)
                # Exclude weight=0 scenarios (burst-only, not for random selection)
                available_fallbacks = [
                    s for s in fallback_scenarios
                    if s.id not in person_scenarios[person_id] and s.weight > 0
                ]

                if not available_fallbacks:
                    break

                # Weight by scenario weight
                weights = [s.weight for s in available_fallbacks]
                scenario = rng.choices(available_fallbacks, weights=weights, k=1)[0]

                # Select participants with relaxed requirements
                participants = _select_participants(
                    scenario,
                    person,
                    department_members,
                    cross_department_members,
                    person_index,
                    rng,
                )

                # Accept even if we have fewer participants than ideal (min 2)
                if len(participants) < 2:
                    continue

                # Generate timestamp
                days_back = rng.randint(1, 29)
                hour = rng.randint(8, 17)
                minute = rng.randint(0, 59)
                base_ts = datetime.now(timezone.utc) - timedelta(days=days_back)
                base_ts = base_ts.replace(hour=hour, minute=minute, second=0, microsecond=0)

                # Apply without file attachment
                result = _apply_scenario(
                    company,
                    container_kind,
                    scenario,
                    participants,
                    None,  # No file attachment for fallback
                    base_ts,
                    rng,
                )

                if result.get("emails_generated", 0) > 0:
                    scenarios_applied += 1
                    stats["scenarios_applied"] += 1
                    stats["total_emails_generated"] += result["emails_generated"]
                    stats["scenarios_by_type"][scenario.id] += 1
                    stats["fallback_scenarios_used"] += 1

                    for p in participants:
                        pid = p.get("id")
                        if pid:
                            person_scenarios[pid].add(scenario.id)

        # Track per-person stats
        scenarios_per_person_count[person_id] = scenarios_applied
        if scenarios_applied < scenarios_per_person:
            stats["employees_below_target"] += 1
        if scenarios_applied < min_scenarios_guaranteed:
            stats["employees_below_minimum"] += 1

        stats["employees_processed"] += 1

    # Compute scalability metrics
    if scenarios_per_person_count:
        counts = list(scenarios_per_person_count.values())
        stats["average_scenarios_per_employee"] = round(sum(counts) / len(counts), 2)
        stats["min_scenarios_per_employee"] = min(counts)
        stats["max_scenarios_per_employee"] = max(counts)
    else:
        stats["min_scenarios_per_employee"] = 0

    # Convert defaultdict to regular dict for JSON serialization
    stats["scenarios_by_type"] = dict(stats["scenarios_by_type"])

    return stats


def generate_single_scenario(
    company: Company,
    scenario_id: str,
    initiator_id: str,
    *,
    seed: int = 1337,
    participant_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Apply a single specific scenario to specific participants.

    Useful for targeted scenario generation or testing.

    Args:
        company: Company data dict
        scenario_id: ID of the scenario to apply
        initiator_id: ID of the person to initiate the scenario
        seed: Seed for randomization
        participant_ids: Optional list of specific participant IDs

    Returns:
        Result dict with generation details
    """
    people, container_kind = _select_people_container(company)
    if not people:
        return {"error": "No employees found", "success": False}

    # Find the scenario
    company_id = _get_company_id(company)
    all_scenarios = get_all_scenarios(company_id)
    scenario = next((s for s in all_scenarios if s.id == scenario_id), None)
    if not scenario:
        return {"error": f"Scenario '{scenario_id}' not found", "success": False}

    # Find the initiator
    initiator = next((p for p in people if p.get("id") == initiator_id), None)
    if not initiator:
        return {"error": f"Person '{initiator_id}' not found", "success": False}

    rng = random.Random(seed)
    files = load_company_files(company_id)

    # Build department index
    department_members: Dict[str, List[Person]] = defaultdict(list)
    for p in people:
        dept_key = (p.get("department") or "").strip().lower()
        if dept_key:
            department_members[dept_key].append(p)

    # Pre-compute cross-department pools and person index
    cross_department_members: Dict[str, List[Person]] = {}
    for dept_key in department_members:
        cross_department_members[dept_key] = [
            p for other_key, members in department_members.items()
            if other_key != dept_key
            for p in members
        ]
    person_index: Dict[str, Person] = {p["id"]: p for p in people if p.get("id")}

    # Select or use specified participants
    if participant_ids:
        participants = [initiator]
        for pid in participant_ids:
            if pid != initiator_id:
                person = person_index.get(pid)
                if person:
                    participants.append(person)
    else:
        participants = _select_participants(
            scenario,
            initiator,
            department_members,
            cross_department_members,
            person_index,
            rng,
        )

    if len(participants) < 2:
        return {"error": "Not enough participants available", "success": False}

    # Select file
    department = initiator.get("department", "")
    file_meta = _select_file_for_scenario(scenario, department, files, rng)

    # Generate timestamp
    days_back = rng.randint(1, 29)
    base_ts = datetime.now(timezone.utc) - timedelta(days=days_back)
    base_ts = base_ts.replace(hour=10, minute=0, second=0, microsecond=0)

    # Apply
    result = _apply_scenario(
        company,
        container_kind,
        scenario,
        participants,
        file_meta,
        base_ts,
        rng,
    )

    result["success"] = True
    result["participants"] = [_person_name(p) for p in participants]

    return result
