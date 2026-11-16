"""
Episodic burst generation for company event fixtures.

Generates time-bounded bursts of increased activity for subsets of employees,
such as project launches, incident response, quarter-end pushes, and on-call shifts.

Bursts are defined in the YAML generation_config.bursts section and resolved
per-employee before event generation. Generators query the burst schedule to
scale their per-person event counts.
"""
from __future__ import annotations

import fnmatch
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .temporal_model import get_window


Person = Dict[str, Any]
Company = Dict[str, Any]


@dataclass
class BurstEvent:
    """A single burst affecting a set of employees during a time window."""

    name: str
    start: datetime
    end: datetime
    intensity_multiplier: float
    affected_employee_ids: Set[str]
    affected_event_types: List[str]
    time_shift: bool = False  # If True, events shift to off-hours


@dataclass
class BurstSchedule:
    """Collection of all active bursts in the generation window."""

    bursts: List[BurstEvent] = field(default_factory=list)

    def multiplier_for(
        self,
        person_id: str,
        event_type: str,
        day: datetime,
    ) -> float:
        """Return the combined intensity multiplier for a person/event/day.

        If multiple bursts overlap, their multipliers are multiplied together.
        Returns 1.0 if no burst is active.
        """
        combined = 1.0
        for burst in self.bursts:
            if person_id not in burst.affected_employee_ids:
                continue
            if event_type not in burst.affected_event_types:
                continue
            if burst.start <= day <= burst.end:
                combined *= burst.intensity_multiplier
        return combined

    def has_time_shift(self, person_id: str, day: datetime) -> bool:
        """Check if a person should have shifted (off-hours) activity on this day."""
        for burst in self.bursts:
            if not burst.time_shift:
                continue
            if person_id not in burst.affected_employee_ids:
                continue
            if burst.start <= day <= burst.end:
                return True
        return False


def generate_burst_schedule(
    company: Company,
    *,
    seed: int = 1337,
    generation_config: Optional[Dict[str, Any]] = None,
) -> BurstSchedule:
    """Generate a burst schedule for the generation window.

    Reads burst definitions from ``generation_config["bursts"]`` and samples
    which employees are affected based on department bias and probability.

    Args:
        company: Company data dict
        seed: Random seed for deterministic generation
        generation_config: Full generation config (with ``bursts`` key)

    Returns:
        BurstSchedule with all resolved bursts
    """
    gen_cfg = generation_config or company.get("_generation_config") or {}
    burst_cfg = gen_cfg.get("bursts", {})

    if not burst_cfg.get("enabled", False):
        return BurstSchedule()

    burst_types = burst_cfg.get("types", [])
    if not burst_types:
        return BurstSchedule()

    # Resolve window
    window_start, window_end = get_window(gen_cfg)
    window_days = max(1, (window_end - window_start).days)

    # Get employees
    people = company.get("employees") or company.get("workers") or []
    if not people:
        return BurstSchedule()

    # Index employees by department for biased selection
    by_department: Dict[str, List[Dict[str, Any]]] = {}
    for person in people:
        dept = person.get("department", "General")
        by_department.setdefault(dept, []).append(person)

    rng = random.Random(seed + 9000)
    schedule = BurstSchedule()

    for burst_def in burst_types:
        name = burst_def.get("name", "unknown")
        probability = float(burst_def.get("probability", 0.0))
        duration_spec = burst_def.get("duration_days", {"mean": 3, "std": 1})
        intensity_spec = burst_def.get("intensity_multiplier", {"mean": 2.0, "std": 0.5})
        affected_types = burst_def.get("affected_event_types", [])
        department_bias = burst_def.get("department_bias", [])
        correlated = burst_def.get("correlated", False)
        time_shift = burst_def.get("time_shift", False)

        if not affected_types:
            continue

        # Determine candidate employees
        if department_bias:
            candidates = []
            for dept_name in department_bias:
                candidates.extend(by_department.get(dept_name, []))
        else:
            candidates = list(people)

        if not candidates:
            continue

        # Sample which employees get this burst
        affected_ids: Set[str] = set()

        if correlated:
            # Correlated bursts: pick entire teams (all candidates from biased departments)
            # Roll once for the whole group
            if rng.random() < probability:
                # Pick a random subset of the candidates (50-100% of them)
                subset_size = max(1, int(len(candidates) * rng.uniform(0.5, 1.0)))
                selected = rng.sample(candidates, min(subset_size, len(candidates)))
                for p in selected:
                    pid = p.get("id")
                    if pid:
                        affected_ids.add(pid)
        else:
            # Independent: each employee rolls independently
            for p in candidates:
                if rng.random() < probability:
                    pid = p.get("id")
                    if pid:
                        affected_ids.add(pid)

        if not affected_ids:
            continue

        # Sample burst timing
        duration_mean = float(duration_spec.get("mean", 3) if isinstance(duration_spec, dict) else duration_spec)
        duration_std = float(duration_spec.get("std", 1) if isinstance(duration_spec, dict) else 0)
        duration_days = max(1, round(rng.gauss(duration_mean, duration_std)))

        # Pick a random start day within the window
        latest_start = max(0, window_days - duration_days)
        start_offset = rng.randint(0, latest_start) if latest_start > 0 else 0
        burst_start = window_start + timedelta(days=start_offset)
        burst_end = burst_start + timedelta(days=duration_days)

        # Sample intensity
        intensity_mean = float(intensity_spec.get("mean", 2.0) if isinstance(intensity_spec, dict) else intensity_spec)
        intensity_std = float(intensity_spec.get("std", 0.5) if isinstance(intensity_spec, dict) else 0)
        intensity = max(1.1, rng.gauss(intensity_mean, intensity_std))

        schedule.bursts.append(BurstEvent(
            name=name,
            start=burst_start,
            end=burst_end,
            intensity_multiplier=intensity,
            affected_employee_ids=affected_ids,
            affected_event_types=affected_types,
            time_shift=time_shift,
        ))

    return schedule


def annotate_employees_with_bursts(
    company: Company,
    schedule: BurstSchedule,
) -> None:
    """Tag each employee with the bursts they are involved in.

    Adds an ``active_bursts`` list to every employee. Each entry contains
    the burst name, time window, intensity multiplier, and affected event
    types.  Employees not involved in any burst get an empty list.

    Args:
        company: Company data dict (modified in-place)
        schedule: The resolved burst schedule
    """
    people = company.get("employees") or company.get("workers") or []

    # Build a lookup: person_id -> list of burst info dicts
    person_bursts: Dict[str, List[Dict[str, Any]]] = {}
    for burst in schedule.bursts:
        info = {
            "burst_name": burst.name,
            "start": burst.start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": burst.end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "intensity_multiplier": round(burst.intensity_multiplier, 2),
            "affected_event_types": burst.affected_event_types,
            "time_shift": burst.time_shift,
        }
        for pid in burst.affected_employee_ids:
            person_bursts.setdefault(pid, []).append(info)

    for person in people:
        pid = person.get("id")
        person["active_bursts"] = person_bursts.get(pid, [])


def apply_burst_to_count(
    base_count: int,
    person_id: str,
    event_type: str,
    schedule: BurstSchedule,
    rng: random.Random,
    window_start: datetime,
    window_end: datetime,
) -> int:
    """Scale a base event count by any active bursts.

    Computes a day-weighted average multiplier across the window,
    then scales the base count. This avoids needing per-day generation.

    Args:
        base_count: The baseline total event count for the window
        person_id: Employee ID
        event_type: Event type key (e.g. "email_events", "logins")
        schedule: The burst schedule
        rng: Random generator
        window_start: Start of generation window
        window_end: End of generation window

    Returns:
        Scaled event count
    """
    if not schedule.bursts:
        return base_count

    span_days = max(1, (window_end - window_start).days)
    total_multiplier = 0.0

    for d in range(span_days):
        day = window_start + timedelta(days=d)
        m = schedule.multiplier_for(person_id, event_type, day)
        total_multiplier += m

    avg_multiplier = total_multiplier / span_days
    scaled = base_count * avg_multiplier

    # Add slight noise so it's not perfectly deterministic
    noise = rng.gauss(1.0, 0.05)
    scaled *= max(0.8, noise)

    return max(0, round(scaled))


def inject_burst_emails(
    company: Company,
    schedule: BurstSchedule,
    *,
    seed: int = 1337,
) -> Dict[str, Any]:
    """Generate email scenarios that explain/justify each active burst.

    For each burst, applies the corresponding email scenario to a subset of
    affected employees using the email scenario engine. This creates
    narrative email threads (project kickoff, incident response, etc.) that
    make the burst activity spikes explainable.

    Args:
        company: Company data dict (modified in-place)
        schedule: The burst schedule from generate_burst_schedule()
        seed: Random seed

    Returns:
        Statistics dict with counts of injected scenarios
    """
    from .builtin_scenarios import BURST_SCENARIO_MAP
    from .email_scenario_engine import generate_single_scenario

    stats: Dict[str, Any] = {
        "burst_emails_injected": 0,
        "scenarios_applied": 0,
        "by_burst_type": {},
    }

    if not schedule.bursts:
        return stats

    rng = random.Random(seed + 11000)

    for burst in schedule.bursts:
        scenario_id = BURST_SCENARIO_MAP.get(burst.name)
        if not scenario_id:
            continue

        affected = list(burst.affected_employee_ids)
        if not affected:
            continue

        # Apply 1-3 instances of the scenario across affected employees
        num_threads = min(len(affected), max(1, len(affected) // 10), 3)
        burst_stats = {"threads": 0, "emails": 0}

        for i in range(num_threads):
            initiator_id = rng.choice(affected)
            # Pick other affected employees as participants
            other_affected = [eid for eid in affected if eid != initiator_id]
            participant_ids = None
            if other_affected:
                n_extra = min(3, len(other_affected))
                participant_ids = [initiator_id] + rng.sample(other_affected, n_extra)

            result = generate_single_scenario(
                company,
                scenario_id=scenario_id,
                initiator_id=initiator_id,
                seed=seed + 11000 + i,
                participant_ids=participant_ids,
            )

            if result.get("success"):
                burst_stats["threads"] += 1
                burst_stats["emails"] += result.get("emails_generated", 0)

        stats["scenarios_applied"] += burst_stats["threads"]
        stats["burst_emails_injected"] += burst_stats["emails"]
        stats["by_burst_type"][burst.name] = burst_stats

    return stats
