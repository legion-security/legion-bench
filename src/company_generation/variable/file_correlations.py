"""
Cross-user file correlation fulfillment driven by FileWorldState.

After file event generation, the world state contains pending ShareReadTask
entries. This module fulfills those tasks: for each shared file, some
recipients generate a read event (with realistic delay) while others
realistically ignore the share.

Usage:
    from company_generation.variable.file_correlations import fulfill_share_reads
    from company_generation.variable.file_events import FileWorldState

    stats = fulfill_share_reads(company, world_state, seed=1337)
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .user_activity import add_file_event_logs
from .file_events import FileWorldState, _primary_email

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


def _format_ts(dt: datetime) -> str:
    """Format datetime to ISO string."""
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _sample_read_delay(rng: random.Random) -> float:
    """Sample delay between share and read in minutes.

    Gaussian: mean=180min (3hr), std=90min, clamped to [10min, 1440min (24hr)].
    """
    value = rng.gauss(180, 90)
    return max(10.0, min(1440.0, value))


def fulfill_share_reads(
    company: Company,
    world_state: FileWorldState,
    *,
    seed: int = 1337,
    read_probability: float = 0.65,
) -> Dict[str, Any]:
    """
    Fulfill pending share-read tasks from the world state.

    For each share event registered during file event generation, each
    recipient has a chance of reading the shared file. The read event
    is generated with a realistic delay (10min-24hr, mean 3hr) and
    includes the shared_by field linking back to the sharer.

    Args:
        company: Company data dict to modify in-place
        world_state: FileWorldState with pending_share_reads
        seed: Random seed
        read_probability: Probability each recipient reads the shared file
            (0.60-0.80 is realistic; default 0.65 = ~35% don't read)

    Returns:
        Statistics dict
    """
    rng = random.Random(seed)
    stats: Dict[str, Any] = {
        "shares_processed": 0,
        "reads_generated": 0,
        "reads_skipped_deleted": 0,
        "reads_skipped_dropoff": 0,
        "recipients_total": 0,
    }

    people, container_kind = _select_people_container(company)
    if not people:
        return stats

    # Build person lookup by ID
    person_by_id: Dict[str, Person] = {}
    for p in people:
        pid = p.get("id")
        if pid:
            person_by_id[pid] = p

    for task in world_state.pending_share_reads:
        stats["shares_processed"] += 1

        for recipient_id in task.recipient_ids:
            stats["recipients_total"] += 1

            # Realistic drop-off: some recipients never read the file
            if rng.random() > read_probability:
                stats["reads_skipped_dropoff"] += 1
                continue

            # Sample read time
            delay_min = _sample_read_delay(rng)
            read_ts = task.share_ts + timedelta(minutes=delay_min)

            # Skip if file was deleted between share and read time
            if world_state.is_deleted(task.path, read_ts):
                stats["reads_skipped_deleted"] += 1
                continue

            # Verify recipient exists
            recipient = person_by_id.get(recipient_id)
            if not recipient:
                continue

            # Build read event
            event: Dict[str, Any] = {
                "ts": _format_ts(read_ts),
                "action": "read",
                "path": task.transformed_path,
                "system": task.system,
                "label": task.label,
                "category": task.category,
                "description": task.description,
                "owner_role": task.owner_role,
                "shared_by": task.sharer_email or task.sharer_id,
                "granted_via": task.granted_via,
            }

            # Add event to recipient's activity
            if container_kind == "worker":
                kwargs = {"worker_id": recipient_id}
            else:
                kwargs = {"employee_id": recipient_id}

            add_file_event_logs(company, **kwargs, log=event)
            stats["reads_generated"] += 1

    return stats


# ---------------------------------------------------------------------------
# Legacy API (kept for backward compatibility with event_correlations.py)
# ---------------------------------------------------------------------------

def generate_file_correlations(
    company: Company,
    *,
    seed: int = 1337,
    scenarios_per_employee: float = 0.15,
    days_back_range: Tuple[int, int] = (1, 25),
) -> Dict[str, Any]:
    """
    Legacy correlation generator — now a no-op stub.

    Share→read correlations are handled by the new world-state-driven
    fulfillment in fulfill_share_reads(). This function is kept so that
    existing callers (event_correlations.py) don't break, but it does
    nothing because the pipeline now runs share fulfillment after file
    event generation.
    """
    return {
        "scenarios_generated": 0,
        "events_generated": 0,
        "by_scenario": {},
        "employees_with_scenarios": 0,
    }
