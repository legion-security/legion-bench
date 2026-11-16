"""
Post-processor that adds correlated file events based on generated emails.

This module scans email_events and generates file access events:
- Sender reads file BEFORE sending email with attachment
- Recipient reads file AFTER receiving email with attachment

Usage:
    from company_generation.variable.email_file_correlator import correlate_email_file_events

    # First generate emails
    generate_scenario_based_emails(company, seed=1337)

    # Then add correlated file events
    stats = correlate_email_file_events(company, seed=1337)
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .user_activity import add_file_event_logs


Person = Dict[str, Any]
Company = Dict[str, Any]


# -----------------------------------------------------------------------------
# Delay Specification (same pattern as event_correlations.py)
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

    value = rng.gauss(mean, std)
    value = max(min_val, value)
    if max_val is not None:
        value = min(max_val, value)

    return value


# -----------------------------------------------------------------------------
# Delay Configurations
# -----------------------------------------------------------------------------

# Sender reads file before attaching to email
# Mean: 15 minutes before, std: 10 min, range: 2 min to 2 hours before
SENDER_READ_DELAY = delay(mean=15, std=10, min_value=2, max_value=120)

# Recipient reads file after receiving email
# Mean: 2 hours after, std: 1 hour, range: 5 min to 8 hours after
RECIPIENT_READ_DELAY = delay(mean=120, std=60, min_value=5, max_value=480)


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


def _event_target_kwargs(kind: str, person_id: str) -> Dict[str, Any]:
    """Get the appropriate kwargs for targeting a person."""
    if kind == "worker":
        return {"worker_id": person_id}
    return {"employee_id": person_id}


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse ISO timestamp string to datetime."""
    try:
        # Handle both formats: with Z and with +00:00
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except (ValueError, AttributeError):
        return None


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


def _get_file_label(path: str) -> str:
    """Get a label for the file based on path/extension."""
    suffix = Path(path).suffix.lower()
    labels = {
        ".pdf": "Document",
        ".docx": "Document",
        ".xlsx": "Spreadsheet",
        ".pptx": "Presentation",
        ".csv": "Data",
        ".txt": "Text",
        ".md": "Documentation",
    }
    return labels.get(suffix, "File")


# -----------------------------------------------------------------------------
# Main Correlator
# -----------------------------------------------------------------------------


def correlate_email_file_events(
    company: Company,
    *,
    seed: int = 1337,
    sender_read_delay: Optional[Dict[str, Any]] = None,
    recipient_read_delay: Optional[Dict[str, Any]] = None,
    recipient_read_probability: float = 0.7,
) -> Dict[str, Any]:
    """
    Scan generated emails and add correlated file events.

    For each email with an attachment that has a file_path:
    - Sender (direction="sent"): add file read event BEFORE email timestamp
    - Recipient (direction="received"): add file read event AFTER email timestamp

    Args:
        company: Company data dict (modified in-place)
        seed: Base seed for deterministic generation
        sender_read_delay: DelaySpec for sender read timing (default: 15±10 min before)
        recipient_read_delay: DelaySpec for recipient read timing (default: 2±1 hr after)
        recipient_read_probability: Probability that recipient reads attachment (default: 0.7)

    Returns:
        Statistics dict with counts of generated events
    """
    sender_delay = sender_read_delay or SENDER_READ_DELAY
    recipient_delay = recipient_read_delay or RECIPIENT_READ_DELAY

    stats: Dict[str, Any] = {
        "emails_scanned": 0,
        "emails_with_attachments": 0,
        "emails_with_file_paths": 0,
        "sender_file_reads_added": 0,
        "recipient_file_reads_added": 0,
        "total_file_events_added": 0,
        "employees_processed": 0,
        "skipped_no_timestamp": 0,
        "skipped_no_file_path": 0,
    }

    people, container_kind = _select_people_container(company)
    if not people:
        return stats

    base_seed = seed or 0

    # Track which (person_id, file_path, approximate_time) combinations we've processed
    # to avoid duplicate file reads for the same email thread
    processed_reads: set = set()

    for idx, person in enumerate(people):
        person_id = person.get("id")
        if not person_id:
            continue

        recent_activity = person.get("recent_activity")
        if not isinstance(recent_activity, dict):
            continue

        email_events = recent_activity.get("email_events")
        if not isinstance(email_events, list):
            continue

        rng = random.Random(base_seed * 1013 + idx)
        person_processed = False

        for email_idx, email in enumerate(email_events):
            if not isinstance(email, dict):
                continue

            stats["emails_scanned"] += 1

            # Check for attachments
            attachments = email.get("attachments")
            if not isinstance(attachments, list) or not attachments:
                continue

            stats["emails_with_attachments"] += 1

            # Get email timestamp
            ts_str = email.get("ts")
            email_ts = _parse_timestamp(ts_str) if ts_str else None
            if not email_ts:
                stats["skipped_no_timestamp"] += 1
                continue

            direction = email.get("direction", "")

            # Process each attachment
            for attachment in attachments:
                if not isinstance(attachment, dict):
                    continue

                file_path = attachment.get("file_path")
                if not file_path:
                    stats["skipped_no_file_path"] += 1
                    continue

                stats["emails_with_file_paths"] += 1

                # Create a dedup key based on file, person, and approximate time (hour)
                time_bucket = email_ts.strftime("%Y-%m-%d-%H")
                dedup_key = (person_id, file_path, time_bucket, direction)

                if dedup_key in processed_reads:
                    continue
                processed_reads.add(dedup_key)

                # Generate correlated file event based on direction
                if direction == "sent":
                    # Sender reads file BEFORE sending
                    delay_minutes = sample_delay(sender_delay, rng)
                    file_ts = email_ts - timedelta(minutes=delay_minutes)

                    _add_file_read_event(
                        company,
                        container_kind,
                        person_id,
                        file_path,
                        file_ts,
                        email.get("thread_id"),
                        email.get("scenario_id"),
                    )

                    stats["sender_file_reads_added"] += 1
                    stats["total_file_events_added"] += 1
                    person_processed = True

                elif direction == "received":
                    # Recipient reads file AFTER receiving (with probability)
                    if rng.random() < recipient_read_probability:
                        delay_minutes = sample_delay(recipient_delay, rng)
                        file_ts = email_ts + timedelta(minutes=delay_minutes)

                        _add_file_read_event(
                            company,
                            container_kind,
                            person_id,
                            file_path,
                            file_ts,
                            email.get("thread_id"),
                            email.get("scenario_id"),
                        )

                        stats["recipient_file_reads_added"] += 1
                        stats["total_file_events_added"] += 1
                        person_processed = True

        if person_processed:
            stats["employees_processed"] += 1

    return stats


def _add_file_read_event(
    company: Company,
    container_kind: str,
    person_id: str,
    file_path: str,
    timestamp: datetime,
    thread_id: Optional[str] = None,
    scenario_id: Optional[str] = None,
) -> None:
    """Add a file read event for the given person."""
    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "action": "read",
        "path": file_path,
        "system": _infer_system(file_path),
        "label": _get_file_label(file_path),
    }

    # Add correlation metadata if available
    if thread_id:
        event["correlated_thread_id"] = thread_id
    if scenario_id:
        event["correlated_scenario_id"] = scenario_id

    add_file_event_logs(
        company,
        **_event_target_kwargs(container_kind, person_id),
        log=event,
    )
