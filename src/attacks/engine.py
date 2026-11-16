"""
Attack event generation engine for security investigation benchmarks.

This module generates attack event chains based on scenario templates,
adding them to company data with proper timing and ground truth metadata.

Usage:
    from attacks import (
        generate_attack,
        generate_attacks,
        get_attack_ground_truth,
    )

    # Generate single attack
    instance = generate_attack(company, "docusign_credential_harvest", "u_0042")

    # Generate attacks across company
    stats = generate_attacks(company, attack_rate=0.02)

    # Retrieve ground truth for evaluation
    ground_truth = get_attack_ground_truth(company)
"""
from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .scenarios import (
    AttackScenario,
    AttackEvent,
    AttackInstance,
    ATTACK_SCENARIOS,
    resolve_attack_parameters,
    render_template,
    get_scenario_iocs,
)
from company_generation.variable.user_activity import (
    add_login_log,
    add_email_event_logs,
    add_app_event_logs,
    add_file_event_logs,
    add_process_event_logs,
    add_mfa_event_logs,
    add_device_event_logs,
    add_print_event_logs,
    add_network_event_logs,
    add_recent_activity_log,
)
from company_generation.variable.event_correlations import sample_delay


Person = Dict[str, Any]
Company = Dict[str, Any]
_ACTIVITY_KEYS = (
    "logins", "email_events", "file_events", "admin_actions",
    "app_events", "process_events", "mfa_events", "device_events",
    "print_events",
)

# Ground truth storage key
ATTACK_GROUND_TRUTH_KEY = "_attack_ground_truth"


def _format_ts(dt: datetime) -> str:
    """Format datetime to ISO string, truncating microseconds for consistency."""
    return dt.replace(microsecond=0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


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


def _get_victim_event_time_range(
    victim: Person,
) -> Optional[Tuple[datetime, datetime]]:
    """Return (earliest, latest) timestamps from the victim's existing events."""
    ra = victim.get("recent_activity") or {}
    timestamps: List[datetime] = []
    for key in _ACTIVITY_KEYS:
        for evt in (ra.get(key) or []):
            ts = evt.get("ts")
            if ts:
                try:
                    timestamps.append(
                        datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    )
                except (ValueError, TypeError):
                    pass
    if not timestamps:
        return None
    return min(timestamps), max(timestamps)


def _generate_attack_id(rng: random.Random) -> str:
    """Generate a unique attack instance ID."""
    return f"atk_{uuid.uuid4().hex[:8]}"


def _generate_event_id(rng: random.Random) -> str:
    """Generate a unique event ID."""
    return f"evt_{uuid.uuid4().hex[:8]}"


# ---- Company file resolution helpers ----------------------------------------

from company_generation.variable.constants_loader import load_company_files as _load_company_files_by_id


def _get_company_id(company: Company) -> str:
    """Extract company_id from the company dict."""
    return (company.get("company") or {}).get("id", "")


def get_accessible_files(
    person: Person,
    company_files: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Return files the employee can access based on their department.

    Access rules:
    - All 'regular' type files are accessible to everyone
    - Files whose owner role starts with the employee's department (case-insensitive)
    """
    dept = (person.get("department") or "").strip().lower()
    accessible = []
    for f in company_files:
        file_type = (f.get("type") or "").lower()
        if file_type == "regular":
            accessible.append(f)
            continue
        owner_role = (f.get("owner role") or "").strip().lower()
        if dept and owner_role.startswith(dept):
            accessible.append(f)
    return accessible


def _should_resolve_company_files(path: str) -> bool:
    """Return True for Unix-style company file system paths that should be resolved.

    Returns False for Windows paths (C:\\, \\\\, etc.) which are local endpoint paths.
    """
    if not path:
        return False
    # Windows drive letter (e.g. C:\, D:\)
    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        return False
    # UNC path (e.g. \\server\share)
    if path.startswith("\\\\"):
        return False
    # Unix-style path starting with /
    return path.startswith("/")


def _infer_system_from_file(file_meta: Dict[str, Any]) -> str:
    """Infer storage system from a company file's path extension."""
    file_path = file_meta.get("path", "")
    suffix = Path(file_path).suffix.lower()
    if suffix in {".docx", ".pptx", ".ppt", ".xlsx", ".xls"}:
        return "microsoft_sharepoint"
    if suffix in {".pdf", ".txt", ".log"}:
        return "document_repository"
    if suffix in {".md"}:
        return "wiki"
    return "fileshare"


def _create_email_event(
    company: Company,
    victim: Person,
    container_kind: str,
    timestamp: datetime,
    event_data: Dict[str, Any],
    resolved_params: Dict[str, str],
    attack_id: str,
    rng: random.Random,
    attack_success: bool = True,
) -> str:
    """Create an email event for the attack chain."""
    victim_id = victim.get("id")
    victim_email = _primary_email(victim)

    # Render template placeholders in data
    from_addr = render_template(event_data.get("from", ""), resolved_params)
    subject = render_template(event_data.get("subject", ""), resolved_params)
    content = render_template(event_data.get("content", ""), resolved_params)

    direction = event_data.get("direction", "received")
    to_personal = event_data.get("to_personal", False)

    # Handle outbound emails to personal addresses
    if direction == "sent" and to_personal:
        # Resolve the personal email destination
        personal_domain = resolved_params.get("personal_domain", "gmail.com")
        external_dest = resolved_params.get("external_destination", "")
        if external_dest and "@" in external_dest:
            to_addr = [external_dest]
        elif external_dest:
            # external_destination is a domain — build an email
            victim_name = (victim_email or "user").split("@")[0]
            to_addr = [f"{victim_name}.backup@{external_dest}"]
        else:
            victim_name = (victim_email or "user").split("@")[0]
            to_addr = [f"{victim_name}.personal@{personal_domain}"]
        from_addr = victim_email or from_addr
    else:
        to_addr = [victim_email]

    # Pass through attachment_types from event data instead of hardcoding []
    attachment_types = event_data.get("attachment_types", [])

    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "direction": direction,
        "external": event_data.get("external", True),
        "from": from_addr,
        "to": to_addr,
        "cc": [],
        "bcc": [],
        "subject": subject,
        "content": content,
        "attachment_types": attachment_types,
    }

    # Add URL if present
    contains_url = event_data.get("contains_url")
    if contains_url:
        event["contains_url"] = render_template(contains_url, resolved_params)
        event["url_clicked"] = 1 if attack_success else 0
    else:
        event["url_clicked"] = None

    # Add attack metadata (render template placeholders in string values)
    metadata = event_data.get("metadata", {})
    rendered_metadata = {
        k: (render_template(v, resolved_params) if isinstance(v, str) else v)
        for k, v in metadata.items()
    }
    event["_attack_metadata"] = {
        "attack_id": attack_id,
        **rendered_metadata,
    }

    add_email_event_logs(
        company,
        **_event_target_kwargs(container_kind, victim_id),
        log=event,
    )

    return _generate_event_id(rng)


def _create_app_event(
    company: Company,
    victim: Person,
    container_kind: str,
    timestamp: datetime,
    event_data: Dict[str, Any],
    resolved_params: Dict[str, str],
    attack_id: str,
    rng: random.Random,
) -> str:
    """Create an app event for the attack chain."""
    victim_id = victim.get("id")

    # Render template placeholders
    resource_name = event_data.get("resource_name", "")
    if resource_name:
        resource_name = render_template(resource_name, resolved_params)

    description = event_data.get("description", "")
    if description:
        description = render_template(description, resolved_params)

    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "app": event_data.get("app", "Unknown"),
        "action": event_data.get("action", "unknown"),
        "success": event_data.get("success", True),
        "resource_type": event_data.get("resource_type", "url"),
        "resource_name": resource_name,
        "description": description,
    }

    # Add attack metadata
    metadata = event_data.get("metadata", {})
    event["_attack_metadata"] = {
        "attack_id": attack_id,
        **metadata,
    }

    add_app_event_logs(
        company,
        **_event_target_kwargs(container_kind, victim_id),
        log=event,
    )

    return _generate_event_id(rng)


def _create_login_event(
    company: Company,
    victim: Person,
    container_kind: str,
    timestamp: datetime,
    event_data: Dict[str, Any],
    resolved_params: Dict[str, str],
    attack_id: str,
    rng: random.Random,
) -> str:
    """Create a login event for the attack chain."""
    victim_id = victim.get("id")

    # Get victim's timezone/geo for legitimate logins
    tz = (victim.get("locations") or {}).get("tz") if isinstance(victim.get("locations"), dict) else None
    tz = tz or victim.get("location") or "UTC"

    # Determine if this is attacker login (has attacker IP/geo)
    ip = event_data.get("ip")
    geo = event_data.get("geo")
    user_agent = event_data.get("user_agent")

    # Render template placeholders
    if ip:
        ip = render_template(ip, resolved_params)
    else:
        # Generate a normal IP for victim
        ip = f"{rng.randint(50, 200)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"

    if geo:
        geo = render_template(geo, resolved_params)
    else:
        geo = tz

    if user_agent:
        user_agent = render_template(user_agent, resolved_params)
    else:
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 Safari/605.1.15",
        ]
        user_agent = rng.choice(user_agents)

    device_id = event_data.get("device_id", "unknown")
    known_device = event_data.get("known_device", False)

    # Get metadata
    metadata = event_data.get("metadata", {})

    # Build login event (using add_login_log which returns the event)
    evt = add_login_log(
        company,
        **_event_target_kwargs(container_kind, victim_id),
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
        known_device=known_device,
        failure_reason=event_data.get("failure_reason"),
        ts=_format_ts(timestamp),
        method=event_data.get("method", "SSO+MFA"),
        success=event_data.get("success", True),
        geo=geo,
    )

    # Add attack metadata to the event
    evt["_attack_metadata"] = {
        "attack_id": attack_id,
        **metadata,
    }

    return _generate_event_id(rng)


def _create_file_event(
    company: Company,
    victim: Person,
    container_kind: str,
    timestamp: datetime,
    event_data: Dict[str, Any],
    resolved_params: Dict[str, str],
    attack_id: str,
    rng: random.Random,
) -> str:
    """Create a file event for the attack chain.

    When the event path is a Unix-style company path (e.g. /shared/documents/),
    it is resolved to real company files the victim can access based on department.
    Windows-style paths (C:\\, \\\\) are left untouched.
    """
    victim_id = victim.get("id")

    action = event_data.get("action", "read")
    path = event_data.get("path", "/shared/document.pdf")

    # Render template placeholders
    if path:
        path = render_template(path, resolved_params)

    metadata = event_data.get("metadata", {})
    count = event_data.get("count")
    system = event_data.get("system", "fileshare")
    label = event_data.get("label")  # Allow label from scenario data
    category = None
    description = None

    # Pre-resolved file (from all_sensitive expansion) — skip random selection
    resolved_file = event_data.get("_resolved_file")
    if resolved_file:
        path = resolved_file.get("path", path)
        system = _infer_system_from_file(resolved_file)
        label = (resolved_file.get("type") or "").capitalize() or None
        category = resolved_file.get("type")
        description = resolved_file.get("content")
    # Resolve company files for Unix-style paths
    elif _should_resolve_company_files(path):
        company_files = _load_company_files_by_id(_get_company_id(company))
        if company_files:
            accessible = get_accessible_files(victim, company_files)
            if accessible:
                # If there's a file_type_preference, try to filter
                pref = metadata.get("file_type_preference")
                if pref:
                    preferred = [f for f in accessible if (f.get("type") or "").lower() == pref.lower()]
                    pool = preferred if preferred else accessible
                else:
                    pool = accessible

                if count and count > 1:
                    # Mass operation: sample multiple files
                    sample_size = min(count, len(pool))
                    chosen_files = rng.sample(pool, sample_size) if sample_size <= len(pool) else rng.choices(pool, k=sample_size)
                    first = chosen_files[0]
                    path = first.get("path", path)
                    system = _infer_system_from_file(first)
                    label = (first.get("type") or "").capitalize() or None
                    category = first.get("type")
                    description = first.get("content")
                    # Store all accessed paths in metadata
                    metadata = {
                        **metadata,
                        "accessed_file_paths": [f.get("path") for f in chosen_files],
                    }
                else:
                    chosen = rng.choice(pool)
                    path = chosen.get("path", path)
                    system = _infer_system_from_file(chosen)
                    label = (chosen.get("type") or "").capitalize() or None
                    category = chosen.get("type")
                    description = chosen.get("content")

    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "action": action,
        "path": path,
        "system": system,
    }

    # Add resolved file metadata
    if label:
        event["label"] = label
    if category:
        event["category"] = category
    if description:
        event["description"] = description

    # Add optional fields
    if "destination" in event_data:
        event["destination"] = render_template(event_data["destination"], resolved_params)
    if "size_bytes" in event_data:
        event["size_bytes"] = event_data["size_bytes"]
    if count:
        event["count"] = count

    # Add attack metadata
    event["_attack_metadata"] = {
        "attack_id": attack_id,
        **metadata,
    }

    add_file_event_logs(
        company,
        **_event_target_kwargs(container_kind, victim_id),
        log=event,
    )

    return _generate_event_id(rng)


def _resolve_victim_device_id(company: Company, victim: Person) -> Optional[str]:
    """Resolve the device_id from the victim's primary device."""
    victim_id = victim.get("id")
    for d in (company.get("devices") or []):
        if isinstance(d, dict) and d.get("owner_user_id") == victim_id and d.get("id"):
            return d["id"]
    return None


def _create_process_event(
    company: Company,
    victim: Person,
    container_kind: str,
    timestamp: datetime,
    event_data: Dict[str, Any],
    resolved_params: Dict[str, str],
    attack_id: str,
    rng: random.Random,
) -> str:
    """Create a process event for the attack chain."""
    victim_id = victim.get("id")

    process_name = event_data.get("process_name", "unknown.exe")
    action = event_data.get("action", "start")

    # Render template placeholders
    if process_name:
        process_name = render_template(process_name, resolved_params)

    command_line = event_data.get("command_line", "")
    if command_line:
        command_line = render_template(command_line, resolved_params)

    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "process_name": process_name,
        "action": action,
    }

    # Resolve victim's device_id so get_host_timeline(device_id=...) works
    device_id = event_data.get("device_id")
    if not device_id:
        device_id = _resolve_victim_device_id(company, victim)
    if device_id:
        event["device_id"] = device_id

    # Add optional fields
    if command_line:
        event["command_line"] = command_line
    if "parent_process" in event_data:
        event["parent_process"] = render_template(event_data["parent_process"], resolved_params)
    if "pid" in event_data:
        event["pid"] = event_data["pid"]
    if "hash" in event_data:
        event["hash"] = event_data["hash"]
    if "path" in event_data:
        event["path"] = render_template(event_data["path"], resolved_params)
    if "user" in event_data:
        event["user"] = render_template(event_data["user"], resolved_params)
    if "user_context" in event_data:
        event["user_context"] = render_template(event_data["user_context"], resolved_params)
    if "integrity_level" in event_data:
        event["integrity_level"] = event_data["integrity_level"]

    # Add attack metadata
    metadata = event_data.get("metadata", {})
    event["_attack_metadata"] = {
        "attack_id": attack_id,
        **metadata,
    }

    add_process_event_logs(
        company,
        **_event_target_kwargs(container_kind, victim_id),
        log=event,
    )

    return _generate_event_id(rng)


def _create_mfa_event(
    company: Company,
    victim: Person,
    container_kind: str,
    timestamp: datetime,
    event_data: Dict[str, Any],
    resolved_params: Dict[str, str],
    attack_id: str,
    rng: random.Random,
) -> str:
    """Create an MFA event for the attack chain."""
    victim_id = victim.get("id")

    action = event_data.get("action", "push_sent")

    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "action": action,
    }

    # Add optional fields
    if "device_name" in event_data:
        event["device_name"] = render_template(event_data["device_name"], resolved_params)
    if "method" in event_data:
        event["method"] = event_data["method"]
    if "count" in event_data:
        event["count"] = event_data["count"]
    if "app" in event_data:
        event["app"] = event_data["app"]
    if "ip" in event_data:
        event["ip"] = render_template(event_data["ip"], resolved_params)
    if "success" in event_data:
        event["success"] = event_data["success"]

    # Add attack metadata
    metadata = event_data.get("metadata", {})
    event["_attack_metadata"] = {
        "attack_id": attack_id,
        **metadata,
    }

    add_mfa_event_logs(
        company,
        **_event_target_kwargs(container_kind, victim_id),
        log=event,
    )

    return _generate_event_id(rng)


def _create_device_event(
    company: Company,
    victim: Person,
    container_kind: str,
    timestamp: datetime,
    event_data: Dict[str, Any],
    resolved_params: Dict[str, str],
    attack_id: str,
    rng: random.Random,
) -> str:
    """Create a device event for the attack chain."""
    victim_id = victim.get("id")

    action = event_data.get("action", "usb_connected")

    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "action": action,
    }

    # Add optional fields
    if "device_type" in event_data:
        event["device_type"] = event_data["device_type"]
    if "vendor" in event_data:
        event["vendor"] = render_template(event_data["vendor"], resolved_params)
    if "product" in event_data:
        event["product"] = render_template(event_data["product"], resolved_params)
    if "serial" in event_data:
        event["serial"] = render_template(event_data["serial"], resolved_params)
    if "software_name" in event_data:
        event["software_name"] = render_template(event_data["software_name"], resolved_params)
    if "software_version" in event_data:
        event["software_version"] = event_data["software_version"]
    if "volume_label" in event_data:
        event["volume_label"] = event_data["volume_label"]
    if "capacity_gb" in event_data:
        event["capacity_gb"] = event_data["capacity_gb"]

    # Add attack metadata
    metadata = event_data.get("metadata", {})
    event["_attack_metadata"] = {
        "attack_id": attack_id,
        **metadata,
    }

    add_device_event_logs(
        company,
        **_event_target_kwargs(container_kind, victim_id),
        log=event,
    )

    return _generate_event_id(rng)


def _create_print_event(
    company: Company,
    victim: Person,
    container_kind: str,
    timestamp: datetime,
    event_data: Dict[str, Any],
    resolved_params: Dict[str, str],
    attack_id: str,
    rng: random.Random,
) -> str:
    """Create a print event for the attack chain."""
    victim_id = victim.get("id")

    printer_name = event_data.get("printer_name", "Office Printer")
    document_name = event_data.get("document_name", "document.pdf")

    # Render template placeholders
    if printer_name:
        printer_name = render_template(printer_name, resolved_params)
    if document_name:
        document_name = render_template(document_name, resolved_params)

    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "printer_name": printer_name,
        "document_name": document_name,
    }

    # Add optional fields
    if "pages" in event_data:
        event["pages"] = event_data["pages"]
    if "copies" in event_data:
        event["copies"] = event_data["copies"]
    if "color" in event_data:
        event["color"] = event_data["color"]
    if "duplex" in event_data:
        event["duplex"] = event_data["duplex"]
    if "paper_size" in event_data:
        event["paper_size"] = event_data["paper_size"]
    if "job_id" in event_data:
        event["job_id"] = event_data["job_id"]
    if "status" in event_data:
        event["status"] = event_data["status"]

    # Add attack metadata
    metadata = event_data.get("metadata", {})
    event["_attack_metadata"] = {
        "attack_id": attack_id,
        **metadata,
    }

    add_print_event_logs(
        company,
        **_event_target_kwargs(container_kind, victim_id),
        log=event,
    )

    return _generate_event_id(rng)


def _resolve_victim_network_id(company: Company, victim: Person) -> str | None:
    """Resolve the network_id from the victim's primary device."""
    victim_id = victim.get("id")
    for d in (company.get("devices") or []):
        if isinstance(d, dict) and d.get("owner_user_id") == victim_id and d.get("network_id"):
            return d["network_id"]
    return None


def _create_network_event(
    company: Company,
    victim: Person,
    container_kind: str,
    timestamp: datetime,
    event_data: Dict[str, Any],
    resolved_params: Dict[str, str],
    attack_id: str,
    rng: random.Random,
) -> str:
    """Create a network event for the attack chain."""
    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "action": event_data.get("action", "allowed"),
        "direction": event_data.get("direction", "outbound"),
    }

    # Render template placeholders for IPs, domains, etc.
    if "source_ip" in event_data:
        event["source_ip"] = render_template(event_data["source_ip"], resolved_params)
    if "destination_ip" in event_data:
        event["destination_ip"] = render_template(event_data["destination_ip"], resolved_params)
    if "destination_port" in event_data:
        event["destination_port"] = event_data["destination_port"]
    if "protocol" in event_data:
        event["protocol"] = event_data["protocol"]
    if "user" in event_data:
        event["user"] = render_template(event_data["user"], resolved_params)
    if "auth" in event_data:
        event["auth"] = event_data["auth"]
    if "bytes_sent" in event_data:
        event["bytes_sent"] = event_data["bytes_sent"]
    if "bytes_received" in event_data:
        event["bytes_received"] = event_data["bytes_received"]
    if "description" in event_data:
        event["description"] = render_template(event_data["description"], resolved_params)

    # Add attack metadata
    metadata = event_data.get("metadata", {})
    event["_attack_metadata"] = {
        "attack_id": attack_id,
        **metadata,
    }

    # Resolve network_id from victim's device
    network_id = _resolve_victim_network_id(company, victim)
    if not network_id:
        # Fallback: pick the first subnet
        subnets = (company.get("network") or {}).get("subnets", [])
        network_id = subnets[0]["id"] if subnets else None
    if network_id:
        add_network_event_logs(
            company,
            network_id=network_id,
            log=event,
        )

    return _generate_event_id(rng)


def _create_admin_event(
    company: Company,
    victim: Person,
    container_kind: str,
    timestamp: datetime,
    event_data: Dict[str, Any],
    resolved_params: Dict[str, str],
    attack_id: str,
    rng: random.Random,
) -> str:
    """Create an admin action event for the attack chain.

    Admin actions use the schema: ts, system, action, approved_by, details.
    """
    victim_id = victim.get("id")

    action = event_data.get("action", "unknown")
    system = event_data.get("system", "azure_ad")
    approved_by = event_data.get("approved_by", "self")

    event: Dict[str, Any] = {
        "ts": _format_ts(timestamp),
        "system": system,
        "action": action,
        "approved_by": approved_by,
    }

    # Build details dict from extra data fields
    details: Dict[str, Any] = {}
    for key in ("resource_type", "resource_id", "resource_name"):
        val = event_data.get(key)
        if val:
            details[key] = render_template(val, resolved_params) if isinstance(val, str) else val
    description = event_data.get("description")
    if description:
        details["description"] = render_template(description, resolved_params)
    if "success" in event_data:
        details["success"] = event_data["success"]
    if details:
        event["details"] = details

    # Add attack metadata
    metadata = event_data.get("metadata", {})
    rendered_metadata = {
        k: (render_template(v, resolved_params) if isinstance(v, str) else v)
        for k, v in metadata.items()
    }
    event["_attack_metadata"] = {
        "attack_id": attack_id,
        **rendered_metadata,
    }

    add_recent_activity_log(
        company,
        **_event_target_kwargs(container_kind, victim_id),
        key="admin_actions",
        log=event,
    )

    return _generate_event_id(rng)


def _dispatch_event_creation(
    event_type: str,
    company: Company,
    victim: Person,
    container_kind: str,
    timestamp: datetime,
    event_data: Dict[str, Any],
    resolved_params: Dict[str, str],
    attack_id: str,
    rng: random.Random,
    attack_success: bool = True,
) -> Optional[str]:
    """Dispatch to the appropriate event creator based on event_type."""
    if event_type == "email":
        return _create_email_event(
            company, victim, container_kind,
            timestamp, event_data, resolved_params, attack_id, rng,
            attack_success=attack_success,
        )
    elif event_type == "app_event":
        return _create_app_event(
            company, victim, container_kind,
            timestamp, event_data, resolved_params, attack_id, rng,
        )
    elif event_type == "login":
        return _create_login_event(
            company, victim, container_kind,
            timestamp, event_data, resolved_params, attack_id, rng,
        )
    elif event_type == "file_event":
        return _create_file_event(
            company, victim, container_kind,
            timestamp, event_data, resolved_params, attack_id, rng,
        )
    elif event_type == "process_event":
        return _create_process_event(
            company, victim, container_kind,
            timestamp, event_data, resolved_params, attack_id, rng,
        )
    elif event_type == "mfa_event":
        return _create_mfa_event(
            company, victim, container_kind,
            timestamp, event_data, resolved_params, attack_id, rng,
        )
    elif event_type == "device_event":
        return _create_device_event(
            company, victim, container_kind,
            timestamp, event_data, resolved_params, attack_id, rng,
        )
    elif event_type == "print_event":
        return _create_print_event(
            company, victim, container_kind,
            timestamp, event_data, resolved_params, attack_id, rng,
        )
    elif event_type == "network_event":
        return _create_network_event(
            company, victim, container_kind,
            timestamp, event_data, resolved_params, attack_id, rng,
        )
    elif event_type == "admin_action":
        return _create_admin_event(
            company, victim, container_kind,
            timestamp, event_data, resolved_params, attack_id, rng,
        )
    return None


# ── Benign network noise templates ───────────────────────────────────────────

_BENIGN_NETWORK_TEMPLATES = [
    {"destination_port": 443, "protocol": "TCP", "direction": "outbound", "description": "HTTPS web browsing"},
    {"destination_port": 443, "protocol": "TCP", "direction": "outbound", "description": "SaaS application traffic"},
    {"destination_port": 443, "protocol": "TCP", "direction": "outbound", "description": "Cloud service connection"},
    {"destination_port": 80, "protocol": "TCP", "direction": "outbound", "description": "HTTP web request"},
    {"destination_port": 443, "protocol": "TCP", "direction": "outbound", "description": "Email sync"},
    {"destination_port": 53, "protocol": "UDP", "direction": "internal", "description": "DNS query"},
    {"destination_port": 53, "protocol": "UDP", "direction": "internal", "description": "DNS lookup"},
    {"destination_port": 445, "protocol": "TCP", "direction": "internal", "description": "SMB file share access"},
    {"destination_port": 389, "protocol": "TCP", "direction": "internal", "description": "LDAP directory query"},
    {"destination_port": 88, "protocol": "TCP", "direction": "internal", "description": "Kerberos authentication"},
    {"destination_port": 443, "protocol": "TCP", "direction": "outbound", "description": "Software update check"},
    {"destination_port": 9100, "protocol": "TCP", "direction": "internal", "description": "Network printer job"},
]

_BENIGN_INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.11", "10.0.1.20", "10.0.1.30", "10.0.2.10", "10.0.2.11",
]


def _inject_benign_network_noise(
    company: Company,
    victim: Person,
    container_kind: str,
    rng: random.Random,
    attack_start: datetime,
    attack_end: datetime,
    count_range: Tuple[int, int] = (8, 20),
    attack_id: Optional[str] = None,
) -> None:
    """
    Inject benign network events around the attack timeframe.

    Generates realistic baseline network traffic (web browsing, DNS, file shares)
    so that malicious network events don't stand out as the only activity.

    These events are tagged with the supplied attack_id and ``kind="benign_noise"``
    so the delta-insert path (used for fast per-run DB construction) can include
    them, while ``extract_attack_events`` excludes them from ground truth.
    """
    # Resolve network_id from victim's device
    network_id = _resolve_victim_network_id(company, victim)
    if not network_id:
        subnets = (company.get("network") or {}).get("subnets", [])
        network_id = subnets[0]["id"] if subnets else None
    if not network_id:
        return  # No subnets available

    num_events = rng.randint(count_range[0], count_range[1])

    # Extend the window by a couple hours on each side
    window_start = attack_start - timedelta(hours=2)
    window_end = attack_end + timedelta(hours=2)
    window_seconds = max(int((window_end - window_start).total_seconds()), 60)

    # Get victim's device IP
    devices = company.get("devices") or []
    source_ip = None
    victim_id = victim.get("id")
    for d in devices:
        if isinstance(d, dict) and d.get("owner_user_id") == victim_id and d.get("ip_address"):
            source_ip = d["ip_address"]
            break
    if not source_ip:
        source_ip = f"10.1.{rng.randint(1, 254)}.{rng.randint(1, 254)}"

    username = victim.get("email", "").split("@")[0] if victim.get("email") else victim_id

    for _ in range(num_events):
        template = rng.choice(_BENIGN_NETWORK_TEMPLATES)
        offset_seconds = rng.randint(0, window_seconds)
        ts_dt = window_start + timedelta(seconds=offset_seconds)

        if template["direction"] == "internal":
            dest_ip = rng.choice(_BENIGN_INTERNAL_IPS)
            auth = rng.choice(["kerberos", "kerberos", "kerberos", "ntlm", "certificate", "none"])
        else:
            # Random external IP
            a = rng.randint(1, 223)
            while a in (10, 127, 169, 172, 192):
                a = rng.randint(1, 223)
            dest_ip = f"{a}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            auth = "none"

        event: Dict[str, Any] = {
            "ts": _format_ts(ts_dt),
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "destination_port": template["destination_port"],
            "protocol": template["protocol"],
            "action": "allowed",
            "direction": template["direction"],
            "user": username,
            "auth": auth,
            "bytes_sent": rng.randint(64, 16384),
            "bytes_received": rng.randint(64, 65536),
            "description": template["description"],
        }

        if attack_id is not None:
            event["_attack_metadata"] = {
                "attack_id": attack_id,
                "kind": "benign_noise",
            }

        add_network_event_logs(company, network_id=network_id, log=event)


def generate_attack(
    company: Company,
    scenario_id: str,
    victim_id: str,
    *,
    success: Optional[bool] = None,
    parameters: Optional[Dict[str, Any]] = None,
    seed: int = 1337,
    days_back: int = 5,
    inject_benign_network_noise: bool = True,
    benign_noise_count_range: Tuple[int, int] = (8, 20),
) -> AttackInstance:
    """
    Generate a single attack scenario targeting a specific victim.

    Args:
        company: Company data dict to modify in-place
        scenario_id: ID of the attack scenario to use
        victim_id: ID of the employee to target
        success: Whether attack succeeds (None = random based on success_rate)
        parameters: Optional parameter overrides
        seed: Random seed for reproducibility
        days_back: How many days back to start the attack
        inject_benign_network_noise: If True, generate benign network events around the attack
        benign_noise_count_range: (min, max) benign network events to inject

    Returns:
        AttackInstance with ground truth metadata

    Raises:
        ValueError: If scenario_id not found or victim not found
    """
    rng = random.Random(seed)

    # Get scenario
    if scenario_id not in ATTACK_SCENARIOS:
        raise ValueError(f"Unknown attack scenario: {scenario_id}")
    scenario = ATTACK_SCENARIOS[scenario_id]

    # Resolve victim
    people, container_kind = _select_people_container(company)
    victim = None
    for p in people:
        if p.get("id") == victim_id:
            victim = p
            break
    if victim is None:
        raise ValueError(f"Victim not found: {victim_id}")

    victim_email = _primary_email(victim) or f"{victim_id}@company.com"

    # Determine success
    if success is None:
        success = rng.random() < scenario.success_rate

    # Generate attack ID
    attack_id = _generate_attack_id(rng)

    # Resolve parameters
    resolved_params = resolve_attack_parameters(scenario, rng, parameters)

    # Resolve victim's device IP for {victim_ip} placeholder in network events
    victim_device_ip = None
    for d in (company.get("devices") or []):
        if isinstance(d, dict) and d.get("owner_user_id") == victim_id and d.get("ip_address"):
            victim_device_ip = d["ip_address"]
            break
    if not victim_device_ip:
        victim_device_ip = f"10.1.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    resolved_params["victim_ip"] = victim_device_ip

    # Derive victim_username from email (local part) for process/network events
    resolved_params["victim_username"] = victim_email.split("@")[0]

    # Resolve {compromised_peer_email} if the scenario needs it but it wasn't
    # statically defined — pick a random colleague from the same department.
    if "compromised_peer_email" not in resolved_params:
        peer_dept = victim.get("department", "")
        peer_candidates = [
            p for p in people
            if p.get("id") != victim_id
            and p.get("department") == peer_dept
            and _primary_email(p)
        ]
        if peer_candidates:
            resolved_params["compromised_peer_email"] = _primary_email(rng.choice(peer_candidates))
        else:
            # Fallback: any employee
            all_others = [p for p in people if p.get("id") != victim_id and _primary_email(p)]
            if all_others:
                resolved_params["compromised_peer_email"] = _primary_email(rng.choice(all_others))

    # Calculate base timestamp — anchor within victim's existing event timeline
    # so the attack lands among normal activity, not after it.
    time_range = _get_victim_event_time_range(victim)
    if time_range:
        range_start, range_end = time_range
        total_seconds = max((range_end - range_start).total_seconds(), 3600)
        # Place attack in the middle 60% of the timeline (skip first/last 20%)
        offset = rng.uniform(total_seconds * 0.2, total_seconds * 0.8)
        base_time = range_start + timedelta(seconds=offset)
        # Snap to business hours
        if base_time.hour < 8 or base_time.hour >= 18:
            base_time = base_time.replace(
                hour=rng.choice([8, 9, 10, 11, 14, 15, 16, 17])
            )
        base_time = base_time.replace(second=rng.randint(0, 59), microsecond=0)
    else:
        hour = rng.choice([8, 9, 10, 11, 14, 15, 16, 17])
        base_time = datetime.now(timezone.utc) - timedelta(days=days_back)
        base_time = base_time.replace(
            hour=hour,
            minute=rng.randint(0, 59),
            second=rng.randint(0, 59),
            microsecond=0,
        )

    # Track timestamps
    start_ts = _format_ts(base_time)
    compromise_ts: Optional[str] = None
    event_ids: List[str] = []

    # Generate event chain
    current_time = base_time

    for attack_event in scenario.events:
        # Check if this event should fire based on success state
        if attack_event.requires_success and not success:
            # Use failure alternative if available
            if attack_event.on_failure:
                failure_data = attack_event.on_failure
                failure_delay = failure_data.get("delay", {"mean": 0, "std": 0, "min": 0, "max": None})
                delay_minutes = sample_delay(failure_delay, rng)
                current_time = current_time + timedelta(minutes=delay_minutes)

                ft = failure_data.get("event_type", attack_event.event_type)
                fd = failure_data.get("data", {})
                eid = _dispatch_event_creation(
                    ft, company, victim, container_kind,
                    current_time, fd, resolved_params, attack_id, rng,
                    attack_success=success,
                )
                if eid:
                    event_ids.append(eid)

            # Stop processing further events on failure path
            break

        # Sample delay for this event
        delay_minutes = sample_delay(attack_event.delay, rng)
        current_time = current_time + timedelta(minutes=delay_minutes)

        event_data = attack_event.data
        event_type = attack_event.event_type

        # ── Handle pre_attempts (variable failed attempts before main event) ──
        if attack_event.pre_attempts:
            pa = attack_event.pre_attempts
            cr = pa.get("count_range", [1, 3])
            num_attempts = rng.randint(cr[0], cr[1])
            pa_delay = pa.get("delay", {"mean": 0.5, "std": 0.3, "min": 0.1, "max": 2})
            overrides = pa.get("data_overrides", {})

            for _ in range(num_attempts):
                attempt_data = {**event_data, **overrides}
                # Merge metadata: keep original metadata, add/override from overrides
                if "metadata" in event_data or "metadata" in overrides:
                    attempt_data["metadata"] = {
                        **event_data.get("metadata", {}),
                        **overrides.get("metadata", {}),
                    }
                eid = _dispatch_event_creation(
                    event_type, company, victim, container_kind,
                    current_time, attempt_data, resolved_params, attack_id, rng,
                    attack_success=success,
                )
                if eid:
                    event_ids.append(eid)
                attempt_delay = sample_delay(pa_delay, rng)
                current_time = current_time + timedelta(minutes=attempt_delay)

        # ── Handle all_sensitive (download ALL sensitive + noise files) ──────
        if event_data.get("all_sensitive") and event_type == "file_event":
            company_files = _load_company_files_by_id(_get_company_id(company))
            accessible = get_accessible_files(victim, company_files) if company_files else []
            sensitive = [f for f in accessible if (f.get("type") or "").lower() in ("confidential", "business")]
            non_sensitive = [f for f in accessible if (f.get("type") or "").lower() not in ("confidential", "business")]
            noise_range = event_data.get("noise_file_range", [5, 15])
            noise_count = min(rng.randint(noise_range[0], noise_range[1]), len(non_sensitive))
            noise_files = rng.sample(non_sensitive, noise_count) if noise_count <= len(non_sensitive) else non_sensitive
            all_files = sensitive + noise_files
            rng.shuffle(all_files)
            for i, file_meta in enumerate(all_files):
                individual_data = {
                    k: v for k, v in event_data.items()
                    if k not in ("all_sensitive", "noise_file_range", "count_range", "count")
                }
                individual_data["_resolved_file"] = file_meta
                file_time = current_time + timedelta(seconds=rng.randint(3, 90) * (i + 1))
                eid = _create_file_event(
                    company, victim, container_kind,
                    file_time, individual_data, resolved_params, attack_id, rng,
                )
                if eid:
                    event_ids.append(eid)
            if all_files:
                current_time = current_time + timedelta(seconds=rng.randint(3, 90) * len(all_files))

        # ── Handle count_range (expand into individual events) ────────────────
        elif event_data.get("count_range") and event_type == "file_event":
            count_range = event_data["count_range"]
            num_files = rng.randint(count_range[0], count_range[1])
            for i in range(num_files):
                individual_data = {
                    k: v for k, v in event_data.items()
                    if k not in ("count_range", "count")
                }
                file_time = current_time + timedelta(seconds=rng.randint(3, 90) * (i + 1))
                eid = _create_file_event(
                    company, victim, container_kind,
                    file_time, individual_data, resolved_params, attack_id, rng,
                )
                event_ids.append(eid)
            # Advance current_time past all the file events
            current_time = current_time + timedelta(seconds=rng.randint(3, 90) * num_files)
        else:
            # ── Standard single-event dispatch ────────────────────────────────
            event_id = _dispatch_event_creation(
                event_type, company, victim, container_kind,
                current_time, event_data, resolved_params, attack_id, rng,
                attack_success=success,
            )
            if event_id is None:
                continue

            event_ids.append(event_id)

        # Track compromise timestamp for attacker logins
        if event_type == "login":
            metadata = event_data.get("metadata", {})
            if metadata.get("is_attacker") and success:
                compromise_ts = _format_ts(current_time)

    # ── Inject benign network noise around the attack timeframe ───────────
    if inject_benign_network_noise:
        _inject_benign_network_noise(
            company, victim, container_kind, rng,
            attack_start=base_time,
            attack_end=current_time,
            count_range=benign_noise_count_range,
            attack_id=attack_id,
        )

    # Get IOCs for this instance
    iocs = get_scenario_iocs(scenario, resolved_params)

    # Create attack instance
    instance = AttackInstance(
        attack_id=attack_id,
        scenario_id=scenario_id,
        victim_id=victim_id,
        victim_email=victim_email,
        success=success,
        start_ts=start_ts,
        compromise_ts=compromise_ts,
        iocs=iocs,
        expected_findings=scenario.expected_findings.copy(),
        event_ids=event_ids,
    )

    # Store ground truth in company data
    if ATTACK_GROUND_TRUTH_KEY not in company:
        company[ATTACK_GROUND_TRUTH_KEY] = []

    company[ATTACK_GROUND_TRUTH_KEY].append({
        "attack_id": instance.attack_id,
        "scenario_id": instance.scenario_id,
        "victim_id": instance.victim_id,
        "victim_email": instance.victim_email,
        "success": instance.success,
        "start_ts": instance.start_ts,
        "compromise_ts": instance.compromise_ts,
        "iocs": instance.iocs,
        "expected_findings": instance.expected_findings,
        "event_ids": instance.event_ids,
        "resolved_params": dict(resolved_params),
    })

    return instance


def generate_attacks(
    company: Company,
    *,
    attack_rate: float = 0.01,
    scenario_ids: Optional[List[str]] = None,
    seed: int = 1337,
    days_back_range: Tuple[int, int] = (1, 14),
    inject_benign_network_noise: bool = True,
    benign_noise_count_range: Tuple[int, int] = (8, 20),
) -> Dict[str, Any]:
    """
    Generate attacks across the company.

    Selects a random subset of employees based on attack_rate and generates
    attack scenarios targeting them.

    Args:
        company: Company data dict to modify in-place
        attack_rate: Fraction of employees to target (0.0-1.0)
        scenario_ids: List of scenario IDs to use (None = all available)
        seed: Base seed for reproducibility
        days_back_range: Range of days back for attack timing (min, max)
        inject_benign_network_noise: If True, generate benign network events around attacks
        benign_noise_count_range: (min, max) benign network events to inject per attack

    Returns:
        Statistics dict with counts and list of AttackInstances
    """
    rng = random.Random(seed)

    stats: Dict[str, Any] = {
        "employees_total": 0,
        "employees_targeted": 0,
        "attacks_successful": 0,
        "attacks_failed": 0,
        "by_scenario": {},
        "instances": [],
    }

    people, _ = _select_people_container(company)
    stats["employees_total"] = len(people)

    if not people:
        return stats

    # Select scenarios to use
    available_scenarios = list(ATTACK_SCENARIOS.keys())
    if scenario_ids:
        available_scenarios = [s for s in scenario_ids if s in ATTACK_SCENARIOS]
    if not available_scenarios:
        return stats

    # Select victims based on attack rate
    num_victims = max(1, int(len(people) * attack_rate))
    num_victims = min(num_victims, len(people))

    # Filter to employees with email addresses
    eligible = [p for p in people if _primary_email(p)]
    if not eligible:
        return stats

    num_victims = min(num_victims, len(eligible))
    victims = rng.sample(eligible, num_victims)

    stats["employees_targeted"] = len(victims)

    for idx, victim in enumerate(victims):
        victim_id = victim.get("id")
        if not victim_id:
            continue

        # Select a random scenario
        scenario_id = rng.choice(available_scenarios)

        # Randomize days back within range
        days_back = rng.randint(days_back_range[0], days_back_range[1])

        # Generate unique seed for this attack
        attack_seed = seed * 1000 + idx

        try:
            instance = generate_attack(
                company,
                scenario_id=scenario_id,
                victim_id=victim_id,
                success=None,  # Random based on success_rate
                seed=attack_seed,
                days_back=days_back,
                inject_benign_network_noise=inject_benign_network_noise,
                benign_noise_count_range=benign_noise_count_range,
            )

            stats["instances"].append(instance)

            if instance.success:
                stats["attacks_successful"] += 1
            else:
                stats["attacks_failed"] += 1

            stats["by_scenario"][scenario_id] = stats["by_scenario"].get(scenario_id, 0) + 1

        except (ValueError, KeyError) as e:
            # Skip if attack generation fails
            continue

    return stats


def get_attack_ground_truth(company: Company) -> List[Dict[str, Any]]:
    """
    Retrieve all attack instances stored in company data for evaluation.

    Args:
        company: Company data dict

    Returns:
        List of attack ground truth dicts
    """
    return company.get(ATTACK_GROUND_TRUTH_KEY, [])


def extract_attack_events(company: Company, attack_id: str) -> List[Dict[str, Any]]:
    """
    Extract all injected events for a given attack_id from company data.

    Scans employee recent_activity buckets and network subnet events for
    entries tagged with ``_attack_metadata.attack_id == attack_id``.

    Returns a list of event dicts (with ``_event_type`` added to each).
    """
    ACTIVITY_KEYS = [
        "logins", "email_events", "file_events", "admin_actions",
        "app_events", "process_events", "mfa_events", "device_events",
        "print_events",
    ]

    events: List[Dict[str, Any]] = []

    # Scan employee / worker activity buckets
    people, _ = _select_people_container(company)
    for person in people:
        ra = person.get("recent_activity") or {}
        person_id = person.get("id")
        for key in ACTIVITY_KEYS:
            for evt in (ra.get(key) or []):
                meta = evt.get("_attack_metadata")
                if isinstance(meta, dict) and meta.get("attack_id") == attack_id:
                    events.append({
                        **evt,
                        "_event_type": key,
                        "employee_id": evt.get("employee_id") or person_id,
                    })

    # Scan network events (stored at subnet level)
    for subnet in (company.get("network") or {}).get("subnets", []):
        for evt in (subnet.get("events") or []):
            meta = evt.get("_attack_metadata")
            if (
                isinstance(meta, dict)
                and meta.get("attack_id") == attack_id
                and meta.get("kind") != "benign_noise"
            ):
                events.append({**evt, "_event_type": "network_events"})

    # Sort by timestamp
    events.sort(key=lambda e: e.get("ts", ""))
    return events


def get_attack_by_id(company: Company, attack_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a specific attack instance by ID.

    Args:
        company: Company data dict
        attack_id: The attack ID to look up

    Returns:
        Attack ground truth dict or None if not found
    """
    ground_truth = get_attack_ground_truth(company)
    for attack in ground_truth:
        if attack.get("attack_id") == attack_id:
            return attack
    return None


def get_attacks_for_victim(company: Company, victim_id: str) -> List[Dict[str, Any]]:
    """
    Retrieve all attacks targeting a specific victim.

    Args:
        company: Company data dict
        victim_id: The victim employee ID

    Returns:
        List of attack ground truth dicts for this victim
    """
    ground_truth = get_attack_ground_truth(company)
    return [a for a in ground_truth if a.get("victim_id") == victim_id]


def clear_attack_ground_truth(company: Company) -> int:
    """
    Clear all attack ground truth from company data.

    Note: This does NOT remove the generated events from user activity logs,
    only the ground truth metadata.

    Args:
        company: Company data dict

    Returns:
        Number of attack records cleared
    """
    if ATTACK_GROUND_TRUTH_KEY in company:
        count = len(company[ATTACK_GROUND_TRUTH_KEY])
        del company[ATTACK_GROUND_TRUTH_KEY]
        return count
    return 0


def generate_multi_victim_attack(
    company: Company,
    scenario_id: str,
    initial_victim_id: str,
    *,
    num_additional_victims: int = 3,
    success: Optional[bool] = None,
    parameters: Optional[Dict[str, Any]] = None,
    seed: int = 1337,
    days_back: int = 5,
    propagation_delay_hours: Tuple[float, float] = (1.0, 24.0),
) -> List[AttackInstance]:
    """
    Generate a multi-victim attack scenario (e.g., ransomware, USB propagation).

    This function generates an initial attack and then propagates it to
    additional victims with realistic timing delays. All instances share
    the same parent attack ID for correlation.

    Args:
        company: Company data dict to modify in-place
        scenario_id: ID of the attack scenario to use
        initial_victim_id: ID of the first victim (patient zero)
        num_additional_victims: Number of additional victims to propagate to
        success: Whether the initial attack succeeds (None = random)
        parameters: Optional parameter overrides
        seed: Random seed for reproducibility
        days_back: How many days back to start the initial attack
        propagation_delay_hours: Range of hours between propagation (min, max)

    Returns:
        List of AttackInstance objects for all victims

    Raises:
        ValueError: If scenario_id not found or initial victim not found
    """
    rng = random.Random(seed)
    instances: List[AttackInstance] = []

    # Generate initial attack
    initial_instance = generate_attack(
        company,
        scenario_id=scenario_id,
        victim_id=initial_victim_id,
        success=success,
        parameters=parameters,
        seed=seed,
        days_back=days_back,
    )
    instances.append(initial_instance)

    # Only propagate if initial attack succeeded
    if not initial_instance.success:
        return instances

    # Get list of potential secondary victims
    people, _ = _select_people_container(company)
    eligible = [
        p for p in people
        if p.get("id") != initial_victim_id
        and _primary_email(p)
    ]

    if not eligible:
        return instances

    # Select secondary victims
    num_secondary = min(num_additional_victims, len(eligible))
    secondary_victims = rng.sample(eligible, num_secondary)

    # Store the parent attack ID for correlation
    parent_attack_id = initial_instance.attack_id

    # Generate propagated attacks with delays
    for idx, victim in enumerate(secondary_victims):
        victim_id = victim.get("id")
        if not victim_id:
            continue

        # Calculate propagation delay
        delay_hours = rng.uniform(propagation_delay_hours[0], propagation_delay_hours[1])
        # Each subsequent victim gets additional delay
        cumulative_delay = delay_hours * (idx + 1)

        # Calculate days back for this victim (less than initial)
        victim_days_back = max(1, days_back - int(cumulative_delay / 24))

        # Generate unique seed for this victim
        victim_seed = seed * 1000 + idx + 1

        try:
            # Build parameters with parent reference
            victim_params = dict(parameters or {})
            victim_params["_parent_attack_id"] = parent_attack_id
            victim_params["_propagation_index"] = idx + 1

            instance = generate_attack(
                company,
                scenario_id=scenario_id,
                victim_id=victim_id,
                success=True,  # Propagated attacks typically succeed
                parameters=victim_params,
                seed=victim_seed,
                days_back=victim_days_back,
            )
            instances.append(instance)

        except (ValueError, KeyError):
            # Skip if attack generation fails for this victim
            continue

    return instances
