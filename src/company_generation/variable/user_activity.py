import uuid
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .temporal_model import (
    CircadianSampler,
    WeeklyCycleModulator,
    format_ts,
    get_window,
    resolve_event_count,
    resolve_person_temporal,
    sample_timestamp,
)


# ---------------------------------------------------------------------------
# Person-index cache – avoids O(N) linear scans in _resolve_worker
# ---------------------------------------------------------------------------
_PERSON_INDEX: Dict[str, Dict[str, Any]] = {}
_PERSON_INDEX_LIST_ID: Optional[int] = None


def _get_person_index(people_list: list) -> Dict[str, Dict[str, Any]]:
    """Return a cached ``{id: person}`` dict for *people_list*.

    The cache is invalidated whenever *people_list* is a different list
    object (checked via ``id()``).
    """
    global _PERSON_INDEX, _PERSON_INDEX_LIST_ID
    list_id = id(people_list)
    if list_id != _PERSON_INDEX_LIST_ID:
        _PERSON_INDEX = {p["id"]: p for p in people_list if p.get("id")}
        _PERSON_INDEX_LIST_ID = list_id
    return _PERSON_INDEX


def invalidate_person_index() -> None:
    """Force rebuild of the person-index cache on the next lookup."""
    global _PERSON_INDEX, _PERSON_INDEX_LIST_ID
    _PERSON_INDEX = {}
    _PERSON_INDEX_LIST_ID = None


def vary_count(mean: int, rng: random.Random, *, cv: float = 0.25) -> int:
    """Return a non-negative integer drawn from a normal distribution.

    Args:
        mean: The target mean count.
        rng: A seeded ``random.Random`` instance for deterministic results.
        cv: Coefficient of variation (std = cv * mean).  Default 0.25 gives
            roughly ±25 % spread.  For *mean* ≤ 1 the value is returned as-is
            to avoid degenerate distributions.

    Returns:
        A non-negative int.  The result is clamped to ``[0, 2 * mean]`` so
        that extreme outliers don't distort a dataset.
    """
    if mean <= 1:
        return max(0, mean)
    std = cv * mean
    value = rng.gauss(mean, std)
    # Clamp to [0, 2*mean] then round
    return max(0, min(round(value), 2 * mean))


def _resolve_worker(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    employee_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Resolve and return a person object from the company:
    - Static fixtures: company['employees'][*]['id'] equals the static user_id (e.g., 'u_0001')
      In this case, provide employee_id or user_id.
    - Full fixtures: company['workers'][*]['id'] is a UUIDv5(company_id:user_id).
      In this case, provide worker_id or user_id.
    """
    if not company or "company" not in company or "id" not in company["company"]:
        raise ValueError("Invalid company object: missing 'company.id'")

    # Prefer employees when present
    employees = company.get("employees")
    if isinstance(employees, list) and employees:
        identifier = employee_id or user_id or worker_id
        if not identifier:
            raise ValueError("Provide 'employee_id' or 'user_id' to resolve an employee")
        index = _get_person_index(employees)
        person = index.get(identifier)
        if person is not None:
            return person
        raise ValueError(f"Employee not found for identifier (employee_id={employee_id}, user_id={user_id})")

    # Fallback to workers (full company)
    workers = company.get("workers")
    if not isinstance(workers, list) or not workers:
        raise ValueError("Company has neither 'employees' nor 'workers' to resolve a person")
    if worker_id is None and user_id is None:
        raise ValueError("Provide 'user_id' or 'worker_id' to resolve a worker")
    resolved_worker_id: Optional[str] = worker_id
    if resolved_worker_id is None and user_id is not None:
        comp_id = company["company"]["id"]
        resolved_worker_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{comp_id}:{user_id}"))
    index = _get_person_index(workers)
    person = index.get(resolved_worker_id)
    if person is not None:
        return person
    raise ValueError(f"Worker not found for identifier (user_id={user_id}, worker_id={worker_id})")


def _collect_person_apps(person: Dict[str, Any]) -> List[str]:
    """
    Return a list of app names the person has access to from their authorisations.
    Authorisations are stored as "AppName - role" strings.
    """
    authorisations = person.get("authorisations") or []
    if not isinstance(authorisations, list):
        return []
    apps: List[str] = []
    for auth in authorisations:
        if isinstance(auth, str) and " - " in auth:
            app_name = auth.rsplit(" - ", 1)[0].strip()
            if app_name and app_name not in apps:
                apps.append(app_name)
    return apps


def _collect_person_device_ids(company: Dict[str, Any], person: Dict[str, Any]) -> List[str]:
    """
    Return a list of device_ids associated with the person.
    - For full fixtures (workers), prefer person['devices'][*]['device_id'] when present.
    - For static fixtures (employees), resolve from company['devices'][*] where owner_user_id == employee id.
    """
    device_ids: List[str] = []
    # Worker-attached devices
    if isinstance(person.get("devices"), list):
        device_ids.extend(
            d.get("device_id")
            for d in person["devices"]
            if isinstance(d, dict) and d.get("device_id")
        )
    if device_ids:
        return device_ids
    # Static employee: lookup in company devices
    comp_devices = company.get("devices") or []
    person_id = person.get("id")
    if person_id and isinstance(comp_devices, list):
        for d in comp_devices:
            if not isinstance(d, dict):
                continue
            if d.get("owner_user_id") == person_id and d.get("id"):
                device_ids.append(d["id"])
    return device_ids


def add_login_log(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,  # deprecated alias; use employee_id for static or keep for full
    employee_id: Optional[str] = None,
    ip: str,
    user_agent: str,
    device_id: Optional[str] = None,
    known_device: Optional[bool] = None,
    failure_reason: Optional[str] = None,
    ts: Optional[str] = None,
    method: Optional[str] = None,
    success: Optional[bool] = None,
    geo: Optional[str] = None,
    app: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Append a single login event to the specified person's recent activity.
    Required fields: ip, user_agent
    Optional fields: device_id, known_device, failure_reason, ts, method, success, geo, app
    If not provided:
      - ts defaults to now (UTC)
      - method defaults to 'SSO+MFA'
      - success defaults to (failure_reason is None)
      - known_device defaults to True if device_id provided and not 'unknown'
      - geo defaults to locations.tz (full) or location (static) if available
      - app defaults to None (if provided, should be an app name from the person's authorisations)
    Returns the appended login event dict.
    """
    person = _resolve_worker(company, user_id=user_id, worker_id=worker_id, employee_id=employee_id)
    now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if success is None:
        success = failure_reason is None
    if known_device is None:
        known_device = bool(device_id) and device_id != "unknown"
    if device_id is None:
        device_id = "unknown"
    if method is None:
        method = "SSO+MFA"
    if ts is None:
        ts = now_iso
    if geo is None:
        # Prefer worker.locations.tz; fallback to employee.location
        geo = (person.get("locations") or {}).get("tz") if isinstance(person.get("locations"), dict) else None
        if not geo:
            geo = person.get("location")
    # If no device specified, prefer a known device for the person
    if device_id is None:
        person_device_ids = _collect_person_device_ids(company, person)
        device_id = person_device_ids[0] if person_device_ids else "unknown"
        if known_device is None:
            known_device = bool(person_device_ids)

    evt: Dict[str, Any] = {
        "ts": ts,
        "ip": ip,
        "method": method,
        "success": bool(success),
    }
    if app:
        evt["app"] = app
    if geo:
        evt["geo"] = geo
    if user_agent:
        evt["user_agent"] = user_agent
    if device_id:
        evt["device_id"] = device_id
    if known_device is not None:
        evt["known_device"] = bool(known_device)
    if failure_reason:
        evt["failure_reason"] = failure_reason

    ra = person.setdefault("recent_activity", {})
    logins: List[Dict[str, Any]] = ra.setdefault("logins", [])
    logins.append(evt)
    return evt


def add_random_login_logs(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,  # deprecated alias; use employee_id for static or keep for full
    employee_id: Optional[str] = None,
    count: int = 1,
    seed: Optional[int] = None,
    safe_mode: bool = True,
    generation_config: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Generate and append 'count' randomized login events for the specified person.
    Uses the devices (if present) and timezone/location to enrich the events.
    Returns the list of appended events.

    .. deprecated::
        For bulk generation, prefer ``login_events.generate_login_event_logs()``
        which produces realistic IP clustering, Zipf-weighted app selection,
        role-conditioned event counts, and stable per-employee profiles.
        This function is retained for backward compatibility (attacks, tests,
        and correlation modules that inject individual events).

    Args:
        company: Company data structure
        user_id/worker_id/employee_id: Identifier for the person
        count: Number of events to generate
        seed: Random seed for reproducibility
        safe_mode: If True, only generate "safe" failure reasons that don't imply
                   follow-up actions (excludes 'account_locked', 'mfa_failed').
                   Set to False if generating correlated scenarios separately.
        generation_config: Optional temporal/circadian config dict
    """
    rng = random.Random(seed) if seed is not None else random.Random()
    person = _resolve_worker(company, user_id=user_id, worker_id=worker_id, employee_id=employee_id)
    tz = (person.get("locations") or {}).get("tz") if isinstance(person.get("locations"), dict) else None
    tz = tz or person.get("location") or "UTC"
    device_ids = _collect_person_device_ids(company, person)
    person_apps = _collect_person_apps(person)

    gen_cfg = generation_config or company.get("_generation_config") or {}

    # Build temporal samplers if config available
    circadian: Optional[CircadianSampler] = None
    weekly: Optional[WeeklyCycleModulator] = None
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    if gen_cfg:
        circadian, weekly = resolve_person_temporal(person, gen_cfg)
        window_start, window_end = get_window(gen_cfg)

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile",
    ]
    methods = ["SSO+MFA", "SSO", "Password+MFA"]
    if safe_mode:
        failure_reasons = ["invalid_password", "captcha_required", "expired_password", "invalid_session"]
    else:
        failure_reasons = ["invalid_password", "mfa_failed", "account_locked", "captcha_required"]

    def random_public_ip() -> str:
        while True:
            a, b, c, d = rng.randint(1, 223), rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254)
            if a in (10, 127, 169, 172, 192):
                continue
            if a == 100 and 64 <= b <= 127:
                continue
            if a == 198 and b in (18, 19):
                continue
            return f"{a}.{b}.{c}.{d}"

    appended: List[Dict[str, Any]] = []
    for _ in range(max(0, int(count))):
        ip = random_public_ip()
        ua = rng.choice(user_agents)
        method = rng.choice(methods)
        is_failure = rng.random() < 0.05
        failure_reason = rng.choice(failure_reasons) if is_failure else None
        kd = bool(device_ids) and (rng.random() < 0.9)
        dev_id = rng.choice(device_ids) if kd else "unknown"

        # Temporal model: smooth circadian sampling with weekly modulation
        if circadian and weekly and window_start and window_end:
            ts_dt = sample_timestamp(circadian, weekly, rng, window_start, window_end)
            ts = format_ts(ts_dt)
        else:
            days_back = rng.randint(0, 29)
            hour = rng.choice([7, 8, 9, 10, 17, 18, 21, 22])
            ts_dt = datetime.now(timezone.utc) - timedelta(days=days_back)
            ts_dt = ts_dt.replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59), microsecond=0)
            ts = ts_dt.isoformat().replace("+00:00", "Z")

        app = rng.choice(person_apps) if person_apps else None

        evt = add_login_log(
            company,
            worker_id=person.get("id"),
            employee_id=person.get("id"),
            ip=ip,
            user_agent=ua,
            device_id=dev_id,
            known_device=kd,
            failure_reason=failure_reason,
            ts=ts,
            method=method,
            success=None,
            geo=tz,
            app=app,
        )
        appended.append(evt)
    return appended


def add_recent_activity_log(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,  # deprecated alias; use employee_id for static or keep for full
    employee_id: Optional[str] = None,
    key: str,
    log: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Append a single 'log' dict to the person's recent_activity under the normalized key.
    Accepted keys (and aliases):
      - 'login_logs', 'logins'           -> 'logins'
      - 'email_logs', 'emails', 'email_events' -> 'email_events'
      - 'file_logs', 'files', 'file_events'    -> 'file_events'
      - 'admin_logs', 'admin_actions'          -> 'admin_actions'
      - 'user_logs', 'user_actions'            -> 'user_actions'
      - 'app_logs', 'app_events'               -> 'app_events'
    Returns the appended log dict.
    """
    key_map = {
        "login_logs": "logins",
        "logins": "logins",
        "email_logs": "email_events",
        "emails": "email_events",
        "email_events": "email_events",
        "file_logs": "file_events",
        "files": "file_events",
        "file_events": "file_events",
        "admin_logs": "admin_actions",
        "admin_actions": "admin_actions",
        "user_logs": "user_actions",
        "user_actions": "user_actions",
        "app_logs": "app_events",
        "app_events": "app_events",
        "process_logs": "process_events",
        "process_events": "process_events",
        "mfa_logs": "mfa_events",
        "mfa_events": "mfa_events",
        "device_logs": "device_events",
        "device_events": "device_events",
        "print_logs": "print_events",
        "print_events": "print_events",
        # network_events are stored at subnet level, not per-employee
    }
    norm_key = key_map.get(key)
    if not norm_key:
        raise ValueError(f"Unsupported recent_activity key '{key}'")
    person = _resolve_worker(company, user_id=user_id, worker_id=worker_id, employee_id=employee_id)
    ra = person.setdefault("recent_activity", {})
    bucket: List[Dict[str, Any]] = ra.setdefault(norm_key, [])
    bucket.append(log)
    return log


def add_file_event_logs(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    employee_id: Optional[str] = None,
    log: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append a single file event log to the specified person's recent activity.

    The log must include at minimum:
      - action: one of {'share', 'modify', 'read'}
      - path: filesystem or repository path for the file
    If ts is omitted it defaults to now (UTC).
    """
    if not isinstance(log, dict):
        raise ValueError("Provide a log dict describing the file event")
    evt = dict(log)
    action = (evt.get("action") or "").lower()
    if action not in {"share", "modify", "read", "delete", "download", "copy", "upload"}:
        raise ValueError(f"Unsupported file event action '{evt.get('action')}'")
    if "path" not in evt or not evt["path"]:
        raise ValueError("File event logs require a 'path' field")
    if "ts" not in evt or not evt["ts"]:
        evt["ts"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    # Normalize action casing for downstream consumers
    evt["action"] = action
    return add_recent_activity_log(
        company,
        user_id=user_id,
        worker_id=worker_id,
        employee_id=employee_id,
        key="file_events",
        log=evt,
    )


def add_email_event_logs(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    employee_id: Optional[str] = None,
    log: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append a single email event log to the specified person's recent activity.

    The log must include at minimum:
      - direction: one of {'sent', 'received'}
    Optional fields:
      - from: sender email address
      - to: list of recipient email addresses
      - cc: list of CC email addresses
      - bcc: list of BCC email addresses
      - subject: email subject line
      - content: email body/description
      - external: boolean indicating if the email is external
      - attachment_types: list of attachment file types (e.g., ['pdf', 'xlsx'])
      - attachments: list of attachment objects with filename, url, optional file_path and size_bytes
    If ts is omitted it defaults to now (UTC).
    """
    if not isinstance(log, dict):
        raise ValueError("Provide a log dict describing the email event")
    evt = dict(log)
    direction = (evt.get("direction") or "").lower()
    if direction not in {"sent", "received"}:
        raise ValueError(f"Unsupported email event direction '{evt.get('direction')}'")
    if "ts" not in evt or not evt["ts"]:
        evt["ts"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    # Normalize direction casing for downstream consumers
    evt["direction"] = direction
    return add_recent_activity_log(
        company,
        user_id=user_id,
        worker_id=worker_id,
        employee_id=employee_id,
        key="email_events",
        log=evt,
    )


def add_app_event_logs(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    employee_id: Optional[str] = None,
    log: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append a single app event log to the specified person's recent activity.

    The log must include at minimum:
      - app: the application name (e.g., 'Slack', 'GitHub', 'Salesforce')
      - action: the action performed (e.g., 'create_document', 'send_message', 'view_record')
    Optional fields:
      - ts: timestamp (defaults to now UTC)
      - details: dict with action-specific details
      - resource_type: type of resource acted on (e.g., 'document', 'message', 'record')
      - resource_id: identifier of the resource
      - resource_name: human-readable name of the resource
    If ts is omitted it defaults to now (UTC).
    """
    if not isinstance(log, dict):
        raise ValueError("Provide a log dict describing the app event")
    evt = dict(log)
    if "app" not in evt or not evt["app"]:
        raise ValueError("App event logs require an 'app' field")
    if "action" not in evt or not evt["action"]:
        raise ValueError("App event logs require an 'action' field")
    if "ts" not in evt or not evt["ts"]:
        evt["ts"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return add_recent_activity_log(
        company,
        user_id=user_id,
        worker_id=worker_id,
        employee_id=employee_id,
        key="app_events",
        log=evt,
    )


def add_process_event_logs(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    employee_id: Optional[str] = None,
    log: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append a single process event log to the specified person's recent activity.

    The log must include at minimum:
      - process_name: the name of the process (e.g., 'powershell.exe', 'cmd.exe')
      - action: one of {'start', 'stop', 'inject', 'spawn'}
    Optional fields:
      - ts: timestamp (defaults to now UTC)
      - parent_process: name of the parent process
      - command_line: full command line arguments
      - pid: process ID
      - hash: file hash (SHA256) of the executable
      - path: full path to the executable
      - user: user context running the process
      - integrity_level: process integrity level (e.g., 'high', 'medium', 'system')
    If ts is omitted it defaults to now (UTC).
    """
    if not isinstance(log, dict):
        raise ValueError("Provide a log dict describing the process event")
    evt = dict(log)
    if "process_name" not in evt or not evt["process_name"]:
        raise ValueError("Process event logs require a 'process_name' field")
    action = (evt.get("action") or "").lower()
    if action not in {"start", "stop", "inject", "spawn"}:
        raise ValueError(f"Unsupported process event action '{evt.get('action')}'")
    evt["action"] = action
    if "ts" not in evt or not evt["ts"]:
        evt["ts"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return add_recent_activity_log(
        company,
        user_id=user_id,
        worker_id=worker_id,
        employee_id=employee_id,
        key="process_events",
        log=evt,
    )


def add_mfa_event_logs(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    employee_id: Optional[str] = None,
    log: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append a single MFA event log to the specified person's recent activity.

    The log must include at minimum:
      - action: one of {'push_sent', 'push_approved', 'push_denied', 'device_registered',
                        'device_removed', 'code_entered', 'code_failed'}
    Optional fields:
      - ts: timestamp (defaults to now UTC)
      - device_name: name of the MFA device (e.g., 'iPhone 15 Pro')
      - method: MFA method (e.g., 'push', 'totp', 'sms', 'hardware_key')
      - count: number of pushes/attempts (for push bombing scenarios)
      - app: application requesting MFA
      - ip: IP address of the request
      - success: whether the MFA attempt succeeded
    If ts is omitted it defaults to now (UTC).
    """
    if not isinstance(log, dict):
        raise ValueError("Provide a log dict describing the MFA event")
    evt = dict(log)
    action = (evt.get("action") or "").lower()
    valid_actions = {
        "push_sent", "push_approved", "push_denied",
        "device_registered", "device_removed",
        "code_entered", "code_failed"
    }
    if action not in valid_actions:
        raise ValueError(f"Unsupported MFA event action '{evt.get('action')}'")
    evt["action"] = action
    if "ts" not in evt or not evt["ts"]:
        evt["ts"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return add_recent_activity_log(
        company,
        user_id=user_id,
        worker_id=worker_id,
        employee_id=employee_id,
        key="mfa_events",
        log=evt,
    )


def add_device_event_logs(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    employee_id: Optional[str] = None,
    log: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append a single device event log to the specified person's recent activity.

    The log must include at minimum:
      - action: one of {'usb_connected', 'usb_disconnected', 'software_install',
                        'software_uninstall', 'bluetooth_connect', 'bluetooth_disconnect'}
    Optional fields:
      - ts: timestamp (defaults to now UTC)
      - device_type: type of device (e.g., 'usb_storage', 'usb_phone', 'bluetooth')
      - vendor: device vendor/manufacturer
      - product: device product name
      - serial: device serial number
      - software_name: name of software being installed/uninstalled
      - software_version: version of software
      - volume_label: USB volume label
      - capacity_gb: storage capacity in GB
    If ts is omitted it defaults to now (UTC).
    """
    if not isinstance(log, dict):
        raise ValueError("Provide a log dict describing the device event")
    evt = dict(log)
    action = (evt.get("action") or "").lower()
    valid_actions = {
        "usb_connected", "usb_disconnected",
        "software_install", "software_uninstall",
        "bluetooth_connect", "bluetooth_disconnect"
    }
    if action not in valid_actions:
        raise ValueError(f"Unsupported device event action '{evt.get('action')}'")
    evt["action"] = action
    if "ts" not in evt or not evt["ts"]:
        evt["ts"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return add_recent_activity_log(
        company,
        user_id=user_id,
        worker_id=worker_id,
        employee_id=employee_id,
        key="device_events",
        log=evt,
    )


def add_print_event_logs(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    employee_id: Optional[str] = None,
    log: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append a single print event log to the specified person's recent activity.

    The log must include at minimum:
      - printer_name: name of the printer
      - document_name: name of the document being printed
    Optional fields:
      - ts: timestamp (defaults to now UTC)
      - pages: number of pages printed
      - copies: number of copies
      - color: whether color printing was used
      - duplex: whether duplex printing was used
      - paper_size: paper size (e.g., 'A4', 'Letter')
      - job_id: print job identifier
      - status: job status (e.g., 'completed', 'cancelled', 'failed')
    If ts is omitted it defaults to now (UTC).
    """
    if not isinstance(log, dict):
        raise ValueError("Provide a log dict describing the print event")
    evt = dict(log)
    if "printer_name" not in evt or not evt["printer_name"]:
        raise ValueError("Print event logs require a 'printer_name' field")
    if "document_name" not in evt or not evt["document_name"]:
        raise ValueError("Print event logs require a 'document_name' field")
    if "ts" not in evt or not evt["ts"]:
        evt["ts"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return add_recent_activity_log(
        company,
        user_id=user_id,
        worker_id=worker_id,
        employee_id=employee_id,
        key="print_events",
        log=evt,
    )


def add_network_event_logs(
    company: Dict[str, Any],
    *,
    network_id: str,
    log: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append a single network event log to the matching subnet's events list.

    Network events are stored at the subnet level (company["network"]["subnets"][i]["events"])
    rather than per-employee, since firewalls log traffic at the network/subnet level.

    The employee can be identified by joining source_ip -> devices.ip_address -> devices.owner_user_id.

    Args:
        company: Company data dict
        network_id: The subnet ID to store the event under (FK to subnets)
        log: Event dict

    The log must include at minimum:
      - source_ip: source IP address
      - destination_ip: destination IP address
      - destination_port: destination port number
      - action: one of {'allowed', 'blocked', 'monitored'}
      - direction: one of {'inbound', 'outbound', 'internal'}
    Optional fields:
      - ts: timestamp (defaults to now UTC)
      - protocol: network protocol (e.g., 'TCP', 'UDP', 'ICMP')
      - user: username from auth/identity
      - auth: authentication type (e.g., 'kerberos', 'ntlm', 'certificate', 'none')
      - bytes_sent: bytes sent
      - bytes_received: bytes received
      - description: human-readable description
    If ts is omitted it defaults to now (UTC).
    """
    if not isinstance(log, dict):
        raise ValueError("Provide a log dict describing the network event")
    evt = dict(log)
    action = (evt.get("action") or "").lower()
    if action not in {"allowed", "blocked", "monitored"}:
        raise ValueError(f"Unsupported network event action '{evt.get('action')}'")
    direction = (evt.get("direction") or "").lower()
    if direction not in {"inbound", "outbound", "internal"}:
        raise ValueError(f"Unsupported network event direction '{evt.get('direction')}'")
    evt["action"] = action
    evt["direction"] = direction
    if "ts" not in evt or not evt["ts"]:
        evt["ts"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    # Find the matching subnet and append the event
    network = company.setdefault("network", {})
    subnets = network.setdefault("subnets", [])
    for subnet in subnets:
        if subnet.get("id") == network_id:
            events: List[Dict[str, Any]] = subnet.setdefault("events", [])
            events.append(evt)
            return evt

    raise ValueError(f"Subnet not found for network_id '{network_id}'")
