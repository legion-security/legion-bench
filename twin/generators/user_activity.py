import uuid
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


def _resolve_worker(company: Dict[str, Any], *, user_id: Optional[str] = None, worker_id: Optional[str] = None, employee_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Resolve and return the worker/employee object from the company using either:
    - employee_id/worker_id: direct ID present in company['employees'][*]['id'] or company['workers'][*]['id']
    - user_id: original static user id (e.g., 'u_0001'); resolved via UUIDv5(company_id:user_id) for full fixtures
    
    Supports both 'employees' and 'workers' keys for backward compatibility.
    """
    if not company or "company" not in company or "id" not in company["company"]:
        raise ValueError("Invalid company object: missing 'company.id'")
    
    # Prefer employees when present (unified key)
    employees = company.get("employees")
    if isinstance(employees, list) and employees:
        identifier = employee_id or user_id or worker_id
        if not identifier:
            raise ValueError("Provide 'employee_id' or 'user_id' to resolve an employee")
        for e in employees:
            if e.get("id") == identifier:
                return e
        raise ValueError(f"Employee not found for identifier (employee_id={employee_id}, user_id={user_id})")
    
    # Fallback to workers (legacy)
    workers = company.get("workers")
    if not isinstance(workers, list) or not workers:
        raise ValueError("Company has neither 'employees' nor 'workers' to resolve a person")
    if worker_id is None and user_id is None:
        raise ValueError("Either 'user_id' or 'worker_id' must be provided")
    resolved_worker_id: Optional[str] = worker_id
    if resolved_worker_id is None and user_id is not None:
        comp_id = company["company"]["id"]
        resolved_worker_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{comp_id}:{user_id}"))
    for w in workers:
        if w.get("id") == resolved_worker_id:
            return w
    raise ValueError(f"Worker not found for identifier (user_id={user_id}, worker_id={worker_id})")


def add_login_log(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    ip: str,
    user_agent: str,
    device_id: Optional[str] = None,
    known_device: Optional[bool] = None,
    failure_reason: Optional[str] = None,
    ts: Optional[str] = None,
    method: Optional[str] = None,
    success: Optional[bool] = None,
    geo: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Append a single login event to the specified user's recent activity.
    Required fields: ip, user_agent
    Optional fields: device_id, known_device, failure_reason, ts, method, success, geo
    If not provided:
      - ts defaults to now (UTC)
      - method defaults to 'SSO+MFA'
      - success defaults to (failure_reason is None)
      - known_device defaults to True if device_id provided and not 'unknown'
      - geo defaults to user's timezone from locations.tz (if available)
    Returns the appended login event dict.
    """
    worker = _resolve_worker(company, user_id=user_id, worker_id=worker_id)
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
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
        geo = (worker.get("locations") or {}).get("tz")

    evt: Dict[str, Any] = {
        "ts": ts,
        "ip": ip,
        "method": method,
        "success": bool(success),
    }
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

    ra = worker.setdefault("recent_activity", {})
    logins: List[Dict[str, Any]] = ra.setdefault("logins", [])
    logins.append(evt)
    try:
        logins.sort(key=lambda e: e.get("ts", ""))
    except Exception:
        pass
    return evt


def add_random_login_logs(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    count: int = 1,
    seed: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Generate and append 'count' randomized login events for the specified user.
    Uses the user's devices and timezone to enrich the events.
    Returns the list of appended events.
    """
    rng = random.Random(seed) if seed is not None else random.Random()
    worker = _resolve_worker(company, user_id=user_id, worker_id=worker_id)
    tz = (worker.get("locations") or {}).get("tz", "UTC")
    device_ids = [d.get("device_id") for d in worker.get("devices", []) if d.get("device_id")]

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile",
    ]
    methods = ["SSO+MFA", "SSO", "Password+MFA"]
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
        kd = bool(device_ids) and (rng.random() < 0.85)
        dev_id = rng.choice(device_ids) if kd else "unknown"
        days_back = rng.randint(0, 29)
        hour = rng.choice([7, 8, 9, 10, 17, 18, 21, 22])
        ts_dt = datetime.now(timezone.utc) - timedelta(days=days_back)
        ts_dt = ts_dt.replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59), microsecond=0)
        ts = ts_dt.isoformat().replace("+00:00", "Z")

        evt = add_login_log(
            company,
            worker_id=worker.get("id"),
            ip=ip,
            user_agent=ua,
            device_id=dev_id,
            known_device=kd,
            failure_reason=failure_reason,
            ts=ts,
            method=method,
            success=None,
            geo=tz,
        )
        appended.append(evt)
    return appended


def add_recent_activity_log(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    key: str,
    log: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Append a single 'log' dict to the user's recent_activity under the normalized key.
    Accepted keys (and aliases):
      - 'login_logs', 'logins'           -> 'logins'
      - 'email_logs', 'emails', 'email_events' -> 'email_events'
      - 'file_logs', 'files', 'file_events'    -> 'file_events'
      - 'admin_logs', 'admin_actions'          -> 'admin_actions'
      - 'user_logs', 'user_actions'            -> 'user_actions'
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
    }
    norm_key = key_map.get(key)
    if not norm_key:
        raise ValueError(f"Unsupported recent_activity key '{key}'")
    worker = _resolve_worker(company, user_id=user_id, worker_id=worker_id)
    ra = worker.setdefault("recent_activity", {})
    bucket: List[Dict[str, Any]] = ra.setdefault(norm_key, [])
    bucket.append(log)
    if all(isinstance(e, dict) and "ts" in e for e in bucket):
        try:
            bucket.sort(key=lambda e: e.get("ts", ""))
        except Exception:
            pass
    return log


def add_file_event_logs(
    company: Dict[str, Any],
    *,
    user_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    log: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append a single file event log to the worker's recent_activity bucket.
    """
    if not isinstance(log, dict):
        raise ValueError("Provide a log dict describing the file event")
    evt = dict(log)
    action = (evt.get("action") or "").lower()
    if action not in {"share", "modify", "read"}:
        raise ValueError(f"Unsupported file event action '{evt.get('action')}'")
    if "path" not in evt or not evt["path"]:
        raise ValueError("File event logs require a 'path' field")
    if "ts" not in evt or not evt["ts"]:
        evt["ts"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    evt["action"] = action
    return add_recent_activity_log(
        company,
        user_id=user_id,
        worker_id=worker_id,
        key="file_events",
        log=evt,
    )



