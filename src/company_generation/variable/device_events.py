"""
Device event log generation for company fixtures.

Generates realistic device events for each employee, including:
- USB peripheral connects/disconnects with per-person device stickiness
- Software install/update events with wave-based rollouts and OS awareness
- Bluetooth connects/disconnects correlated to meetings
- Morning dock-in / evening dock-out patterns with cascade sub-devices
- Department-aware category weights and type-specific disconnect profiles

USB storage events are kept rare for baseline activity so that attack-injected
USB storage events stand out only slightly above normal noise, not as unique events.
"""
from __future__ import annotations

import hashlib
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .user_activity import (
    add_device_event_logs,
    _collect_person_apps,
    _collect_person_device_ids,
    vary_count,
)
from .temporal_model import (
    CircadianSampler,
    WeeklyCycleModulator,
    format_ts,
    get_window,
    resolve_event_count,
    resolve_person_temporal,
    sample_timestamp,
)
from .episodic_bursts import BurstSchedule, apply_burst_to_count

Person = Dict[str, Any]
Company = Dict[str, Any]

_DEFAULT_DEVICE_EVENTS = 3

# ── USB peripherals (non-storage) ────────────────────────────────────────────

_USB_PERIPHERALS: List[Dict[str, str]] = [
    {"device_type": "usb_mouse", "vendor": "Logitech", "product": "MX Master 3S"},
    {"device_type": "usb_mouse", "vendor": "Logitech", "product": "G Pro Wireless"},
    {"device_type": "usb_mouse", "vendor": "Razer", "product": "DeathAdder V3"},
    {"device_type": "usb_keyboard", "vendor": "Logitech", "product": "MX Keys"},
    {"device_type": "usb_keyboard", "vendor": "Microsoft", "product": "Ergonomic Keyboard"},
    {"device_type": "usb_keyboard", "vendor": "Corsair", "product": "K70 RGB"},
    {"device_type": "usb_webcam", "vendor": "Logitech", "product": "C920 HD Pro"},
    {"device_type": "usb_webcam", "vendor": "Logitech", "product": "Brio 4K"},
    {"device_type": "usb_headset", "vendor": "Jabra", "product": "Evolve2 75"},
    {"device_type": "usb_headset", "vendor": "Poly", "product": "Voyager Focus 2"},
    {"device_type": "usb_headset", "vendor": "Logitech", "product": "Zone Wireless 2"},
    {"device_type": "usb_phone", "vendor": "Apple", "product": "iPhone (charging)"},
    {"device_type": "usb_phone", "vendor": "Samsung", "product": "Galaxy S24 (charging)"},
    {"device_type": "usb_hub", "vendor": "Anker", "product": "PowerExpand 8-in-1"},
    {"device_type": "usb_hub", "vendor": "CalDigit", "product": "TS4 Thunderbolt Hub"},
    {"device_type": "usb_dock", "vendor": "Dell", "product": "WD22TB4 Thunderbolt Dock"},
    {"device_type": "usb_dock", "vendor": "Lenovo", "product": "ThinkPad USB-C Dock"},
]

# USB storage devices (rare in baseline)
_USB_STORAGE: List[Dict[str, Any]] = [
    {"device_type": "usb_storage", "vendor": "SanDisk", "product": "Ultra Flair 64GB", "volume_label": "SANDISK", "capacity_gb": 64},
    {"device_type": "usb_storage", "vendor": "Kingston", "product": "DataTraveler 32GB", "volume_label": "KINGSTON", "capacity_gb": 32},
    {"device_type": "usb_storage", "vendor": "Samsung", "product": "BAR Plus 128GB", "volume_label": "SAMSUNG", "capacity_gb": 128},
]

# ── Bluetooth devices ────────────────────────────────────────────────────────

_BLUETOOTH_DEVICES: List[Dict[str, str]] = [
    {"device_type": "bluetooth_headphones", "vendor": "Apple", "product": "AirPods Pro"},
    {"device_type": "bluetooth_headphones", "vendor": "Sony", "product": "WH-1000XM5"},
    {"device_type": "bluetooth_headphones", "vendor": "Bose", "product": "QuietComfort Ultra"},
    {"device_type": "bluetooth_headphones", "vendor": "Jabra", "product": "Elite 85t"},
    {"device_type": "bluetooth_keyboard", "vendor": "Apple", "product": "Magic Keyboard"},
    {"device_type": "bluetooth_keyboard", "vendor": "Logitech", "product": "K380"},
    {"device_type": "bluetooth_mouse", "vendor": "Apple", "product": "Magic Mouse"},
    {"device_type": "bluetooth_mouse", "vendor": "Logitech", "product": "Pebble Mouse 2"},
    {"device_type": "bluetooth_speaker", "vendor": "JBL", "product": "Clip 4"},
]

# ── Software updates (with OS field) ─────────────────────────────────────────
# os: "Windows", "macOS", or None (cross-platform)

_COMMON_SOFTWARE_UPDATES: List[Dict[str, Any]] = [
    {"software_name": "Windows Update", "software_version": "KB5034441", "os": "Windows"},
    {"software_name": "Windows Update", "software_version": "KB5035853", "os": "Windows"},
    {"software_name": "Google Chrome", "software_version": "122.0.6261.112", "os": None},
    {"software_name": "Google Chrome", "software_version": "123.0.6312.58", "os": None},
    {"software_name": "Microsoft Edge", "software_version": "122.0.2365.80", "os": None},
    {"software_name": "Mozilla Firefox", "software_version": "124.0.1", "os": None},
    {"software_name": "Microsoft Defender", "software_version": "1.407.521.0", "os": "Windows"},
    {"software_name": "Visual Studio Code", "software_version": "1.87.2", "os": None},
    {"software_name": "Adobe Acrobat Reader", "software_version": "24.001.20604", "os": None},
    {"software_name": "7-Zip", "software_version": "24.01", "os": "Windows"},
    {"software_name": "Notepad++", "software_version": "8.6.4", "os": "Windows"},
    {"software_name": "macOS Update", "software_version": "14.4.1", "os": "macOS"},
    {"software_name": "macOS Update", "software_version": "14.5", "os": "macOS"},
    {"software_name": "Xcode", "software_version": "15.3", "os": "macOS"},
    {"software_name": "Homebrew", "software_version": "4.2.18", "os": "macOS"},
]

# App-specific software updates (matched to authorised apps)
_APP_SOFTWARE_UPDATES: Dict[str, List[Dict[str, Any]]] = {
    "Slack": [
        {"software_name": "Slack", "software_version": "4.37.98", "os": None},
        {"software_name": "Slack", "software_version": "4.38.115", "os": None},
    ],
    "Microsoft Teams": [
        {"software_name": "Microsoft Teams", "software_version": "24033.811.2738.2546", "os": None},
    ],
    "Zoom": [
        {"software_name": "Zoom Workplace", "software_version": "6.0.0", "os": None},
        {"software_name": "Zoom Workplace", "software_version": "5.17.11", "os": None},
    ],
    "Notion": [
        {"software_name": "Notion", "software_version": "3.2.0", "os": None},
    ],
    "Figma": [
        {"software_name": "Figma", "software_version": "124.1.0", "os": None},
    ],
    "1Password": [
        {"software_name": "1Password", "software_version": "8.10.28", "os": None},
    ],
    "Dropbox": [
        {"software_name": "Dropbox", "software_version": "196.3.6108", "os": None},
    ],
    "Box": [
        {"software_name": "Box Drive", "software_version": "2.36.97", "os": None},
    ],
    "Tableau": [
        {"software_name": "Tableau Desktop", "software_version": "2024.1.1", "os": None},
    ],
    "Power BI": [
        {"software_name": "Power BI Desktop", "software_version": "2.127.1060.0", "os": "Windows"},
    ],
}

# ── Dock / hub types that trigger cascade ─────────────────────────────────────

_DOCKABLE_TYPES = {"usb_dock", "usb_hub"}

# ── Department device profiles (category weights) ────────────────────────────
# Keys: usb, software, bluetooth — must sum to ~1.0

_DEPT_DEVICE_PROFILES: Dict[str, Dict[str, float]] = {
    "Engineering":  {"usb": 0.30, "software": 0.45, "bluetooth": 0.25},
    "Sales":        {"usb": 0.15, "software": 0.30, "bluetooth": 0.55},
    "Executive":    {"usb": 0.15, "software": 0.25, "bluetooth": 0.60},
    "IT":           {"usb": 0.30, "software": 0.50, "bluetooth": 0.20},
    "Finance":      {"usb": 0.35, "software": 0.45, "bluetooth": 0.20},
    "_default":     {"usb": 0.40, "software": 0.40, "bluetooth": 0.20},
}

# ── Department USB storage rates ──────────────────────────────────────────────

_DEPT_USB_STORAGE_RATES: Dict[str, float] = {
    "IT": 0.12,
    "Engineering": 0.08,
    "Executive": 0.02,
    "_default": 0.05,
}

# ── Disconnect profiles by device type ────────────────────────────────────────
# rate: probability of generating a disconnect event
# duration_range: (min_seconds, max_seconds) for disconnect offset

_DISCONNECT_PROFILES: Dict[str, Dict[str, Any]] = {
    "usb_dock":             {"rate": 0.95, "duration_range": (28800, 36000)},  # 8-10h
    "usb_hub":              {"rate": 0.95, "duration_range": (28800, 36000)},
    "usb_mouse":            {"rate": 0.20, "duration_range": (300, 3600)},     # 5min-1h
    "usb_keyboard":         {"rate": 0.20, "duration_range": (300, 3600)},
    "usb_webcam":           {"rate": 0.60, "duration_range": (1800, 14400)},   # 30min-4h
    "usb_headset":          {"rate": 0.60, "duration_range": (1800, 14400)},
    "usb_phone":            {"rate": 0.90, "duration_range": (1800, 7200)},    # 30min-2h
    "usb_storage":          {"rate": 0.95, "duration_range": (300, 3600)},     # 5min-1h
    "bluetooth_headphones": {"rate": 0.85, "duration_range": (1800, 14400)},   # 30min-4h
    "bluetooth_keyboard":   {"rate": 0.20, "duration_range": (300, 3600)},
    "bluetooth_mouse":      {"rate": 0.20, "duration_range": (300, 3600)},
    "bluetooth_speaker":    {"rate": 0.70, "duration_range": (1800, 14400)},
}

# ── Personal inventory slot definitions ───────────────────────────────────────
# (category, min_count, max_count, source_catalog_key)

_INVENTORY_SLOTS: List[Tuple[str, int, int, str]] = [
    ("mouse",    1, 1, "usb_mouse"),
    ("keyboard", 1, 1, "usb_keyboard"),
    ("headset",  0, 1, "usb_headset"),
    ("dock",     0, 1, "usb_dock"),
    ("bt_headphones", 0, 1, "bluetooth_headphones"),
]

# Pre-index catalogs by device_type for inventory building
_CATALOG_BY_TYPE: Dict[str, List[Dict[str, str]]] = {}
for _dev in _USB_PERIPHERALS + _BLUETOOTH_DEVICES:
    _CATALOG_BY_TYPE.setdefault(_dev["device_type"], []).append(_dev)


def _format_ts(dt: datetime) -> str:
    """Format datetime to ISO string."""
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


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


def _gen_serial(rng: random.Random) -> str:
    """Generate a random device serial number."""
    return "".join(rng.choices("0123456789ABCDEF", k=12))


# ── New helper functions ──────────────────────────────────────────────────────

def _deterministic_serial(person_id: str, product: str) -> str:
    """Generate a stable serial number for a person+product combination."""
    key = f"{person_id}:{product}"
    return hashlib.sha256(key.encode()).hexdigest()[:12].upper()


def _get_person_os(company: Company, person: Person) -> str:
    """Resolve the primary OS for a person from the company device registry."""
    person_id = person.get("id")
    if not person_id:
        return "Windows"
    comp_devices = company.get("devices") or []
    for d in comp_devices:
        if isinstance(d, dict) and d.get("owner_user_id") == person_id:
            os_val = d.get("os")
            if os_val:
                return os_val
    return "Windows"


def _build_personal_inventory(
    person: Person,
    rng: random.Random,
) -> List[Dict[str, str]]:
    """Assign a small personal device inventory (2-5 items) with stable serials."""
    person_id = person.get("id", "unknown")
    inventory: List[Dict[str, str]] = []
    for _category, min_count, max_count, type_key in _INVENTORY_SLOTS:
        catalog = _CATALOG_BY_TYPE.get(type_key, [])
        if not catalog:
            continue
        count = rng.randint(min_count, max_count)
        if count <= 0:
            continue
        chosen = rng.choice(catalog)
        item = dict(chosen)
        item["serial"] = _deterministic_serial(person_id, chosen["product"])
        inventory.append(item)
    return inventory


def _filter_software_by_os(
    person_os: str,
    software_list: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Filter software list to entries compatible with the person's OS."""
    result = []
    for sw in software_list:
        sw_os = sw.get("os")
        if sw_os is None or sw_os == person_os:
            result.append(sw)
    return result


def _preroll_update_waves(
    rng: random.Random,
    window_start: datetime,
    window_end: datetime,
    software_list: List[Dict[str, Any]],
) -> Dict[str, datetime]:
    """Pre-roll a rollout date for each distinct software update.

    Returns a mapping from "software_name:software_version" -> wave_date.
    """
    span_days = max(1, (window_end - window_start).days)
    waves: Dict[str, datetime] = {}
    for sw in software_list:
        key = f"{sw['software_name']}:{sw['software_version']}"
        if key not in waves:
            offset = rng.randint(0, span_days - 1)
            waves[key] = window_start + timedelta(days=offset)
    return waves


def _sample_near_wave(
    rng: random.Random,
    wave_date: datetime,
    window_start: datetime,
    window_end: datetime,
    circadian: Optional[CircadianSampler],
    weekly: Optional[WeeklyCycleModulator],
) -> datetime:
    """Sample a timestamp biased to within ±2 days of the wave date."""
    drift_days = rng.gauss(0, 0.8)
    drift_days = max(-2.0, min(2.0, drift_days))
    target_day = wave_date + timedelta(days=drift_days)
    target_day = max(window_start, min(target_day, window_end - timedelta(hours=1)))
    if circadian:
        utc_hour = circadian.sample_utc_hour(rng)
    else:
        utc_hour = rng.choice([9.0, 10.0, 11.0, 14.0, 15.0, 16.0])
    hour_int = int(utc_hour) % 24
    frac = utc_hour - int(utc_hour)
    minute = int(frac * 60)
    return target_day.replace(
        hour=hour_int,
        minute=minute,
        second=rng.randint(0, 59),
        microsecond=0,
        tzinfo=timezone.utc,
    )


def _generate_dock_cascade(
    dock_ts: datetime,
    inventory: List[Dict[str, str]],
    rng: random.Random,
    device_id: Optional[str],
) -> List[Dict[str, Any]]:
    """Generate 2-4 sub-device connection events within seconds of a dock connect."""
    cascade_types = {"usb_mouse", "usb_keyboard", "usb_webcam", "usb_headset"}
    cascade_devices = [d for d in inventory if d.get("device_type") in cascade_types]
    if not cascade_devices:
        return []
    count = min(len(cascade_devices), rng.randint(2, 4))
    selected = rng.sample(cascade_devices, count)
    events: List[Dict[str, Any]] = []
    for dev in selected:
        offset_sec = rng.randint(1, 30)
        ts_dt = dock_ts + timedelta(seconds=offset_sec)
        evt: Dict[str, Any] = {
            "ts": _format_ts(ts_dt),
            "action": "usb_connected",
            "device_type": dev["device_type"],
            "vendor": dev["vendor"],
            "product": dev["product"],
            "serial": dev.get("serial", ""),
        }
        if device_id:
            evt["device_id"] = device_id
        events.append(evt)
    return events


def _generate_morning_evening_pairs(
    inventory: List[Dict[str, str]],
    rng: random.Random,
    window_start: datetime,
    window_end: datetime,
    weekly: Optional[WeeklyCycleModulator],
    circadian: Optional[CircadianSampler],
    device_id: Optional[str],
) -> List[Dict[str, Any]]:
    """Generate daily dock connect/disconnect pairs with cascade sub-devices.

    For each workday in the window, with ~90% attendance:
    - Morning connect ~08:00-09:30
    - Cascade sub-device connects 1-30s after dock
    - Evening disconnect ~17:00-18:30
    """
    docks = [d for d in inventory if d.get("device_type") in _DOCKABLE_TYPES]
    if not docks:
        return []
    dock = docks[0]
    events: List[Dict[str, Any]] = []
    span_days = max(1, (window_end - window_start).days)
    for day_offset in range(span_days):
        day = window_start + timedelta(days=day_offset)
        dow = day.weekday()
        # Skip weekends via weekly modulator
        if weekly:
            w = weekly.weight_for_day(dow)
            if rng.random() > w:
                continue
        elif dow >= 5:
            continue
        # ~90% attendance
        if rng.random() > 0.90:
            continue
        # Morning connect
        arrive_hour = rng.uniform(8.0, 9.5)
        if circadian:
            arrive_hour = arrive_hour + rng.gauss(0, 0.3)
            arrive_hour = max(7.0, min(arrive_hour, 10.5))
        arrive_min = int((arrive_hour % 1) * 60)
        morning_ts = day.replace(
            hour=int(arrive_hour),
            minute=arrive_min,
            second=rng.randint(0, 59),
            microsecond=0,
            tzinfo=timezone.utc,
        )
        connect_evt: Dict[str, Any] = {
            "ts": _format_ts(morning_ts),
            "action": "usb_connected",
            "device_type": dock["device_type"],
            "vendor": dock["vendor"],
            "product": dock["product"],
            "serial": dock.get("serial", ""),
        }
        if device_id:
            connect_evt["device_id"] = device_id
        events.append(connect_evt)
        # Cascade sub-devices
        events.extend(_generate_dock_cascade(morning_ts, inventory, rng, device_id))
        # Evening disconnect
        leave_hour = rng.uniform(17.0, 18.5)
        leave_min = int((leave_hour % 1) * 60)
        evening_ts = day.replace(
            hour=int(leave_hour),
            minute=leave_min,
            second=rng.randint(0, 59),
            microsecond=0,
            tzinfo=timezone.utc,
        )
        disconnect_evt: Dict[str, Any] = {
            "ts": _format_ts(evening_ts),
            "action": "usb_disconnected",
            "device_type": dock["device_type"],
            "vendor": dock["vendor"],
            "product": dock["product"],
            "serial": dock.get("serial", ""),
        }
        if device_id:
            disconnect_evt["device_id"] = device_id
        events.append(disconnect_evt)
    return events


def _generate_bt_meeting_events(
    person: Person,
    inventory: List[Dict[str, str]],
    rng: random.Random,
    device_id: Optional[str],
) -> List[Dict[str, Any]]:
    """Generate Bluetooth headphone events correlated to Zoom/Teams meetings.

    Reads app_events for meeting actions. For ~70% of meetings, generates a
    BT headphone connect before and disconnect after the meeting.
    """
    bt_headphones = [
        d for d in inventory
        if d.get("device_type") == "bluetooth_headphones"
    ]
    if not bt_headphones:
        return []
    headphone = bt_headphones[0]
    ra = person.get("recent_activity") or {}
    app_events = ra.get("app_events") or []
    meeting_actions = {"join_meeting", "host_meeting", "schedule_meeting"}
    meeting_apps = {"Zoom", "Microsoft Teams"}
    meetings = [
        e for e in app_events
        if isinstance(e, dict)
        and e.get("app") in meeting_apps
        and e.get("action") in meeting_actions
        and e.get("ts")
    ]
    if not meetings:
        return []
    events: List[Dict[str, Any]] = []
    for mtg in meetings:
        if rng.random() > 0.70:
            continue
        try:
            mtg_ts = datetime.fromisoformat(mtg["ts"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        # Connect 0-5 min before meeting
        pre_offset = rng.randint(0, 300)
        connect_ts = mtg_ts - timedelta(seconds=pre_offset)
        connect_evt: Dict[str, Any] = {
            "ts": _format_ts(connect_ts),
            "action": "bluetooth_connect",
            "device_type": headphone["device_type"],
            "vendor": headphone["vendor"],
            "product": headphone["product"],
        }
        if device_id:
            connect_evt["device_id"] = device_id
        events.append(connect_evt)
        # Disconnect 5-30 min after meeting
        post_offset = rng.randint(300, 1800)
        disconnect_ts = mtg_ts + timedelta(seconds=post_offset)
        disconnect_evt: Dict[str, Any] = {
            "ts": _format_ts(disconnect_ts),
            "action": "bluetooth_disconnect",
            "device_type": headphone["device_type"],
            "vendor": headphone["vendor"],
            "product": headphone["product"],
        }
        if device_id:
            disconnect_evt["device_id"] = device_id
        events.append(disconnect_evt)
    return events


def _maybe_disconnect(
    connect_event: Dict[str, Any],
    ts_dt: datetime,
    rng: random.Random,
    device_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Generate a type-specific disconnect event based on _DISCONNECT_PROFILES.

    Returns the disconnect event dict, or None if no disconnect should occur.
    """
    device_type = connect_event.get("device_type", "")
    profile = _DISCONNECT_PROFILES.get(device_type)
    if not profile:
        # Fallback: 40% chance, 1min-4h
        if rng.random() < 0.40:
            offset = rng.randint(60, 14400)
        else:
            return None
    else:
        if rng.random() >= profile["rate"]:
            return None
        lo, hi = profile["duration_range"]
        offset = rng.randint(lo, hi)
    disc_ts = ts_dt + timedelta(seconds=offset)
    action = connect_event["action"]
    if "usb" in action:
        disc_action = "usb_disconnected"
    elif "bluetooth" in action:
        disc_action = "bluetooth_disconnect"
    else:
        return None
    disc_event: Dict[str, Any] = {
        "ts": _format_ts(disc_ts),
        "action": disc_action,
        "device_type": device_type,
        "vendor": connect_event.get("vendor", ""),
        "product": connect_event.get("product", ""),
    }
    serial = connect_event.get("serial")
    if serial:
        disc_event["serial"] = serial
    if device_id:
        disc_event["device_id"] = device_id
    return disc_event


# ── Main generation function ──────────────────────────────────────────────────

def generate_device_event_logs(
    company: Company,
    *,
    seed: int = 1337,
    replace_existing: bool = True,
    events_multiplier: float = 1.0,
    baseline_std_scale: float = 1.0,
    generation_config: Optional[Dict[str, Any]] = None,
    burst_schedule: Optional[BurstSchedule] = None,
) -> Dict[str, int]:
    """
    Populate each person's recent_activity.device_events with realistic device events.

    Generates a mix of:
    - Structured morning/evening dock patterns with cascade sub-devices
    - Bluetooth headphone events correlated to meetings
    - Software update waves (OS-aware, clustered in time)
    - Random USB/BT/Software events with department-aware weights

    Args:
        company: Company data dict
        seed: Base seed for deterministic generation
        replace_existing: If True, replace existing device events; if False, append
        events_multiplier: Multiplier for baseline device event rate (1.0 = normal)
        generation_config: Optional temporal/circadian config dict
        burst_schedule: Optional burst schedule for activity scaling

    Returns:
        Statistics dict with counts of generated events
    """
    people, container_kind = _select_people_container(company)

    stats: Dict[str, Any] = {
        "employees_total": len(people),
        "employees_with_events": 0,
        "events_requested": 0,
        "events_added": 0,
        "usb_events": 0,
        "software_events": 0,
        "bluetooth_events": 0,
        "event_types": defaultdict(int),
    }

    gen_cfg = generation_config or company.get("_generation_config") or {}

    if not people or events_multiplier == 0:
        stats["event_types"] = dict(stats["event_types"])
        return stats

    # Pre-compute window for temporal model
    window_start = window_end = None
    if gen_cfg:
        window_start, window_end = get_window(gen_cfg)

    base_seed = seed or 0

    # ── Phase 0: Pre-roll software update waves ──────────────────────────
    wave_rng = random.Random(base_seed * 7919)
    update_waves: Dict[str, datetime] = {}
    if window_start and window_end:
        # Build a global software list for wave pre-rolling
        all_sw = list(_COMMON_SOFTWARE_UPDATES)
        for app_updates in _APP_SOFTWARE_UPDATES.values():
            all_sw.extend(app_updates)
        update_waves = _preroll_update_waves(wave_rng, window_start, window_end, all_sw)

    for idx_person, person in enumerate(people):
        person_id = person.get("id")
        if not person_id:
            continue

        ra = person.setdefault("recent_activity", {})
        if replace_existing:
            ra.pop("device_events", None)

        rng = random.Random(base_seed * 1019 + idx_person)

        # Use baseline-driven event count if available, scaled by multiplier
        if gen_cfg:
            target_events = resolve_event_count(
                person, "device", _DEFAULT_DEVICE_EVENTS, rng,
                scale_factor=events_multiplier,
                baseline_std_scale=baseline_std_scale,
            )
        else:
            target_events = max(0, round(vary_count(_DEFAULT_DEVICE_EVENTS, rng) * events_multiplier))

        if not replace_existing:
            existing = ra.get("device_events")
            existing_count = len(existing) if isinstance(existing, list) else 0
            target_events = max(target_events - existing_count, 0)

        if target_events <= 0:
            continue

        # Apply burst scaling
        if burst_schedule and burst_schedule.bursts and window_start and window_end:
            target_events = apply_burst_to_count(
                target_events, person_id, "device_events",
                burst_schedule, rng, window_start, window_end,
            )

        if target_events <= 0:
            continue

        # ── Phase 1: Per-person setup ────────────────────────────────────

        # Build personal device inventory
        inventory = _build_personal_inventory(person, rng)

        # Resolve OS from company device registry
        person_os = _get_person_os(company, person)

        # Build temporal samplers
        circadian = weekly = None
        if gen_cfg:
            circadian, weekly = resolve_person_temporal(person, gen_cfg)

        # Resolve department
        department = person.get("department", "")

        # Read device baseline category weights (baseline > department > default)
        baselines = person.get("behavior_baselines") or {}
        device_bl = baselines.get("device_baseline") or {}
        cat_weights = device_bl.get("category_weights") or {}
        if cat_weights:
            usb_weight = float(cat_weights.get("usb", 0.40))
            sw_weight = float(cat_weights.get("software", 0.40))
            bt_weight = float(cat_weights.get("bluetooth", 0.20))
        else:
            dept_profile = _DEPT_DEVICE_PROFILES.get(
                department, _DEPT_DEVICE_PROFILES["_default"]
            )
            usb_weight = dept_profile["usb"]
            sw_weight = dept_profile["software"]
            bt_weight = dept_profile["bluetooth"]
        total_w = usb_weight + sw_weight + bt_weight
        usb_thresh = usb_weight / total_w if total_w > 0 else 0.40
        sw_thresh = usb_thresh + sw_weight / total_w if total_w > 0 else 0.80

        # USB storage rate: baseline > department > default
        if device_bl.get("usb_storage_rate") is not None:
            person_usb_storage_rate = float(device_bl["usb_storage_rate"])
        else:
            person_usb_storage_rate = _DEPT_USB_STORAGE_RATES.get(
                department, _DEPT_USB_STORAGE_RATES["_default"]
            )

        # Collect person apps and filter software by OS
        person_apps = _collect_person_apps(person)
        person_sw_updates: List[Dict[str, Any]] = list(_COMMON_SOFTWARE_UPDATES)
        for app_name in person_apps:
            if app_name in _APP_SOFTWARE_UPDATES:
                person_sw_updates.extend(_APP_SOFTWARE_UPDATES[app_name])
        person_sw_updates = _filter_software_by_os(person_os, person_sw_updates)
        if not person_sw_updates:
            # Fallback: use cross-platform only
            person_sw_updates = [
                sw for sw in _COMMON_SOFTWARE_UPDATES if sw.get("os") is None
            ]

        device_ids = _collect_person_device_ids(company, person)
        device_id = rng.choice(device_ids) if device_ids else None

        stats["events_requested"] += target_events

        # ── Phase 2: Structured events ───────────────────────────────────
        structured_events: List[Dict[str, Any]] = []

        # Morning/evening dock pairs + cascade
        if window_start and window_end:
            dock_events = _generate_morning_evening_pairs(
                inventory, rng, window_start, window_end,
                weekly, circadian, device_id,
            )
            structured_events.extend(dock_events)

        # Bluetooth meeting-correlated events
        bt_meeting_events = _generate_bt_meeting_events(
            person, inventory, rng, device_id,
        )
        structured_events.extend(bt_meeting_events)

        # Cap structured events at ~60% of target to leave room for random variety
        max_structured = int(target_events * 0.60)
        if len(structured_events) > max_structured:
            rng.shuffle(structured_events)
            structured_events = structured_events[:max_structured]

        # Emit structured events
        for evt in structured_events:
            add_device_event_logs(
                company,
                **_event_target_kwargs(container_kind, person_id),
                log=evt,
            )
            action = evt.get("action", "")
            stats["events_added"] += 1
            stats["event_types"][action] += 1
            if "usb" in action:
                stats["usb_events"] += 1
            elif "bluetooth" in action:
                stats["bluetooth_events"] += 1
            elif "software" in action:
                stats["software_events"] += 1

        events_generated = len(structured_events)

        # ── Phase 3: Remaining random events ─────────────────────────────
        remaining = max(0, target_events - events_generated)

        for _ in range(remaining):
            roll = rng.random()

            # Temporal model: smooth circadian sampling
            if circadian and weekly and window_start and window_end:
                ts_dt = sample_timestamp(circadian, weekly, rng, window_start, window_end)
                ts = format_ts(ts_dt)
            else:
                days_back = rng.randint(0, 29)
                hour = rng.choice([7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18])
                ts_dt = datetime.now(timezone.utc) - timedelta(days=days_back)
                ts_dt = ts_dt.replace(
                    hour=hour,
                    minute=rng.randint(0, 59),
                    second=rng.randint(0, 59),
                    microsecond=0,
                )
                ts = _format_ts(ts_dt)

            if roll < usb_thresh:
                # ── USB event ────────────────────────────────────────
                if rng.random() < person_usb_storage_rate:
                    usb_dev = rng.choice(_USB_STORAGE)
                    event: Dict[str, Any] = {
                        "ts": ts,
                        "action": "usb_connected",
                        "device_type": usb_dev["device_type"],
                        "vendor": usb_dev["vendor"],
                        "product": usb_dev["product"],
                        "serial": _gen_serial(rng),
                        "volume_label": usb_dev.get("volume_label", ""),
                        "capacity_gb": usb_dev.get("capacity_gb", 0),
                    }
                else:
                    # Draw from personal inventory (USB devices) if available
                    usb_inventory = [
                        d for d in inventory
                        if d.get("device_type", "").startswith("usb_")
                    ]
                    if usb_inventory:
                        usb_dev_inv = rng.choice(usb_inventory)
                        event = {
                            "ts": ts,
                            "action": "usb_connected",
                            "device_type": usb_dev_inv["device_type"],
                            "vendor": usb_dev_inv["vendor"],
                            "product": usb_dev_inv["product"],
                            "serial": usb_dev_inv.get("serial", _gen_serial(rng)),
                        }
                    else:
                        usb_dev_rand = rng.choice(_USB_PERIPHERALS)
                        event = {
                            "ts": ts,
                            "action": "usb_connected",
                            "device_type": usb_dev_rand["device_type"],
                            "vendor": usb_dev_rand["vendor"],
                            "product": usb_dev_rand["product"],
                            "serial": _gen_serial(rng),
                        }
                if device_id:
                    event["device_id"] = device_id

                add_device_event_logs(
                    company,
                    **_event_target_kwargs(container_kind, person_id),
                    log=event,
                )
                stats["events_added"] += 1
                stats["usb_events"] += 1
                stats["event_types"]["usb_connected"] += 1
                events_generated += 1

                # Type-specific disconnect
                disc_evt = _maybe_disconnect(event, ts_dt, rng, device_id)
                if disc_evt:
                    add_device_event_logs(
                        company,
                        **_event_target_kwargs(container_kind, person_id),
                        log=disc_evt,
                    )
                    stats["events_added"] += 1
                    stats["usb_events"] += 1
                    stats["event_types"]["usb_disconnected"] += 1

            elif roll < sw_thresh:
                # ── Software install event (wave-biased) ─────────────
                sw = rng.choice(person_sw_updates)
                wave_key = f"{sw['software_name']}:{sw['software_version']}"
                wave_date = update_waves.get(wave_key)
                if wave_date and window_start and window_end:
                    sw_ts_dt = _sample_near_wave(
                        rng, wave_date, window_start, window_end,
                        circadian, weekly,
                    )
                    sw_ts = format_ts(sw_ts_dt)
                else:
                    sw_ts = ts

                event = {
                    "ts": sw_ts,
                    "action": "software_install",
                    "software_name": sw["software_name"],
                    "software_version": sw["software_version"],
                }
                if device_id:
                    event["device_id"] = device_id

                add_device_event_logs(
                    company,
                    **_event_target_kwargs(container_kind, person_id),
                    log=event,
                )
                stats["events_added"] += 1
                stats["software_events"] += 1
                stats["event_types"]["software_install"] += 1
                events_generated += 1

            else:
                # ── Bluetooth event ──────────────────────────────────
                # Draw from personal inventory (BT devices) if available
                bt_inventory = [
                    d for d in inventory
                    if d.get("device_type", "").startswith("bluetooth_")
                ]
                if bt_inventory:
                    bt_dev = rng.choice(bt_inventory)
                else:
                    bt_dev = rng.choice(_BLUETOOTH_DEVICES)
                event = {
                    "ts": ts,
                    "action": "bluetooth_connect",
                    "device_type": bt_dev["device_type"],
                    "vendor": bt_dev["vendor"],
                    "product": bt_dev["product"],
                }
                if device_id:
                    event["device_id"] = device_id

                add_device_event_logs(
                    company,
                    **_event_target_kwargs(container_kind, person_id),
                    log=event,
                )
                stats["events_added"] += 1
                stats["bluetooth_events"] += 1
                stats["event_types"]["bluetooth_connect"] += 1
                events_generated += 1

                # Type-specific disconnect
                disc_evt = _maybe_disconnect(event, ts_dt, rng, device_id)
                if disc_evt:
                    add_device_event_logs(
                        company,
                        **_event_target_kwargs(container_kind, person_id),
                        log=disc_evt,
                    )
                    stats["events_added"] += 1
                    stats["bluetooth_events"] += 1
                    stats["event_types"]["bluetooth_disconnect"] += 1

        if events_generated:
            stats["employees_with_events"] += 1

    stats["event_types"] = dict(stats["event_types"])
    return stats
