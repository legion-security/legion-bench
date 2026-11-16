"""
Network event log generation for company fixtures.

Generates baseline network/firewall logs stored at the subnet level, including:
- Internal traffic: file shares (445), DNS (53), LDAP (389), internal HTTP (80/443), printing (9100)
- Outbound traffic: HTTPS (443), HTTP (80), SaaS APIs, cloud services
- Rare noise: NTP (123), SMTP (25/587), ICMP pings

Events are stored under company["network"]["subnets"][i]["events"] rather than
per-employee, since firewalls log traffic at the network/subnet level.
The employee can be identified by joining source_ip -> devices.ip_address -> devices.owner_user_id.
"""
from __future__ import annotations

import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .user_activity import (
    add_network_event_logs,
    _collect_person_device_ids,
    vary_count,
)
from .temporal_model import (
    format_ts,
    get_window,
    resolve_event_count,
    resolve_person_temporal,
    sample_timestamp,
)
from .episodic_bursts import BurstSchedule, apply_burst_to_count

Person = Dict[str, Any]
Company = Dict[str, Any]

_DEFAULT_NETWORK_EVENTS = 5

# ── Internal traffic templates ──────────────────────────────────────────────

_INTERNAL_TRAFFIC: List[Dict[str, Any]] = [
    {"destination_port": 445, "protocol": "TCP", "description": "SMB file share access"},
    {"destination_port": 445, "protocol": "TCP", "description": "SMB file share browsing"},
    {"destination_port": 53, "protocol": "UDP", "description": "DNS query to internal resolver"},
    {"destination_port": 53, "protocol": "UDP", "description": "DNS lookup"},
    {"destination_port": 389, "protocol": "TCP", "description": "LDAP directory query"},
    {"destination_port": 636, "protocol": "TCP", "description": "LDAPS directory query"},
    {"destination_port": 88, "protocol": "TCP", "description": "Kerberos authentication"},
    {"destination_port": 80, "protocol": "TCP", "description": "Internal HTTP service"},
    {"destination_port": 443, "protocol": "TCP", "description": "Internal HTTPS service"},
    {"destination_port": 9100, "protocol": "TCP", "description": "Network printer job"},
    {"destination_port": 3389, "protocol": "TCP", "description": "RDP session to internal host"},
    {"destination_port": 5985, "protocol": "TCP", "description": "WinRM remote management"},
    {"destination_port": 135, "protocol": "TCP", "description": "RPC endpoint mapper"},
]

# ── Outbound traffic templates ──────────────────────────────────────────────

_OUTBOUND_TRAFFIC: List[Dict[str, Any]] = [
    {"destination_port": 443, "protocol": "TCP", "description": "HTTPS web browsing"},
    {"destination_port": 443, "protocol": "TCP", "description": "HTTPS API call"},
    {"destination_port": 443, "protocol": "TCP", "description": "SaaS application traffic"},
    {"destination_port": 443, "protocol": "TCP", "description": "Cloud service connection"},
    {"destination_port": 80, "protocol": "TCP", "description": "HTTP web browsing"},
    {"destination_port": 443, "protocol": "TCP", "description": "Software update check"},
    {"destination_port": 443, "protocol": "TCP", "description": "Email sync (Exchange Online)"},
    {"destination_port": 443, "protocol": "TCP", "description": "Teams/Slack communication"},
]

# ── Rare noise traffic ──────────────────────────────────────────────────────

_RARE_TRAFFIC: List[Dict[str, Any]] = [
    {"destination_port": 123, "protocol": "UDP", "description": "NTP time sync"},
    {"destination_port": 25, "protocol": "TCP", "description": "SMTP mail relay"},
    {"destination_port": 587, "protocol": "TCP", "description": "SMTP submission"},
    {"destination_port": 0, "protocol": "ICMP", "description": "ICMP ping"},
    {"destination_port": 514, "protocol": "UDP", "description": "Syslog forwarding"},
    {"destination_port": 161, "protocol": "UDP", "description": "SNMP query"},
]

# ── Auth type weights ───────────────────────────────────────────────────────

_AUTH_TYPES = ["kerberos", "ntlm", "certificate", "none"]
_AUTH_WEIGHTS = [60, 20, 10, 10]

# ── Internal server IPs (common targets) ────────────────────────────────────

_INTERNAL_SERVER_IPS = [
    "10.0.1.10",   # Domain controller
    "10.0.1.11",   # DNS server
    "10.0.1.20",   # File server
    "10.0.1.21",   # Print server
    "10.0.1.30",   # LDAP server
    "10.0.2.10",   # Web server
    "10.0.2.11",   # App server
    "10.0.2.20",   # Database server
]


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



def _random_external_ip(rng: random.Random) -> str:
    """Generate a random public IP address."""
    while True:
        a = rng.randint(1, 223)
        b, c, d = rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254)
        if a in (10, 127, 169, 172, 192):
            continue
        if a == 100 and 64 <= b <= 127:
            continue
        if a == 198 and b in (18, 19):
            continue
        return f"{a}.{b}.{c}.{d}"


def _get_device_ip(company: Company, person: Person) -> str | None:
    """Get the IP address of the person's primary device."""
    device_ids = _collect_person_device_ids(company, person)
    if not device_ids:
        return None
    devices = company.get("devices") or []
    for d in devices:
        if not isinstance(d, dict):
            continue
        if d.get("id") in device_ids and d.get("ip_address"):
            return d["ip_address"]
    return None


def _get_device_network_id(company: Company, person: Person) -> str | None:
    """Get the network_id of the person's primary device."""
    device_ids = _collect_person_device_ids(company, person)
    if not device_ids:
        return None
    devices = company.get("devices") or []
    for d in devices:
        if not isinstance(d, dict):
            continue
        if d.get("id") in device_ids and d.get("network_id"):
            return d["network_id"]
    return None


def generate_network_event_logs(
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
    Populate subnet-level network event logs with baseline network traffic.

    Network events are stored under company["network"]["subnets"][i]["events"]
    rather than per-employee, since firewalls log traffic at the network/subnet level.
    The employee can be identified by joining source_ip -> devices.ip_address -> devices.owner_user_id.

    Generates a mix of:
    - Internal traffic (~45%): SMB, DNS, LDAP, Kerberos, RDP, printing
    - Outbound traffic (~45%): HTTPS, HTTP, SaaS, cloud services
    - Rare noise (~10%): NTP, SMTP, ICMP
    - ~2% blocked traffic (random port scans, policy violations)

    Args:
        company: Company data dict
        seed: Base seed for deterministic generation
        replace_existing: If True, replace existing network events; if False, append
        events_multiplier: Multiplier for baseline network event rate (1.0 = normal)

    Returns:
        Statistics dict with counts of generated events
    """
    people, container_kind = _select_people_container(company)

    stats: Dict[str, Any] = {
        "employees_total": len(people),
        "employees_with_events": 0,
        "events_requested": 0,
        "events_added": 0,
        "internal_events": 0,
        "outbound_events": 0,
        "rare_events": 0,
        "blocked_events": 0,
        "event_types": defaultdict(int),
    }

    gen_cfg = generation_config or company.get("_generation_config") or {}

    if not people or events_multiplier == 0:
        stats["event_types"] = dict(stats["event_types"])
        return stats

    # Clear subnet events if replacing
    if replace_existing:
        for subnet in (company.get("network") or {}).get("subnets", []):
            subnet["events"] = []

    # Pre-compute window for temporal model
    window_start = window_end = None
    if gen_cfg:
        window_start, window_end = get_window(gen_cfg)

    base_seed = seed or 0

    for idx_person, person in enumerate(people):
        person_id = person.get("id")
        if not person_id:
            continue

        network_id = _get_device_network_id(company, person)
        if not network_id:
            continue

        rng = random.Random(base_seed * 1021 + idx_person)

        # Use baseline-driven event count if available, scaled by multiplier
        if gen_cfg:
            target_events = resolve_event_count(
                person, "network", _DEFAULT_NETWORK_EVENTS, rng,
                scale_factor=events_multiplier,
                baseline_std_scale=baseline_std_scale,
            )
        else:
            target_events = max(0, round(vary_count(_DEFAULT_NETWORK_EVENTS, rng) * events_multiplier))

        # Apply burst scaling
        if burst_schedule and burst_schedule.bursts and window_start and window_end:
            target_events = apply_burst_to_count(
                target_events, person_id, "network_events",
                burst_schedule, rng, window_start, window_end,
            )

        if target_events <= 0:
            continue

        # Build temporal samplers for this person
        circadian = weekly = None
        if gen_cfg:
            circadian, weekly = resolve_person_temporal(person, gen_cfg)

        # Read traffic weights from baseline
        baselines = person.get("behavior_baselines") or {}
        net_bl = baselines.get("network_baseline") or {}
        traffic_w = net_bl.get("traffic_weights") or {}
        int_w = float(traffic_w.get("internal", 0.45))
        out_w = float(traffic_w.get("outbound", 0.45))
        rare_w = float(traffic_w.get("rare", 0.10))
        total_w = int_w + out_w + rare_w
        int_thresh = int_w / total_w if total_w > 0 else 0.45
        out_thresh = int_thresh + out_w / total_w if total_w > 0 else 0.90

        stats["events_requested"] += target_events

        source_ip = _get_device_ip(company, person) or f"10.1.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        username = person.get("email", "").split("@")[0] if person.get("email") else person_id

        events_generated = 0

        for _ in range(target_events):
            roll = rng.random()

            # Temporal model: smooth circadian sampling
            if circadian and weekly and window_start and window_end:
                ts_dt = sample_timestamp(circadian, weekly, rng, window_start, window_end)
                ts = format_ts(ts_dt)
            else:
                days_back = rng.randint(0, 29)
                hour = rng.choice([7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
                ts_dt = datetime.now(timezone.utc) - timedelta(days=days_back)
                ts_dt = ts_dt.replace(
                    hour=hour,
                    minute=rng.randint(0, 59),
                    second=rng.randint(0, 59),
                    microsecond=0,
                )
                ts = _format_ts(ts_dt)

            # Decide if blocked (~2%)
            is_blocked = rng.random() < 0.02
            action = "blocked" if is_blocked else "allowed"

            # Select auth type
            auth = rng.choices(_AUTH_TYPES, weights=_AUTH_WEIGHTS, k=1)[0]

            if roll < int_thresh:
                # ── Internal traffic ────────────────────────────────────
                template = rng.choice(_INTERNAL_TRAFFIC)
                destination_ip = rng.choice(_INTERNAL_SERVER_IPS)
                direction = "internal"

                event: Dict[str, Any] = {
                    "ts": ts,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "destination_port": template["destination_port"],
                    "protocol": template["protocol"],
                    "action": action,
                    "direction": direction,
                    "user": username,
                    "auth": auth,
                    "bytes_sent": rng.randint(64, 8192),
                    "bytes_received": rng.randint(64, 32768),
                    "description": template["description"],
                }

                add_network_event_logs(
                    company,
                    network_id=network_id,
                    log=event,
                )
                stats["events_added"] += 1
                stats["internal_events"] += 1
                stats["event_types"][f"internal_{template['destination_port']}"] += 1
                if is_blocked:
                    stats["blocked_events"] += 1
                events_generated += 1

            elif roll < out_thresh:
                # ── Outbound traffic ────────────────────────────────────
                template = rng.choice(_OUTBOUND_TRAFFIC)
                destination_ip = _random_external_ip(rng)
                direction = "outbound"

                event = {
                    "ts": ts,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "destination_port": template["destination_port"],
                    "protocol": template["protocol"],
                    "action": action,
                    "direction": direction,
                    "user": username,
                    "auth": "none",  # outbound typically no internal auth
                    "bytes_sent": rng.randint(256, 16384),
                    "bytes_received": rng.randint(1024, 65536),
                    "description": template["description"],
                }

                add_network_event_logs(
                    company,
                    network_id=network_id,
                    log=event,
                )
                stats["events_added"] += 1
                stats["outbound_events"] += 1
                stats["event_types"][f"outbound_{template['destination_port']}"] += 1
                if is_blocked:
                    stats["blocked_events"] += 1
                events_generated += 1

            else:
                # ── Rare noise traffic ──────────────────────────────────
                template = rng.choice(_RARE_TRAFFIC)

                if template["protocol"] == "ICMP":
                    dest_ip = rng.choice(_INTERNAL_SERVER_IPS)
                    direction = "internal"
                elif template["destination_port"] in (123, 514, 161):
                    dest_ip = rng.choice(_INTERNAL_SERVER_IPS)
                    direction = "internal"
                else:
                    dest_ip = _random_external_ip(rng)
                    direction = "outbound"

                event = {
                    "ts": ts,
                    "source_ip": source_ip,
                    "destination_ip": dest_ip,
                    "destination_port": template["destination_port"],
                    "protocol": template["protocol"],
                    "action": action,
                    "direction": direction,
                    "user": username,
                    "auth": "none",
                    "bytes_sent": rng.randint(32, 1024),
                    "bytes_received": rng.randint(32, 1024),
                    "description": template["description"],
                }

                add_network_event_logs(
                    company,
                    network_id=network_id,
                    log=event,
                )
                stats["events_added"] += 1
                stats["rare_events"] += 1
                stats["event_types"][f"rare_{template['destination_port']}"] += 1
                if is_blocked:
                    stats["blocked_events"] += 1
                events_generated += 1

        if events_generated:
            stats["employees_with_events"] += 1

    stats["event_types"] = dict(stats["event_types"])
    return stats
