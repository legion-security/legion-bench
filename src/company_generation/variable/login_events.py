"""
Realistic login event generation for company fixtures.

Produces enterprise-grade authentication patterns:
- IP clustering: office NAT, VPN gateways, stable home IPs, rare travel IPs
- Zipf-weighted app selection from each person's authorised apps
- Role-conditioned event counts (IT/Security ~3x general staff)
- Stable per-employee device/UA profiles
- Conditional MFA behaviour based on app sensitivity and device familiarity
- Per-person failure rates sampled from U(0.003, 0.03)

The existing ``login_correlations.py`` (lockout/unlock, MFA reset, device
registration, MFA bypass chains) remains a separate enrichment pass.
"""
from __future__ import annotations

import hashlib
import math
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .user_activity import (
    add_login_log,
    _collect_person_apps,
    _collect_person_device_ids,
)
from .temporal_model import (
    format_ts,
    get_window,
    resolve_person_temporal,
    sample_timestamp,
)
from .episodic_bursts import BurstSchedule, apply_burst_to_count

Person = Dict[str, Any]
Company = Dict[str, Any]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Department → (office_pct, travel_pct) resolved via department categories.
from .department_categories import (
    get_ip_weights as _get_ip_weights,
    classify_role_tier as _classify_role_tier_cat,
)
_DEFAULT_OFFICE_PCT = 0.55
_DEFAULT_TRAVEL_PCT = 0.03

# Role-tier → (mean_events_per_day, std)
_DEFAULT_LOGIN_RATES: Dict[str, Tuple[float, float]] = {
    # General IC
    "general_ic":       (3.0, 1.0),
    "general_senior":   (4.0, 1.5),
    # Engineering
    "eng_ic":           (4.0, 1.5),
    "eng_senior":       (5.0, 1.5),
    # IT / Security / Infra
    "ops_ic":           (8.0, 3.0),
    "ops_senior":       (10.0, 3.0),
    # Sales / CS
    "sales_ic":         (5.0, 2.0),
    "cs_ic":            (5.0, 2.0),
    # Management
    "manager":          (5.0, 2.0),
    # Executive
    "executive":        (3.0, 1.0),
}


# App sensitivity tiers for auth method selection
_HIGH_SENSITIVITY_APPS = {
    "AWS", "Google Cloud Platform", "Azure", "Salesforce",
    "Okta", "1Password", "Snowflake",
}
_LOW_SENSITIVITY_APPS = {
    "Slack", "Zoom", "Microsoft Teams", "Figma", "Canva",
    "Trello", "Notion", "Asana",
}
# Everything else is medium.

# Centrality ranking for Zipf weighting (lower rank → higher weight)
_APP_CENTRALITY_RANK: Dict[str, int] = {
    "Okta": 1,
    "Google Workspace": 2,
    "Slack": 3,
    "Microsoft 365": 4,
    "Microsoft Teams": 5,
    "Jira": 6,
    "GitHub": 7,
    "Zoom": 8,
    "Confluence": 9,
    "AWS": 10,
    "Salesforce": 11,
    "1Password": 12,
}

# Failure reasons (safe_mode excludes account_locked / mfa_failed)
_SAFE_FAILURE_WEIGHTS = [
    ("invalid_password", 60),
    ("expired_password", 15),
    ("captcha_required", 15),
    ("invalid_session", 10),
]
_FULL_FAILURE_WEIGHTS = [
    ("invalid_password", 50),
    ("expired_password", 10),
    ("captcha_required", 10),
    ("invalid_session", 10),
    ("account_locked", 10),
    ("mfa_failed", 10),
]

# User-agent templates
_UA_TEMPLATES = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

# Regions for VPN gateways (keyed by location prefix)
_LOCATION_TO_REGION: Dict[str, str] = {
    "US": "US",
    "UK": "UK",
    "DE": "DE",
    "NL": "NL",
    "IL": "IL",
    "IN": "IN",
    "SG": "SG",
    "JP": "JP",
    "AU": "AU",
}

# Travel geo labels
_TRAVEL_GEOS = [
    "US-Airport-WiFi", "UK-Hotel-WiFi", "DE-Conference-WiFi",
    "SG-Hotel-WiFi", "JP-Hotel-WiFi", "AU-Coworking-WiFi",
    "US-Coffee-Shop", "UK-Airport-WiFi", "NL-Coworking-WiFi",
]


# ---------------------------------------------------------------------------
# IP model helpers (built once per company)
# ---------------------------------------------------------------------------

def _deterministic_public_ip(seed_material: str, index: int = 0) -> str:
    """Generate a deterministic public IP from a seed string + index."""
    h = hashlib.sha256(f"{seed_material}:{index}".encode()).digest()
    a, b, c, d = h[0], h[1], h[2], h[3]
    # Ensure it looks like a public IP (avoid private/reserved ranges)
    a = (a % 200) + 11  # 11-210, avoids 0, 10, 127
    if a in (10, 127, 169, 172, 192):
        a += 5
    if a > 223:
        a = 100
    d = max(1, d % 254)
    return f"{a}.{b}.{c}.{d}"


def _build_office_nat_ips(
    subnets: List[Dict[str, Any]], seed: int,
) -> Dict[str, List[str]]:
    """For each office subnet, generate 1-3 deterministic public NAT IPs.

    Returns ``{location: [ip, ...]}`` mapping.
    """
    office_ips: Dict[str, List[str]] = {}
    for subnet in subnets:
        loc = subnet.get("location", "")
        net_id = subnet.get("id", "")
        rng = random.Random(seed ^ hash(net_id))
        count = rng.randint(1, 3)
        ips = [
            _deterministic_public_ip(f"office-nat:{net_id}", i)
            for i in range(count)
        ]
        office_ips[loc] = ips
    return office_ips


def _build_vpn_gateway_ips(seed: int) -> Dict[str, str]:
    """One VPN gateway IP per region."""
    regions = ["US", "UK", "DE", "NL", "IL", "IN", "SG", "JP", "AU"]
    return {
        region: _deterministic_public_ip(f"vpn-gw:{region}", seed)
        for region in regions
    }


def _build_home_ips(
    person_id: str, isps: List[str], seed: int,
) -> List[Tuple[str, str]]:
    """1-2 stable home IPs per employee, paired with ISP name.

    Returns ``[(ip, isp), ...]``.
    """
    rng = random.Random(seed ^ hash(person_id))
    count = rng.choice([1, 1, 1, 2])  # 75% chance of 1, 25% chance of 2
    if not isps:
        isps = ["Comcast", "Charter"]
    results: List[Tuple[str, str]] = []
    for i in range(count):
        ip = _deterministic_public_ip(f"home:{person_id}", i)
        isp = isps[i % len(isps)]
        results.append((ip, isp))
    return results


def _location_to_region(location: str) -> str:
    """Extract region from location code like 'US-SF-HQ' → 'US'."""
    prefix = location.split("-")[0] if location else ""
    return _LOCATION_TO_REGION.get(prefix, "US")


# ---------------------------------------------------------------------------
# Per-employee stable profile
# ---------------------------------------------------------------------------

def _build_person_user_agents(person_id: str, seed: int) -> List[Tuple[str, float]]:
    """1-2 stable UAs per employee. Primary ~90%, secondary ~10%.

    Returns ``[(ua_string, weight), ...]``.
    """
    rng = random.Random(seed ^ hash(f"ua:{person_id}"))
    primary_idx = rng.randint(0, len(_UA_TEMPLATES) - 1)
    if rng.random() < 0.35:
        # Two UAs
        secondary_idx = rng.randint(0, len(_UA_TEMPLATES) - 1)
        while secondary_idx == primary_idx:
            secondary_idx = rng.randint(0, len(_UA_TEMPLATES) - 1)
        return [
            (_UA_TEMPLATES[primary_idx], 0.90),
            (_UA_TEMPLATES[secondary_idx], 0.10),
        ]
    return [(_UA_TEMPLATES[primary_idx], 1.0)]


def _zipf_app_weights(apps: List[str], alpha: float = 1.2) -> List[Tuple[str, float]]:
    """Zipf-weighted app selection.

    Core apps (Okta, Google Workspace, Slack, etc.) are ranked via a
    centrality lookup table; remaining apps get rank = max_rank + offset.

    Returns ``[(app_name, weight), ...]`` where weights are normalised.
    """
    if not apps:
        return []

    ranked: List[Tuple[str, int]] = []
    max_known = max(_APP_CENTRALITY_RANK.values()) if _APP_CENTRALITY_RANK else 0
    offset = 1
    for app in apps:
        if app in _APP_CENTRALITY_RANK:
            ranked.append((app, _APP_CENTRALITY_RANK[app]))
        else:
            ranked.append((app, max_known + offset))
            offset += 1

    # Sort by rank so Zipf weighting is applied in order
    ranked.sort(key=lambda x: x[1])

    weights: List[Tuple[str, float]] = []
    for i, (app, _rank) in enumerate(ranked):
        w = 1.0 / ((i + 1) ** alpha)
        weights.append((app, w))

    total = sum(w for _, w in weights)
    if total > 0:
        weights = [(app, w / total) for app, w in weights]
    return weights


def _pick_weighted(items: List[Tuple[str, float]], rng: random.Random) -> str:
    """Pick from a list of (item, weight) tuples."""
    r = rng.random()
    cumulative = 0.0
    for item, weight in items:
        cumulative += weight
        if r <= cumulative:
            return item
    return items[-1][0] if items else ""


def _resolve_auth_method(
    app: str, known_device: bool, rng: random.Random,
) -> str:
    """Auth method conditional on app sensitivity and device familiarity."""
    if app in _HIGH_SENSITIVITY_APPS:
        return "SSO+MFA"

    if app in _LOW_SENSITIVITY_APPS:
        if known_device:
            r = rng.random()
            if r < 0.90:
                return "SSO"
            return "SSO+MFA"
        else:
            r = rng.random()
            if r < 0.50:
                return "SSO+MFA"
            if r < 0.80:
                return "Password+MFA"
            return "SSO"

    # Medium sensitivity (default)
    if known_device:
        r = rng.random()
        if r < 0.85:
            return "SSO"
        return "SSO+MFA"
    else:
        r = rng.random()
        if r < 0.70:
            return "SSO+MFA"
        return "Password+MFA"


# ---------------------------------------------------------------------------
# Event count: role-tier defaults + YAML override
# ---------------------------------------------------------------------------

def _classify_role_tier(person: Person, company: Optional[Company] = None) -> str:
    """Classify a person into a login rate tier (delegates to department_categories)."""
    return _classify_role_tier_cat(person, company)


def _resolve_login_count(
    person: Person,
    rng: random.Random,
    *,
    window_days: int = 30,
    scale_factor: float = 1.0,
    baseline_std_scale: float = 1.0,
    company: Optional[Company] = None,
) -> int:
    """Resolve total login events for the generation window.

    Resolution order:
    1. person["behavior_baselines"]["login_baseline"]["avg_events_per_day"]
    2. Code defaults by role tier
    3. Fallback 3.0/day

    ``scale_factor`` is applied to the final count (e.g. 2.0 doubles the count).
    ``baseline_std_scale`` multiplies the std deviation (e.g. 2.0 = wider spread).
    """
    baselines = person.get("behavior_baselines") or {}
    login_bl = baselines.get("login_baseline") or {}

    avg_spec = login_bl.get("avg_events_per_day")
    if avg_spec is not None:
        if isinstance(avg_spec, dict):
            mean_pd = float(avg_spec.get("mean", 3.0))
            std_pd = float(avg_spec.get("std", 1.0)) * baseline_std_scale
        else:
            mean_pd = float(avg_spec)
            std_pd = mean_pd * 0.25 * baseline_std_scale
    else:
        tier = _classify_role_tier(person, company)
        mean_pd, std_pd = _DEFAULT_LOGIN_RATES.get(tier, (3.0, 1.0))
        std_pd = std_pd * baseline_std_scale

    person_rate = max(0.1, rng.gauss(mean_pd, std_pd))
    # Per-person multiplicative variation: λ' = λ · (1 + ε), ε ~ N(0, 0.0625)
    epsilon = rng.gauss(0.0, 0.25 * baseline_std_scale)
    person_rate = person_rate * (1.0 + epsilon)
    person_rate = max(0.1, person_rate)
    total = person_rate * window_days
    return max(1, round(total * scale_factor))


# ---------------------------------------------------------------------------
# IP selection per event
# ---------------------------------------------------------------------------

def _pick_ip(
    person: Person,
    home_ips: List[Tuple[str, str]],
    office_ips: Dict[str, List[str]],
    vpn_ips: Dict[str, str],
    rng: random.Random,
    company: Optional[Company] = None,
) -> Tuple[str, str, str]:
    """Select an IP, geo label, and source type for a single event.

    Returns ``(ip, geo_label, source_type)``
    where source_type ∈ {"office", "vpn", "home", "travel"}.
    """
    dept = person.get("department", "")
    location = person.get("location", "")
    region = _location_to_region(location)

    office_pct, travel_pct = _get_ip_weights(dept, company)

    # VPN percentage from baseline
    baselines = person.get("behavior_baselines") or {}
    login_bl = baselines.get("login_baseline") or {}
    vpn_spec = login_bl.get("vpn_pct")
    if isinstance(vpn_spec, dict):
        vpn_pct = float(vpn_spec.get("mean", 0.20))
    elif vpn_spec is not None:
        vpn_pct = float(vpn_spec)
    else:
        vpn_pct = 0.20

    # Normalize: home_pct gets the remainder
    home_pct = max(0.0, 1.0 - office_pct - vpn_pct - travel_pct)

    r = rng.random()

    if r < office_pct:
        # Office NAT IP
        loc_ips = office_ips.get(location)
        if loc_ips:
            ip = rng.choice(loc_ips)
        else:
            # Fallback: any office
            all_ips = [ip for ips in office_ips.values() for ip in ips]
            ip = rng.choice(all_ips) if all_ips else _deterministic_public_ip(f"fallback:{location}", 0)
        return ip, location, "office"

    if r < office_pct + vpn_pct:
        # VPN gateway
        gw = vpn_ips.get(region)
        if not gw:
            gw = vpn_ips.get("US", _deterministic_public_ip("vpn-fallback", 0))
        return gw, f"VPN-{region}", "vpn"

    if r < office_pct + vpn_pct + home_pct:
        # Home ISP
        if home_ips:
            ip, isp = rng.choice(home_ips)
            return ip, f"Home-{isp}", "home"
        # Fallback
        ip = _deterministic_public_ip(f"home-fallback:{person.get('id', '')}", 0)
        return ip, "Home-ISP", "home"

    # Travel
    ip = _deterministic_public_ip(
        f"travel:{person.get('id', '')}:{rng.randint(0, 999)}", rng.randint(0, 99)
    )
    geo = rng.choice(_TRAVEL_GEOS)
    return ip, geo, "travel"


# ---------------------------------------------------------------------------
# Day-based location planning (temporal coherence)
# ---------------------------------------------------------------------------

def _resolve_vpn_pct(person: Person) -> float:
    """Extract VPN usage percentage from person baselines."""
    baselines = person.get("behavior_baselines") or {}
    login_bl = baselines.get("login_baseline") or {}
    vpn_spec = login_bl.get("vpn_pct")
    if isinstance(vpn_spec, dict):
        return float(vpn_spec.get("mean", 0.20))
    elif vpn_spec is not None:
        return float(vpn_spec)
    return 0.20


def _build_day_plans(
    rng: random.Random,
    unique_days: list,
    office_pct: float,
    travel_pct: float,
    vpn_pct: float,
) -> dict:
    """Build per-day location schedules for temporal coherence.

    Instead of picking a random location for each event independently,
    this creates a schedule for each day so a person stays in one
    location for contiguous blocks, with at most one transition
    (commute) per day.

    Returns ``{date: [(boundary_hour, location_type), ...]}``
    where *location_type* is one of ``"office"``, ``"home"``,
    ``"vpn"``, ``"travel"``.  The first tuple always has
    ``boundary_hour = 0``.  An event at hour *H* uses the
    *location_type* of the last entry whose ``boundary_hour <= H``.
    """
    # When not at office, some sessions go through VPN
    non_office = max(0.01, 1.0 - office_pct)
    vpn_overlay = min(0.8, vpn_pct / non_office)

    # ~20% of office days are mixed (commute mid-day)
    mixed_frac = 0.20

    plans: dict = {}
    for day in unique_days:
        is_weekend = day.weekday() >= 5

        if is_weekend:
            # Weekends: home, occasionally VPN
            loc = "vpn" if rng.random() < vpn_overlay else "home"
            plans[day] = [(0, loc)]
            continue

        r = rng.random()

        if r < travel_pct:
            # Travel day — might use VPN while traveling
            loc = "vpn" if rng.random() < 0.4 else "travel"
            plans[day] = [(0, loc)]
        elif r < travel_pct + office_pct:
            # Office day — possibly mixed with home/vpn
            if rng.random() < mixed_frac:
                transition = rng.randint(11, 14)
                away = "vpn" if rng.random() < vpn_overlay else "home"
                if rng.random() < 0.5:
                    plans[day] = [(0, away), (transition, "office")]
                else:
                    plans[day] = [(0, "office"), (transition, away)]
            else:
                plans[day] = [(0, "office")]
        elif r < travel_pct + office_pct + vpn_pct:
            plans[day] = [(0, "vpn")]
        else:
            plans[day] = [(0, "home")]

    return plans


def _resolve_day_location(
    plan: List[Tuple[int, str]], hour: int,
) -> str:
    """Look up the location type for a given hour in a day plan."""
    loc_type = plan[0][1]
    for boundary_hour, block_type in plan:
        if hour >= boundary_hour:
            loc_type = block_type
    return loc_type


def _pick_ip_for_location(
    location_type: str,
    person: Person,
    home_ips: List[Tuple[str, str]],
    office_ips: Dict[str, List[str]],
    vpn_ips: Dict[str, str],
    rng: random.Random,
) -> Tuple[str, str, str]:
    """Select IP and geo label for a given location type.

    Like ``_pick_ip`` but takes the location type as input rather than
    rolling a random choice, enabling plan-based location assignment.

    Returns ``(ip, geo_label, source_type)``.
    """
    location = person.get("location", "")
    region = _location_to_region(location)

    if location_type == "office":
        loc_ips = office_ips.get(location)
        if loc_ips:
            ip = rng.choice(loc_ips)
        else:
            all_ips = [ip for ips in office_ips.values() for ip in ips]
            ip = rng.choice(all_ips) if all_ips else _deterministic_public_ip(f"fallback:{location}", 0)
        return ip, location, "office"

    if location_type == "vpn":
        gw = vpn_ips.get(region)
        if not gw:
            gw = vpn_ips.get("US", _deterministic_public_ip("vpn-fallback", 0))
        return gw, f"VPN-{region}", "vpn"

    if location_type == "home":
        if home_ips:
            ip, isp = rng.choice(home_ips)
            return ip, f"Home-{isp}", "home"
        ip = _deterministic_public_ip(f"home-fallback:{person.get('id', '')}", 0)
        return ip, "Home-ISP", "home"

    # travel
    ip = _deterministic_public_ip(
        f"travel:{person.get('id', '')}:{rng.randint(0, 999)}", rng.randint(0, 99)
    )
    geo = rng.choice(_TRAVEL_GEOS)
    return ip, geo, "travel"


# ---------------------------------------------------------------------------
# Failure model
# ---------------------------------------------------------------------------

def _pick_failure_reason(
    failure_weights: List[Tuple[str, int]], rng: random.Random,
) -> str:
    """Weighted selection of failure reason."""
    total = sum(w for _, w in failure_weights)
    r = rng.randint(1, total)
    cumulative = 0
    for reason, weight in failure_weights:
        cumulative += weight
        if r <= cumulative:
            return reason
    return failure_weights[-1][0]


# ---------------------------------------------------------------------------
# People container helpers
# ---------------------------------------------------------------------------

def _select_people_container(company: Company) -> Tuple[List[Person], str]:
    """Select employees or workers list."""
    employees = company.get("employees")
    if isinstance(employees, list) and employees:
        return employees, "employee"
    workers = company.get("workers")
    if isinstance(workers, list) and workers:
        return workers, "worker"
    return [], "employee"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_login_event_logs(
    company: Company,
    *,
    seed: int = 1337,
    replace_existing: bool = True,
    events_multiplier: float = 1.0,
    baseline_std_scale: float = 1.0,
    generation_config: Optional[Dict[str, Any]] = None,
    burst_schedule: Optional[BurstSchedule] = None,
    safe_mode: bool = True,
) -> Dict[str, Any]:
    """Generate realistic login events for every person in the company.

    Args:
        company: Company data dict (modified in-place).
        seed: Base seed for deterministic generation.
        replace_existing: If True, clear existing logins first.
        events_multiplier: Multiplier for baseline login event rate
            (1.0 = normal, 2.0 = double, 0.5 = half).
        generation_config: Temporal model config dict.
        burst_schedule: Optional burst schedule for scaling event counts.
        safe_mode: If True, exclude failure reasons that imply follow-up
            actions (account_locked, mfa_failed).

    Returns:
        Statistics dict with generation details.
    """
    people, container_kind = _select_people_container(company)

    stats: Dict[str, Any] = {
        "employees_total": len(people),
        "employees_with_events": 0,
        "events_requested": 0,
        "events_added": 0,
        "successful_events": 0,
        "failed_events": 0,
        "ip_source_distribution": defaultdict(int),
        "apps_used": defaultdict(int),
        "auth_methods": defaultdict(int),
    }

    if not people:
        return _finalize_stats(stats)

    gen_cfg = generation_config or company.get("_generation_config") or {}

    # Pre-compute window for temporal model and burst scaling
    if gen_cfg:
        window_start, window_end = get_window(gen_cfg)
        window_days = gen_cfg.get("temporal", {}).get("window_days", 30)
    else:
        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(days=30)
        window_days = 30

    # Build company-wide IP infrastructure (once)
    subnets = (company.get("network") or {}).get("subnets", [])
    office_ips = _build_office_nat_ips(subnets, seed)
    vpn_ips = _build_vpn_gateway_ips(seed)

    failure_weights = _SAFE_FAILURE_WEIGHTS if safe_mode else _FULL_FAILURE_WEIGHTS

    # Clear existing if requested
    if replace_existing:
        for person in people:
            ra = person.setdefault("recent_activity", {})
            ra["logins"] = []

    base_seed = seed or 0

    for idx, person in enumerate(people):
        person_id = person.get("id")
        if not person_id:
            continue

        person_seed = base_seed * 1021 + idx
        rng = random.Random(person_seed)

        # --- Resolve event count ---
        target_count = _resolve_login_count(
            person, rng,
            window_days=window_days,
            scale_factor=events_multiplier,
            baseline_std_scale=baseline_std_scale,
            company=company,
        )

        # Apply burst scaling
        if burst_schedule and burst_schedule.bursts and window_start and window_end:
            target_count = apply_burst_to_count(
                target_count, person_id, "logins",
                burst_schedule, rng, window_start, window_end,
            )

        if target_count <= 0:
            continue

        stats["events_requested"] += target_count

        # --- Build stable per-person profile ---
        baselines = person.get("behavior_baselines") or {}
        login_bl = baselines.get("login_baseline") or {}
        isps = login_bl.get("isps") or ["Comcast", "Charter"]
        home_ips = _build_home_ips(person_id, isps, seed)
        ua_profile = _build_person_user_agents(person_id, seed)
        person_apps = _collect_person_apps(person)
        app_weights = _zipf_app_weights(person_apps)
        device_ids = _collect_person_device_ids(company, person)

        # Per-person failure rate: U(0.003, 0.03)
        failure_rate = rng.uniform(0.003, 0.03)

        # Per-person primary device affinity: U(0.85, 0.95)
        device_affinity = rng.uniform(0.85, 0.95) if device_ids else 0.0
        primary_device = device_ids[0] if device_ids else None

        # Build temporal samplers
        circadian = weekly = None
        if gen_cfg:
            circadian, weekly = resolve_person_temporal(person, gen_cfg)

        # --- Resolve location planning parameters ---
        vpn_pct = _resolve_vpn_pct(person)
        dept = person.get("department", "")
        office_pct, travel_pct = _get_ip_weights(dept, company)

        # --- Phase 1: Generate all timestamps ---
        timestamps: List[datetime] = []
        for _ in range(target_count):
            if circadian and weekly:
                ts_dt = sample_timestamp(circadian, weekly, rng, window_start, window_end)
            else:
                days_back = rng.randint(0, max(1, window_days - 1))
                hour = rng.choice([7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18])
                ts_dt = window_end - timedelta(days=days_back)
                ts_dt = ts_dt.replace(
                    hour=hour, minute=rng.randint(0, 59),
                    second=rng.randint(0, 59), microsecond=0,
                )
            timestamps.append(ts_dt)
        timestamps.sort()

        # --- Phase 2: Build day location plans ---
        unique_days = sorted(set(t.date() for t in timestamps))
        day_plans = _build_day_plans(
            rng, unique_days, office_pct, travel_pct, vpn_pct,
        )

        # --- Phase 3: Generate events in chronological order ---
        events_for_person = 0
        id_kwargs: Dict[str, Any] = {}
        if container_kind == "employee":
            id_kwargs["employee_id"] = person_id
        else:
            id_kwargs["worker_id"] = person_id

        for ts_dt in timestamps:
            ts = format_ts(ts_dt)

            # Look up day plan for location coherence
            plan = day_plans.get(ts_dt.date(), [(0, "home")])
            loc_type = _resolve_day_location(plan, ts_dt.hour)

            # IP from day plan
            ip, geo, source_type = _pick_ip_for_location(
                loc_type, person, home_ips, office_ips, vpn_ips, rng,
            )
            stats["ip_source_distribution"][source_type] += 1

            # App (Zipf-weighted)
            app = _pick_weighted(app_weights, rng) if app_weights else None
            if app:
                stats["apps_used"][app] += 1

            # Device
            if primary_device and rng.random() < device_affinity:
                dev_id = primary_device
                known_device = True
            elif device_ids and len(device_ids) > 1:
                dev_id = rng.choice(device_ids[1:])
                known_device = True
            else:
                dev_id = "unknown"
                known_device = False

            # User agent (weighted)
            ua = _pick_weighted(ua_profile, rng)

            # Success / failure
            is_failure = rng.random() < failure_rate
            failure_reason = _pick_failure_reason(failure_weights, rng) if is_failure else None

            # Auth method
            method = _resolve_auth_method(app or "", known_device, rng)
            stats["auth_methods"][method] += 1

            # Emit event via the canonical add_login_log
            add_login_log(
                company,
                **id_kwargs,
                ip=ip,
                user_agent=ua,
                device_id=dev_id,
                known_device=known_device,
                failure_reason=failure_reason,
                ts=ts,
                method=method,
                success=None,  # derived from failure_reason inside add_login_log
                geo=geo,
                app=app,
            )

            if is_failure:
                stats["failed_events"] += 1
            else:
                stats["successful_events"] += 1

            stats["events_added"] += 1
            events_for_person += 1

        if events_for_person > 0:
            stats["employees_with_events"] += 1

    return _finalize_stats(stats)


def _finalize_stats(stats: Dict[str, Any]) -> Dict[str, Any]:
    """Convert defaultdicts to regular dicts for serialisation."""
    for key in ("ip_source_distribution", "apps_used", "auth_methods"):
        if isinstance(stats.get(key), defaultdict):
            stats[key] = dict(stats[key])
    return stats
