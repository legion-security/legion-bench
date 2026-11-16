"""
Full company generator that produces complete employee objects with activity data.

This is the "complete" generator that produces employees with:
- Full account objects with MFA settings
- Embedded device references
- Behavior baselines
- Recent activity (logins, emails, files, admin actions)
- Risk flags, DLP profile, sessions, tokens

Use this when you need a complete company fixture in one step.
For incremental enrichment, use company_static_generator.py + enrichment CLIs.
"""
import argparse
import json
import math
import random
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

from .static.cloud_assets import CloudConfig, generate_cloud_instances, generate_containers


@dataclass
class DistributionSpec:
    """Specification for a value sampled from a normal distribution."""
    mean: float
    std: float
    min_val: Optional[float] = None
    max_val: Optional[float] = None


@dataclass
class LoginBaselineSpec:
    """Specification for login baseline with optional distributions."""
    vpn_pct: Optional[Union[DistributionSpec, float]] = None
    hours: Optional[List[str]] = None
    asn: Optional[List[int]] = None
    isps: Optional[List[str]] = None


@dataclass
class EmailBaselineSpec:
    """Specification for email baseline with optional distributions."""
    avg_inbound_per_day: Optional[Union[DistributionSpec, int]] = None
    trusted_domains: Optional[List[str]] = None
    typical_attachments: Optional[List[str]] = None


@dataclass
class AppEventBaselineSpec:
    """Specification for app event baseline with optional distributions."""
    avg_events_per_day: Optional[Union[DistributionSpec, int]] = None


@dataclass
class BaselineSpec:
    """Container for all baseline specifications."""
    login_baseline: Optional[LoginBaselineSpec] = None
    email_baseline: Optional[EmailBaselineSpec] = None
    process_baseline: Optional[List[str]] = None
    net_baseline: Optional[List[str]] = None
    app_event_baseline: Optional[AppEventBaselineSpec] = None


@dataclass
class RolePolicy:
    """Policy defining baselines for a specific role."""
    baselines: BaselineSpec


@dataclass
class NoiseConfig:
    """Configuration for post-processing noise."""
    enabled: bool = True
    numeric_noise_pct: float = 0.05  # +/- 5% random noise


@dataclass
class CompanyConfig:
    company_id: str
    company_name: str
    domain: str
    num_employees: int = 1000
    seed: int = 1337
    locations: Tuple[str, ...] = ("US-NY", "US-CA", "NL-AMS", "IN-BLR")
    departments: Tuple[str, ...] = (
        "Executive",
        "Finance",
        "HR",
        "Engineering",
        "IT",
        "Sales",
        "Marketing",
        "Support",
        "Legal",
        "Security",
    )
    role_policies: Dict[str, RolePolicy] = field(default_factory=dict)
    default_baseline_policy: Optional[RolePolicy] = None
    noise_config: NoiseConfig = field(default_factory=NoiseConfig)


TITLES_BY_DEPT = {
    "Executive": ["CEO", "CFO", "COO", "CTO", "CFO", "CMO", "CHRO", "CIO"],
    "Finance": ["VP Finance", "Director Finance", "Sr Accountant", "Accountant"],
    "HR": ["VP HR", "HR Business Partner", "Recruiter"],
    "Engineering": ["VP Engineering", "Director Engineering", "Staff Engineer", "Senior Engineer", "Engineer"],
    "IT": ["IT Director", "Sysadmin", "IT Support Specialist"],
    "Sales": ["VP Sales", "Sales Director", "Account Executive", "SDR"],
    "Marketing": ["VP Marketing", "Director Marketing", "Content Manager", "Marketing Specialist"],
    "Support": ["Support Manager", "Senior Support Engineer", "Support Engineer"],
    "Legal": ["General Counsel", "Counsel"],
    "Security": ["Director Security", "Security Engineer", "Analyst"],
}

# Default baseline values used when no role policy is specified
DEFAULT_LOGIN_BASELINE = LoginBaselineSpec(
    vpn_pct=DistributionSpec(mean=0.2, std=0.05, min_val=0.0, max_val=1.0),
    hours=["08:00-10:00", "16:30-19:00"],
    asn=[13335, 15169, 16509],
    isps=["Comcast", "AT&T", "KPN", "Airtel"],
)

DEFAULT_EMAIL_BASELINE = EmailBaselineSpec(
    avg_inbound_per_day=DistributionSpec(mean=45, std=10, min_val=0, max_val=None),
    trusted_domains=None,  # Will be filled with company domain
    typical_attachments=["pdf", "xlsx", "docx"],
)

DEFAULT_PROCESS_BASELINE = ["chrome", "outlook", "slack"]
DEFAULT_NET_BASELINE = ["api.github.com", "microsoft.com", "googleapis.com"]
DEFAULT_APP_EVENT_BASELINE = AppEventBaselineSpec(
    avg_events_per_day=DistributionSpec(mean=6, std=2, min_val=0, max_val=None),
)


def _sample_distribution(
    spec: Union[DistributionSpec, float, int],
    rng: random.Random,
    as_int: bool = False,
    min_clamp: Optional[float] = None,
    max_clamp: Optional[float] = None,
) -> Union[float, int]:
    """Sample from normal distribution or return static value.

    Args:
        spec: Either a DistributionSpec for sampling, or a static value
        rng: Random number generator for deterministic sampling
        as_int: If True, return an integer
        min_clamp: Optional minimum value to clamp to (overrides spec.min_val)
        max_clamp: Optional maximum value to clamp to (overrides spec.max_val)

    Returns:
        Sampled or static value, optionally clamped and converted to int
    """
    if isinstance(spec, DistributionSpec):
        value = rng.gauss(spec.mean, spec.std)
        # Apply clamping from spec or overrides
        min_val = min_clamp if min_clamp is not None else spec.min_val
        max_val = max_clamp if max_clamp is not None else spec.max_val
        if min_val is not None:
            value = max(value, min_val)
        if max_val is not None:
            value = min(value, max_val)
    else:
        value = spec

    return int(round(value)) if as_int else value


def _get_role_policy(
    department: str,
    title: str,
    role_policies: Dict[str, RolePolicy],
    default_policy: Optional[RolePolicy],
) -> Optional[RolePolicy]:
    """Match role to policy using priority: 'Dept - Title' > 'Title' > default.

    Args:
        department: User's department
        title: User's job title
        role_policies: Dictionary of role-specific policies
        default_policy: Fallback policy if no match found

    Returns:
        Matched RolePolicy or default_policy
    """
    # Try full match: "Department - Title"
    full_key = f"{department} - {title}"
    if full_key in role_policies:
        return role_policies[full_key]

    # Try title-only match (cross-department)
    if title in role_policies:
        return role_policies[title]

    # Fall back to default
    return default_policy


def _generate_behavior_baselines(
    cfg: CompanyConfig,
    user: Dict,
    devices_by_owner: Dict[str, List[Dict]],
    rng: random.Random,
) -> Dict:
    """Generate baselines using role policy and sampling.

    Args:
        cfg: Company configuration with role policies
        user: User dictionary with department and title
        devices_by_owner: Devices indexed by owner user_id
        rng: Random number generator

    Returns:
        Dictionary with login_baseline, email_baseline, process_baseline, net_baseline
    """
    # Get the applicable role policy
    policy = _get_role_policy(
        user["department"],
        user["title"],
        cfg.role_policies,
        cfg.default_baseline_policy,
    )

    # Extract baseline specs from policy, or use defaults
    if policy and policy.baselines:
        login_spec = policy.baselines.login_baseline or DEFAULT_LOGIN_BASELINE
        email_spec = policy.baselines.email_baseline or DEFAULT_EMAIL_BASELINE
        process_baseline = policy.baselines.process_baseline or DEFAULT_PROCESS_BASELINE
        net_baseline = policy.baselines.net_baseline or DEFAULT_NET_BASELINE
        app_event_spec = policy.baselines.app_event_baseline or DEFAULT_APP_EVENT_BASELINE
    else:
        login_spec = DEFAULT_LOGIN_BASELINE
        email_spec = DEFAULT_EMAIL_BASELINE
        process_baseline = DEFAULT_PROCESS_BASELINE
        net_baseline = DEFAULT_NET_BASELINE
        app_event_spec = DEFAULT_APP_EVENT_BASELINE

    # Sample login baseline values
    vpn_pct_spec = login_spec.vpn_pct if login_spec.vpn_pct is not None else DEFAULT_LOGIN_BASELINE.vpn_pct
    vpn_pct = _sample_distribution(vpn_pct_spec, rng, as_int=False, min_clamp=0.0, max_clamp=1.0)

    login_baseline = {
        "countries": [user["location"].split("-")[-1]],
        "asn": login_spec.asn if login_spec.asn is not None else DEFAULT_LOGIN_BASELINE.asn,
        "isps": login_spec.isps if login_spec.isps is not None else DEFAULT_LOGIN_BASELINE.isps,
        "vpn_pct": vpn_pct,
        "hours": login_spec.hours if login_spec.hours is not None else DEFAULT_LOGIN_BASELINE.hours,
        "devices": [d["hostname"] for d in devices_by_owner.get(user["id"], [])],
    }

    # Sample email baseline values
    avg_inbound_spec = email_spec.avg_inbound_per_day if email_spec.avg_inbound_per_day is not None else DEFAULT_EMAIL_BASELINE.avg_inbound_per_day
    avg_inbound_per_day = _sample_distribution(avg_inbound_spec, rng, as_int=True, min_clamp=0)

    trusted_domains = email_spec.trusted_domains if email_spec.trusted_domains is not None else [cfg.domain]
    typical_attachments = email_spec.typical_attachments if email_spec.typical_attachments is not None else DEFAULT_EMAIL_BASELINE.typical_attachments

    email_baseline = {
        "avg_inbound_per_day": avg_inbound_per_day,
        "trusted_domains": trusted_domains,
        "typical_attachments": typical_attachments,
    }

    # Sample app event baseline values
    app_avg_spec = app_event_spec.avg_events_per_day if app_event_spec.avg_events_per_day is not None else DEFAULT_APP_EVENT_BASELINE.avg_events_per_day
    app_avg_events = _sample_distribution(app_avg_spec, rng, as_int=False, min_clamp=0)
    app_baseline = {
        "avg_events_per_day": app_avg_events,
    }

    return {
        "login_baseline": login_baseline,
        "email_baseline": email_baseline,
        "process_baseline": list(process_baseline),  # Copy to avoid mutation
        "net_baseline": list(net_baseline),
        "app_baseline": app_baseline,
    }


def _apply_numeric_noise(
    value: Union[float, int],
    noise_config: NoiseConfig,
    rng: random.Random,
    min_val: Optional[float] = None,
    max_val: Optional[float] = None,
    as_int: bool = False,
) -> Union[float, int]:
    """Apply +/- percentage noise to a numeric value.

    Args:
        value: The base value to apply noise to
        noise_config: Configuration specifying noise percentage
        rng: Random number generator
        min_val: Optional minimum value to clamp to
        max_val: Optional maximum value to clamp to
        as_int: If True, return an integer

    Returns:
        Value with noise applied
    """
    if not noise_config.enabled:
        return int(round(value)) if as_int else value

    # Apply uniform noise within +/- noise_pct
    noise_factor = 1.0 + rng.uniform(-noise_config.numeric_noise_pct, noise_config.numeric_noise_pct)
    noisy_value = value * noise_factor

    # Clamp to bounds
    if min_val is not None:
        noisy_value = max(noisy_value, min_val)
    if max_val is not None:
        noisy_value = min(noisy_value, max_val)

    return int(round(noisy_value)) if as_int else noisy_value


def _apply_baseline_noise(
    baselines: Dict,
    noise_config: NoiseConfig,
    rng: random.Random,
) -> Dict:
    """Apply noise to vpn_pct and avg_inbound_per_day in baselines.

    Args:
        baselines: Dictionary with login_baseline and email_baseline
        noise_config: Configuration for noise application
        rng: Random number generator

    Returns:
        Baselines dictionary with noise applied to numeric fields
    """
    # Apply noise to vpn_pct
    if "login_baseline" in baselines and "vpn_pct" in baselines["login_baseline"]:
        baselines["login_baseline"]["vpn_pct"] = _apply_numeric_noise(
            baselines["login_baseline"]["vpn_pct"],
            noise_config,
            rng,
            min_val=0.0,
            max_val=1.0,
            as_int=False,
        )

    # Apply noise to avg_inbound_per_day
    if "email_baseline" in baselines and "avg_inbound_per_day" in baselines["email_baseline"]:
        baselines["email_baseline"]["avg_inbound_per_day"] = _apply_numeric_noise(
            baselines["email_baseline"]["avg_inbound_per_day"],
            noise_config,
            rng,
            min_val=0,
            max_val=None,
            as_int=True,
        )

    return baselines


def deterministic_rng(seed: int) -> random.Random:
    return random.Random(seed)


def pick_manager_indices(rng: random.Random, n: int, manager_ratio: float = 0.12) -> List[int]:
    num_managers = max(1, int(n * manager_ratio))
    return sorted(rng.sample(range(n), num_managers))


def generate_departments(cfg: CompanyConfig, rng: random.Random) -> List[Dict]:
    departments = []
    for i, name in enumerate(cfg.departments):
        departments.append({
            "id": f"dept_{i}",
            "name": name,
            "manager_user_id": None,
        })
    return departments


def generate_users(cfg: CompanyConfig, departments: List[Dict], rng: random.Random) -> List[Dict]:
    users: List[Dict] = []
    vip_emails = set()
    # Ensure 1-2% VIPs
    desired_vips = max(5, int(cfg.num_employees * 0.015))
    fnames = [
        "Alex", "Sam", "Taylor", "Jordan", "Casey", "Drew", "Riley", "Morgan", "Jamie", "Cameron",
        "Avery", "Quinn", "Hayden", "Parker", "Reese", "Rowan", "Elliot", "Logan", "Skyler", "Emerson"
    ]
    lnames = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
        "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"
    ]

    dept_weights = [
        0.01,  # Executive
        0.08,  # Finance
        0.05,  # HR
        0.40,  # Engineering
        0.08,  # IT
        0.15,  # Sales
        0.08,  # Marketing
        0.10,  # Support
        0.03,  # Legal
        0.02,  # Security
    ]

    # Normalize weights
    total_w = sum(dept_weights)
    dept_weights = [w / total_w for w in dept_weights]
    dept_ids = [d["id"] for d in departments]
    dept_names = {d["id"]: d["name"] for d in departments}

    # Prepick some managers per department
    per_dept_target = {d["id"]: max(1, int(cfg.num_employees * w * 0.12)) for d, w in zip(departments, dept_weights)}
    managers_remaining = {d: per_dept_target[d] for d in per_dept_target}

    # Generate users with stable but varied attributes
    for idx in range(cfg.num_employees):
        dept_id = rng.choices(dept_ids, weights=dept_weights, k=1)[0]
        first = rng.choice(fnames)
        last = rng.choice(lnames)
        email_base = f"{first}.{last}".lower()
        # Avoid collisions by appending number when necessary
        suffix = 1
        email = f"{email_base}@{cfg.domain}"
        while email in vip_emails or any(u["email"] == email for u in users):
            suffix += 1
            email = f"{email_base}{suffix}@{cfg.domain}"

        # Title selection leaning senior for managers
        titles = TITLES_BY_DEPT.get(dept_names[dept_id], ["Employee"])
        is_manager = managers_remaining.get(dept_id, 0) > 0 and rng.random() < 0.5
        title_idx = 0 if (is_manager and len(titles) > 1) else min(len(titles) - 1, math.floor(rng.random() * len(titles)))
        title = titles[title_idx]

        # Locations distribution
        location = rng.choice(cfg.locations)

        # MFA coverage ~90%
        mfa_pool = ["okta_push", "totp", "webauthn", "sms"]
        use_mfa = rng.random() < 0.9
        mfa = rng.sample(mfa_pool, k=rng.randint(1, 2)) if use_mfa else []

        # Hire date within last 8 years
        days_back = rng.randint(30, 8 * 365)
        hire_dt = date.today() - timedelta(days=days_back)

        user = {
            "id": f"u_{idx:04d}",
            "email": email,
            "display_name": f"{first} {last}",
            "department_id": dept_id,
            "department": dept_names[dept_id],
            "title": title,
            "manager_id": None,  # filled later
            "vip": False,
            "mfa": mfa,
            "risk_state": "none",
            "location": location,
            "hire_date": hire_dt.isoformat(),
        }
        users.append(user)
        if is_manager:
            managers_remaining[dept_id] = max(0, managers_remaining[dept_id] - 1)

    # Assign managers per department
    by_dept = {}
    for u in users:
        by_dept.setdefault(u["department_id"], []).append(u)
    for dept_id, members in by_dept.items():
        # pick a few senior titles to be managers
        manager_candidates = [u for u in members if any(k in u["title"].lower() for k in ["vp", "director", "manager", "chief", "lead"]) or rng.random() < 0.1]
        if not manager_candidates and members:
            manager_candidates = [rng.choice(members)]
        for u in members:
            if u in manager_candidates:
                continue
            u["manager_id"] = rng.choice(manager_candidates)["id"]

    # Mark VIPs: executives and a few finance/engineering leaders
    exec_users = [u for u in users if u["department"] == "Executive" or any(x in u["title"].lower() for x in ["chief", "cfo", "ceo"])]
    additional_vips = rng.sample([u for u in users if u not in exec_users], k=max(0, desired_vips - len(exec_users)))
    for u in exec_users + additional_vips:
        u["vip"] = True
        vip_emails.add(u["email"])

    return users


def generate_departments_manager_links(departments: List[Dict], users: List[Dict]):
    by_dept = {}
    for u in users:
        by_dept.setdefault(u["department_id"], []).append(u)
    for d in departments:
        members = by_dept.get(d["id"], [])
        if members:
            # choose most senior title if available
            def title_rank(t: str) -> int:
                tl = t.lower()
                if any(k in tl for k in ["chief", "ceo", "cfo", "coo", "general counsel"]):
                    return 0
                if "vp" in tl:
                    return 1
                if "director" in tl:
                    return 2
                if "manager" in tl:
                    return 3
                return 4

            manager = sorted(members, key=lambda u: title_rank(u["title"]))[0]
            d["manager_user_id"] = manager["id"]


def generate_groups(cfg: CompanyConfig, users: List[Dict], rng: random.Random) -> List[Dict]:
    groups = []
    # Department groups
    by_dept = {}
    for u in users:
        by_dept.setdefault(u["department_id"], []).append(u["id"])
    for dept_id, member_ids in by_dept.items():
        groups.append({
            "id": f"grp_{dept_id}",
            "name": f"{dept_id}_all",
            "description": "All users in department",
            "members": member_ids,
        })
    # VIP group
    vip_members = [u["id"] for u in users if u["vip"]]
    groups.append({
        "id": "grp_vips",
        "name": "VIPs",
        "description": "Executive and designated VIP users",
        "members": vip_members,
    })
    # IT Admins / Security group (small)
    it_sec = [u["id"] for u in users if u["department"] in ("IT", "Security") and any(k in u["title"].lower() for k in ["director", "engineer", "admin", "analyst"])][: max(5, int(0.02 * len(users)))]
    groups.append({
        "id": "grp_admins",
        "name": "Admins",
        "description": "Privileged administrators",
        "members": it_sec,
    })
    return groups


def generate_network(cfg: CompanyConfig, rng: random.Random, last_updated: str) -> Dict:
    subnets = []
    for i, loc in enumerate(cfg.locations):
        # simple /24 per location
        base_octet = 10 + i
        cidr = f"{base_octet}.10.10.0/24"
        subnets.append({"id": f"net_{i}", "cidr": cidr, "location": loc, "name": f"corp-{loc.lower()}"})
    return {"subnets": subnets, "lastUpdated": last_updated}


def generate_devices(cfg: CompanyConfig, users: List[Dict], network: Dict, rng: random.Random) -> List[Dict]:
    devices: List[Dict] = []
    os_choices = ["Windows", "macOS", "Linux"]
    subnet_ids = [s["id"] for s in network["subnets"]]
    for idx, user in enumerate(users):
        os = rng.choices(os_choices, weights=[0.6, 0.35, 0.05], k=1)[0]
        hostname = f"{user['display_name'].split()[0]}-{user['id'].split('_')[1]}".upper()
        subnet_id = rng.choice(subnet_ids)
        # simple deterministic-ish IP based on index
        ip_address = f"10.{10 + subnet_ids.index(subnet_id)}.{(idx // 250) % 256}.{(idx % 250) + 5}"
        devices.append({
            "id": f"dev_{idx:05d}",
            "hostname": hostname,
            "os": os,
            "owner_user_id": user["id"],
            "ip_address": ip_address,
            "network_id": subnet_id,
        })
    return devices


def generate_mailboxes(cfg: CompanyConfig, users: List[Dict], rng: random.Random) -> List[Dict]:
    mailboxes: List[Dict] = []
    # Personal mailboxes
    for u in users:
        mailboxes.append({
            "address": u["email"],
            "created_at": f"{u['hire_date']}T09:00:00Z",
            "is_distribution_list": False,
            "members": [],
            "delegates": [],
            "rules": [],
        })
    # A few distribution lists per department
    depts = {}
    for u in users:
        depts.setdefault(u["department"], []).append(u["email"])
    for dept, emails in depts.items():
        if not emails:
            continue
        if rng.random() < 0.8:
            dl_addr = f"{dept.lower()}@{cfg.domain}".replace(" ", "-")
            members = rng.sample(emails, k=min(len(emails), max(3, int(0.2 * len(emails)))))
            delegates = rng.sample(members, k=min(len(members), max(1, len(members)//10)))
            mailboxes.append({
                "address": dl_addr,
                "created_at": f"{users[0]['hire_date']}T09:00:00Z",
                "is_distribution_list": True,
                "members": sorted(set(members)),
                "delegates": sorted(set(delegates)),
                "rules": [],
            })
    return mailboxes


# -------- Full employee enrichment (twin/schemas/user.schema.json) --------

SCHEMA_VERSION = "1.1.0"


def _tz_for_location(loc: str) -> str:
    mapping = {
        "US-NY": "America/New_York",
        "US-CA": "America/Los_Angeles",
        "NL-AMS": "Europe/Amsterdam",
        "IN-BLR": "Asia/Kolkata",
    }
    return mapping.get(loc, "UTC")


def _employment_type(rng: random.Random) -> str:
    # ~85% FTE, 10% contractor, 3% vendor, 2% intern
    r = rng.random()
    if r < 0.85:
        return "FTE"
    if r < 0.95:
        return "contractor"
    if r < 0.98:
        return "vendor"
    return "intern"


def _map_mfa_methods(methods: List[str]) -> List[str]:
    mapped = []
    for m in methods:
        ml = m.lower()
        if "okta_push" in ml or "push" in ml:
            mapped.append("push")
        elif "totp" in ml:
            mapped.append("totp")
        elif "webauthn" in ml or "u2f" in ml or "security_key" in ml:
            mapped.append("u2f")
        elif "sms" in ml:
            mapped.append("sms")
    # de-dup and fallback
    return sorted(set(mapped)) or ["push"]


def _recent_activity_for_user(
    rng: random.Random,
    baseline_dt: datetime,
    location_tz: str,
    user_ip_base: str,
    device_ids: List[str],
) -> Dict:
    # Window: [baseline - 30 days, baseline)
    # start_dt reserved for future windowing; keep derived from baseline for clarity

    def within_window(days_back: int, hours_offset: int = 0) -> str:
        ts = baseline_dt - timedelta(days=days_back, hours=hours_offset)
        return ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

    # Logins (3-7 entries)
    logins = []
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile",
    ]

    for _ in range(rng.randint(3, 7)):
        days_back = rng.randint(0, 29)
        hour = rng.choice([8, 9, 10, 17, 18, 22])
        # generate external-ish IPs (fallback to user_ip_base sometimes)
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
        ip = random_public_ip()
        method = rng.choice(["SSO+MFA", "SSO", "Password+MFA"])
        success = rng.random() > 0.05
        # device context
        known_device = rng.random() < 0.85 and bool(device_ids)
        dev_id = rng.choice(device_ids) if known_device and device_ids else None
        login_evt = {
            "ts": within_window(days_back, hours_offset=hour - 12),
            "ip": ip,
            "geo": location_tz,
            "method": method,
            "success": success,
            "user_agent": rng.choice(user_agents),
            "device_id": dev_id if dev_id else "unknown",
            "known_device": bool(dev_id),
        }
        if not success:
            login_evt["failure_reason"] = rng.choice([
                "invalid_password", "mfa_failed", "account_locked", "captcha_required"
            ])
        logins.append(login_evt)

    # Email events (5-15 entries)
    email_events = []
    for _ in range(rng.randint(5, 15)):
        days_back = rng.randint(0, 29)
        direction = rng.choice(["sent", "received"])  # simple balance
        external = direction == "sent" and rng.random() < 0.3
        attachments = []
        if rng.random() < 0.25:
            attachments = rng.sample(["pdf", "xlsx", "docx", "zip"], k=rng.randint(1, 2))
        # generate addressing
        subject_pool = [
            "Weekly sync notes", "Quarterly budget review", "Incident follow-up",
            "Hiring pipeline", "Product roadmap updates"
        ]
        from_addr = f"no-reply@{location_tz.replace('/', '.').lower()}.example" if direction == "received" else None
        to_list = []
        cc_list = []
        bcc_list = []
        if direction == "sent":
            # send to 1-3 recipients
            to_list = [f"user{rng.randint(1,99)}@example.com" for _ in range(rng.randint(1, 3))]
            if rng.random() < 0.3:
                cc_list = [f"manager{rng.randint(1,5)}@{location_tz.split('/')[-1].lower()}.corp"]
            if rng.random() < 0.1:
                bcc_list = [f"audit@{location_tz.split('/')[-1].lower()}.corp"]
        else:
            from_addr = f"partner{rng.randint(1,50)}@partner.example"
        email_events.append({
            "ts": within_window(days_back, hours_offset=rng.randint(-10, 10)),
            "direction": direction,
            "external": external,
            "attachment_types": attachments,
            "from": from_addr,
            "to": to_list,
            "cc": cc_list,
            "bcc": bcc_list,
            "subject": rng.choice(subject_pool),
            "content": "Placeholder content. TODO: replace with GPT-4.1-mini.",
        })

    # File events (3-10 entries)
    file_events = []
    for _ in range(rng.randint(3, 10)):
        days_back = rng.randint(0, 29)
        action = rng.choice(["read", "write", "download", "upload", "share"])
        path = rng.choice([
            "drive://eng/sre/runbook.pdf",
            "drive://sales/2025/q3_pipeline.xlsx",
            "drive://finance/budget_2025.xlsx",
            "share://team/project/spec.docx",
        ])
        label = rng.choice(["Public", "Internal", "Confidential"])
        system = rng.choice(["google_drive", "onedrive", "confluence"])
        evt = {
            "ts": within_window(days_back, hours_offset=rng.randint(-10, 10)),
            "action": action,
            "path": path,
            "label": label,
            "system": system,
        }
        if action == "share":
            share_count = rng.randint(1, 3)
            evt["shared_with"] = [f"user{rng.randint(1,99)}@example.com" for _ in range(share_count)]
        file_events.append(evt)

    # Admin actions (0-2 entries)
    admin_actions = []
    for _ in range(rng.randint(0, 2)):
        days_back = rng.randint(0, 29)
        admin_actions.append({
            "ts": within_window(days_back, hours_offset=rng.randint(-10, 10)),
            "system": rng.choice(["okta", "o365", "github"]),
            "action": rng.choice(["add_group", "revoke_token", "reset_mfa"]),
            "approved_by": rng.choice(["change-mgmt", "oncall", "self"]),
        })

    # User actions
    user_actions = []
    for _ in range(rng.randint(0, 2)):
        days_back = rng.randint(0, 29)
        user_actions.append({
            "ts": within_window(days_back, hours_offset=rng.randint(-10, 10)),
            "action": rng.choice(["password_change", "mfa_method_change"]),
            "details": {}
        })

    return {
        "logins": sorted(logins, key=lambda e: e["ts"]),
        "email_events": sorted(email_events, key=lambda e: e["ts"]),
        "file_events": sorted(file_events, key=lambda e: e["ts"]),
        "admin_actions": sorted(admin_actions, key=lambda e: e["ts"]),
        "user_actions": sorted(user_actions, key=lambda e: e["ts"]) ,
    }


def _validate_employees_privileged_mfa(employees: List[Dict]) -> None:
    for emp in employees:
        if emp.get("risk_flags", {}).get("privileged"):
            has_mfa = any(
                a.get("mfa", {}).get("enabled") for a in emp.get("accounts", [])
            )
            if not has_mfa:
                # Ensure at least one account has MFA enabled
                for a in emp.get("accounts", []):
                    a.setdefault("mfa", {}).update({"enabled": True, "methods": a.get("mfa", {}).get("methods", ["push"])})


def _build_full_employees(
    cfg: CompanyConfig,
    users: List[Dict],
    devices: List[Dict],
    groups: List[Dict],
    baseline_instant: str,
    scenario_id: str,
    rng: random.Random,
) -> List[Dict]:
    """Build full employee objects with all enrichments (accounts, devices, activity)."""
    # Index devices by owner
    devices_by_owner: Dict[str, List[Dict]] = {}
    for d in devices:
        devices_by_owner.setdefault(d["owner_user_id"], []).append(d)

    # Helper: is privileged
    admin_group = next((g for g in groups if g["id"] == "grp_admins"), {"members": []})
    admin_members = set(admin_group.get("members", []))

    baseline_dt = datetime.fromisoformat(baseline_instant.replace("Z", "+00:00"))

    employees: List[Dict] = []
    for u in users:
        # Stable UUID derived from company and user id
        employee_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"{cfg.company_id}:{u['id']}")
        tz = _tz_for_location(u["location"])  # IANA tz string
        emp_type = _employment_type(rng)
        mfa_methods = _map_mfa_methods(u.get("mfa", []))
        # Compose accounts
        username_base = u["email"].split("@")[0]
        is_privileged = u["id"] in admin_members
        accounts = [
            {
                "system": "ad",
                "username": username_base,
                "mfa": {"enabled": len(mfa_methods) > 0, "methods": mfa_methods},
                "roles": (["User", "admin"] if is_privileged else ["User"]),
                "groups": [],
                "shadow_account": False,
            },
            ({
                "system": "okta",
                "username": u["email"],
                "mfa": {"enabled": len(mfa_methods) > 0, "methods": mfa_methods},
                "roles": (["end_user", "admin"] if is_privileged else ["end_user"]),
                "groups": [],
                "shadow_account": False,
            }),
            {
                "system": "o365",
                "username": u["email"],
                "mfa": {"enabled": len(mfa_methods) > 0, "methods": mfa_methods},
                "roles": ["User"],
                "groups": [],
                "shadow_account": False,
            },
            {
                "system": "vpn",
                "username": username_base,
                "mfa": {"enabled": len(mfa_methods) > 0, "methods": mfa_methods},
                "roles": ["User"],
                "groups": [],
                "shadow_account": False,
            },
        ]
        if u["department"] in ("Engineering", "IT", "Security"):
            accounts.append({
                "system": "github",
                "username": username_base,
                "mfa": {"enabled": len(mfa_methods) > 0, "methods": mfa_methods},
                "roles": ["member"],
                "groups": [],
                "shadow_account": False,
            })

        # Devices
        employee_devices: List[Dict] = []
        for d in devices_by_owner.get(u["id"], []):
            employee_devices.append({
                "device_id": d["id"],
                "hostname": d["hostname"],
                "type": "laptop",
                "os": d["os"],
                "ownership": "corp",
                "edr_installed": True,
                "edr_agent_id": f"edr-{d['id']}",
                "last_patch_date": (baseline_dt - timedelta(days=random.randint(5, 45))).date().isoformat(),
                "local_admin": u["department"] in ("Engineering", "IT", "Security"),
            })

        # Behavior baselines (role-based with variation)
        behavior_baselines = _generate_behavior_baselines(cfg, u, devices_by_owner, rng)
        behavior_baselines = _apply_baseline_noise(behavior_baselines, cfg.noise_config, rng)

        # Risk flags
        hire_dt = date.fromisoformat(u["hire_date"]) if u.get("hire_date") else date.today()
        new_hire = (datetime.combine(hire_dt, datetime.min.time(), tzinfo=timezone.utc) > baseline_dt - timedelta(days=90))
        risk_flags = {
            "privileged": is_privileged,
            "new_hire": bool(new_hire),
            "departing": False,
            "contractor": emp_type == "contractor",
        }

        # DLP profile only (compliance removed)
        dlp_profile = {
            "typical_types": ["pdf", "xlsx", "docx"],
            "max_normal_file_mb": 50,
        }

        # Sessions/Tokens (empty or minimal)
        # Sessions across platforms
        session_platforms = ["vpn", "web", "mobile", "app"]
        revocable_sessions = []
        for p in session_platforms:
            revocable_sessions.append({
                "platform": p,
                "session_id": f"{p}-{u['id']}-{rng.randint(1,3)}",
                "issued_at": (baseline_dt - timedelta(days=rng.randint(1, 6))).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
                "device_fingerprint": devices_by_owner.get(u["id"], [{}])[0].get("hostname", "unknown"),
                "external_ip": f"73.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
            })
        token_inventory: List[Dict] = []

        # Recent activity bounded to last month
        user_ip_base = devices_by_owner.get(u["id"], [{}])[0].get("ip_address", "73.12.34.56")
        dev_ids = [d["id"] for d in devices_by_owner.get(u["id"], [])]
        recent_activity = _recent_activity_for_user(rng, baseline_dt, tz, user_ip_base, dev_ids)

        # Manager UUID (if any)
        manager_uuid = None
        if u.get("manager_id"):
            manager_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{cfg.company_id}:{u['manager_id']}"))

        employee = {
            "schema_version": SCHEMA_VERSION,
            "scenario_id": scenario_id,
            "id": str(employee_uuid),
            "name": u["display_name"],
            "emails": [u["email"]],
            "department": u["department"],
            "title": u["title"],
            "manager_id": manager_uuid,
            "employment_type": emp_type,
            "locations": {
                "home_city": u["location"],
                "home_country": u["location"].split("-")[-1],
                "office_site": u["location"],
                "tz": tz,
            },
            "working_hours": {"weekday_start": "09:00", "weekday_end": "17:30", "weekend": False},
            "accounts": accounts,
            "devices": employee_devices or [],
            "data_access": [],
            "risk_flags": risk_flags,
            "behavior_baselines": behavior_baselines,
            "lifecycle": {
                "hire_date": u.get("hire_date"),
                "role_changes": [],
                "permission_changes": [],
            },
            "dlp_profile": dlp_profile,
            "revocable_sessions": revocable_sessions,
            "token_inventory": token_inventory,
            "baseline_instant": baseline_instant,
            "recent_activity": recent_activity,
            "overview": {
                "leaver": False,
            }
        }
        employees.append(employee)

    return employees


def generate_company(cfg: CompanyConfig, baseline_date: str, scenario_id: str) -> Dict:
    """Generate a complete company fixture with full employee objects and activity data."""
    rng = deterministic_rng(cfg.seed)
    departments = generate_departments(cfg, rng)
    users = generate_users(cfg, departments, rng)
    generate_departments_manager_links(departments, users)
    groups = generate_groups(cfg, users, rng)
    # Baseline instant at midnight UTC of provided date
    baseline_instant = f"{baseline_date}T00:00:00Z"
    network = generate_network(cfg, rng, baseline_instant)
    devices = generate_devices(cfg, users, network, rng)
    mailboxes = generate_mailboxes(cfg, users, rng)
    # Cloud assets (multicloud)
    cloud_cfg = CloudConfig()
    instances = generate_cloud_instances(cloud_cfg, rng)
    containers = generate_containers(cloud_cfg, instances, rng)
    employees = _build_full_employees(cfg, users, devices, groups, baseline_instant, scenario_id, rng)
    _validate_employees_privileged_mfa(employees)
    return {
        "company": {
            "id": cfg.company_id,
            "name": cfg.company_name,
            "domain": cfg.domain,
            "locations": list(cfg.locations),
        },
        "departments": departments,
        "groups": groups,
        "devices": devices,
        "mailboxes": mailboxes,
        "network": network,
        "employees": employees,  # Changed from "workers" to "employees"
        "cloud": {
            "instances": instances,
            "containers": containers,
        },
    }


def _parse_distribution_spec(value: Any) -> Union[DistributionSpec, float, int]:
    """Parse a YAML value into a DistributionSpec or static value.

    Args:
        value: Either a dict with mean/std keys, or a static numeric value

    Returns:
        DistributionSpec if dict format, otherwise the original value
    """
    if isinstance(value, dict) and "mean" in value:
        return DistributionSpec(
            mean=value["mean"],
            std=value.get("std", 0),
            min_val=value.get("min_val"),
            max_val=value.get("max_val"),
        )
    return value


def _parse_login_baseline_spec(data: Optional[Dict]) -> Optional[LoginBaselineSpec]:
    """Parse login baseline spec from YAML data."""
    if not data:
        return None

    vpn_pct = None
    if "vpn_pct" in data:
        vpn_pct = _parse_distribution_spec(data["vpn_pct"])

    return LoginBaselineSpec(
        vpn_pct=vpn_pct,
        hours=data.get("hours"),
        asn=data.get("asn"),
        isps=data.get("isps"),
    )


def _parse_email_baseline_spec(data: Optional[Dict]) -> Optional[EmailBaselineSpec]:
    """Parse email baseline spec from YAML data."""
    if not data:
        return None

    avg_inbound = None
    if "avg_inbound_per_day" in data:
        avg_inbound = _parse_distribution_spec(data["avg_inbound_per_day"])

    return EmailBaselineSpec(
        avg_inbound_per_day=avg_inbound,
        trusted_domains=data.get("trusted_domains"),
        typical_attachments=data.get("typical_attachments"),
    )


def _parse_baseline_spec(data: Optional[Dict]) -> Optional[BaselineSpec]:
    """Parse baseline spec from YAML data."""
    if not data:
        return None

    return BaselineSpec(
        login_baseline=_parse_login_baseline_spec(data.get("login_baseline")),
        email_baseline=_parse_email_baseline_spec(data.get("email_baseline")),
        process_baseline=data.get("process_baseline"),
        net_baseline=data.get("net_baseline"),
    )


def _parse_role_policy(data: Dict) -> RolePolicy:
    """Parse a role policy from YAML data."""
    baselines = _parse_baseline_spec(data.get("baselines"))
    return RolePolicy(baselines=baselines or BaselineSpec())


def _parse_noise_config(data: Optional[Dict]) -> NoiseConfig:
    """Parse noise configuration from YAML data."""
    if not data:
        return NoiseConfig()

    return NoiseConfig(
        enabled=data.get("enabled", True),
        numeric_noise_pct=data.get("numeric_noise_pct", 0.05),
    )


def _load_company_config_from_yaml(
    yaml_path: str,
    seed: int,
    baseline_date: str,
) -> CompanyConfig:
    """Load CompanyConfig from YAML file with role_policies support.

    Args:
        yaml_path: Path to the YAML configuration file
        seed: Random seed for deterministic generation
        baseline_date: Baseline date string (unused in config, for reference)

    Returns:
        CompanyConfig populated from YAML file

    The YAML file should have the following structure:
    ```yaml
    company_id: "corp_001"
    company_name: "Acme Corp"
    domain: "corp.example"
    num_employees: 1000
    locations: ["US-NY", "US-CA"]
    departments: ["Engineering", "Finance", ...]

    role_policies:
      "Engineering - Software Engineer":
        baselines:
          login_baseline:
            vpn_pct: { mean: 0.15, std: 0.05 }
            hours: ["08:00-10:00", "17:00-20:00"]
          email_baseline:
            avg_inbound_per_day: { mean: 35, std: 10 }
          process_baseline: ["chrome", "vscode", "terminal"]
          net_baseline: ["api.github.com", "npm.org"]

    defaults:
      baseline_policy:
        baselines:
          login_baseline:
            vpn_pct: { mean: 0.2, std: 0.05 }
          email_baseline:
            avg_inbound_per_day: { mean: 45, std: 10 }

    noise_config:
      enabled: true
      numeric_noise_pct: 0.05
    ```
    """
    path = Path(yaml_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {yaml_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    # Parse role policies
    role_policies: Dict[str, RolePolicy] = {}
    if "role_policies" in data:
        for role_key, policy_data in data["role_policies"].items():
            role_policies[role_key] = _parse_role_policy(policy_data)

    # Parse default baseline policy
    default_baseline_policy = None
    if "defaults" in data and "baseline_policy" in data["defaults"]:
        default_baseline_policy = _parse_role_policy(data["defaults"]["baseline_policy"])

    # Parse noise config
    noise_config = _parse_noise_config(data.get("noise_config"))

    # Parse locations and departments (convert to tuples)
    locations = tuple(data.get("locations", ("US-NY", "US-CA", "NL-AMS", "IN-BLR")))
    departments = tuple(data.get("departments", (
        "Executive", "Finance", "HR", "Engineering", "IT",
        "Sales", "Marketing", "Support", "Legal", "Security"
    )))

    return CompanyConfig(
        company_id=data.get("company_id", "corp_001"),
        company_name=data.get("company_name", "Acme Corp"),
        domain=data.get("domain", "corp.example"),
        num_employees=data.get("num_employees", 1000),
        seed=seed,
        locations=locations,
        departments=departments,
        role_policies=role_policies,
        default_baseline_policy=default_baseline_policy,
        noise_config=noise_config,
    )


def main():
    parser = argparse.ArgumentParser(description="Generate deterministic company fixture (~1000 employees)")
    parser.add_argument("--config", help="Path to YAML config file with role_policies (optional)")
    parser.add_argument("--company-id", default="corp_001")
    parser.add_argument("--company-name", default="Acme Corp")
    parser.add_argument("--domain", default="corp.example")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--employees", type=int, default=1000)
    parser.add_argument("--baseline-date", default="2025-10-01", help="Baseline date (YYYY-MM-DD), recent activity generated within prior month")
    parser.add_argument("--scenario-id", default="scenario_default")
    parser.add_argument("--out", required=True, help="Output JSON file path")
    args = parser.parse_args()

    # Validate baseline-date format
    try:
        datetime.strptime(args.baseline_date, "%Y-%m-%d")
    except ValueError as exc:
        raise SystemExit(f"Invalid --baseline-date '{args.baseline_date}', expected YYYY-MM-DD") from exc

    # Load config from YAML or use CLI arguments
    if args.config:
        cfg = _load_company_config_from_yaml(args.config, args.seed, args.baseline_date)
        # CLI overrides for employees count if specified and different from default
        if args.employees != 1000:
            cfg.num_employees = args.employees
        # CLI overrides for company metadata if specified and different from defaults
        if args.company_id != "corp_001":
            cfg.company_id = args.company_id
        if args.company_name != "Acme Corp":
            cfg.company_name = args.company_name
        if args.domain != "corp.example":
            cfg.domain = args.domain
    else:
        cfg = CompanyConfig(
            company_id=args.company_id,
            company_name=args.company_name,
            domain=args.domain,
            num_employees=args.employees,
            seed=args.seed,
        )

    data = generate_company(cfg, args.baseline_date, args.scenario_id)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Wrote company fixture: {args.out}")


if __name__ == "__main__":
    main()

