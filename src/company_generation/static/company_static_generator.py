import argparse
import json
import random
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

import yaml

from ..company_generator import TITLES_BY_DEPT, deterministic_rng
from .cloud_assets import CloudConfig, generate_cloud_instances, generate_containers


# ----------------------------- Config models -----------------------------


@dataclass
class NamesPool:
    first: List[str] = field(
        default_factory=lambda: [
            "Alex",
            "Sam",
            "Taylor",
            "Jordan",
            "Casey",
            "Drew",
            "Riley",
            "Morgan",
            "Jamie",
            "Cameron",
            "Avery",
            "Quinn",
            "Hayden",
            "Parker",
            "Reese",
            "Rowan",
            "Elliot",
            "Logan",
            "Skyler",
            "Emerson",
        ]
    )
    last: List[str] = field(
        default_factory=lambda: [
            "Smith",
            "Johnson",
            "Williams",
            "Brown",
            "Jones",
            "Garcia",
            "Miller",
            "Davis",
            "Rodriguez",
            "Martinez",
            "Hernandez",
            "Lopez",
            "Gonzalez",
            "Wilson",
            "Anderson",
            "Thomas",
            "Taylor",
            "Moore",
            "Jackson",
            "Martin",
        ]
    )


@dataclass
class OverallConfig:
    employees: int = 1000
    names: NamesPool = field(default_factory=NamesPool)
    department_distribution: Mapping[str, float] = field(default_factory=dict)
    role_distribution: Mapping[str, Mapping[str, float]] = field(default_factory=dict)
    # Map: department -> { role -> manager_role }
    role_managers: Mapping[str, Mapping[str, str]] = field(default_factory=dict)


@dataclass
class RolePolicy:
    baselines: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DepartmentSpec:
    name: str
    manager_name: Optional[str] = None


@dataclass
class GroupSpec:
    id: str
    name: str
    description: str = ""
    members: List[str] = field(default_factory=list)  # emails
    authorisations: List[str] = field(default_factory=list)
    # New: allow selecting members by role titles instead of explicit emails
    member_roles: List[str] = field(default_factory=list)


@dataclass
class DevicesSpec:
    count: Optional[int] = None
    network_distribution: Mapping[str, float] = field(default_factory=dict)  # net_id -> weight


@dataclass
class DLSpec:
    address: str
    members_from_department: Optional[str] = None
    members: List[str] = field(default_factory=list)  # explicit emails
    delegate_count: int = 0


@dataclass
class MailboxesSpec:
    distribution_lists: List[DLSpec] = field(default_factory=list)


@dataclass
class CompanySpec:
    id: str
    name: str
    domain: str
    locations: Tuple[str, ...] = ("US-NY", "US-CA", "NL-AMS", "IN-BLR")


@dataclass
class NetworkSpec:
    id: str
    name: str
    cidr: str
    location: str


@dataclass
class StaticCompanyConfig:
    company: CompanySpec
    overall: OverallConfig = field(default_factory=OverallConfig)
    departments: List[DepartmentSpec] = field(default_factory=list)
    groups: List[GroupSpec] = field(default_factory=list)
    devices: DevicesSpec = field(default_factory=DevicesSpec)
    mailboxes: MailboxesSpec = field(default_factory=MailboxesSpec)
    seed: int = 1337
    baseline_date: str = "2025-10-01"
    # Optional: explicit networks
    networks: List[NetworkSpec] = field(default_factory=list)
    # Per-role policies and defaults
    role_policies: Mapping[str, RolePolicy] = field(default_factory=dict)
    default_role_policy: RolePolicy = field(default_factory=RolePolicy)
    # Raw generation config for temporal models, bursts, confounders
    generation_config: Dict[str, Any] = field(default_factory=dict)


# ------------------------------ YAML loader ------------------------------


def _load_yaml_config(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("Top-level YAML must be a mapping")
    return data


def _coerce_list(value: Any) -> List[str]:
    """
    Convert a YAML field that may be a list, tuple, string, or None into a clean list of strings.
    - Strings are split on commas to support comma-separated values in YAML.
    - Whitespace is trimmed; empty entries are discarded.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, tuple):
        return [str(v).strip() for v in list(value) if str(v).strip()]
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(",")]
        return [p for p in parts if p]
    # Fallback to single-item list
    s = str(value).strip()
    return [s] if s else []


def _coerce_static_config(data: Dict[str, Any], seed: int, baseline_date: str) -> StaticCompanyConfig:
    company_raw = data.get("company", {})
    if not all(k in company_raw for k in ("id", "name", "domain")):
        raise ValueError("company.id, company.name, company.domain are required in YAML")

    comp = CompanySpec(
        id=str(company_raw["id"]),
        name=str(company_raw["name"]),
        domain=str(company_raw["domain"]),
        locations=tuple(company_raw.get("locations") or ("US-NY", "US-CA", "NL-AMS", "IN-BLR")),
    )

    overall_raw = data.get("overall", {}) or {}
    names_raw = (overall_raw.get("names") or {})
    names = NamesPool(
        first=list(names_raw.get("first") or NamesPool().first),
        last=list(names_raw.get("last") or NamesPool().last),
    )
    overall = OverallConfig(
        employees=int(overall_raw.get("employees") or 1000),
        names=names,
        department_distribution=dict(overall_raw.get("department_distribution") or {}),
        role_distribution=dict(overall_raw.get("role_distribution") or {}),
        role_managers=dict(overall_raw.get("role_managers") or {}),
    )

    departments = [
        DepartmentSpec(name=str(d.get("name")), manager_name=d.get("manager_name"))
        for d in (data.get("departments") or [])
        if d and d.get("name")
    ]

    groups = [
        GroupSpec(
            id=str(g.get("id")),
            name=str(g.get("name")),
            description=str(g.get("description") or ""),
            members=_coerce_list(g.get("members")),
            authorisations=_coerce_list(g.get("authorisations")),
            member_roles=_coerce_list(g.get("member_roles")),
        )
        for g in (data.get("groups") or [])
        if g and g.get("id") and g.get("name")
    ]

    devices_raw = data.get("devices") or {}
    devices = DevicesSpec(
        count=(int(devices_raw.get("count")) if devices_raw.get("count") is not None else None),
        network_distribution=dict(devices_raw.get("network_distribution") or {}),
    )

    mboxes_raw = data.get("mailboxes") or {}
    dls: List[DLSpec] = []
    for dl in (mboxes_raw.get("distribution_lists") or []):
        if not dl or not dl.get("address"):
            continue
        dls.append(
            DLSpec(
                address=str(dl.get("address")),
                members_from_department=(dl.get("members_from_department") if dl.get("members_from_department") else None),
                members=list(dl.get("members") or []),
                delegate_count=int(dl.get("delegate_count") or 0),
            )
        )
    mailboxes = MailboxesSpec(distribution_lists=dls)

    # Optional: networks
    networks: List[NetworkSpec] = []
    for n in (data.get("networks") or []) or []:
        if not n:
            continue
        nid = str(n.get("id")) if n.get("id") is not None else None
        name = str(n.get("name")) if n.get("name") is not None else None
        cidr = str(n.get("cidr")) if n.get("cidr") is not None else None
        loc = str(n.get("location")) if n.get("location") is not None else None
        if nid and name and cidr and loc:
            networks.append(NetworkSpec(id=nid, name=name, cidr=cidr, location=loc))

    # Role policies and defaults
    def _coerce_role_policy(raw: Dict[str, Any]) -> RolePolicy:
        return RolePolicy(baselines=dict(raw.get("baselines") or {}))

    role_policies_raw = data.get("role_policies") or {}
    role_policies: Dict[str, RolePolicy] = {}
    for role, rp_raw in role_policies_raw.items():
        if not isinstance(rp_raw, dict):
            continue
        role_policies[str(role)] = _coerce_role_policy(rp_raw)

    defaults_raw = (data.get("defaults") or {}).get("baseline_policy") or {}
    default_role_policy = _coerce_role_policy(defaults_raw)

    # Generation config (temporal, bursts, confounders)
    generation_config = dict(data.get("generation_config") or {})

    return StaticCompanyConfig(
        company=comp,
        overall=overall,
        departments=departments,
        groups=groups,
        devices=devices,
        mailboxes=mailboxes,
        seed=int(data.get("seed") or seed),
        baseline_date=str(data.get("baseline_date") or baseline_date),
        networks=networks,
        role_policies=role_policies,
        default_role_policy=default_role_policy,
        generation_config=generation_config,
    )


# -------------------------- Generation primitives ------------------------


def _normalize(weights: Mapping[str, float]) -> Dict[str, float]:
    if not weights:
        return {}
    total = sum(float(v) for v in weights.values())
    if total <= 0:
        return {k: 1.0 / len(weights) for k in weights}
    return {k: float(v) / total for k, v in weights.items()}


def _titles_distribution_for_department(dept: str, role_dist: Mapping[str, Mapping[str, float]]) -> List[Tuple[str, float]]:
    # Executive department: all additional employees are Executive Assistants
    if dept == "Executive":
        return [("Executive Assistant", 1.0)]

    # All other departments: role_distribution is required
    custom = role_dist.get(dept)
    if not custom:
        raise ValueError(f"role_distribution is required for department '{dept}'. Please specify roles in the configuration.")

    nd = _normalize(custom)
    return list(nd.items())


def _rank_title(t: str) -> int:
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


def _choose_weighted(rng: random.Random, items: List[Tuple[str, float]]) -> str:
    labels = [i[0] for i in items]
    weights = [i[1] for i in items]
    return rng.choices(labels, weights=weights, k=1)[0]


def _generate_departments(cfg: StaticCompanyConfig) -> List[Dict[str, Any]]:
    names = [d.name for d in cfg.departments] or list(TITLES_BY_DEPT.keys())
    # Ensure Executive exists to host C-suite
    if "Executive" not in names:
        names = ["Executive"] + names
    departments: List[Dict[str, Any]] = []
    for i, name in enumerate(names):
        departments.append({"id": f"dept_{i}", "name": name, "manager_user_id": None})
    return departments


def _generate_users(cfg: StaticCompanyConfig, departments: List[Dict[str, Any]], rng: random.Random) -> List[Dict[str, Any]]:
    num = cfg.overall.employees
    first_names = cfg.overall.names.first
    last_names = cfg.overall.names.last

    dept_names = [d["name"] for d in departments]
    default_dist = {name: 1.0 / len(departments) for name in dept_names} if departments else {}
    dept_dist = default_dist.copy()
    custom_dist = _normalize(cfg.overall.department_distribution)
    for k, v in custom_dist.items():
        if k in dept_dist:
            dept_dist[k] = v
    # Normalize again
    dept_dist = _normalize(dept_dist)

    # Precompute choices list aligned to department ids
    name_to_id = {d["name"]: d["id"] for d in departments}
    dept_ids = [name_to_id[n] for n in dept_names]
    weights = [dept_dist[n] for n in dept_names]

    users: List[Dict[str, Any]] = []
    email_taken: Dict[str, int] = {}

    def _new_email(first: str, last: str) -> str:
        email_base = f"{first}.{last}".lower()
        count = email_taken.get(email_base, 0)
        email = f"{email_base}@{cfg.company.domain}" if count == 0 else f"{email_base}{count+1}@{cfg.company.domain}"
        email_taken[email_base] = count + 1
        return email

    def _make_user(uidx: int, dept_id: str, dept_name: str, title: str, manager_id: Optional[str] = None, location: Optional[str] = None) -> Dict[str, Any]:
        first = rng.choice(first_names)
        last = rng.choice(last_names)
        email = _new_email(first, last)
        return {
            "id": f"u_{uidx:04d}",
            "email": email,
            "display_name": f"{first} {last}",
            "department_id": dept_id,
            "department": dept_name,
            "title": title,
            "manager_id": manager_id,
            "location": location if location is not None else rng.choice(list(cfg.company.locations)),
        }
    # Seed C-suite in Executive + their assistants
    exec_dept = next((d for d in departments if d["name"] == "Executive"), None)
    exec_dept_id = exec_dept["id"] if exec_dept else departments[0]["id"]
    exec_roles = ["CEO", "COO", "CTO", "CFO", "CMO", "CHRO", "CIO"]
    next_uidx = 0
    for role in exec_roles:
        if len(users) >= num:
            break
        exec_user = _make_user(next_uidx, exec_dept_id, "Executive", role)
        users.append(exec_user)
        next_uidx += 1
        # Assistant if capacity allows
        if len(users) < num:
            asst = _make_user(next_uidx, exec_dept_id, "Executive", "Executive Assistant", manager_id=exec_user["id"], location=exec_user["location"])
            users.append(asst)
            next_uidx += 1

    # Generate remaining employees per distributions
    remaining = max(0, num - len(users))
    for _ in range(remaining):
        dept_id = rng.choices(dept_ids, weights=weights, k=1)[0]
        dept_name = next(d["name"] for d in departments if d["id"] == dept_id)
        title = _choose_weighted(rng, _titles_distribution_for_department(dept_name, cfg.overall.role_distribution))
        users.append(_make_user(next_uidx, dept_id, dept_name, title))
        next_uidx += 1

    # Managers assigned later via role_managers; fallback to seniority if none configured
    return users


def _apply_department_managers(cfg: StaticCompanyConfig, departments: List[Dict[str, Any]], users: List[Dict[str, Any]]) -> None:
    # Set manager_user_id per department, respecting requested manager_name when possible
    name_to_dept = {d.name: d for d in cfg.departments}
    by_dept_users: Dict[str, List[Dict[str, Any]]] = {}
    for u in users:
        by_dept_users.setdefault(u["department_id"], []).append(u)

    for d in departments:
        dept_name = d["name"]
        members = by_dept_users.get(d["id"], [])
        manager_id: Optional[str] = None
        spec = name_to_dept.get(dept_name)
        if spec and spec.manager_name:
            # Best-effort match by display_name
            for u in members:
                if u.get("display_name") == spec.manager_name:
                    manager_id = u["id"]
                    break
        if not manager_id and members:
            manager = sorted(members, key=lambda u: _rank_title(u["title"]))[0]
            manager_id = manager["id"]
        d["manager_user_id"] = manager_id


def _is_vp_or_csuite(title: str) -> bool:
    tl = title.lower()
    return ("vp" in tl) or any(k in tl for k in ["chief", "ceo", "coo", "cfo", "cto", "cmo", "chro", "cio", "general counsel"]) 


def _assign_managers_role_based(cfg: StaticCompanyConfig, departments: List[Dict[str, Any]], users: List[Dict[str, Any]], rng: random.Random) -> None:
    # Build indices
    users_by_id: Dict[str, Dict[str, Any]] = {u["id"]: u for u in users}
    by_dept_role: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for u in users:
        by_dept_role.setdefault((u["department_id"], u["title"]), []).append(u)

    # For each dept and role, assign managers according to overall.role_managers
    for d in departments:
        dept_id = d["id"]
        dept_name = d["name"]
        role_map = cfg.overall.role_managers.get(dept_name, {})

        # First, ensure assistants report to their exec
        execs = [u for u in users if u["department_id"] == dept_id and u["title"] in ("CEO", "COO", "CTO", "CFO", "CMO", "CHRO", "CIO")]
        for exec_u in execs:
            for u in users:
                if u["department_id"] == dept_id and u["title"] == "Executive Assistant" and u.get("manager_id") is None:
                    u["manager_id"] = exec_u["id"]

        # For each role governed by a manager role, assign reports to managers of that role
        for role, mgr_role in role_map.items():
            members = list(by_dept_role.get((dept_id, role), []))
            if not members:
                continue
            mgrs = list(by_dept_role.get((dept_id, mgr_role), []))
            if not mgrs:
                # Fallback: most senior in dept
                dept_members = [u for u in users if u["department_id"] == dept_id]
                if not dept_members:
                    continue
                mgr_candidate = sorted(dept_members, key=lambda u: _rank_title(u["title"]))[0]
                mgrs = [mgr_candidate]
            # Homogenous teams: assign only this role's members to these managers
            # Round-robin across managers
            for idx, m in enumerate(members):
                m["manager_id"] = mgrs[idx % len(mgrs)]["id"]

        # For roles without explicit mapping, leave as-is; they'll be handled by seniority fallback later


def _generate_network(cfg: StaticCompanyConfig, users: List[Dict[str, Any]], last_updated: str) -> Dict[str, Any]:
    # Use explicit networks if provided
    if cfg.networks:
        subnets = [
            {"id": n.id, "cidr": n.cidr, "location": n.location, "name": n.name}
            for n in cfg.networks
        ]
        # Validate unique ids
        seen = set()
        uniq = []
        for s in subnets:
            if s["id"] in seen:
                continue
            seen.add(s["id"])
            uniq.append(s)
        return {"subnets": uniq, "lastUpdated": last_updated}

    # Auto-generate networks: max 300 employees per network per location
    # Count employees per location
    employees_by_location: Dict[str, int] = {}
    for user in users:
        loc = user.get("location")
        if loc:
            employees_by_location[loc] = employees_by_location.get(loc, 0) + 1

    subnets: List[Dict[str, Any]] = []
    net_idx = 0
    for i, loc in enumerate(cfg.company.locations):
        emp_count = employees_by_location.get(loc, 0)
        # Create one network per 300 employees (rounded up)
        networks_needed = max(1, (emp_count + 299) // 300)  # ceiling division

        for net_num in range(networks_needed):
            base_octet = 10 + net_idx
            cidr = f"{base_octet}.10.10.0/24"
            suffix = f"-{net_num + 1}" if networks_needed > 1 else ""
            subnets.append({
                "id": f"net_{net_idx}",
                "cidr": cidr,
                "location": loc,
                "name": f"corp-{loc.lower()}{suffix}"
            })
            net_idx += 1

    return {"subnets": subnets, "lastUpdated": last_updated}


def _generate_devices(cfg: StaticCompanyConfig, users: List[Dict[str, Any]], network: Dict[str, Any], rng: random.Random) -> List[Dict[str, Any]]:
    subnet_ids = [s["id"] for s in network.get("subnets", [])]

    # Helper: choose subnet preferring user's location
    subnets_by_loc: Dict[str, List[str]] = {}
    for s in network.get("subnets", []):
        subnets_by_loc.setdefault(s["location"], []).append(s["id"])

    # Fallback distribution across subnets if needed
    dist = _normalize(cfg.devices.network_distribution)
    if not dist and subnet_ids:
        dist = {sid: 1.0 / len(subnet_ids) for sid in subnet_ids}

    def pick_subnet_for_user(user: Dict[str, Any]) -> str:
        loc = user.get("location")
        loc_subnets = subnets_by_loc.get(loc) or []
        if loc_subnets:
            return rng.choice(loc_subnets)
        # fallback by distribution
        labels = list(dist.keys())
        weights = [dist.get(sid, 0.0) for sid in labels]
        if not labels:
            return "net_0"
        if sum(weights) <= 0:
            return rng.choice(labels)
        return rng.choices(labels, weights=weights, k=1)[0]

    def _os_choice(weights: Mapping[str, float]) -> str:
        labels = list(weights.keys())
        probs = list(_normalize(weights).values())
        return rng.choices(labels, weights=probs, k=1)[0]

    devices: List[Dict[str, Any]] = []
    dev_idx = 0

    # If role policies exist (or defaults), generate per-employee counts; else legacy behavior
    # if cfg.role_policies or cfg.default_role_policy:
    #     for user in users:
    #         pol = cfg.role_policies.get(user["title"]) or cfg.default_role_policy
    #         count = max(0, int(pol.devices.count))
    #         for _ in range(count):
    #             subnet_id = pick_subnet_for_user(user) if subnet_ids else "net_0"
    #             ip_address = f"10.{10 + (subnet_ids.index(subnet_id) if subnet_id in subnet_ids else 0)}.{(dev_idx // 250) % 256}.{(dev_idx % 250) + 5}"
    #             hostname = f"{user['display_name'].split()[0]}-{user['id'].split('_')[1]}".upper()
    #             devices.append({
    #                 "id": f"dev_{dev_idx:05d}",
    #                 "hostname": hostname,
    #                 "os": _os_choice(pol.devices.os_weights),
    #                 "owner_user_id": user["id"],
    #                 "ip_address": ip_address,
    #                 "network_id": subnet_id,
    #             })
    #             dev_idx += 1
    #     return devices

    # Legacy behavior: fixed device count distributed across network, round-robin owners
    dev_count = cfg.devices.count if cfg.devices.count is not None else max(len(users), 0)
    owner_index = 0
    for _ in range(dev_count):
        owner = users[owner_index % len(users)] if users else None
        owner_index += 1
        subnet_id = pick_subnet_for_user(owner) if subnet_ids and owner else (subnet_ids[0] if subnet_ids else "net_0")
        ip_address = f"10.{10 + (subnet_ids.index(subnet_id) if subnet_id in subnet_ids else 0)}.{(dev_idx // 250) % 256}.{(dev_idx % 250) + 5}"
        hostname = f"{(owner.get('display_name').split()[0] if owner else 'HOST')}-{(owner.get('id').split('_')[1] if owner else f'{dev_idx:05d}')}".upper()
        devices.append({
            "id": f"dev_{dev_idx:05d}",
            "hostname": hostname,
            "os": rng.choices(["Windows", "macOS", "Linux"], weights=[0.6, 0.35, 0.05], k=1)[0],
            "owner_user_id": owner.get("id") if owner else None,
            "ip_address": ip_address,
            "network_id": subnet_id,
        })
        dev_idx += 1
    return devices


def _generate_groups(cfg: StaticCompanyConfig, users: List[Dict[str, Any]], rng: random.Random) -> List[Dict[str, Any]]:
    email_to_id = {u["email"]: u["id"] for u in users}
    users_by_title: Dict[str, List[str]] = {}
    for u in users:
        users_by_title.setdefault(u["title"].lower(), []).append(u["id"])
    # Support selecting members by "Department - Title" as well
    users_by_dept_title: Dict[Tuple[str, str], List[str]] = {}
    for u in users:
        users_by_dept_title.setdefault((u["department"].lower(), u["title"].lower()), []).append(u["id"])
    groups: List[Dict[str, Any]] = []

    if cfg.groups:
        for g in cfg.groups:
            # From explicit member emails
            members_ids = [email_to_id[e] for e in g.members if e in email_to_id]
            # From role titles (case-insensitive exact match)
            for role in g.member_roles:
                r = str(role).strip()
                rl = r.lower()
                # Prefer explicit "Department - Title" match when provided
                dept_name: Optional[str] = None
                title_name: Optional[str] = None
                if " - " in r:
                    dept_name, title_name = r.split(" - ", 1)
                elif "-" in r and r.count("-") == 1:
                    # Be forgiving about missing spaces around hyphen
                    dept_name, title_name = r.split("-", 1)
                if dept_name is not None and title_name is not None:
                    key = (dept_name.strip().lower(), title_name.strip().lower())
                    members_ids.extend(users_by_dept_title.get(key, []))
                else:
                    # Fallback to role-only (title) across all departments
                    members_ids.extend(users_by_title.get(rl, []))
            # dedupe
            members_ids = sorted(set(members_ids))
            groups.append(
                {
                    "id": g.id,
                    "name": g.name,
                    "description": g.description,
                    "members": members_ids,
                    "authorisations": g.authorisations,
                }
            )
        return groups

    # Auto-generate: department groups, VIPs, Admins
    by_dept: Dict[str, List[str]] = {}
    dept_id_to_name: Dict[str, str] = {}
    for u in users:
        by_dept.setdefault(u["department_id"], []).append(u["id"])
        dept_id_to_name.setdefault(u["department_id"], u.get("department", u["department_id"]))
    for dept_id, member_ids in by_dept.items():
        dept_name = dept_id_to_name.get(dept_id, dept_id)
        groups.append({"id": f"grp_{dept_id}", "name": f"{dept_name} - All", "description": f"All users in {dept_name}", "members": member_ids, "authorisations": []})

    # VIPs by title pattern
    vip_ids = [u["id"] for u in users if _rank_title(u["title"]) <= 1]
    groups.append({"id": "grp_vips", "name": "VIPs", "description": "Executives and designated VIPs", "members": vip_ids, "authorisations": []})

    # Admins: IT/Security engineers and directors
    admin_ids = [
        u["id"]
        for u in users
        if u["department"] in ("IT", "Security") and any(k in u["title"].lower() for k in ["director", "engineer", "admin", "analyst"])
    ]
    groups.append({"id": "grp_admins", "name": "Admins", "description": "Privileged administrators", "members": admin_ids[: max(5, int(0.02 * len(users)))], "authorisations": []})
    return groups


def _apply_role_policies_to_users(cfg: StaticCompanyConfig, users: List[Dict[str, Any]]) -> None:
    """Populate behavior_baselines on each employee from role_policies."""
    for u in users:
        dept = u.get("department", "")
        title = u.get("title", "")
        role_key = f"{dept} - {title}"
        pol = cfg.role_policies.get(role_key) or cfg.default_role_policy
        u["behavior_baselines"] = dict(pol.baselines)


def _generate_mailboxes(cfg: StaticCompanyConfig, users: List[Dict[str, Any]], groups: List[Dict[str, Any]], rng: random.Random) -> List[Dict[str, Any]]:
    mailboxes: List[Dict[str, Any]] = []

    # Personal mailboxes for every employee
    created_at = f"{cfg.baseline_date}T09:00:00Z"
    for u in users:
        mailboxes.append(
            {
                "address": u["email"],
                "created_at": created_at,
                "is_distribution_list": False,
                "members": [],
                "delegates": [],
                "rules": [],
            }
        )

    # Distribution lists: configured or auto per department
    by_dept_emails: Dict[str, List[str]] = {}
    for u in users:
        by_dept_emails.setdefault(u["department"], []).append(u["email"])

    if cfg.mailboxes and cfg.mailboxes.distribution_lists:
        for dl in cfg.mailboxes.distribution_lists:
            members: List[str] = list(dl.members)
            if dl.members_from_department:
                members.extend(by_dept_emails.get(dl.members_from_department, []))
            members = sorted(set(members))
            delegates = rng.sample(members, k=min(len(members), max(0, dl.delegate_count))) if members and dl.delegate_count > 0 else []
            mailboxes.append(
                {
                    "address": dl.address,
                    "created_at": created_at,
                    "is_distribution_list": True,
                    "members": members,
                    "delegates": sorted(set(delegates)),
                    "rules": [],
                }
            )
        # do not return yet; we may add group DLs below

    # Auto-generate one DL per department when none provided
    if not (cfg.mailboxes and cfg.mailboxes.distribution_lists):
        for dept, emails in by_dept_emails.items():
            if not emails:
                continue
            addr = f"{dept.lower().replace(' ', '-') }@{cfg.company.domain}"
            members = rng.sample(emails, k=min(len(emails), max(3, int(0.2 * len(emails)))))
            delegates = rng.sample(members, k=min(len(members), max(1, len(members) // 10)))
            mailboxes.append(
                {
                    "address": addr,
                    "created_at": created_at,
                    "is_distribution_list": True,
                    "members": sorted(set(members)),
                    "delegates": sorted(set(delegates)),
                    "rules": [],
                }
            )

    # Add a DL for each group
    existing = {m["address"] for m in mailboxes}
    for g in groups:
        addr = f"{g['id']}@{cfg.company.domain}"
        if addr in existing:
            continue
        # members are user emails derived from ids
        id_to_email = {u["id"]: u["email"] for u in users}
        members = sorted(id_to_email.get(uid) for uid in g.get("members", []) if id_to_email.get(uid))
        mailboxes.append(
            {
                "address": addr,
                "created_at": created_at,
                "is_distribution_list": True,
                "members": members,
                "delegates": [],
                "rules": [],
            }
        )
    return mailboxes


# ----------------------------- Orchestration -----------------------------


def generate_company_static(cfg: StaticCompanyConfig) -> Dict[str, Any]:
    rng = deterministic_rng(cfg.seed)
    departments = _generate_departments(cfg)
    users = _generate_users(cfg, departments, rng)
    # Apply role-based attributes first
    _apply_role_policies_to_users(cfg, users)
    # Manager assignment: role-based when configured, else seniority fallback
    if cfg.overall.role_managers:
        _assign_managers_role_based(cfg, departments, users, rng)
    # Always ensure department manager links set
    _apply_department_managers(cfg, departments, users)
    baseline_instant = f"{cfg.baseline_date}T00:00:00Z"
    network = _generate_network(cfg, users, baseline_instant)
    devices = _generate_devices(cfg, users, network, rng)
    groups = _generate_groups(cfg, users, rng)
    # Propagate group authorisations to users
    if cfg.groups:
        auth_by_group = {g.id: g.authorisations for g in cfg.groups}
        groups_by_id = {g["id"]: g for g in groups}
        for g_id, auths in auth_by_group.items():
            g_doc = groups_by_id.get(g_id)
            if not g_doc:
                continue
            member_ids = set(g_doc.get("members", []))
            for u in users:
                if u["id"] in member_ids:
                    u.setdefault("authorisations", [])
                    u["authorisations"] = sorted(set(u["authorisations"]) | set(auths))
    mailboxes = _generate_mailboxes(cfg, users, groups, rng)
    # Default cloud assets when not specified in YAML (no YAML controls yet; can add later)
    cloud_cfg = CloudConfig()
    instances = generate_cloud_instances(cloud_cfg, rng)
    containers = generate_containers(cloud_cfg, instances, rng)
    return {
        "company": {
            "id": cfg.company.id,
            "name": cfg.company.name,
            "domain": cfg.company.domain,
            "locations": list(cfg.company.locations),
        },
        "departments": departments,
        "employees": users,
        "groups": groups,
        "devices": devices,
        "mailboxes": mailboxes,
        "network": network,
        "cloud": {"instances": instances, "containers": containers},
        "_generation_config": cfg.generation_config,
    }


# ---------------------------------- CLI ----------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate static company fixture from YAML config")
    parser.add_argument("--config", required=True, help="Path to YAML config")
    parser.add_argument("--out-dir", default="bench/fixtures", help="Output base directory")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--baseline-date", default="2025-10-01", help="Baseline date (YYYY-MM-DD)")
    args = parser.parse_args()

    # Validate baseline-date format early
    try:
        datetime.strptime(args.baseline_date, "%Y-%m-%d")
    except ValueError as exc:
        raise SystemExit(f"Invalid --baseline-date '{args.baseline_date}', expected YYYY-MM-DD") from exc

    cfg_path = Path(args.config)
    raw = _load_yaml_config(cfg_path)
    cfg = _coerce_static_config(raw, seed=args.seed, baseline_date=args.baseline_date)

    out_dir = Path(args.out_dir) / cfg.company.id
    out_dir.mkdir(parents=True, exist_ok=True)

    static_doc = generate_company_static(cfg)
    out_path = out_dir / "company_static.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(static_doc, f, indent=2)
    print(f"Wrote static company: {out_path}")


if __name__ == "__main__":
    main()


