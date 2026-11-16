"""Threat intelligence capabilities — IOC reputation via attack ground truth."""

import hashlib
import json
import sqlite3
from typing import Any, Dict, List, Optional, Tuple


# -----------------------------------------------------------------------------
# Prior-activity attribution
#
# A real feed tells you what an indicator was reported for *before* — it does not
# name the campaign you are currently investigating. So a hit never reports the
# activity family the live attack belongs to; it reports a different family,
# picked deterministically from the indicator value so repeat lookups agree.
# -----------------------------------------------------------------------------

_ACTIVITY_FAMILIES: Dict[str, List[str]] = {
    "phishing": ["credential_harvesting", "phishing_page_hosting", "business_email_compromise"],
    "malware": ["malware_distribution", "loader_c2", "infostealer_c2"],
    "account_takeover": ["credential_stuffing", "password_spraying", "session_token_replay"],
    "exfiltration": ["data_exfiltration", "unauthorized_data_staging"],
    "lateral_movement": ["lateral_movement", "privilege_escalation", "persistence_tooling"],
    "cloud_abuse": ["cloud_resource_abuse", "cryptomining", "cloud_account_recon"],
    "supply_chain": ["supply_chain_compromise", "malicious_package_hosting"],
    "destructive": ["ransomware_deployment", "data_destruction"],
    # No catalog scenario maps here, so it is always a safe decoy family.
    "network_abuse": ["ssh_brute_force", "port_scanning", "web_app_attack", "spam_relay"],
}

# Catalog attack_type -> activity family.
_FAMILY_BY_ATTACK_TYPE: Dict[str, str] = {
    "phishing": "phishing",
    "aitm_phishing": "phishing",
    "device_code_phishing": "phishing",
    "consent_phishing": "phishing",
    "bec": "phishing",
    "malware": "malware",
    "account_takeover": "account_takeover",
    "credential_access": "account_takeover",
    "data_exfiltration": "exfiltration",
    "dlp": "exfiltration",
    "lateral_movement": "lateral_movement",
    "persistence": "lateral_movement",
    "privilege_escalation": "lateral_movement",
    "defense_evasion": "lateral_movement",
    "cloud_recon": "cloud_abuse",
    "cloud_execution": "cloud_abuse",
    "supply_chain": "supply_chain",
    "ransomware": "destructive",
    "impact": "destructive",
    "destruction": "destructive",
}

# Fallback when a scenario_id is not in the catalog (substring -> family).
_FAMILY_KEYWORDS: List[Tuple[str, str]] = [
    ("phish", "phishing"), ("lure", "phishing"), ("bec", "phishing"),
    ("consent", "phishing"), ("device_code", "phishing"), ("aitm", "phishing"),
    ("ransom", "destructive"), ("wiper", "destructive"), ("destruct", "destructive"),
    ("malware", "malware"), ("lnk", "malware"), ("dll", "malware"),
    ("dropper", "malware"), ("stealer", "malware"), ("rat", "malware"),
    ("macro", "malware"), ("lolbin", "malware"), ("fileless", "malware"),
    ("exfil", "exfiltration"), ("dlp", "exfiltration"), ("staging", "exfiltration"),
    ("theft", "exfiltration"), ("export", "exfiltration"),
    ("lateral", "lateral_movement"), ("persistence", "lateral_movement"),
    ("privilege", "lateral_movement"), ("scheduled_task", "lateral_movement"),
    ("gpo", "lateral_movement"), ("suppression", "lateral_movement"),
    ("cloud", "cloud_abuse"), ("container", "cloud_abuse"),
    ("crypto", "cloud_abuse"), ("s3", "cloud_abuse"),
    ("supply", "supply_chain"), ("pipeline", "supply_chain"), ("package", "supply_chain"),
    ("credential", "account_takeover"), ("password", "account_takeover"),
    ("mfa", "account_takeover"), ("kerberos", "account_takeover"),
    ("dcsync", "account_takeover"), ("ticket", "account_takeover"),
    ("token", "account_takeover"), ("takeover", "account_takeover"),
    ("login", "account_takeover"), ("travel", "account_takeover"),
]

# Ground-truth IOC field -> generic indicator type. The ground-truth field names
# encode the technique ("evilginx_domain", "phishing_url"), so a hit reports only
# the kind of indicator that matched, never the role it played in the attack.
_INDICATOR_TYPES: Dict[str, str] = {
    "attacker_domain": "domain", "phishing_domain": "domain", "c2_domain": "domain",
    "evilginx_domain": "domain", "malware_domain": "domain",
    "phishing_url": "url", "c2_url": "url", "payload_url": "url",
    "credential_harvest_url": "url",
    "attacker_ip": "ip", "c2_ip": "ip", "proxy_ip": "ip", "vpn_ip": "ip",
    "login_ip": "ip",
    "malware_hash": "file_hash", "payload_hash": "file_hash", "dropper_hash": "file_hash",
    "attacker_email": "email_address", "phishing_sender": "email_address",
    "c2_email": "email_address",
    "malware_filename": "filename", "payload_filename": "filename",
    "dropper_filename": "filename", "attachment_filename": "filename",
}

_SCENARIO_ATTACK_TYPES: Optional[Dict[str, str]] = None


def _scenario_attack_types() -> Dict[str, str]:
    """Lazy-load the scenario_id -> attack_type map from the attack catalog."""
    global _SCENARIO_ATTACK_TYPES
    if _SCENARIO_ATTACK_TYPES is None:
        try:
            from attacks.scenarios import ATTACK_SCENARIOS  # noqa: PLC0415

            _SCENARIO_ATTACK_TYPES = {
                sid: getattr(scenario, "attack_type", "") or ""
                for sid, scenario in ATTACK_SCENARIOS.items()
            }
        except Exception:
            _SCENARIO_ATTACK_TYPES = {}
    return _SCENARIO_ATTACK_TYPES


def _live_family(scenario_id: Optional[str]) -> Optional[str]:
    """Activity family of the attack actually running — never reported."""
    if not scenario_id:
        return None
    attack_type = _scenario_attack_types().get(scenario_id, "")
    family = _FAMILY_BY_ATTACK_TYPE.get(attack_type)
    if family:
        return family
    sid = scenario_id.lower()
    for keyword, fam in _FAMILY_KEYWORDS:
        if keyword in sid:
            return fam
    return None


def _prior_activity(scenario_id: Optional[str], ioc_value: str) -> str:
    """Pick a reported activity from a family other than the live attack's.

    Deterministic in ``ioc_value``, so the same indicator always reports the
    same prior activity within and across lookups.
    """
    live = _live_family(scenario_id)
    if live is None:
        # Unknown scenario: fall back to the family no scenario can belong to.
        candidates = ["network_abuse"]
    else:
        candidates = [fam for fam in _ACTIVITY_FAMILIES if fam != live]

    digest = hashlib.sha256(ioc_value.lower().encode("utf-8")).digest()
    family = candidates[digest[0] % len(candidates)]
    labels = _ACTIVITY_FAMILIES[family]
    return labels[digest[1] % len(labels)]


def _association(
    attack_id: str,
    scenario_id: Optional[str],
    ioc_field: str,
    ioc_value: str,
) -> Dict[str, Any]:
    """Build one associated-attack entry with prior (not live) attribution."""
    return {
        "attack_id": attack_id,
        "reported_activity": _prior_activity(scenario_id, ioc_value),
        "indicator_type": _INDICATOR_TYPES.get(ioc_field, "indicator"),
    }


def _extract_iocs_from_ground_truth(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Load all attack ground truth and parse IOCs."""
    cursor = conn.cursor()
    cursor.execute("SELECT attack_id, scenario_id, iocs, success FROM attack_ground_truth")
    results = []
    for row in cursor.fetchall():
        iocs = {}
        if row[2]:
            try:
                iocs = json.loads(row[2]) if isinstance(row[2], str) else row[2]
            except (json.JSONDecodeError, TypeError):
                pass
        results.append({
            "attack_id": row[0],
            "scenario_id": row[1],
            "iocs": iocs,
            "success": bool(row[3]),
        })
    return results


def lookup_domain(
    conn: sqlite3.Connection,
    *,
    domain: str,
) -> Dict[str, Any]:
    """Look up a domain against known threat intelligence.

    Args:
        domain: Domain name to check.

    Returns:
        Dict with domain, verdict (malicious/unknown), and associated attacks —
        each carrying the activity the domain was previously reported for.
    """
    attacks = _extract_iocs_from_ground_truth(conn)
    associated = []

    for atk in attacks:
        iocs = atk["iocs"]
        domain_fields = [
            "attacker_domain", "phishing_domain", "c2_domain",
            "evilginx_domain", "malware_domain",
        ]
        for field in domain_fields:
            if iocs.get(field) and domain.lower() in iocs[field].lower():
                associated.append(
                    _association(atk["attack_id"], atk["scenario_id"], field, domain)
                )
                break
        # Also check URLs for the domain
        url_fields = ["phishing_url", "c2_url", "payload_url"]
        for field in url_fields:
            val = iocs.get(field, "")
            if val and domain.lower() in val.lower():
                if not any(a["attack_id"] == atk["attack_id"] for a in associated):
                    associated.append(
                        _association(atk["attack_id"], atk["scenario_id"], field, domain)
                    )
                break

    return {
        "domain": domain,
        "verdict": "malicious" if associated else "unknown",
        "associated_attacks": associated,
    }


def lookup_ip(
    conn: sqlite3.Connection,
    *,
    ip_address: str,
) -> Dict[str, Any]:
    """Look up an IP address against known threat intelligence.

    Args:
        ip_address: IP address to check.

    Returns:
        Dict with ip, verdict, and associated attacks — each carrying the
        activity the IP was previously reported for.
    """
    attacks = _extract_iocs_from_ground_truth(conn)
    associated = []

    for atk in attacks:
        iocs = atk["iocs"]
        ip_fields = ["attacker_ip", "c2_ip", "proxy_ip", "vpn_ip"]
        for field in ip_fields:
            if iocs.get(field) == ip_address:
                associated.append(
                    _association(atk["attack_id"], atk["scenario_id"], field, ip_address)
                )
                break

    # Also check login events for this IP linked to attacks
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT DISTINCT agt.attack_id, agt.scenario_id
        FROM login_events le
        JOIN attack_ground_truth agt ON agt.victim_id = le.employee_id
        WHERE le.ip = ? AND le.success = 1
        """,
        (ip_address,),
    )
    for row in cursor.fetchall():
        if not any(a["attack_id"] == row[0] for a in associated):
            associated.append(
                _association(row[0], row[1], "login_ip", ip_address)
            )

    return {
        "ip": ip_address,
        "verdict": "malicious" if associated else "unknown",
        "associated_attacks": associated,
    }


def lookup_hash(
    conn: sqlite3.Connection,
    *,
    file_hash: str,
) -> Dict[str, Any]:
    """Look up a file hash against known threat intelligence.

    Args:
        file_hash: SHA256 or other file hash to check.

    Returns:
        Dict with hash, verdict, first_seen, hosts_affected, and associated
        attacks — each carrying the activity the hash was previously reported for.
    """
    attacks = _extract_iocs_from_ground_truth(conn)
    associated = []

    for atk in attacks:
        iocs = atk["iocs"]
        hash_fields = ["malware_hash", "payload_hash", "dropper_hash"]
        for field in hash_fields:
            if iocs.get(field) == file_hash:
                associated.append(
                    _association(atk["attack_id"], atk["scenario_id"], field, file_hash)
                )
                break

    # Check process events for this hash
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT MIN(ts), COUNT(DISTINCT employee_id), COUNT(DISTINCT device_id)
        FROM process_events WHERE hash = ?
        """,
        (file_hash,),
    )
    row = cursor.fetchone()

    return {
        "hash": file_hash,
        "verdict": "malicious" if associated else "unknown",
        "first_seen": row[0] if row else None,
        "hosts_affected": row[2] if row else 0,
        "users_affected": row[1] if row else 0,
        "associated_attacks": associated,
    }


def lookup_url(
    conn: sqlite3.Connection,
    *,
    url: str,
) -> Dict[str, Any]:
    """Look up a URL against known threat intelligence.

    Args:
        url: URL to check.

    Returns:
        Dict with url, verdict, and associated attacks — each carrying the
        activity the URL was previously reported for.
    """
    attacks = _extract_iocs_from_ground_truth(conn)
    associated = []

    for atk in attacks:
        iocs = atk["iocs"]
        url_fields = ["phishing_url", "c2_url", "payload_url", "credential_harvest_url"]
        for field in url_fields:
            if iocs.get(field) and url.lower() in iocs[field].lower():
                associated.append(
                    _association(atk["attack_id"], atk["scenario_id"], field, url)
                )
                break

    # Also check email events for this URL
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM email_events WHERE contains_url LIKE ?",
        (f"%{url}%",),
    )
    email_count = cursor.fetchone()[0]

    return {
        "url": url,
        "verdict": "malicious" if associated else "unknown",
        "associated_attacks": associated,
        "seen_in_emails": email_count,
    }


def lookup_email_address(
    conn: sqlite3.Connection,
    *,
    email: str,
) -> Dict[str, Any]:
    """Look up an email address against known threat intelligence.

    Args:
        email: Email address to check.

    Returns:
        Dict with email, verdict, and associated attacks — each carrying the
        activity the address was previously reported for.
    """
    attacks = _extract_iocs_from_ground_truth(conn)
    associated = []

    for atk in attacks:
        iocs = atk["iocs"]
        email_fields = ["attacker_email", "phishing_sender", "c2_email"]
        for field in email_fields:
            if iocs.get(field) and email.lower() == iocs[field].lower():
                associated.append(
                    _association(atk["attack_id"], atk["scenario_id"], field, email)
                )
                break

    # Check if this is a known internal employee
    cursor = conn.cursor()
    cursor.execute("SELECT id, display_name FROM employees WHERE email = ?", (email,))
    emp_row = cursor.fetchone()

    # Count emails sent from this address
    cursor.execute("SELECT COUNT(*) FROM email_events WHERE sender = ?", (email,))
    sent_count = cursor.fetchone()[0]

    return {
        "email": email,
        "verdict": "malicious" if associated else "unknown",
        "is_internal": emp_row is not None,
        "employee_name": emp_row[1] if emp_row else None,
        "total_emails_sent": sent_count,
        "associated_attacks": associated,
    }


def lookup_filename(
    conn: sqlite3.Connection,
    *,
    filename: str,
) -> Dict[str, Any]:
    """Look up a filename against known threat intelligence.

    Args:
        filename: Filename to check.

    Returns:
        Dict with filename, verdict, and associated attacks/observations — each
        association carrying the activity the filename was previously reported for.
    """
    attacks = _extract_iocs_from_ground_truth(conn)
    associated = []

    for atk in attacks:
        iocs = atk["iocs"]
        filename_fields = [
            "malware_filename", "payload_filename", "dropper_filename",
            "attachment_filename",
        ]
        for field in filename_fields:
            if iocs.get(field) and filename.lower() in iocs[field].lower():
                associated.append(
                    _association(atk["attack_id"], atk["scenario_id"], field, filename)
                )
                break

    # Check process events for this filename
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT COUNT(*) as executions, COUNT(DISTINCT employee_id) as users,
               COUNT(DISTINCT device_id) as hosts, MIN(ts) as first_seen, MAX(ts) as last_seen
        FROM process_events WHERE process_name LIKE ? OR path LIKE ?
        """,
        (f"%{filename}%", f"%{filename}%"),
    )
    proc_row = cursor.fetchone()

    # Check email attachments for this filename
    cursor.execute(
        "SELECT COUNT(*) FROM email_events WHERE attachments LIKE ?",
        (f"%{filename}%",),
    )
    email_count = cursor.fetchone()[0]

    return {
        "filename": filename,
        "verdict": "malicious" if associated else "unknown",
        "associated_attacks": associated,
        "seen_in_processes": proc_row[0] if proc_row else 0,
        "users_affected": proc_row[1] if proc_row else 0,
        "hosts_affected": proc_row[2] if proc_row else 0,
        "first_seen": proc_row[3] if proc_row else None,
        "last_seen": proc_row[4] if proc_row else None,
        "seen_in_email_attachments": email_count,
    }


def get_known_iocs(
    conn: sqlite3.Connection,
    *,
    ioc_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List all known IOCs from attack ground truth.

    Args:
        ioc_type: Filter by IOC type (e.g. "domain", "ip", "hash", "url", "email").
                  None = return all.

    Returns:
        List of IOC dicts with type, value, and the attack reference the
        indicator is grouped under. The ground-truth field name and scenario are
        withheld — they would name the technique and the campaign outright.
    """
    attacks = _extract_iocs_from_ground_truth(conn)

    type_field_map = {
        "domain": ["attacker_domain", "phishing_domain", "c2_domain", "evilginx_domain", "malware_domain"],
        "ip": ["attacker_ip", "c2_ip", "proxy_ip", "vpn_ip"],
        "hash": ["malware_hash", "payload_hash", "dropper_hash"],
        "url": ["phishing_url", "c2_url", "payload_url", "credential_harvest_url"],
        "email": ["attacker_email", "phishing_sender", "c2_email"],
        "filename": ["malware_filename", "payload_filename", "dropper_filename", "attachment_filename"],
    }

    results: List[Dict[str, Any]] = []
    seen = set()

    for atk in attacks:
        iocs = atk["iocs"]
        for ioc_t, fields in type_field_map.items():
            if ioc_type and ioc_type != ioc_t:
                continue
            for field in fields:
                val = iocs.get(field)
                if val and (ioc_t, val) not in seen:
                    seen.add((ioc_t, val))
                    results.append({
                        "type": ioc_t,
                        "value": val,
                        "attack_id": atk["attack_id"],
                        "reported_activity": _prior_activity(atk["scenario_id"], val),
                    })

    return results
