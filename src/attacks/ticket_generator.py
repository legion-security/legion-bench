"""
Auto-generate scenario ticket YAMLs from attack ground truth.

Given company data with injected attacks, produces YAML files matching
the format expected by the SOC agent runner (twin/run_scenario.py).

Usage:
    from attacks.ticket_generator import generate_tickets, save_tickets

    tickets = generate_tickets(company_data, "path/to/company.json")
    paths = save_tickets(tickets, "scenarios/")
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


# ---------------------------------------------------------------------------
# IOC key → category mapping
# ---------------------------------------------------------------------------

IOC_KEY_CATEGORIES: Dict[str, str] = {
    "attacker_ip": "ips",
    "attacker_email": "emails",
    "attacker_domain": "domains",
    "phishing_domain": "domains",
    "c2_domain": "domains",
    "evilginx_domain": "domains",
    "miner_pool": "domains",
    "phishing_url": "urls",
    "c2_url": "urls",
    "download_url": "urls",
    "external_destination": "urls",
}

# Keys to skip when categorizing IOCs (informational, not network indicators)
_SKIP_IOC_KEYS = {"attacker_geo", "malware_name", "token_stealer_name", "attacker_user_agent"}


# ---------------------------------------------------------------------------
# Alert templates for all 17 scenarios
# ---------------------------------------------------------------------------

ALERT_TEMPLATES: Dict[str, dict] = {
    # ── Phishing ──────────────────────────────────────────────────────────
    "docusign_credential_harvest": {
        "title_template": "Anomalous sign-in detected for {victim_email}",
        "severity": "high",
        "source": "splunk_es",
        "description_template": (
            "Splunk ES correlation rule triggered: a sign-in for {victim_email} "
            "at {compromise_ts} originated from a location and device not "
            "previously associated with this account. "
            "Investigate whether this activity is legitimate and determine the "
            "root cause."
        ),
        "difficulty": "easy",
        "tags": ["phishing", "credential_theft", "account_compromise"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "microsoft_365_credential_harvest": {
        "title_template": "Anomalous sign-in from unrecognized device for {victim_email}",
        "severity": "high",
        "source": "splunk_es",
        "description_template": (
            "Splunk ES correlation rule triggered: a sign-in for {victim_email} "
            "at {compromise_ts} used an unrecognized device and originated from "
            "a location not previously seen for this user. "
            "Investigate whether this activity is legitimate and determine the "
            "root cause."
        ),
        "difficulty": "easy",
        "tags": ["phishing", "credential_theft", "account_compromise"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "it_support_malware": {
        "title_template": "Endpoint behavioral detection for {victim_email}",
        "severity": "critical",
        "source": "crowdstrike",
        "description_template": (
            "CrowdStrike Falcon triggered a behavioral detection on the endpoint "
            "associated with {victim_email} at {compromise_ts}. A process "
            "execution matched suspicious activity patterns. "
            "Investigate the process chain and determine the full scope of "
            "activity on this endpoint."
        ),
        "difficulty": "medium",
        "tags": ["phishing", "malware", "c2"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "voicemail_phishing": {
        "title_template": "Suspicious authentication activity for {victim_email}",
        "severity": "high",
        "source": "splunk_es",
        "description_template": (
            "Splunk ES correlation rule triggered: an authentication anomaly was "
            "detected for {victim_email} at {compromise_ts}. The session "
            "characteristics do not match the user's typical sign-in patterns. "
            "Investigate the authentication events and any preceding activity "
            "that may explain how the session was established."
        ),
        "difficulty": "medium",
        "tags": ["phishing", "mfa_bypass", "credential_theft"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "vendor_invoice_qr": {
        "title_template": "Suspicious inbound email flagged for {victim_email}",
        "severity": "medium",
        "source": "defender_o365",
        "description_template": (
            "Defender for Office 365 flagged a suspicious inbound email to "
            "{victim_email} containing an attachment that matched heuristic "
            "detection rules. "
            "Investigate the email, determine whether the user interacted with "
            "the attachment, and assess any subsequent account activity."
        ),
        "difficulty": "medium",
        "tags": ["phishing", "qr_code", "credential_theft"],
        "initial_indicator_keys": [("victim_email", "email")],
    },

    # ── Account Takeover ──────────────────────────────────────────────────
    "credential_stuffing_impossible_travel": {
        "title_template": "Multiple failed authentications followed by successful sign-in for {victim_email}",
        "severity": "high",
        "source": "splunk_es",
        "description_template": (
            "Splunk ES correlation rule triggered: multiple failed authentication "
            "attempts were observed for {victim_email}, followed by a successful "
            "sign-in at {compromise_ts}. "
            "Investigate the source of the authentication attempts, review login "
            "patterns, and determine whether the account has been compromised."
        ),
        "difficulty": "medium",
        "tags": ["account_takeover", "credential_stuffing", "impossible_travel"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "mfa_fatigue_push_bombing": {
        "title_template": "Unusual MFA activity detected for {victim_email}",
        "severity": "high",
        "source": "splunk_es",
        "description_template": (
            "Splunk ES correlation rule triggered: an anomalous volume of MFA "
            "push notifications was detected for {victim_email}, with one "
            "notification approved at {compromise_ts}. "
            "Investigate the MFA activity and any subsequent sign-in events."
        ),
        "difficulty": "medium",
        "tags": ["account_takeover", "mfa_fatigue", "push_bombing"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "session_hijacking_token_theft": {
        "title_template": "Endpoint detection and anomalous sign-in for {victim_email}",
        "severity": "critical",
        "source": "crowdstrike",
        "description_template": (
            "CrowdStrike Falcon flagged a suspicious process on the endpoint "
            "associated with {victim_email}. Shortly after, an anomalous "
            "authentication event was observed at {compromise_ts}. "
            "Investigate the endpoint activity and any related authentication "
            "events to determine scope."
        ),
        "difficulty": "hard",
        "tags": ["account_takeover", "session_hijacking", "token_theft"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "helpdesk_social_engineering": {
        "title_template": "New device enrollment after credential reset for {victim_email}",
        "severity": "high",
        "source": "entra_id",
        "description_template": (
            "Entra ID flagged a credential reset for {victim_email} followed by "
            "enrollment of a new device at {compromise_ts}. A sign-in from an "
            "unrecognized location occurred shortly after. "
            "Investigate the circumstances of the credential reset and subsequent "
            "account activity."
        ),
        "difficulty": "hard",
        "tags": ["account_takeover", "social_engineering", "helpdesk"],
        "initial_indicator_keys": [("victim_email", "email")],
    },

    # ── Malware ───────────────────────────────────────────────────────────
    "lolbins_attack": {
        "title_template": "Suspicious process chain detected on endpoint for {victim_email}",
        "severity": "critical",
        "source": "crowdstrike",
        "description_template": (
            "CrowdStrike Falcon detected a chain of suspicious process executions "
            "on the endpoint associated with {victim_email}, starting at "
            "{start_ts}. Multiple behavioral detection rules were triggered. "
            "Investigate the full process chain, identify any external "
            "communication, and determine the scope of compromise."
        ),
        "difficulty": "hard",
        "tags": ["malware", "lolbins", "living_off_the_land"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "ransomware_deployment": {
        "title_template": "Multiple critical endpoint alerts for {victim_email}",
        "severity": "critical",
        "source": "crowdstrike",
        "description_template": (
            "CrowdStrike Falcon generated multiple high-severity detections on "
            "the endpoint associated with {victim_email}. Suspicious activity "
            "was first detected at {start_ts}, with subsequent alerts indicating "
            "potential file system modifications. "
            "Immediate investigation required to determine scope and impact."
        ),
        "difficulty": "hard",
        "tags": ["malware", "ransomware", "lateral_movement"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "fileless_malware_powershell": {
        "title_template": "Suspicious script execution on endpoint for {victim_email}",
        "severity": "critical",
        "source": "crowdstrike",
        "description_template": (
            "CrowdStrike Falcon triggered a detection for suspicious script "
            "execution on the endpoint associated with {victim_email} at "
            "{compromise_ts}. Anomalous network activity was also observed "
            "from this host. "
            "Investigate the process execution chain, network connections, and "
            "determine the scope of impact."
        ),
        "difficulty": "hard",
        "tags": ["malware", "fileless", "powershell", "dns_tunneling"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "usb_malware_spread": {
        "title_template": "Suspicious activity following removable media event for {victim_email}",
        "severity": "high",
        "source": "crowdstrike",
        "description_template": (
            "CrowdStrike Falcon detected suspicious process activity on the "
            "endpoint associated with {victim_email} at {compromise_ts}, "
            "correlated with a removable media connection event. "
            "Investigate the endpoint activity and determine whether any "
            "propagation has occurred."
        ),
        "difficulty": "medium",
        "tags": ["malware", "usb", "cryptominer", "propagation"],
        "initial_indicator_keys": [("victim_email", "email")],
    },

    # ── DLP ────────────────────────────────────────────────────────────────
    "mass_download_resignation": {
        "title_template": "DLP policy alert: unusual file access volume for {victim_email}",
        "severity": "high",
        "source": "purview",
        "description_template": (
            "Microsoft Purview triggered a DLP policy alert for {victim_email} "
            "starting at {start_ts}. An unusual volume of file access activity "
            "was detected from corporate repositories. "
            "Investigate the scope of data access and determine whether any "
            "data was transferred externally."
        ),
        "difficulty": "medium",
        "tags": ["dlp", "data_exfiltration", "insider_threat"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "personal_email_exfil": {
        "title_template": "DLP policy alert: outbound email activity for {victim_email}",
        "severity": "medium",
        "source": "defender_o365",
        "description_template": (
            "Defender for Office 365 flagged outbound email activity from "
            "{victim_email} at {start_ts} that matched a DLP policy rule for "
            "sensitive content. "
            "Investigate the nature of the outbound content and whether it "
            "constitutes a policy violation."
        ),
        "difficulty": "easy",
        "tags": ["dlp", "data_exfiltration", "email"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "cloud_storage_sync_exfil": {
        "title_template": "DLP policy alert: unapproved application activity for {victim_email}",
        "severity": "high",
        "source": "purview",
        "description_template": (
            "Microsoft Purview flagged an application installation on the endpoint "
            "associated with {victim_email} at {start_ts} that does not match the "
            "approved software inventory. Subsequent data transfer activity was "
            "also observed. "
            "Investigate the application and associated data movement."
        ),
        "difficulty": "medium",
        "tags": ["dlp", "data_exfiltration", "cloud_storage"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
    "screenshot_print_exfil": {
        "title_template": "DLP policy alert: print and removable media activity for {victim_email}",
        "severity": "medium",
        "source": "purview",
        "description_template": (
            "Microsoft Purview detected print job and removable media file "
            "transfer activity associated with {victim_email} at {start_ts} "
            "that matched DLP policy rules for sensitive document handling. "
            "Investigate the documents involved and determine whether data "
            "removal occurred."
        ),
        "difficulty": "medium",
        "tags": ["dlp", "data_exfiltration", "physical"],
        "initial_indicator_keys": [("victim_email", "email")],
    },
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _is_resolved(value: str) -> bool:
    """Return False if the value still contains unresolved {placeholder} tokens."""
    return "{" not in value


def categorize_iocs(iocs: Dict[str, str]) -> Dict[str, List[str]]:
    """
    Categorize a flat IOC dict into grouped categories for the YAML output.

    Args:
        iocs: Dict mapping IOC key names to values (e.g. {"attacker_ip": "1.2.3.4"})

    Returns:
        Dict with keys "domains", "ips", "urls", "emails" — empty categories removed.
    """
    result: Dict[str, List[str]] = {}
    for key, value in iocs.items():
        if key in _SKIP_IOC_KEYS or not value or not _is_resolved(value):
            continue
        category = IOC_KEY_CATEGORIES.get(key)
        if category is None:
            continue
        if value not in result.get(category, []):
            result.setdefault(category, []).append(value)
    return result


def _enrich_victim_info(
    company: Dict[str, Any],
    victim_id: str,
    victim_email: str,
) -> Dict[str, str]:
    """
    Look up employee details for use in alert description templates.

    Returns dict with: victim_name, victim_title, victim_location, victim_device_os.
    """
    info: Dict[str, str] = {
        "victim_name": victim_email.split("@")[0].replace(".", " ").title(),
        "victim_title": "Employee",
        "victim_location": "Unknown",
        "victim_device_os": "Windows",
    }

    # Find employee
    people = company.get("employees") or company.get("workers") or []
    employee = None
    for p in people:
        if p.get("id") == victim_id:
            employee = p
            break

    if employee:
        info["victim_name"] = employee.get("display_name") or info["victim_name"]
        info["victim_title"] = employee.get("title") or info["victim_title"]
        info["victim_location"] = employee.get("location") or info["victim_location"]

    # Find device OS
    devices = company.get("devices") or []
    for d in devices:
        if d.get("owner_user_id") == victim_id and d.get("os"):
            info["victim_device_os"] = d["os"]
            break

    return info


def _lookup_attacker_geo(
    company: Dict[str, Any],
    victim_id: str,
    attacker_ip: str,
) -> Optional[str]:
    """Find the geo location for an attacker IP from the victim's login events."""
    people = company.get("employees") or company.get("workers") or []
    for p in people:
        if p.get("id") == victim_id:
            for login in p.get("recent_activity", {}).get("logins", []):
                if login.get("ip") == attacker_ip and login.get("geo"):
                    return login["geo"]
            break
    return None


def _safe_render(template: str, ctx: Dict[str, str]) -> str:
    """Replace {key} placeholders in template; leave unresolved ones as-is."""
    def _replace(match: re.Match) -> str:
        key = match.group(1)
        return ctx.get(key, match.group(0))
    return re.sub(r"\{(\w+)\}", _replace, template)


def generate_ticket(
    attack: Dict[str, Any],
    company: Dict[str, Any],
    company_data_file: str,
) -> Optional[Dict]:
    """
    Build a single scenario YAML dict from an attack ground truth entry.

    Args:
        attack: One entry from company["_attack_ground_truth"]
        company: Full company data dict
        company_data_file: Path to the company JSON file (stored in YAML)

    Returns:
        YAML-ready dict or None if the scenario has no template.
    """
    scenario_id = attack["scenario_id"]
    template = ALERT_TEMPLATES.get(scenario_id)
    if template is None:
        from .generic_ticket import get_template
        template = get_template(scenario_id)
    if template is None:
        return None

    attack_id = attack["attack_id"]
    victim_id = attack["victim_id"]
    victim_email = attack["victim_email"]
    iocs = attack.get("iocs") or {}

    # Build rendering context — start with resolved_params from attack generation
    # so all template placeholders (victim_username, malicious_app_name, etc.) resolve
    resolved = attack.get("resolved_params") or {}
    victim_info = _enrich_victim_info(company, victim_id, victim_email)
    ctx: Dict[str, str] = {
        **{k: str(v) for k, v in resolved.items()},
        "victim_email": victim_email,
        "victim_id": victim_id,
        "victim_username": victim_email.split("@")[0],
        "start_ts": attack.get("start_ts", ""),
        "compromise_ts": attack.get("compromise_ts") or attack.get("start_ts", ""),
        **victim_info,
        **{k: str(v) for k, v in iocs.items()},
    }

    # Resolve attacker_geo from login events if not already in IOCs
    if "attacker_geo" not in ctx or not _is_resolved(ctx.get("attacker_geo", "")):
        attacker_ip = iocs.get("attacker_ip")
        if attacker_ip:
            geo = _lookup_attacker_geo(company, victim_id, attacker_ip)
            if geo:
                ctx["attacker_geo"] = geo

    # Render title and description
    title = _safe_render(template["title_template"], ctx)
    description = _safe_render(template["description_template"], ctx)

    # Build initial indicators from template spec
    initial_indicators = []
    for ioc_key, indicator_type in template["initial_indicator_keys"]:
        value = ctx.get(ioc_key)
        if value:
            initial_indicators.append({"type": indicator_type, "value": value})

    # Categorize IOCs
    expected_iocs = categorize_iocs(iocs)

    # Build YAML-ready scenario ID with attack suffix
    atk_suffix = attack_id.replace("atk_", "")
    yaml_id = f"{scenario_id}_{atk_suffix}"

    scenario_name = title

    return {
        "scenario": {
            "id": yaml_id,
            "name": scenario_name,
            "difficulty": template["difficulty"],
            "tags": template["tags"],
        },
        "company": {
            "data_file": company_data_file,
        },
        "alert": {
            "title": title,
            "severity": template["severity"],
            "source": template["source"],
            "description": description,
            "initial_indicators": initial_indicators,
        },
        "evaluation": {
            "attack_ids": [attack_id],
            "expected_findings": attack.get("expected_findings", []),
            "expected_iocs": expected_iocs,
        },
    }


def generate_tickets(
    company: Dict[str, Any],
    company_data_file: str,
) -> List[Dict]:
    """
    Generate scenario tickets for all successful attacks in company data.

    Args:
        company: Company data dict with _attack_ground_truth
        company_data_file: Path to the company JSON file

    Returns:
        List of YAML-ready ticket dicts.
    """
    ground_truth = company.get("_attack_ground_truth", [])
    tickets = []
    for attack in ground_truth:
        if not attack.get("success"):
            continue
        ticket = generate_ticket(attack, company, company_data_file)
        if ticket is not None:
            tickets.append(ticket)
    return tickets


def save_tickets(
    tickets: List[Dict],
    output_dir: str,
) -> List[Path]:
    """
    Write each ticket as a YAML file.

    Args:
        tickets: List of YAML-ready ticket dicts
        output_dir: Directory to write files to

    Returns:
        List of written file paths.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for ticket in tickets:
        yaml_id = ticket["scenario"]["id"]
        path = out / f"{yaml_id}.yaml"
        with path.open("w", encoding="utf-8") as f:
            yaml.dump(ticket, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        written.append(path)
    return written
