"""
Attack scenario definitions for security testing and investigation benchmarks.

This module defines attack scenario templates that can be used to generate
realistic attack event chains for testing AI agents' investigation capabilities.

Each scenario defines:
- Attack type and metadata
- Event chain with timing specifications
- Parameterizable elements (domains, subjects, URLs)
- Ground truth for evaluation (IOCs, expected findings)

Usage:
    from attacks import (
        AttackScenario,
        AttackEvent,
        AttackInstance,
        ATTACK_SCENARIOS,
        render_template,
    )
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AttackEvent:
    """
    Single event in an attack chain.

    Attributes:
        event_type: Type of event ("email", "app_event", "login", "file_event")
        delay: Timing specification with mean, std, min, max in minutes
        data: Event-specific data with {slot} placeholders
        requires_success: Only fires if attack succeeds (default True)
        on_failure: Alternative event specification if attack fails
        pre_attempts: Generate variable failed attempts before the main event.
            Format: {"count_range": [min, max], "delay": {delay_spec},
                     "data_overrides": {"action": "blocked", ...}}
            The main event data is merged with data_overrides for each attempt.
    """
    event_type: str
    delay: Dict[str, float]
    data: Dict[str, Any]
    requires_success: bool = True
    on_failure: Optional[Dict[str, Any]] = None
    pre_attempts: Optional[Dict[str, Any]] = None


@dataclass
class AttackScenario:
    """
    Defines an attack template.

    Attributes:
        id: Unique identifier for the scenario (e.g., "docusign_credential_harvest")
        name: Human-readable name (e.g., "DocuSign Credential Harvesting")
        description: Detailed description of the attack
        attack_type: Category of attack ("phishing", "bec", "malware", etc.)
        tier: Reasoning-difficulty tier from Legion-Bench:
            - "T1": single-action / minutes-scale attack with a direct indicator
              (pattern matching).
            - "T2": multi-step single-session attack across hours requiring
              cross-source inference.
            - "T3": multi-day / identity-chained campaign requiring long-horizon
              hypothesis maintenance.
        events: List of AttackEvent objects defining the attack chain
        parameters: Default values for parameterizable slots
        success_rate: Probability victim falls for the attack (0.0-1.0)
        iocs: List of indicator of compromise patterns
        expected_findings: What an investigator should discover
        relevant_ioc_keys: IOC keys relevant to this scenario (filters get_scenario_iocs).
            If empty, all non-empty IOCs are included (legacy behavior).
    """
    id: str
    name: str
    description: str
    attack_type: str
    events: List[AttackEvent]
    parameters: Dict[str, Any]
    tier: str = "T2"
    success_rate: float = 0.7
    iocs: List[str] = field(default_factory=list)
    expected_findings: List[str] = field(default_factory=list)
    relevant_ioc_keys: List[str] = field(default_factory=list)


@dataclass
class AttackInstance:
    """
    Ground truth for a specific attack instance.

    Stores all information needed to evaluate whether an AI investigator
    correctly identified and analyzed the attack.

    Attributes:
        attack_id: Unique ID for this attack instance
        scenario_id: Which scenario template was used
        victim_id: ID of the targeted employee
        victim_email: Email address of the victim
        success: Whether the victim fell for the attack
        start_ts: When the attack began
        compromise_ts: When credentials/access was compromised (if successful)
        iocs: Specific IOCs for this instance
        expected_findings: What investigator should discover
        event_ids: References to generated event IDs
    """
    attack_id: str
    scenario_id: str
    victim_id: str
    victim_email: str
    success: bool
    start_ts: str
    compromise_ts: Optional[str]
    iocs: Dict[str, str]
    expected_findings: List[str]
    event_ids: List[str] = field(default_factory=list)


def _delay(
    mean: float,
    std: float,
    min_value: float = 0,
    max_value: Optional[float] = None,
) -> Dict[str, Any]:
    """Helper to create delay specification."""
    return {
        "mean": mean,
        "std": std,
        "min": min_value,
        "max": max_value,
    }


# -----------------------------------------------------------------------------
# Shared Attacker Infrastructure Parameters
# -----------------------------------------------------------------------------

SHARED_ATTACKER_INFRA = {
    # Command & Control infrastructure
    "c2_domains": [
        "cdn-static-assets.com",
        "api-telemetry-service.net",
        "update-service-cdn.com",
        "analytics-tracking-api.net",
        "cloud-sync-service.com",
        "secure-update-service.net",
    ],
    "c2_ips": [
        "185.234.72.",
        "91.134.128.",
        "45.227.255.",
        "103.152.220.",
        "194.26.29.",
    ],

    # Evilginx/Phishing proxy infrastructure
    "evilginx_domains": [
        "login-secure-portal.com",
        "auth-verification-center.net",
        "identity-confirm-service.com",
    ],

    # Attacker geolocations (for impossible travel detection)
    "attacker_geos": [
        "Eastern Europe",
        "Russia",
        "China",
        "North Korea",
        "Unknown VPN",
        "Nigeria",
    ],

    # Attacker user agents
    "attacker_user_agents": [
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 Chrome/90.0",
        "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 Chrome/91.0 Mobile",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/92.0",
        "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
        "python-requests/2.28.0",
    ],

    # Common malicious file names
    "malicious_executables": [
        "TeamViewer_Setup.exe",
        "AnyDesk_Installer.exe",
        "IT_Support_Tool.exe",
        "VPN_Client_Update.exe",
        "Security_Patch.exe",
    ],

    # Malicious attachment names
    "malicious_attachments": [
        "Invoice_Details.pdf",
        "Voicemail_Message.html",
        "Payment_Confirmation.pdf",
        "Urgent_Document.pdf",
    ],
}


# Registry of all attack scenarios — single source of truth in catalog_scenarios.py
from .catalog_scenarios import CATALOG_SCENARIOS as ATTACK_SCENARIOS  # noqa: E402

# -----------------------------------------------------------------------------
# Template Rendering Utilities
# -----------------------------------------------------------------------------

def render_template(template: str, params: Dict[str, Any]) -> str:
    """
    Render a template string with parameter values.

    Supports {slot} placeholders that are replaced with values from params.

    Args:
        template: String with {slot} placeholders
        params: Dict mapping slot names to values

    Returns:
        Rendered string with placeholders replaced
    """
    result = template
    # Find all {slot} patterns
    pattern = re.compile(r'\{(\w+)\}')

    for match in pattern.finditer(template):
        slot_name = match.group(1)
        if slot_name in params:
            value = params[slot_name]
            result = result.replace(match.group(0), str(value))

    return result


def select_random_param(
    param_name: str,
    parameters: Dict[str, Any],
    rng: random.Random,
) -> Any:
    """
    Select a random value for a parameterizable slot.

    If the parameter value is a list, selects randomly from it.
    Otherwise returns the value directly.

    Args:
        param_name: Name of the parameter
        parameters: Dict of parameter definitions
        rng: Random number generator

    Returns:
        Selected parameter value
    """
    if param_name not in parameters:
        return f"{{{param_name}}}"  # Return placeholder if not found

    value = parameters[param_name]
    if isinstance(value, list) and value:
        return rng.choice(value)
    return value


def resolve_attack_parameters(
    scenario: AttackScenario,
    rng: random.Random,
    overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """
    Resolve all parameterizable slots for an attack instance.

    Selects random values for each parameter and builds derived values
    (like attacker_email from sender_prefix + attacker_domain).

    Args:
        scenario: The attack scenario
        rng: Random number generator
        overrides: Optional dict of parameter overrides

    Returns:
        Dict mapping slot names to resolved values
    """
    params = scenario.parameters.copy()

    # Apply overrides
    if overrides:
        params.update(overrides)

    resolved: Dict[str, str] = {}

    # Select base attacker parameters
    attacker_domain = select_random_param("attacker_domains", params, rng)
    sender_prefix = select_random_param("sender_prefixes", params, rng)
    sender_name = select_random_param("sender_names", params, rng)
    attacker_geo = select_random_param("attacker_geos", params, rng)

    # Build core attacker values
    resolved["attacker_domain"] = str(attacker_domain) if attacker_domain else ""
    if sender_prefix and attacker_domain:
        resolved["attacker_email"] = f"{sender_prefix}@{attacker_domain}"
    else:
        resolved["attacker_email"] = ""
    resolved["sender_name"] = str(sender_name) if sender_name else ""
    resolved["attacker_geo"] = str(attacker_geo) if attacker_geo else ""

    # Select attacker IP
    ip_range = select_random_param("attacker_ip_ranges", params, rng)
    if ip_range and not ip_range.startswith("{"):
        resolved["attacker_ip"] = f"{ip_range}{rng.randint(1, 254)}"
    else:
        resolved["attacker_ip"] = f"185.234.72.{rng.randint(1, 254)}"

    # Select attacker user agent
    resolved["attacker_user_agent"] = str(select_random_param("attacker_user_agents", params, rng) or "")

    # Phishing-specific parameters
    phishing_domain = select_random_param("phishing_domains", params, rng)
    if phishing_domain and not str(phishing_domain).startswith("{"):
        resolved["phishing_domain"] = str(phishing_domain)
        resolved["phishing_url"] = f"https://{phishing_domain}/view/document/{rng.randint(10000, 99999)}"
    else:
        resolved["phishing_domain"] = ""
        resolved["phishing_url"] = ""

    # Document type (used in multiple scenarios)
    document_type = select_random_param("document_types", params, rng)
    resolved["document_type"] = str(document_type) if document_type else ""

    # Evilginx domain for MFA bypass attacks
    evilginx_domain = select_random_param("evilginx_domains", params, rng)
    if evilginx_domain and not str(evilginx_domain).startswith("{"):
        resolved["evilginx_domain"] = str(evilginx_domain)

    # C2 infrastructure
    c2_domain = select_random_param("c2_domains", params, rng)
    if c2_domain and not str(c2_domain).startswith("{"):
        resolved["c2_domain"] = str(c2_domain)
        resolved["c2_url"] = f"https://{c2_domain}/api/v1/{rng.randint(1000, 9999)}"

    # Malware-specific parameters
    malware_name = select_random_param("malware_names", params, rng)
    if malware_name and not str(malware_name).startswith("{"):
        resolved["malware_name"] = str(malware_name)

    download_url = select_random_param("download_urls", params, rng)
    if download_url and not str(download_url).startswith("{"):
        resolved["download_url"] = str(download_url)

    # Token stealer for session hijacking
    token_stealer = select_random_param("token_stealer_names", params, rng)
    if token_stealer and not str(token_stealer).startswith("{"):
        resolved["token_stealer_name"] = str(token_stealer)

    # Device code parameter (device code phishing)
    device_code = select_random_param("device_codes", params, rng)
    if device_code and not str(device_code).startswith("{"):
        resolved["device_code"] = str(device_code)

    # Attacker device for MFA attacks
    attacker_device = select_random_param("attacker_devices", params, rng)
    if attacker_device and not str(attacker_device).startswith("{"):
        resolved["attacker_device"] = str(attacker_device)

    # Help desk ticket subject
    ticket_subject = select_random_param("ticket_subjects", params, rng)
    if ticket_subject and not str(ticket_subject).startswith("{"):
        resolved["ticket_subject"] = str(ticket_subject)

    # Voicemail-specific parameters
    caller_number = select_random_param("caller_numbers", params, rng)
    if caller_number and not str(caller_number).startswith("{"):
        resolved["caller_number"] = str(caller_number)
    duration = select_random_param("durations", params, rng)
    if duration and not str(duration).startswith("{"):
        resolved["duration"] = str(duration)
    resolved["call_time"] = f"{rng.randint(8, 17)}:{rng.randint(10, 59):02d} AM"

    # Vendor invoice parameters
    vendor_name = select_random_param("vendor_names", params, rng)
    if vendor_name and not str(vendor_name).startswith("{"):
        resolved["vendor_name"] = str(vendor_name)
    resolved["invoice_number"] = f"INV-{rng.randint(100000, 999999)}"
    amount = select_random_param("amounts", params, rng)
    if amount and not str(amount).startswith("{"):
        resolved["amount"] = str(amount)
    resolved["due_date"] = f"2024-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"

    # USB malware parameters
    usb_vendor = select_random_param("usb_vendors", params, rng)
    if usb_vendor and not str(usb_vendor).startswith("{"):
        resolved["usb_vendor"] = str(usb_vendor)
    resolved["serial_number"] = f"{rng.randint(10000000, 99999999)}"
    miner_pool = select_random_param("miner_pools", params, rng)
    if miner_pool and not str(miner_pool).startswith("{"):
        resolved["miner_pool"] = str(miner_pool)

    # DLP parameters
    target_path = select_random_param("target_paths", params, rng)
    if target_path and not str(target_path).startswith("{"):
        resolved["target_path"] = str(target_path)
    external_dest = select_random_param("external_destinations", params, rng)
    if external_dest and not str(external_dest).startswith("{"):
        resolved["external_destination"] = str(external_dest)
    sensitive_pattern = select_random_param("sensitive_patterns", params, rng)
    if sensitive_pattern and not str(sensitive_pattern).startswith("{"):
        resolved["sensitive_pattern"] = str(sensitive_pattern)

    # Personal email exfil parameters
    source_app = select_random_param("source_apps", params, rng)
    if source_app and not str(source_app).startswith("{"):
        resolved["source_app"] = str(source_app)
    personal_domain = select_random_param("personal_domains", params, rng)
    if personal_domain and not str(personal_domain).startswith("{"):
        resolved["personal_domain"] = str(personal_domain)
    export_type = select_random_param("export_types", params, rng)
    if export_type and not str(export_type).startswith("{"):
        resolved["export_type"] = str(export_type)
    sensitive_data = select_random_param("sensitive_data_types", params, rng)
    if sensitive_data and not str(sensitive_data).startswith("{"):
        resolved["sensitive_data_type"] = str(sensitive_data)

    # Cloud sync parameters
    sync_app = select_random_param("sync_apps", params, rng)
    if sync_app and not str(sync_app).startswith("{"):
        resolved["sync_app"] = str(sync_app)
    source_loc = select_random_param("source_locations", params, rng)
    if source_loc and not str(source_loc).startswith("{"):
        resolved["source_location"] = str(source_loc)
    share_type = select_random_param("share_types", params, rng)
    if share_type and not str(share_type).startswith("{"):
        resolved["share_type"] = str(share_type)

    # Screenshot/print exfil parameters
    screenshot_tool = select_random_param("screenshot_tools", params, rng)
    if screenshot_tool and not str(screenshot_tool).startswith("{"):
        resolved["screenshot_tool"] = str(screenshot_tool)
    printer = select_random_param("printers", params, rng)
    if printer and not str(printer).startswith("{"):
        resolved["printer"] = str(printer)

    # OAuth consent phishing parameters
    malicious_app = select_random_param("malicious_app_names", params, rng)
    if malicious_app and not str(malicious_app).startswith("{"):
        resolved["malicious_app_name"] = str(malicious_app)
    malicious_app_id = select_random_param("malicious_app_ids", params, rng)
    if malicious_app_id and not str(malicious_app_id).startswith("{"):
        resolved["malicious_app_id"] = str(malicious_app_id)

    # Thread hijacking parameters
    compromised_peer = select_random_param("compromised_peer_emails", params, rng)
    if compromised_peer and not str(compromised_peer).startswith("{"):
        resolved["compromised_peer_email"] = str(compromised_peer)
    hijacked_subject = select_random_param("hijacked_thread_subjects", params, rng)
    if hijacked_subject and not str(hijacked_subject).startswith("{"):
        resolved["hijacked_thread_subject"] = str(hijacked_subject)
    hijack_body = select_random_param("hijack_lure_bodies", params, rng)
    if hijack_body and not str(hijack_body).startswith("{"):
        resolved["hijack_lure_body"] = render_template(str(hijack_body), resolved)

    # BEC invoice diversion parameters
    fraud_subject = select_random_param("fraudulent_invoice_subjects", params, rng)
    if fraud_subject and not str(fraud_subject).startswith("{"):
        resolved["fraudulent_invoice_subject"] = str(fraud_subject)
    fraud_body = select_random_param("fraudulent_invoice_bodies", params, rng)
    if fraud_body and not str(fraud_body).startswith("{"):
        resolved["fraudulent_invoice_body"] = str(fraud_body)

    # Auto-generated IDs for Graph API resource references
    resolved["msg_id"] = f"AAMk{rng.randint(100000, 999999)}"
    resolved["item_id"] = f"01{rng.randint(100000, 999999):06X}"

    # Build subject (may reference other resolved values)
    subject_template = select_random_param("subjects", params, rng)
    if subject_template and not str(subject_template).startswith("{subjects}"):
        resolved["subject"] = render_template(str(subject_template), resolved)
    else:
        resolved["subject"] = ""

    # Build email body
    body_template = select_random_param("email_bodies", params, rng)
    if body_template and not str(body_template).startswith("{email_bodies}"):
        resolved["email_body"] = render_template(str(body_template), resolved)
    else:
        resolved["email_body"] = ""

    return resolved


def get_scenario_iocs(
    scenario: AttackScenario,
    resolved_params: Dict[str, str],
) -> Dict[str, str]:
    """
    Extract IOCs for a specific attack instance.

    Only includes IOCs listed in the scenario's ``relevant_ioc_keys``.
    If ``relevant_ioc_keys`` is empty, falls back to returning all non-empty IOCs.

    Args:
        scenario: The attack scenario
        resolved_params: Resolved parameter values

    Returns:
        Dict of IOC names to values (only non-empty, scenario-relevant values)
    """
    # Collect all potential IOCs
    all_iocs = {
        "attacker_email": resolved_params.get("attacker_email", ""),
        "attacker_domain": resolved_params.get("attacker_domain", ""),
        "phishing_url": resolved_params.get("phishing_url", ""),
        "phishing_domain": resolved_params.get("phishing_domain", ""),
        "attacker_ip": resolved_params.get("attacker_ip", ""),
        "attacker_geo": resolved_params.get("attacker_geo", ""),
        "c2_domain": resolved_params.get("c2_domain", ""),
        "c2_url": resolved_params.get("c2_url", ""),
        "evilginx_domain": resolved_params.get("evilginx_domain", ""),
        "malware_name": resolved_params.get("malware_name", ""),
        "download_url": resolved_params.get("download_url", ""),
        "token_stealer_name": resolved_params.get("token_stealer_name", ""),
        "miner_pool": resolved_params.get("miner_pool", ""),
        "external_destination": resolved_params.get("external_destination", ""),
    }

    # Filter by scenario-specific relevant keys if defined
    if scenario.relevant_ioc_keys:
        allowed = set(scenario.relevant_ioc_keys)
        return {k: v for k, v in all_iocs.items() if v and k in allowed}

    # Fallback: return all non-empty values
    return {k: v for k, v in all_iocs.items() if v}
