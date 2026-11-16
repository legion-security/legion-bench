"""
Generic ticket template generator for attack scenarios.

Generates ALERT_TEMPLATES-compatible dicts from AttackScenario metadata,
covering all scenarios in the catalog — not just the 17 with hand-crafted
templates in ticket_generator.py.

Usage:
    from attacks.generic_ticket import get_template

    template = get_template("aitm_phishing")  # works for all 74 scenarios
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .scenarios import AttackScenario, ATTACK_SCENARIOS
from .ticket_generator import ALERT_TEMPLATES


# ---------------------------------------------------------------------------
# attack_type -> (severity, primary source)
# ---------------------------------------------------------------------------

_TYPE_TO_SEVERITY_SOURCE: Dict[str, Tuple[str, str]] = {
    "phishing": ("high", "defender_o365"),
    "aitm_phishing": ("high", "defender_o365"),
    "device_code_phishing": ("high", "defender_o365"),
    "consent_phishing": ("high", "defender_o365"),
    "bec": ("high", "defender_o365"),
    "account_takeover": ("high", "splunk_es"),
    "credential_access": ("high", "splunk_es"),
    "malware": ("critical", "crowdstrike"),
    "ransomware": ("critical", "crowdstrike"),
    "lateral_movement": ("critical", "crowdstrike"),
    "persistence": ("medium", "entra_id"),
    "privilege_escalation": ("critical", "splunk_es"),
    "defense_evasion": ("medium", "splunk_es"),
    "cloud_recon": ("high", "splunk_es"),
    "cloud_execution": ("high", "splunk_es"),
    "data_exfiltration": ("high", "purview"),
    "dlp": ("high", "purview"),
    "supply_chain": ("critical", "splunk_es"),
    "impact": ("critical", "crowdstrike"),
    "destruction": ("critical", "crowdstrike"),
}

# source display names for description opening
_SOURCE_DISPLAY: Dict[str, str] = {
    "splunk_es": "Splunk Enterprise Security",
    "defender_o365": "Defender for Office 365",
    "crowdstrike": "CrowdStrike Falcon",
    "purview": "Microsoft Purview",
    "entra_id": "Entra ID",
}




# ---------------------------------------------------------------------------
# attack_type -> generic alert title (no attack technique in title)
# ---------------------------------------------------------------------------

_TYPE_TO_ALERT_TITLE: Dict[str, str] = {
    "phishing": "Suspicious inbound email activity for {victim_email}",
    "aitm_phishing": "Anomalous authentication event for {victim_email}",
    "device_code_phishing": "Anomalous authentication event for {victim_email}",
    "consent_phishing": "Suspicious application consent activity for {victim_email}",
    "bec": "Suspicious email activity flagged for {victim_email}",
    "account_takeover": "Anomalous authentication pattern for {victim_email}",
    "credential_access": "Credential-related alert for {victim_email}",
    "malware": "Endpoint behavioral detection for {victim_email}",
    "ransomware": "Multiple critical endpoint detections for {victim_email}",
    "lateral_movement": "Suspicious network activity involving {victim_email}",
    "persistence": "Suspicious configuration change for {victim_email}",
    "privilege_escalation": "Privilege-related alert for {victim_email}",
    "defense_evasion": "Security configuration change involving {victim_email}",
    "cloud_recon": "Unusual cloud API activity for {victim_email}",
    "cloud_execution": "Suspicious cloud activity for {victim_email}",
    "data_exfiltration": "DLP alert: unusual data transfer for {victim_email}",
    "dlp": "DLP policy alert for {victim_email}",
    "supply_chain": "Supply chain security alert involving {victim_email}",
    "impact": "Critical endpoint alert for {victim_email}",
    "destruction": "Critical endpoint alert for {victim_email}",
}

# ---------------------------------------------------------------------------
# attack_type -> minimal trigger description (what the detection tool saw)
# ---------------------------------------------------------------------------

_TYPE_TO_TRIGGER_DESCRIPTION: Dict[str, str] = {
    "phishing": (
        "flagged suspicious inbound email activity targeting "
        "{victim_email} at {start_ts}. The message matched heuristic detection rules."
    ),
    "aitm_phishing": (
        "detected an anomalous authentication event for "
        "{victim_email} at {compromise_ts}. The session characteristics do not match "
        "typical sign-in patterns for this user."
    ),
    "device_code_phishing": (
        "detected an anomalous authentication event for "
        "{victim_email} at {compromise_ts}. The sign-in method and session origin "
        "are inconsistent with this user's history."
    ),
    "consent_phishing": (
        "flagged a suspicious application consent grant for "
        "{victim_email} at {compromise_ts}. The consented permissions exceed "
        "typical usage patterns."
    ),
    "bec": (
        "flagged suspicious email activity involving "
        "{victim_email} at {start_ts}. The message characteristics triggered "
        "policy rules."
    ),
    "account_takeover": (
        "detected an anomalous authentication pattern for "
        "{victim_email} at {compromise_ts}. Sign-in characteristics deviate "
        "from the user's baseline."
    ),
    "credential_access": (
        "detected suspicious credential-related activity involving "
        "{victim_email} at {compromise_ts}."
    ),
    "malware": (
        "triggered a behavioral detection on the endpoint associated with "
        "{victim_email} at {compromise_ts}. Process execution matched "
        "suspicious activity patterns."
    ),
    "ransomware": (
        "generated multiple high-severity detections on the endpoint "
        "associated with {victim_email}, starting at {start_ts}. "
        "File system modifications were observed."
    ),
    "lateral_movement": (
        "detected suspicious network activity originating from the "
        "endpoint associated with {victim_email} at {start_ts}."
    ),
    "persistence": (
        "flagged a suspicious configuration change associated with "
        "{victim_email} at {compromise_ts}."
    ),
    "privilege_escalation": (
        "detected suspicious privilege-related activity involving "
        "{victim_email} at {compromise_ts}."
    ),
    "defense_evasion": (
        "detected a security configuration change associated with "
        "{victim_email} at {compromise_ts}."
    ),
    "cloud_recon": (
        "detected unusual cloud API activity associated with "
        "{victim_email} at {start_ts}."
    ),
    "cloud_execution": (
        "detected suspicious cloud resource activity associated with "
        "{victim_email} at {start_ts}."
    ),
    "data_exfiltration": (
        "triggered a DLP policy alert for {victim_email} at "
        "{start_ts}. Unusual data transfer volume was detected."
    ),
    "dlp": (
        "triggered a DLP policy alert for {victim_email} at "
        "{start_ts}. Data handling activity matched policy rules."
    ),
    "supply_chain": (
        "flagged suspicious supply chain activity associated with "
        "{victim_email} at {start_ts}."
    ),
    "impact": (
        "generated critical alerts on the endpoint associated with "
        "{victim_email} at {start_ts}. Significant system modifications "
        "were observed."
    ),
    "destruction": (
        "generated critical alerts on the endpoint associated with "
        "{victim_email} at {start_ts}. Significant system modifications "
        "were observed."
    ),
}


def _infer_difficulty(scenario: AttackScenario) -> str:
    """Heuristic difficulty based on event chain length and attack type."""
    n_events = len(scenario.events)
    hard_types = {"ransomware", "destruction", "lateral_movement",
                  "aitm_phishing", "device_code_phishing", "consent_phishing"}
    if scenario.attack_type in hard_types or n_events > 10:
        return "hard"
    if n_events <= 5 and scenario.attack_type in {"phishing", "dlp"}:
        return "easy"
    return "medium"


def _build_title_template(scenario: AttackScenario) -> str:
    """Build a generic alert-style title from attack_type (no attack name leak)."""
    return _TYPE_TO_ALERT_TITLE.get(
        scenario.attack_type,
        "Security alert for {victim_email}",
    )


def _build_description_template(
    scenario: AttackScenario,
    source_display: str,
) -> str:
    """Build a minimal alert description — only the triggering anomaly, not the attack chain."""
    trigger = _TYPE_TO_TRIGGER_DESCRIPTION.get(scenario.attack_type)
    if trigger:
        return (
            source_display + " " + trigger + " "
            "Investigate the full scope of the activity, identify indicators "
            "of compromise, and determine the impact."
        )

    # Fallback — still no scenario.description leak
    return (
        source_display + " detected suspicious activity involving "
        "{victim_email} at {start_ts}. "
        "Investigate the full scope of the activity, identify indicators "
        "of compromise, and determine the impact."
    )


def _build_initial_indicator_keys(
    scenario: AttackScenario,
) -> List[Tuple[str, str]]:
    """Only provide the victim email — the agent must discover attacker IOCs."""
    return [("victim_email", "email")]


def _build_tags(scenario: AttackScenario) -> List[str]:
    """Build tag list from attack_type and event metadata."""
    tags: List[str] = [scenario.attack_type]

    # Extract unique attack phases from events
    phases: Set[str] = set()
    for event in scenario.events:
        phase = (event.data.get("metadata") or {}).get("attack_phase")
        if phase and phase not in tags:
            phases.add(phase)

    # Add the most informative phases as tags
    for phase in sorted(phases):
        if phase not in tags:
            tags.append(phase)

    return tags


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_template(scenario: AttackScenario) -> Dict[str, Any]:
    """
    Build an ALERT_TEMPLATES-compatible dict from AttackScenario metadata.

    Returns a dict with the same keys as hand-crafted entries in ALERT_TEMPLATES:
    title_template, severity, source, description_template, difficulty, tags,
    initial_indicator_keys.
    """
    severity, source = _TYPE_TO_SEVERITY_SOURCE.get(
        scenario.attack_type, ("high", "splunk_es"),
    )
    source_display = _SOURCE_DISPLAY.get(source, source)
    difficulty = _infer_difficulty(scenario)

    return {
        "title_template": _build_title_template(scenario),
        "severity": severity,
        "source": source,
        "description_template": _build_description_template(scenario, source_display),
        "difficulty": difficulty,
        "tags": _build_tags(scenario),
        "initial_indicator_keys": _build_initial_indicator_keys(scenario),
    }


def get_template(scenario_id: str) -> Optional[Dict[str, Any]]:
    """
    Return the ticket template for a scenario.

    Checks ALERT_TEMPLATES first (hand-crafted, higher quality), then falls
    back to auto-generating from the AttackScenario definition.
    """
    # Hand-crafted template takes priority
    template = ALERT_TEMPLATES.get(scenario_id)
    if template is not None:
        return template

    # Auto-generate from scenario metadata
    scenario = ATTACK_SCENARIOS.get(scenario_id)
    if scenario is None:
        return None

    return generate_template(scenario)
