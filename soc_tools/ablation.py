"""Tool ablations — benchmark arms that restrict what the agent's tools give it.

An ablation narrows the capability surface without touching the underlying twin
data, so a run measures how much of an agent's performance came from the tooling
doing the analysis for it rather than from the agent's own reasoning.

Three independent knobs, composable:

``drop_capabilities``
    Capability refs removed from the tool schema entirely. The agent never sees
    them and cannot call them.

``keep_capabilities``
    An allowlist: when set, *only* these capability refs survive. Use this for
    minimal-tooling arms, where naming what stays is both shorter and safe
    against catalog drift — a tool added later is excluded by default rather
    than silently joining the arm.

``threat_intel_verdict_only``
    Threat-intel lookups keep their malicious/unknown verdict but lose all
    attack attribution, so a hit no longer hands the agent a campaign to pivot
    on. Tool descriptions are rewritten to match, otherwise the schema would
    promise campaign data the results no longer carry.

Capability refs (``"identity.get_risky_users"``) are the stable key here — they
are declared in the catalog YAML and, unlike ``prefix_function`` query names,
do not change when a category swaps platforms.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional


# -----------------------------------------------------------------------------
# Tier 1 — tools carrying their own detection logic
#
# These do not merely retrieve: each applies a threshold, a score, or a built-in
# indicator list, so a hit is already a finding. Removing them forces the agent
# to derive the same conclusions from raw event retrieval, which stays available
# (the DLP tools read file_events/email_events/print_events, all still reachable
# through the SIEM).
# -----------------------------------------------------------------------------

TIER1_ANALYSIS_CAPABILITIES: FrozenSet[str] = frozenset({
    # risk_score = failed_logins*2 + mfa_denials*3, gated at >=3 / >=2, ranked
    "identity.get_risky_users",
    # synthesises alerts from file_events, severity assigned by action
    "dlp.get_dlp_alerts",
    # synthesises alerts, GROUP BY employee HAVING file_count >= 10
    "dlp.get_irm_alerts",
    # external + (url or attachment) prefilter, then tags urgency keywords
    "email_gateway.find_phishing_indicators",
    # built-in 12-entry LOLBin / offensive-tooling list
    "edr.detect_suspicious_processes",
})


# -----------------------------------------------------------------------------
# Minimal-tooling arm: raw SQL + IOC reputation only
#
# ``siem.run_query`` is self-sufficient — its description embeds the full schema
# for all 13 event and reference tables — so an agent holding just these two
# tools can still reach the underlying telemetry, it simply has to write the
# queries and do the correlation itself.
#
# Not covered by run_query's documented schema: the six CNAPP cloud_* tables.
# Cloud scenarios are therefore near-blind in this arm unless the agent guesses
# those table names, which no observed run has done.
# -----------------------------------------------------------------------------

SIEM_RUN_QUERY = "siem.run_query"

# Enumerates every IOC in the twin's ground truth. In isolated mode exactly one
# attack is injected, so it returns that attack's complete indicator set — an
# answer key, not an investigation. Excluded from the minimal arm below so IOC
# recall there reflects discovery rather than enumeration. Still present in the
# baseline and the tier-1 arms, where 39 tools make it an unattractive option
# (called in 6 of 2394 observed runs).
TI_KNOWN_IOC_LIST = "threat_intel.get_known_iocs"

# Every threat_intel capability in the catalog. Kept complete so the smoke test
# can assert it against the YAML and catch catalog drift; the arm below subtracts
# from it rather than maintaining a second hand-written list.
THREAT_INTEL_CAPABILITIES: FrozenSet[str] = frozenset({
    "threat_intel.lookup_domain",
    "threat_intel.lookup_ip",
    "threat_intel.lookup_hash",
    "threat_intel.lookup_url",
    "threat_intel.lookup_email_address",
    "threat_intel.lookup_filename",
    TI_KNOWN_IOC_LIST,
})

# The minimal arm's surface: raw SQL + per-indicator reputation lookups.
TI_AND_QUERY_CAPABILITIES: FrozenSet[str] = (
    THREAT_INTEL_CAPABILITIES - {TI_KNOWN_IOC_LIST}
) | {SIEM_RUN_QUERY}

# The floor: a single tool. No reputation oracle, so the agent cannot ask whether
# an indicator is known-bad — it has to argue maliciousness from the telemetry's
# own shape (timing, volume, unusual pairings). Isolating this against
# ti_and_query separates "can it query" from "can it judge".
QUERY_ONLY_CAPABILITIES: FrozenSet[str] = frozenset({SIEM_RUN_QUERY})


# -----------------------------------------------------------------------------
# Threat-intel verdict-only mode
# -----------------------------------------------------------------------------

# Keys carrying attack attribution. Stripped recursively from threat_intel
# results, so nested association entries go with their container.
_ATTRIBUTION_KEYS: FrozenSet[str] = frozenset({
    "associated_attacks",
    "attack_id",
    "reported_activity",
    "indicator_type",
    "scenario_id",
})

# Descriptions rewritten so the schema stops advertising campaign data. Keys are
# capability refs; every threat_intel function that mentions attacks is covered.
_TI_VERDICT_ONLY_DESCRIPTIONS: Dict[str, str] = {
    "threat_intel.lookup_domain":
        "Check a domain against threat intelligence. Returns a verdict of "
        "'malicious' or 'unknown'. No attribution detail is available.",
    "threat_intel.lookup_ip":
        "Check an IP address against threat intelligence. Returns a verdict of "
        "'malicious' or 'unknown'. No attribution detail is available.",
    "threat_intel.lookup_hash":
        "Check a file hash against threat intelligence. Returns a verdict of "
        "'malicious' or 'unknown', plus first-seen time and how many hosts and "
        "users ran the binary. No attribution detail is available.",
    "threat_intel.lookup_url":
        "Check a URL against threat intelligence. Returns a verdict of "
        "'malicious' or 'unknown', plus how many emails contained the URL. "
        "No attribution detail is available.",
    "threat_intel.lookup_email_address":
        "Check an email address against threat intelligence. Returns a verdict "
        "of 'malicious' or 'unknown', whether the address is internal, and how "
        "many emails it sent. No attribution detail is available.",
    "threat_intel.lookup_filename":
        "Check a filename against threat intelligence. Returns a verdict of "
        "'malicious' or 'unknown', plus how often the filename appears in "
        "process executions and email attachments. No attribution detail is "
        "available.",
    "threat_intel.get_known_iocs":
        "List all known indicators of compromise from threat intelligence "
        "feeds as type/value pairs. Can filter by IOC type. No attribution "
        "detail is available.",
}

_THREAT_INTEL_PREFIX = "threat_intel."


def strip_attribution(value: Any) -> Any:
    """Recursively drop attack-attribution keys from a tool result.

    Verdicts and telemetry counts derived from the twin database are kept — they
    are observable facts about the environment, not labels naming the attack.
    """
    if isinstance(value, dict):
        return {
            k: strip_attribution(v)
            for k, v in value.items()
            if k not in _ATTRIBUTION_KEYS
        }
    if isinstance(value, list):
        return [strip_attribution(v) for v in value]
    return value


# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class AblationConfig:
    """A named restriction applied to a ToolRegistry for one benchmark arm."""

    name: str
    drop_capabilities: FrozenSet[str] = frozenset()
    keep_capabilities: Optional[FrozenSet[str]] = None
    threat_intel_verdict_only: bool = False

    @property
    def is_noop(self) -> bool:
        return (
            not self.drop_capabilities
            and self.keep_capabilities is None
            and not self.threat_intel_verdict_only
        )

    def allows(self, capability_ref: str) -> bool:
        """Whether a capability survives this ablation and reaches the agent."""
        if self.keep_capabilities is not None and capability_ref not in self.keep_capabilities:
            return False
        return capability_ref not in self.drop_capabilities

    def description_for(self, capability_ref: str) -> Optional[str]:
        """Replacement tool description for a capability, or None to keep the catalog's."""
        if self.threat_intel_verdict_only:
            return _TI_VERDICT_ONLY_DESCRIPTIONS.get(capability_ref)
        return None

    def sanitize_result(self, capability_ref: str, result: Any) -> Any:
        """Post-process a capability's return value under this ablation."""
        if self.threat_intel_verdict_only and capability_ref.startswith(_THREAT_INTEL_PREFIX):
            return strip_attribution(result)
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Serialisable form, recorded in run traces so an arm is self-describing."""
        return {
            "name": self.name,
            "dropped_capabilities": sorted(self.drop_capabilities),
            "kept_capabilities": (
                sorted(self.keep_capabilities) if self.keep_capabilities is not None else None
            ),
            "threat_intel_verdict_only": self.threat_intel_verdict_only,
        }

    def summary(self) -> str:
        if self.is_noop:
            return f"{self.name} (no restrictions)"
        parts: List[str] = []
        if self.keep_capabilities is not None:
            parts.append(f"only {len(self.keep_capabilities)} capability(ies) kept")
        if self.drop_capabilities:
            parts.append(f"{len(self.drop_capabilities)} capability(ies) removed")
        if self.threat_intel_verdict_only:
            parts.append("threat-intel verdict only")
        return f"{self.name} ({'; '.join(parts)})"


NO_ABLATION = AblationConfig(name="none")

PRESETS: Dict[str, AblationConfig] = {
    "none": NO_ABLATION,
    "no_tier1": AblationConfig(
        name="no_tier1",
        drop_capabilities=TIER1_ANALYSIS_CAPABILITIES,
    ),
    "ti_verdict_only": AblationConfig(
        name="ti_verdict_only",
        threat_intel_verdict_only=True,
    ),
    "no_tier1_ti_verdict_only": AblationConfig(
        name="no_tier1_ti_verdict_only",
        drop_capabilities=TIER1_ANALYSIS_CAPABILITIES,
        threat_intel_verdict_only=True,
    ),
    # Minimal tooling: raw SQL + IOC reputation, nothing else. Every other
    # platform disappears, so all correlation is the agent's own work.
    "ti_and_query": AblationConfig(
        name="ti_and_query",
        keep_capabilities=TI_AND_QUERY_CAPABILITIES,
    ),
    # Same, with threat-intel reduced to a bare verdict.
    "ti_and_query_verdict_only": AblationConfig(
        name="ti_and_query_verdict_only",
        keep_capabilities=TI_AND_QUERY_CAPABILITIES,
        threat_intel_verdict_only=True,
    ),
    # One tool: raw SQL, no reputation oracle at all.
    "query_only": AblationConfig(
        name="query_only",
        keep_capabilities=QUERY_ONLY_CAPABILITIES,
    ),
}

# Convenience alias for the combined arm. It resolves to the same config object,
# so traces and result filenames always carry the canonical, precise name
# ("no_tier1_ti_verdict_only") no matter which spelling was passed on the CLI —
# the tier-2 and tier-3 analysis tools are still present, and the arm name should
# not claim otherwise.
PRESETS["no_analysis"] = PRESETS["no_tier1_ti_verdict_only"]

PRESET_NAMES: List[str] = list(PRESETS.keys())


def resolve(name: Optional[str]) -> AblationConfig:
    """Look up a preset by name. None or 'none' yields the unrestricted config.

    Raises:
        ValueError: if the name is not a known preset.
    """
    if name is None:
        return NO_ABLATION
    key = name.strip()
    if key not in PRESETS:
        raise ValueError(
            f"Unknown ablation: {name!r}. Available: {', '.join(PRESET_NAMES)}"
        )
    return PRESETS[key]
