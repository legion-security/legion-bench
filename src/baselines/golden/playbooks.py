"""Loader for the golden SOC playbook mermaid files.

Returns each playbook truncated to the *pre-Verdict* portion — i.e. only
the data-gathering phases (Triage / Enrichment / Scoping for the
identity-style playbooks; Initiation / User Context / Destination /
Content / Channel-Specific for the DLP playbook).

The Verdict / Containment / Post-Incident phases are excluded so the
agent's final answer is purely an investigation report, not a triage
decision and remediation plan.
"""
from __future__ import annotations

from pathlib import Path

from baselines.workflow_router import GoldenWorkflow

PLAYBOOK_DIR = Path(__file__).resolve().parents[3] / "golden_workflows"

PLAYBOOK_FILES: dict[GoldenWorkflow, str] = {
    "AccountTakeover": "Golden_Standard_AccountTakeover_SOC_Playbook.mermaid",
    "Malware": "Golden_Standard_Malware_SOC_Playbook.mermaid",
    "Phishing": "Golden_Standard_Phishing_Playbook.mermaid",
    "DLP": "Golden_Standard_DLP_Playbook.mermaid",
}

# Substring marker that introduces the Verdict/Decision phase. Everything
# from this line onward is dropped from the prompt.
_CUTOFF_MARKERS: dict[GoldenWorkflow, str] = {
    "AccountTakeover": "%% PHASE 4: VERDICT",
    "Malware": "%% PHASE 4: VERDICT",
    "Phishing": "%% PHASE 4: VERDICT",
    # DLP file uses a different structure: PHASE3 IS the decision phase.
    "DLP": 'subgraph PHASE3["🧠 DECISION"]',
}


def _playbook_path(workflow: GoldenWorkflow) -> Path:
    fname = PLAYBOOK_FILES[workflow]
    return PLAYBOOK_DIR / fname


def load_playbook_raw(workflow: GoldenWorkflow) -> str:
    """Return the full mermaid file contents."""
    return _playbook_path(workflow).read_text(encoding="utf-8")


def load_playbook_pre_verdict(workflow: GoldenWorkflow) -> str:
    """Return only the data-gathering phases of the playbook.

    Cuts the file at the Verdict/Decision marker. The result is still
    valid mermaid in spirit (the styling block is dropped along with the
    later phases — that's fine, the LLM only cares about the node text).

    Strips a leading ``` ```mermaid ``` markdown fence if present (the DLP
    playbook is wrapped in one; the other files are not). The caller is
    expected to wrap the returned text in its own fence.
    """
    text = load_playbook_raw(workflow)
    marker = _CUTOFF_MARKERS[workflow]

    cut_idx = text.find(marker)
    if cut_idx == -1:
        raise ValueError(
            f"Verdict cutoff marker {marker!r} not found in playbook for "
            f"{workflow}. Has the mermaid file changed?"
        )
    truncated = text[:cut_idx]

    lines = truncated.splitlines()
    # Drop a leading ```mermaid fence if present.
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    return "\n".join(lines).rstrip()
