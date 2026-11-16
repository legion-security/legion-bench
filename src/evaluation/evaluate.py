"""Orchestrator for evaluation and human-readable report formatting."""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.base import InvestigationResult
from evaluation.events import compute_tool_call_attack_precision, evaluate_event_recall
from evaluation.findings import evaluate_findings
from evaluation.iocs import compute_ioc_precision, evaluate_iocs
from evaluation.models import EvaluationResult


def _collect_known_ioc_values(
    company_data: Optional[Dict[str, Any]],
    attack_ids: List[str],
) -> List[str]:
    """Flatten every IoC value from ``_attack_ground_truth`` for the given
    attack IDs across all 19 IoC types. Used to mark agent-listed IoCs that
    are real but fall outside the 4 evaluated categories as neutral (neither
    a precision hit nor miss).
    """
    if not company_data or not attack_ids:
        return []
    ground_truth = company_data.get("_attack_ground_truth") or []
    wanted = set(attack_ids)
    values: List[str] = []
    for atk in ground_truth:
        if atk.get("attack_id") not in wanted:
            continue
        for value in (atk.get("iocs") or {}).values():
            if isinstance(value, str) and value:
                values.append(value)
    return values


def _load_company_data(scenario: dict) -> Optional[Dict[str, Any]]:
    """Best-effort load of the company JSON referenced by the scenario."""
    data_file = (scenario.get("company") or {}).get("data_file")
    if not data_file:
        return None
    path = Path(data_file)
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_investigation(
    result: InvestigationResult,
    scenario: dict,
    eval_model: str = "gpt-4o-mini",
    company_data: Optional[Dict[str, Any]] = None,
    attack_events: Optional[list] = None,
) -> EvaluationResult:
    """Run the full evaluation pipeline on an investigation result.

    Args:
        result: The agent's InvestigationResult.
        scenario: The parsed scenario YAML dict (must contain 'evaluation' key).
        eval_model: LLM model to use for findings evaluation.
        company_data: Pre-loaded company dict (used to extract attack events
            when ``attack_events`` is not provided).
        attack_events: Pre-extracted attack events (preferred — bypasses any
            need to reload the company). Use the output of
            ``attacks.engine.extract_attack_events``.

    Returns:
        EvaluationResult with findings recall, IOC recall, event recall, and efficiency.
    """
    evaluation = scenario.get("evaluation", {})
    expected_findings = evaluation.get("expected_findings", [])
    expected_iocs = evaluation.get("expected_iocs", {})
    attack_ids = evaluation.get("attack_ids", []) or []

    # Evaluate findings (LLM-based)
    findings_result = evaluate_findings(result.report, expected_findings, model=eval_model)

    # Evaluate IOCs (deterministic) — recall + precision. Precision uses a
    # ground-truth allow-set so that real attack indicators outside the 4
    # evaluated categories (malware names, miner pools, etc.) do not count
    # as false positives just because they happen to match the regex.
    if company_data is None and attack_ids:
        company_data = _load_company_data(scenario)
    known_iocs = _collect_known_ioc_values(company_data, attack_ids)

    iocs_result = evaluate_iocs(result.report, expected_iocs)
    iocs_result.precision = compute_ioc_precision(
        result.report, expected_iocs, known_iocs=known_iocs
    )

    # Evaluate event recall (deterministic) and tool-call attack precision.
    # Both metrics are derived from the same attack-events ground truth, so
    # we compute them together when that ground truth is available.
    events_result = None
    resolved_attack_events = attack_events
    if not resolved_attack_events and attack_ids and company_data is not None:
        from evaluation.events import _extract_attack_events  # local — keep import private
        resolved_attack_events = _extract_attack_events(company_data, attack_ids)

    if resolved_attack_events:
        events_result = evaluate_event_recall(
            tool_calls=result.tool_calls, attack_events=resolved_attack_events
        )
        events_result.tool_call_precision = compute_tool_call_attack_precision(
            tool_calls=result.tool_calls, attack_events=resolved_attack_events
        )

    return EvaluationResult(
        findings=findings_result,
        iocs=iocs_result,
        tool_call_count=len(result.tool_calls),
        events=events_result,
    )


def format_evaluation_report(eval_result: EvaluationResult) -> str:
    """Format an EvaluationResult as a human-readable console report."""
    lines = []
    lines.append("EVALUATION RESULTS")
    lines.append("=" * 50)

    # Findings
    fr = eval_result.findings
    lines.append(f"\nFindings Recall: {fr.found_count}/{fr.total_expected} ({fr.recall:.0%})")
    lines.append("-" * 40)
    for m in fr.matches:
        status = "FOUND" if m.found else "MISSED"
        conf = f" (confidence: {m.confidence:.0%})" if m.found else ""
        lines.append(f"  [{status}] {m.finding}{conf}")
        lines.append(f"           Evidence: {m.evidence}")

    # Raw LLM judge response
    if fr.raw_judge_response:
        lines.append(f"\n  Judge LLM raw response:")
        lines.append(f"  {fr.raw_judge_response}")

    # IOCs
    ir = eval_result.iocs
    lines.append(f"\nIOC Recall: {ir.total_found}/{ir.total_expected} ({ir.overall_recall:.0%})")
    lines.append("-" * 40)
    for cat_name, cat in ir.categories.items():
        lines.append(f"  {cat_name}: {len(cat.found)}/{len(cat.expected)} ({cat.recall:.0%})")
        for ioc in cat.found:
            lines.append(f"    FOUND : {ioc}")
        for ioc in cat.missed:
            lines.append(f"    MISSED: {ioc}")

    # Event recall
    er = eval_result.events
    if er is not None:
        lines.append(
            f"\nEvent Recall: {er.found_count}/{er.total_expected} ({er.recall:.0%})"
        )
        lines.append("-" * 40)
        by_type: dict[str, list] = {}
        for m in er.matches:
            by_type.setdefault(m.event_type, []).append(m)
        for et in sorted(by_type):
            ms = by_type[et]
            found = sum(1 for m in ms if m.found)
            lines.append(f"  {et}: {found}/{len(ms)}")
            for m in ms:
                status = "FOUND " if m.found else "MISSED"
                disc = {k: v for k, v in m.signature.items() if k not in ("ts", "employee_id", "source_ip")}
                pid = m.signature.get("employee_id") or m.signature.get("source_ip")
                via = f" via {m.matched_in}" if m.matched_in else ""
                lines.append(f"    [{status}] ts={m.signature.get('ts')} id={pid} {disc}{via}")

    # Efficiency
    lines.append(f"\nTool Calls: {eval_result.tool_call_count}")

    # Composite score (only when event recall is available)
    cs = eval_result.composite_score
    if cs is not None:
        lines.append(
            f"\nComposite Score: {cs:.2f}  (0.5*FR + 0.3*IR + 0.2*ER)"
        )

    lines.append("=" * 50)
    return "\n".join(lines)


def evaluation_to_dict(eval_result: EvaluationResult) -> dict:
    """Convert EvaluationResult to a JSON-serializable dict."""
    d = asdict(eval_result)
    d["composite_score"] = eval_result.composite_score
    return d
