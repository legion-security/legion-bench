"""Aggregate benchmark results into comparison tables and reports."""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from attacks.scenarios import ATTACK_SCENARIOS
from bench.runner import single_results_dir
from bench.stats import fmt_ci, methods_note, series_ci
from evaluation.min_tool_calls import min_tool_calls_for_events
from evaluation.models import composite_score, f1_score


TIER_ORDER = ["T1", "T2", "T3"]


def _scenario_tier_map() -> Dict[str, str]:
    """Map scenario_id → tier label using the attack catalog as the source of truth."""
    if isinstance(ATTACK_SCENARIOS, dict):
        items = ATTACK_SCENARIOS.values()
    else:
        items = ATTACK_SCENARIOS
    return {s.id: getattr(s, "tier", None) or "?" for s in items}


def _resolve_tier(trace: dict, tier_map: Dict[str, str]) -> str:
    """Resolve the catalog tier for a trace.

    Isolated-mode traces use a hash-suffixed ``scenario_id`` (e.g.
    ``docusign_credential_harvest_72e4b66e``) that won't match the catalog.
    Fall back to ``attack_details.scenario_id`` / ``base_scenario_id`` first,
    then strip the hash suffix as a last resort.
    """
    base = (trace.get("attack_details") or {}).get("scenario_id") or trace.get("base_scenario_id")
    if base and base in tier_map:
        return tier_map[base]
    sid = trace.get("scenario_id") or ""
    if sid in tier_map:
        return tier_map[sid]
    if "_" in sid:
        stripped = sid.rsplit("_", 1)[0]
        if stripped in tier_map:
            return tier_map[stripped]
    return "?"


def _resolve_base_scenario(trace: dict) -> str:
    """Resolve the catalog scenario id, ignoring the per-victim hash suffix.

    Isolated mode mints a unique ``scenario_id`` per (scenario, victim), so it is
    the wrong unit to cluster on for confidence intervals — five victims of one
    scenario are not five independent observations. Prefer the explicit base id
    the runner records, then fall back to stripping the hash suffix.
    """
    base = (trace.get("attack_details") or {}).get("scenario_id") or trace.get("base_scenario_id")
    if base:
        return str(base)
    sid = str(trace.get("scenario_id") or "")
    tier_map = _scenario_tier_map()
    if sid in tier_map:
        return sid
    if "_" in sid:
        stripped = sid.rsplit("_", 1)[0]
        if stripped in tier_map:
            return stripped
    return sid


def _resolve_tool_call_efficiency(trace: dict, ev: dict) -> Optional[float]:
    """Read efficiency from the trace, or backfill it from attack_details.events.

    The runner started writing ``evaluation.tool_call_efficiency`` after this
    metric was added; older traces lack it but ship the attack events under
    ``attack_details.events``, which is enough to recompute the minimum.
    """
    eff = ev.get("tool_call_efficiency")
    if eff is not None:
        return eff
    attack_events = ((trace.get("attack_details") or {}).get("events")) or []
    if not attack_events:
        return None
    min_tc = min_tool_calls_for_events(attack_events, use_ilp=False)
    tcc = ev.get("tool_call_count", len(trace.get("tool_calls", [])))
    if not min_tc or tcc is None:
        return None
    return tcc / min_tc


def load_traces(results_dir: str) -> List[dict]:
    """Load all trace JSON files from a results directory."""
    traces = []
    sr_dir = single_results_dir(Path(results_dir))
    if not sr_dir.exists():
        return traces
    for p in sorted(sr_dir.glob("*.json")):
        with open(p, "r") as f:
            traces.append(json.load(f))
    return traces


def build_dataframe(traces: List[dict]) -> pd.DataFrame:
    """Build a DataFrame with one row per run from trace dicts."""
    tier_map = _scenario_tier_map()
    rows = []
    for t in traces:
        ev = t.get("evaluation") or {}
        findings = ev.get("findings") or {}
        iocs = ev.get("iocs") or {}
        events = ev.get("events") or {}

        sid = t.get("scenario_id")
        ioc_prec = (iocs.get("precision") or {}) if isinstance(iocs, dict) else {}
        events_prec = (events.get("tool_call_precision") or {}) if events else {}
        row = {
            "scenario_id": sid,
            "base_scenario_id": _resolve_base_scenario(t),
            "scenario_name": t.get("scenario_name"),
            "tier": _resolve_tier(t, tier_map),
            "agent": t.get("agent_type"),
            "model": t.get("model"),
            "findings_recall": findings.get("recall"),
            "findings_found": findings.get("found_count"),
            "findings_total": findings.get("total_expected"),
            "ioc_recall": iocs.get("overall_recall"),
            "ioc_found": iocs.get("total_found"),
            "ioc_total": iocs.get("total_expected"),
            "ioc_precision": ioc_prec.get("precision"),
            "ioc_f1": f1_score(ioc_prec.get("precision"), iocs.get("overall_recall")),
            "ioc_listed": ioc_prec.get("listed_count"),
            "event_recall": events.get("recall") if events else None,
            "event_found": events.get("found_count") if events else None,
            "event_total": events.get("total_expected") if events else None,
            "tool_call_attack_precision": events_prec.get("precision"),
            "useful_tool_calls": events_prec.get("useful_count"),
            "composite_score": ev.get("composite_score") if ev.get("composite_score") is not None else composite_score(
                findings.get("recall"),
                iocs.get("overall_recall"),
                events.get("recall") if events else None,
            ),
            "tool_call_count": ev.get("tool_call_count", len(t.get("tool_calls", []))),
            "min_tool_calls": ev.get("min_tool_calls"),
            "tool_call_efficiency": _resolve_tool_call_efficiency(t, ev),
            "llm_calls": t.get("llm_calls", 0),
            "duration_s": t.get("duration_seconds", 0),
            "error": t.get("error"),
        }

        # Per-IOC-category recall
        for cat_name, cat_data in iocs.get("categories", {}).items():
            row[f"ioc_{cat_name}_recall"] = cat_data.get("recall")

        # Per-event-type recall
        if events and events.get("matches"):
            type_totals: dict[str, int] = {}
            type_found: dict[str, int] = {}
            for m in events["matches"]:
                et = m.get("event_type") or "unknown"
                type_totals[et] = type_totals.get(et, 0) + 1
                if m.get("found"):
                    type_found[et] = type_found.get(et, 0) + 1
            for et, total in type_totals.items():
                row[f"event_{et}_recall"] = type_found.get(et, 0) / total if total else None

        # Attack details (from isolated mode)
        attack = t.get("attack_details") or {}
        row["attack_id"] = attack.get("attack_id")
        row["victim_id"] = t.get("victim_id") or attack.get("victim_id")
        row["victim_email"] = t.get("victim_email") or attack.get("victim_email")
        row["attack_start_ts"] = attack.get("start_ts")
        row["attack_compromise_ts"] = attack.get("compromise_ts")
        row["attack_iocs"] = json.dumps(attack.get("iocs", {})) if attack.get("iocs") else None
        row["attack_expected_findings"] = json.dumps(attack.get("expected_findings", [])) if attack.get("expected_findings") else None
        row["attack_event_count"] = len(attack.get("event_ids", []))

        rows.append(row)

    return pd.DataFrame(rows)


def _fmt(val, pct=False) -> str:
    """Format a value for table display."""
    if val is None or pd.isna(val):
        return "-"
    if pct:
        return f"{val:.0%}"
    if isinstance(val, float):
        return f"{val:.2f}"
    return str(int(val))


def _table_agent_comparison(df: pd.DataFrame) -> str:
    """Table 1: Agent comparison averaged across scenarios."""
    if df.empty:
        return "No data for agent comparison.\n"

    has_events = "event_recall" in df.columns and df["event_recall"].notna().any()

    lines = ["## Agent Comparison (averaged across scenarios)\n"]
    lines.append(methods_note() + "\n")
    if has_events:
        lines.append("| Agent | Runs | Scenarios | Findings Recall | IOC Recall | IOC Precision | IOC F1 | Event Recall | TC-Attack Precision | TC Efficiency | Composite | Tool Calls (avg) | LLM Calls (avg) | Duration (avg) |")
        lines.append("|-------|------|-----------|----------------|------------|---------------|--------|--------------|---------------------|---------------|-----------|-------------------|------------------|----------------|")
    else:
        lines.append("| Agent | Runs | Scenarios | Findings Recall | IOC Recall | IOC Precision | IOC F1 | Tool Calls (avg) | LLM Calls (avg) | Duration (avg) |")
        lines.append("|-------|------|-----------|----------------|------------|---------------|--------|-------------------|------------------|----------------|")

    grouped = df[df["error"].isna()].groupby("agent")
    for agent, grp in sorted(grouped):
        n_runs = len(grp)
        n_scen = grp["base_scenario_id"].nunique() if "base_scenario_id" in grp.columns else "-"
        fr = fmt_ci(series_ci(grp, "findings_recall"), pct=True)
        ir = fmt_ci(series_ci(grp, "ioc_recall"), pct=True)
        ip = fmt_ci(series_ci(grp, "ioc_precision"), pct=True)
        if1 = fmt_ci(series_ci(grp, "ioc_f1"), pct=True)
        tc = fmt_ci(series_ci(grp, "tool_call_count"), decimals=1)
        lc = fmt_ci(series_ci(grp, "llm_calls"), decimals=1)
        dur = fmt_ci(series_ci(grp, "duration_s"), decimals=0)
        if has_events:
            er = fmt_ci(series_ci(grp, "event_recall"), pct=True)
            tcap = fmt_ci(series_ci(grp, "tool_call_attack_precision"), pct=True)
            tce = fmt_ci(series_ci(grp, "tool_call_efficiency"), decimals=1)
            cs = fmt_ci(series_ci(grp, "composite_score"))
            lines.append(f"| {agent} | {n_runs} | {n_scen} | {fr} | {ir} | {ip} | {if1} | {er} | {tcap} | {tce} | {cs} | {tc} | {lc} | {dur}s |")
        else:
            lines.append(f"| {agent} | {n_runs} | {n_scen} | {fr} | {ir} | {ip} | {if1} | {tc} | {lc} | {dur}s |")

    lines.append("")
    return "\n".join(lines)


def _table_scenario_difficulty(df: pd.DataFrame) -> str:
    """Table 2: Scenario difficulty averaged across agents."""
    if df.empty:
        return "No data for scenario difficulty.\n"

    has_events = "event_recall" in df.columns and df["event_recall"].notna().any()

    lines = ["## Scenario Difficulty (averaged across agents)\n"]
    if has_events:
        lines.append("| Scenario | Tier | Avg Findings Recall | Avg IOC Recall | Avg Event Recall | Hardest For |")
        lines.append("|----------|------|---------------------|----------------|------------------|-------------|")
    else:
        lines.append("| Scenario | Tier | Avg Findings Recall | Avg IOC Recall | Hardest For |")
        lines.append("|----------|------|---------------------|----------------|-------------|")

    valid = df[df["error"].isna()]
    grouped = valid.groupby("scenario_id")
    for sid, grp in sorted(grouped):
        fr = _fmt(grp["findings_recall"].mean(), pct=True)
        ir = _fmt(grp["ioc_recall"].mean(), pct=True)
        tier = grp["tier"].iloc[0] if "tier" in grp.columns and not grp.empty else "?"

        # Find which agent had lowest findings recall
        hardest = "-"
        if not grp["findings_recall"].isna().all():
            worst_idx = grp["findings_recall"].idxmin()
            hardest = grp.loc[worst_idx, "agent"]

        if has_events:
            er = _fmt(grp["event_recall"].mean(), pct=True)
            lines.append(f"| {sid} | {tier} | {fr} | {ir} | {er} | {hardest} |")
        else:
            lines.append(f"| {sid} | {tier} | {fr} | {ir} | {hardest} |")

    lines.append("")
    return "\n".join(lines)


def _table_full_matrix(df: pd.DataFrame) -> str:
    """Table 3: Full matrix — Agent x Scenario (findings recall)."""
    if df.empty:
        return "No data for full matrix.\n"

    valid = df[df["error"].isna()]
    agents = sorted(valid["agent"].unique())
    scenarios = sorted(valid["scenario_id"].unique())

    if not agents or not scenarios:
        return "No data for full matrix.\n"

    lines = ["## Full Matrix: Findings Recall (Agent x Scenario)\n"]
    header = "| Scenario | Tier | " + " | ".join(agents) + " |"
    sep = "|" + "---|" * (len(agents) + 2)
    lines.append(header)
    lines.append(sep)

    pivot = valid.pivot_table(
        index="scenario_id", columns="agent", values="findings_recall", aggfunc="mean"
    )
    tier_per_scenario = (
        valid.groupby("scenario_id")["tier"].first().to_dict() if "tier" in valid.columns else {}
    )

    for sid in scenarios:
        cells = []
        for agent in agents:
            val = pivot.loc[sid, agent] if sid in pivot.index and agent in pivot.columns else None
            cells.append(_fmt(val, pct=True))
        tier = tier_per_scenario.get(sid, "?")
        lines.append(f"| {sid} | {tier} | " + " | ".join(cells) + " |")

    lines.append("")
    return "\n".join(lines)


def _table_event_recall_matrix(df: pd.DataFrame) -> str:
    """Event recall — Agent x Scenario."""
    if "event_recall" not in df.columns or df["event_recall"].isna().all():
        return ""
    valid = df[df["error"].isna()]
    if valid.empty or valid["event_recall"].isna().all():
        return ""

    agents = sorted(valid["agent"].unique())
    scenarios = sorted(valid["scenario_id"].unique())
    if not agents or not scenarios:
        return ""

    lines = ["## Event Recall (Agent x Scenario)\n"]
    header = "| Scenario | Tier | " + " | ".join(agents) + " |"
    sep = "|" + "---|" * (len(agents) + 2)
    lines.append(header)
    lines.append(sep)

    pivot = valid.pivot_table(
        index="scenario_id", columns="agent", values="event_recall", aggfunc="mean"
    )
    tier_per_scenario = (
        valid.groupby("scenario_id")["tier"].first().to_dict() if "tier" in valid.columns else {}
    )
    for sid in scenarios:
        cells = []
        for agent in agents:
            val = pivot.loc[sid, agent] if sid in pivot.index and agent in pivot.columns else None
            cells.append(_fmt(val, pct=True))
        tier = tier_per_scenario.get(sid, "?")
        lines.append(f"| {sid} | {tier} | " + " | ".join(cells) + " |")

    lines.append("")
    return "\n".join(lines)


def _table_event_types(df: pd.DataFrame) -> str:
    """Per-event-type recall by agent."""
    cols = [c for c in df.columns if c.startswith("event_") and c.endswith("_recall") and c != "event_recall"]
    if not cols:
        return ""
    valid = df[df["error"].isna()]
    if valid.empty:
        return ""

    type_names = [c.replace("event_", "").replace("_recall", "") for c in cols]
    agents = sorted(valid["agent"].unique())

    lines = ["## Event Recall by Type (averaged across scenarios)\n"]
    header = "| Agent | " + " | ".join(type_names) + " |"
    sep = "|" + "---|" * (len(type_names) + 1)
    lines.append(header)
    lines.append(sep)

    grouped = valid.groupby("agent")
    for agent, grp in sorted(grouped):
        cells = [_fmt(grp[c].mean(), pct=True) for c in cols]
        lines.append(f"| {agent} | " + " | ".join(cells) + " |")

    lines.append("")
    return "\n".join(lines)


def _table_ioc_categories(df: pd.DataFrame) -> str:
    """Table 4: Per-IOC-category recall by agent."""
    ioc_cols = [c for c in df.columns if c.startswith("ioc_") and c.endswith("_recall") and c != "ioc_recall"]
    if not ioc_cols:
        return ""

    valid = df[df["error"].isna()]
    agents = sorted(valid["agent"].unique())
    cat_names = [c.replace("ioc_", "").replace("_recall", "") for c in ioc_cols]

    lines = ["## IOC Category Recall by Agent\n"]
    header = "| Agent | " + " | ".join(cat_names) + " |"
    sep = "|" + "---|" * (len(cat_names) + 1)
    lines.append(header)
    lines.append(sep)

    grouped = valid.groupby("agent")
    for agent, grp in sorted(grouped):
        cells = []
        for col in ioc_cols:
            cells.append(_fmt(grp[col].mean(), pct=True))
        lines.append(f"| {agent} | " + " | ".join(cells) + " |")

    lines.append("")
    return "\n".join(lines)


def _table_attack_details(traces: List[dict]) -> str:
    """Table 5: Attack event details per run (isolated mode)."""
    # Filter traces that have attack_details
    attack_traces = [t for t in traces if t.get("attack_details")]
    if not attack_traces:
        return ""

    lines = ["## Attack Event Details\n"]
    tier_map = _scenario_tier_map()

    for t in attack_traces:
        ad = t["attack_details"]
        ev = t.get("evaluation") or {}
        findings = ev.get("findings") or {}
        iocs_eval = ev.get("iocs") or {}
        events_eval = ev.get("events") or {}

        sid = t.get("scenario_id", "?")
        agent = t.get("agent_type", "?")
        model = t.get("model", "?")
        tier = _resolve_tier(t, tier_map)

        lines.append(f"### {sid} — {agent} / {model}\n")
        lines.append(f"- **Tier:** `{tier}`")
        lines.append(f"- **Attack ID:** `{ad.get('attack_id', 'N/A')}`")
        lines.append(f"- **Victim:** {ad.get('victim_email', 'N/A')} (`{ad.get('victim_id', 'N/A')}`)")
        lines.append(f"- **Success:** {ad.get('success', 'N/A')}")
        lines.append(f"- **Start:** {ad.get('start_ts', 'N/A')}")
        lines.append(f"- **Compromise:** {ad.get('compromise_ts', 'N/A')}")
        lines.append(f"- **Injected Events:** {len(ad.get('event_ids', []))}")
        if events_eval:
            er = events_eval.get("recall")
            er_str = f"{er:.0%}" if er is not None else "-"
            lines.append(
                f"- **Events surfaced in tool calls:** "
                f"{events_eval.get('found_count', 0)}/{events_eval.get('total_expected', 0)} ({er_str})"
            )

        # IOCs
        iocs = ad.get("iocs", {})
        if iocs:
            lines.append(f"\n**IOCs ({len(iocs)}):**\n")
            lines.append("| Key | Value | Found |")
            lines.append("|-----|-------|-------|")
            # Build set of found IOC values from evaluation
            found_ioc_values = set()
            for cat_data in iocs_eval.get("categories", {}).values():
                for v in (cat_data.get("found") or []):
                    found_ioc_values.add(v.lower().strip())
            for k, v in sorted(iocs.items()):
                found = "Yes" if str(v).lower().strip() in found_ioc_values else "No"
                lines.append(f"| {k} | `{v}` | {found} |")

        # Expected findings
        expected = ad.get("expected_findings", [])
        if expected:
            lines.append(f"\n**Expected Findings ({len(expected)}):**\n")
            matches = {m["finding"]: m for m in (findings.get("matches") or [])}
            for f_text in expected:
                match = matches.get(f_text)
                if match and match.get("found"):
                    status = "FOUND"
                else:
                    status = "MISSED"
                lines.append(f"- [{status}] {f_text}")

        # Event IDs
        event_ids = ad.get("event_ids", [])
        if event_ids:
            lines.append(f"\n<details><summary>Injected Event IDs ({len(event_ids)})</summary>\n")
            for eid in event_ids:
                lines.append(f"- `{eid}`")
            lines.append("\n</details>")

        lines.append("")

    return "\n".join(lines)


def _table_tier_distribution(df: pd.DataFrame) -> str:
    """Per-tier scenario coverage and overall metric averages (across all agents)."""
    if df.empty or "tier" not in df.columns:
        return ""

    valid = df[df["error"].isna()]
    if valid.empty:
        return ""

    has_events = "event_recall" in valid.columns and valid["event_recall"].notna().any()

    lines = ["## Per-Tier Distribution (averaged across agents and scenarios)\n"]
    lines.append(methods_note() + "\n")
    if has_events:
        lines.append("| Tier | Scenarios | Runs | Findings Recall | IOC Recall | IOC F1 | Event Recall | Composite | Tool Calls (avg) | TC Efficiency |")
        lines.append("|------|-----------|------|-----------------|------------|--------|--------------|-----------|-------------------|---------------|")
    else:
        lines.append("| Tier | Scenarios | Runs | Findings Recall | IOC Recall | IOC F1 | Tool Calls (avg) |")
        lines.append("|------|-----------|------|-----------------|------------|--------|-------------------|")

    tiers_present = [t for t in TIER_ORDER if t in valid["tier"].unique()]
    # Catch any unexpected labels (e.g. "?") so we don't silently drop runs.
    tiers_present += sorted(set(valid["tier"].unique()) - set(TIER_ORDER))

    for tier in tiers_present:
        grp = valid[valid["tier"] == tier]
        if grp.empty:
            continue
        n_scen = grp["scenario_id"].nunique()
        n_runs = len(grp)
        fr = fmt_ci(series_ci(grp, "findings_recall"), pct=True)
        ir = fmt_ci(series_ci(grp, "ioc_recall"), pct=True)
        if1 = fmt_ci(series_ci(grp, "ioc_f1"), pct=True)
        tc = fmt_ci(series_ci(grp, "tool_call_count"), decimals=1)
        if has_events:
            er = fmt_ci(series_ci(grp, "event_recall"), pct=True)
            cs = fmt_ci(series_ci(grp, "composite_score"))
            tce = fmt_ci(series_ci(grp, "tool_call_efficiency"), decimals=1)
            lines.append(f"| {tier} | {n_scen} | {n_runs} | {fr} | {ir} | {if1} | {er} | {cs} | {tc} | {tce} |")
        else:
            lines.append(f"| {tier} | {n_scen} | {n_runs} | {fr} | {ir} | {if1} | {tc} |")

    lines.append("")
    return "\n".join(lines)


def _table_agent_by_tier(df: pd.DataFrame) -> str:
    """Agent x Tier matrix: how each agent's metrics vary across reasoning tiers."""
    if df.empty or "tier" not in df.columns:
        return ""

    valid = df[df["error"].isna()]
    if valid.empty:
        return ""

    tiers_present = [t for t in TIER_ORDER if t in valid["tier"].unique()]
    tiers_present += sorted(set(valid["tier"].unique()) - set(TIER_ORDER))
    agents = sorted(valid["agent"].unique())
    if not tiers_present or not agents:
        return ""

    has_events = "event_recall" in valid.columns and valid["event_recall"].notna().any()

    lines = ["## Agent Performance by Tier\n"]
    lines.append(methods_note() + "\n")

    # (column, label, percent-formatted, decimals when not percent)
    metric_specs = [
        ("findings_recall", "Findings Recall", True, 2),
        ("ioc_recall", "IOC Recall", True, 2),
        ("ioc_f1", "IOC F1", True, 2),
        ("tool_call_count", "Tool Calls (avg)", False, 1),
        ("tool_call_efficiency", "Tool Call Efficiency (avg)", False, 1),
    ]
    if has_events:
        metric_specs.insert(3, ("event_recall", "Event Recall", True, 2))
        metric_specs.insert(4, ("composite_score", "Composite Score", False, 2))

    for col, label, pct, decimals in metric_specs:
        if col not in valid.columns or valid[col].isna().all():
            continue
        lines.append(f"### {label}\n")
        header = "| Agent | " + " | ".join(tiers_present) + " | Overall |"
        sep = "|" + "---|" * (len(tiers_present) + 2)
        lines.append(header)
        lines.append(sep)
        for agent in agents:
            agrp = valid[valid["agent"] == agent]
            cells = []
            for tier in tiers_present:
                tgrp = agrp[agrp["tier"] == tier]
                cells.append(fmt_ci(series_ci(tgrp, col), pct=pct, decimals=decimals))
            overall = fmt_ci(series_ci(agrp, col), pct=pct, decimals=decimals)
            lines.append(f"| {agent} | " + " | ".join(cells) + f" | {overall} |")
        lines.append("")

    return "\n".join(lines)


def _table_errors(df: pd.DataFrame) -> str:
    """Table 6: Error summary."""
    lines = ["## Error Summary\n"]
    lines.append("| Agent | Model | Errors | Error Rate |")
    lines.append("|-------|-------|--------|------------|")

    grouped = df.groupby(["agent", "model"])
    for (agent, model), grp in sorted(grouped):
        total = len(grp)
        errors = grp["error"].notna().sum()
        rate = f"{errors / total:.0%}" if total > 0 else "-"
        lines.append(f"| {agent} | {model} | {errors} | {rate} |")

    lines.append("")
    return "\n".join(lines)


def _write_errors(traces: List[dict], errors_path: Path) -> int:
    """Write a JSONL file with one entry per failed run. Returns the count."""
    written = 0
    with open(errors_path, "w") as f:
        for t in traces:
            err = t.get("error")
            if not err:
                continue
            entry = {
                "scenario_id": t.get("scenario_id"),
                "scenario_name": t.get("scenario_name"),
                "agent": t.get("agent_type"),
                "model": t.get("model"),
                "duration_seconds": t.get("duration_seconds", 0),
                "victim_id": t.get("victim_id"),
                "eval_mode": t.get("eval_mode"),
                "error": err,
            }
            f.write(json.dumps(entry, default=str) + "\n")
            written += 1
    return written


CI_METRICS = [
    "findings_recall",
    "ioc_recall",
    "ioc_precision",
    "ioc_f1",
    "event_recall",
    "tool_call_attack_precision",
    "tool_call_efficiency",
    "composite_score",
    "tool_call_count",
    "llm_calls",
    "duration_s",
]


def build_ci_table(df: pd.DataFrame) -> pd.DataFrame:
    """Tidy one-row-per-(grouping, group, metric) table of means with intervals.

    This is the machine-readable companion to the Markdown tables — the source
    the paper figures and any significance testing should read, so numbers can
    never drift between prose and plot.
    """
    valid = df[df["error"].isna()] if "error" in df.columns else df
    rows: List[dict] = []

    def _emit(grouping: str, group: str, frame: pd.DataFrame) -> None:
        for metric in CI_METRICS:
            if metric not in frame.columns or frame[metric].isna().all():
                continue
            ci = series_ci(frame, metric)
            if ci.mean is None:
                continue
            rows.append({
                "grouping": grouping,
                "group": group,
                "metric": metric,
                **ci.as_dict(),
                "ci_half_width": ci.half_width,
            })

    if valid.empty:
        return pd.DataFrame(
            columns=["grouping", "group", "metric", "mean", "ci_lo", "ci_hi", "n",
                     "n_clusters", "ci_method", "ci_confidence", "ci_half_width"]
        )

    _emit("overall", "all", valid)
    for agent, grp in valid.groupby("agent"):
        _emit("agent", str(agent), grp)
    if "tier" in valid.columns:
        for tier, grp in valid.groupby("tier"):
            _emit("tier", str(tier), grp)
        for (agent, tier), grp in valid.groupby(["agent", "tier"]):
            _emit("agent_tier", f"{agent}|{tier}", grp)
    if "model" in valid.columns and valid["model"].nunique() > 1:
        for model, grp in valid.groupby("model"):
            _emit("model", str(model), grp)

    return pd.DataFrame(rows)


def generate_report(results_dir: str) -> None:
    """Generate a Markdown report, CSV, and errors JSONL from benchmark results.

    Output layout:
        <results_dir>/single_results/*.json   (per-run traces, written by runner)
        <results_dir>/results.csv             (one row per run)
        <results_dir>/report.md               (aggregate tables)
        <results_dir>/errors.jsonl            (one line per failed run)
    """
    traces = load_traces(results_dir)
    out_dir = Path(results_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if not traces:
        print(f"No result files found in {single_results_dir(out_dir)}")
        return

    df = build_dataframe(traces)

    # Save CSV
    csv_path = out_dir / "results.csv"
    df.to_csv(csv_path, index=False)
    print(f"Saved {csv_path}")

    # Save errors (always overwrite — empty if no errors)
    errors_path = out_dir / "errors.jsonl"
    n_errors = _write_errors(traces, errors_path)
    print(f"Saved {errors_path} ({n_errors} error{'s' if n_errors != 1 else ''})")

    # Save aggregate metrics with confidence intervals
    ci_df = build_ci_table(df)
    ci_path = out_dir / "metrics_ci.csv"
    ci_df.to_csv(ci_path, index=False)
    print(f"Saved {ci_path} ({len(ci_df)} aggregate metric{'s' if len(ci_df) != 1 else ''})")

    # Build report
    sections = [
        f"# Benchmark Report\n",
        f"**Runs:** {len(df)} | "
        f"**Scenarios:** {df['scenario_id'].nunique()} | "
        f"**Agents:** {df['agent'].nunique()} | "
        f"**Models:** {df['model'].nunique()}\n",
        _table_agent_comparison(df),
        _table_tier_distribution(df),
        _table_agent_by_tier(df),
        _table_scenario_difficulty(df),
        _table_full_matrix(df),
        _table_event_recall_matrix(df),
        _table_event_types(df),
        _table_ioc_categories(df),
        _table_attack_details(traces),
        _table_errors(df),
    ]

    report = "\n".join(sections)

    # Save report
    report_path = out_dir / "report.md"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"Saved {report_path}")

    # Print to stdout
    print()
    print(report)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate aggregate report from benchmark results",
    )
    parser.add_argument(
        "results_dir",
        help="Directory containing benchmark result JSON files",
    )
    args = parser.parse_args()

    generate_report(args.results_dir)


if __name__ == "__main__":
    main()
