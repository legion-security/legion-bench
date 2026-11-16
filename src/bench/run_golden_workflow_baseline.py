"""Convenience entry point for the golden-workflow baseline.

Runs the deterministic golden-playbook agent through the standard
isolated- / realistic-mode evaluation harness so the resulting traces
carry the same metrics (event recall, IOC F1, tool-call attack
precision, findings recall, composite score) as the LLM agents.

Usage:

    poetry run run_golden_workflow_baseline isolated \\
        --company bench/fixtures/meridianhcp/baseline/meridianhcp/company_attacks.json \\
        --output-dir results/isolated/meridian/golden_workflow \\
        --model gpt-5.5

Equivalent to:

    poetry run python -m bench.run_baseline isolated \\
        --baseline golden_workflow \\
        --company ... --output-dir ... --model gpt-5.5
"""
from __future__ import annotations

from bench.run_baseline import main as _run_baseline_main


def main() -> None:
    _run_baseline_main(default_baseline="golden_workflow")


if __name__ == "__main__":
    main()
