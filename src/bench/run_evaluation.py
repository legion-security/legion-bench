#!/usr/bin/env python3
"""
CLI entry point for the two-mode SOC investigation benchmark.

Usage:
    # Mode 1 — Isolated: one attack at a time, fresh data per run
    python -m bench.run_evaluation isolated \
        --company bench/fixtures/nexustech_global/baseline/nexustech_global/company_enriched.json \
        --n-victims 5 \
        --agents spa,react \
        --models gpt-4o \
        --output-dir results/isolated

    # Mode 2 — Realistic: batch attacks, all coexist in same data
    python -m bench.run_evaluation realistic \
        --company bench/fixtures/nexustech_global/baseline/nexustech_global/company_enriched.json \
        --attack-rate 0.10 \
        --agents spa,react \
        --models gpt-4o \
        --output-dir results/realistic

    # List all available scenario IDs
    python -m bench.run_evaluation list-scenarios
"""
import argparse
import logging

from attacks.scenarios import ATTACK_SCENARIOS
from bench.evaluation_modes import run_isolated_mode, run_realistic_mode
from bench.runner import AGENT_CLASSES, ALL_AGENTS
from soc_tools import ablation as ablation_mod


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments shared by both modes."""
    parser.add_argument(
        "--company",
        required=True,
        help="Path to company JSON fixture",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help="Run a single scenario ID (e.g. --scenario aitm_phishing). "
             "Use 'list-scenarios' to see all IDs.",
    )
    parser.add_argument(
        "--scenarios",
        default=None,
        help="Comma-separated scenario IDs (e.g. --scenarios aitm_phishing,kerberoasting). "
             "Omit to run all.",
    )
    parser.add_argument(
        "--agents",
        default="spa",
        help=f"Comma-separated agent names (default: spa). Available: {','.join(ALL_AGENTS)}",
    )
    parser.add_argument(
        "--models",
        default="gpt-4o",
        help="Comma-separated model names (default: gpt-4o)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=15,
        help="Max LLM turns per investigation (default: 15)",
    )
    parser.add_argument(
        "--eval-model",
        default="gpt-4o-mini",
        help="Model for evaluation LLM judge (default: gpt-4o-mini)",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Output directory for results",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip runs that already have result files",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of parallel run workers (default: 4). Set to 1 for sequential. "
             "Bumping this multiplies LLM API concurrency — watch rate limits.",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Show a tqdm progress bar instead of a per-run status line.",
    )
    parser.add_argument(
        "--ablation",
        default="none",
        choices=ablation_mod.PRESET_NAMES,
        help="Restrict the agent's tool surface for this arm (default: none). "
             "'no_tier1' removes the tools that carry their own detection logic; "
             "'ti_verdict_only' strips attack attribution from threat-intel "
             "lookups; 'no_analysis' applies both. The twin data is unchanged.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run SOC investigation benchmark in isolated or realistic mode",
    )
    subparsers = parser.add_subparsers(dest="mode")

    # --- Isolated mode ---
    iso = subparsers.add_parser(
        "isolated",
        help="One attack at a time, fresh company data per run",
    )
    _add_common_args(iso)
    iso.add_argument(
        "--n-victims",
        type=int,
        default=5,
        help="Number of different employees to target per scenario (default: 5)",
    )
    iso.add_argument(
        "--debug",
        action="store_true",
        help="Keep attacked company JSON and ticket YAML for each run (in _debug/ subdir)",
    )

    # --- Realistic mode ---
    real = subparsers.add_parser(
        "realistic",
        help="Batch attacks at a specified rate, investigate each",
    )
    _add_common_args(real)
    real.add_argument(
        "--attack-rate",
        type=float,
        default=0.10,
        help="Fraction of employees to target, 0.0-1.0 (default: 0.10)",
    )

    # --- List scenarios ---
    subparsers.add_parser(
        "list-scenarios",
        help="List all available scenario IDs",
    )

    args = parser.parse_args()

    if args.mode is None:
        parser.print_help()
        return

    if args.mode == "list-scenarios":
        print(f"Available Attack Scenarios ({len(ATTACK_SCENARIOS)}):")
        print("=" * 70)
        for sid, scenario in ATTACK_SCENARIOS.items():
            print(f"  {sid:<45} {scenario.attack_type:<20} {scenario.name}")
        return

    # Common setup
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    agents = [a.strip() for a in args.agents.split(",")]
    models = [m.strip() for m in args.models.split(",")]

    for a in agents:
        if a not in AGENT_CLASSES:
            parser.error(f"Unknown agent: {a}. Choose from: {', '.join(ALL_AGENTS)}")

    # Merge --scenario (single) and --scenarios (multiple)
    scenario_ids = None
    if args.scenario and args.scenarios:
        parser.error("Use --scenario for one ID or --scenarios for multiple, not both.")
    elif args.scenario:
        scenario_ids = [args.scenario]
    elif args.scenarios:
        scenario_ids = [s.strip() for s in args.scenarios.split(",") if s.strip()]

    # Validate scenario IDs
    if scenario_ids is not None:
        bad = [s for s in scenario_ids if s not in ATTACK_SCENARIOS]
        if bad:
            parser.error(
                f"Unknown scenario(s): {', '.join(bad)}\n"
                f"Run 'python -m bench.run_evaluation list-scenarios' to see all IDs."
            )

    if args.mode == "isolated":
        run_isolated_mode(
            company_path=args.company,
            scenario_ids=scenario_ids,
            n_victims=args.n_victims,
            agents=agents,
            models=models,
            seed=args.seed,
            max_turns=args.max_turns,
            eval_model=args.eval_model,
            output_dir=args.output_dir,
            resume=args.resume,
            debug=args.debug,
            workers=args.workers,
            progress=args.progress,
            ablation=ablation_mod.resolve(args.ablation),
        )

    elif args.mode == "realistic":
        if args.attack_rate <= 0 or args.attack_rate > 1:
            parser.error("--attack-rate must be between 0.0 and 1.0")

        run_realistic_mode(
            company_path=args.company,
            attack_rate=args.attack_rate,
            scenario_ids=scenario_ids,
            agents=agents,
            models=models,
            seed=args.seed,
            max_turns=args.max_turns,
            eval_model=args.eval_model,
            output_dir=args.output_dir,
            resume=args.resume,
            workers=args.workers,
            progress=args.progress,
            ablation=ablation_mod.resolve(args.ablation),
        )


if __name__ == "__main__":
    main()
