"""CLI entry point for deterministic baseline runs."""

from __future__ import annotations

import argparse
import logging
from typing import Optional, Sequence

from bench.evaluation_modes import run_isolated_mode, run_realistic_mode

BASELINES = {"golden_workflow"}


def _add_common_args(parser: argparse.ArgumentParser, default_baseline: Optional[str]) -> None:
    baseline_required = default_baseline is None
    parser.add_argument(
        "--baseline",
        required=baseline_required,
        default=default_baseline,
        choices=sorted(BASELINES),
        help=(
            "Deterministic baseline to run "
            f"(default: {default_baseline})"
            if default_baseline
            else "Deterministic baseline to run"
        ),
    )
    parser.add_argument("--company", required=True, help="Path to company JSON fixture")
    parser.add_argument("--scenario", default=None, help="Single scenario ID")
    parser.add_argument("--scenarios", default=None, help="Comma-separated scenario IDs")
    parser.add_argument("--model", default="deterministic", help="Model label stored in trace metadata")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-turns", type=int, default=80, help="Mapped to deterministic tool-call budget")
    parser.add_argument("--eval-model", default="gpt-4o-mini")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")


def _build_parser(default_baseline: Optional[str] = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic LEGION baselines.")
    sub = parser.add_subparsers(dest="mode")

    iso = sub.add_parser("isolated", help="Run isolated evaluation mode")
    _add_common_args(iso, default_baseline)
    iso.add_argument("--n-victims", type=int, default=5)
    iso.add_argument("--debug", action="store_true")

    real = sub.add_parser("realistic", help="Run realistic evaluation mode")
    _add_common_args(real, default_baseline)
    real.add_argument("--attack-rate", type=float, default=0.10)
    return parser


def _parse_scenarios(args: argparse.Namespace, parser: argparse.ArgumentParser) -> Optional[list[str]]:
    if args.scenario and args.scenarios:
        parser.error("Use either --scenario or --scenarios, not both.")
    if args.scenario:
        return [args.scenario]
    if args.scenarios:
        values = [s.strip() for s in args.scenarios.split(",") if s.strip()]
        if not values:
            parser.error("--scenarios was provided but no valid scenario IDs were parsed.")
        return values
    return None


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    default_baseline: Optional[str] = None,
) -> None:
    parser = _build_parser(default_baseline=default_baseline)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.mode is None:
        parser.print_help()
        return

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    scenario_ids = _parse_scenarios(args, parser)
    agents = [args.baseline]
    models = [args.model]

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
        )
        return

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
    )


if __name__ == "__main__":
    main()
