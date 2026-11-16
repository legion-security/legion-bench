"""CLI entry point for running SOC investigation scenarios with an agent."""

import argparse
import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from agents.spa import SPAAgent
from agents.direct import DirectAgent
from agents.react import ReActAgent
from agents.reflexion import ReflexionAgent
from agents.multi import MultiAgent
from evaluation import evaluate_investigation, evaluation_to_dict, format_evaluation_report
from soc_tools.run_scenario import load_scenario, setup_scenario


AGENT_CLASSES = {
    "spa": SPAAgent,
    "direct": DirectAgent,
    "react": ReActAgent,
    "reflexion": ReflexionAgent,
    "multi": MultiAgent,
}



def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a SOC investigation scenario with an autonomous agent",
    )
    parser.add_argument("scenario", help="Path to scenario YAML file")
    parser.add_argument("--model", default="gpt-4o", help="LLM model name (default: gpt-4o)")
    parser.add_argument(
        "--agent",
        default="spa",
        choices=list(AGENT_CLASSES.keys()),
        help="Agent strategy (default: spa)",
    )
    parser.add_argument("--max-turns", type=int, default=15, help="Max LLM turns (default: 15)")
    parser.add_argument("--output", default=None, help="Save trace to a specific JSON file path")
    parser.add_argument("--no-output", action="store_true", help="Don't save trace at all (by default saves to results/<scenario_id>/<timestamp>.json)")
    parser.add_argument("--db-path", default=None, help="Path for SQLite database")
    parser.add_argument("--eval-model", default="gpt-4o-mini", help="Model for evaluation judge (default: gpt-4o-mini)")
    parser.add_argument("--no-eval", action="store_true", help="Skip evaluation after investigation")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Load scenario and set up tools
    scenario = load_scenario(args.scenario)
    registry = setup_scenario(scenario, db_path=args.db_path)

    sc = scenario["scenario"]

    # Create agent
    agent_cls = AGENT_CLASSES[args.agent]
    agent_kwargs = {
        "model": args.model,
        "registry": registry,
        "scenario": scenario,
        "max_turns": args.max_turns,
    }
    agent = agent_cls(**agent_kwargs)

    # Run investigation
    result = agent.run()

    # Print final report
    print(f"\n{'=' * 70}")
    print("INVESTIGATION REPORT")
    print(f"{'=' * 70}\n")
    print(result.report)

    # Run evaluation
    eval_dict = None
    if not args.no_eval and "evaluation" in scenario:
        eval_result = evaluate_investigation(result, scenario, eval_model=args.eval_model)
        eval_dict = evaluation_to_dict(eval_result)

        print(f"\n{'=' * 70}")
        print(format_evaluation_report(eval_result))
        print(f"{'=' * 70}")

    # Determine output path: explicit --output, or auto-generated under results/
    out_path: Path | None = None
    if args.output:
        out_path = Path(args.output)
    elif not args.no_output:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = Path("results") / sc["id"] / f"{ts}.json"

    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)

        trace = {
            "scenario_id": sc["id"],
            "scenario_name": sc["name"],
            "agent_type": args.agent,
            "model": args.model,
            "report": result.report,
            "llm_calls": result.llm_calls,
            "tool_calls": [asdict(tc) for tc in result.tool_calls],
            "messages": result.messages,
            "metadata": result.metadata,
        }
        if eval_dict is not None:
            trace["evaluation"] = eval_dict

        with open(out_path, "w") as f:
            json.dump(trace, f, indent=2, default=str)

        print(f"\nTrace saved to {out_path}")

    registry.close()


if __name__ == "__main__":
    main()
