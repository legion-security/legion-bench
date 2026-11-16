"""Benchmark orchestrator: run agents across scenarios and collect results."""

import argparse
import json
import logging
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path
from typing import List, Tuple

from tqdm import tqdm


class _ThreadAwareStdout:
    """Stdout proxy that drops writes from threads flagged 'quiet'.

    Used to silence per-turn agent prints when running with --progress, while
    still letting the orchestrator (main thread) print the tqdm bar and any
    summary lines. tqdm writes to stderr by default, so it is unaffected.
    """

    def __init__(self, original):
        self._original = original
        self._local = threading.local()

    @property
    def quiet(self) -> bool:
        return getattr(self._local, "on", False)

    @quiet.setter
    def quiet(self, value: bool) -> None:
        self._local.on = value

    def write(self, data):
        if getattr(self._local, "on", False):
            return len(data) if isinstance(data, str) else 0
        return self._original.write(data)

    def flush(self):
        return self._original.flush()

    def __getattr__(self, name):
        return getattr(self._original, name)


_thread_stdout: _ThreadAwareStdout | None = None
_install_lock = threading.Lock()


def _install_thread_aware_stdout() -> _ThreadAwareStdout:
    global _thread_stdout
    with _install_lock:
        if _thread_stdout is None:
            _thread_stdout = _ThreadAwareStdout(sys.stdout)
            sys.stdout = _thread_stdout
    return _thread_stdout

from agents.spa import SPAAgent
from agents.direct import DirectAgent
from agents.react import ReActAgent
from agents.reflexion import ReflexionAgent
from agents.multi import MultiAgent
from evaluation import evaluate_investigation, evaluation_to_dict
from soc_tools import ablation as ablation_mod
from soc_tools.ablation import NO_ABLATION, AblationConfig
from soc_tools.run_scenario import load_scenario, setup_scenario

logger = logging.getLogger(__name__)

AGENT_CLASSES = {
    "spa": SPAAgent,
    "direct": DirectAgent,
    "react": ReActAgent,
    "reflexion": ReflexionAgent,
    "multi": MultiAgent,
}

try:
    from baselines.golden import GoldenWorkflowAgent

    AGENT_CLASSES["golden_workflow"] = GoldenWorkflowAgent
except ModuleNotFoundError:
    logger.debug("Golden-workflow baseline not available; skipping registration.")


ALL_AGENTS = list(AGENT_CLASSES.keys())


def discover_scenarios(paths: List[str]) -> List[Path]:
    """Resolve scenario paths: directories are globbed for *.yaml, files used directly."""
    scenarios = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            scenarios.extend(sorted(path.glob("*.yaml")))
        elif path.is_file() and path.suffix in (".yaml", ".yml"):
            scenarios.append(path)
        else:
            # Try as glob pattern
            matches = sorted(Path(".").glob(p))
            scenarios.extend(f for f in matches if f.suffix in (".yaml", ".yml"))
    return scenarios


SINGLE_RESULTS_SUBDIR = "single_results"


def result_filename(
    scenario_id: str,
    agent: str,
    model: str,
    ablation: str | None = None,
) -> str:
    """Build deterministic filename for a run result.

    Ablated arms carry the ablation name in the filename so they cannot silently
    overwrite an unrestricted run of the same (scenario, agent, model).
    """
    safe_model = model.replace("/", "_").replace(":", "_")
    stem = f"{scenario_id}__{agent}__{safe_model}"
    if ablation and ablation != "none":
        stem = f"{stem}__ablation_{ablation}"
    return f"{stem}.json"


def single_results_dir(output_dir: Path) -> Path:
    """Return the subdirectory where per-run trace JSONs live."""
    return Path(output_dir) / SINGLE_RESULTS_SUBDIR


def result_path(
    output_dir: Path,
    scenario_id: str,
    agent: str,
    model: str,
    ablation: str | None = None,
) -> Path:
    """Resolve the absolute path of a per-run trace file."""
    return single_results_dir(output_dir) / result_filename(
        scenario_id, agent, model, ablation
    )


def build_run_matrix(
    scenario_paths: List[Path],
    agents: List[str],
    models: List[str],
) -> List[Tuple[Path, str, str]]:
    """Build the cartesian product of (scenario_path, agent, model)."""
    matrix = []
    for sp in scenario_paths:
        for agent in agents:
            for model in models:
                matrix.append((sp, agent, model))
    return matrix


def filter_completed(
    matrix: List[Tuple[Path, str, str]],
    output_dir: Path,
    ablation: str | None = None,
) -> List[Tuple[Path, str, str]]:
    """Remove runs that already have result files in output_dir."""
    filtered = []
    for scenario_path, agent, model in matrix:
        scenario = load_scenario(str(scenario_path))
        sid = scenario["scenario"]["id"]
        if not result_path(output_dir, sid, agent, model, ablation).exists():
            filtered.append((scenario_path, agent, model))
    return filtered


def run_single(
    scenario_path: Path,
    agent_name: str,
    model: str,
    max_turns: int,
    eval_model: str,
    output_dir: Path,
    db_path: str | None = None,
    quiet: bool = False,
    company_data: dict | None = None,
    skip_db_build: bool = False,
    attack_events: list | None = None,
    ablation: AblationConfig | None = None,
) -> dict:
    """Execute a single (scenario, agent, model) run.

    Returns the trace dict (also saved to disk).

    When quiet=True, stdout writes from this thread are suppressed for the
    duration of the run (used by --progress mode to keep the bar clean).

    When skip_db_build=True, db_path is assumed to be a pre-built SQLite
    database — the company JSON is not re-parsed and the DB is not rebuilt.

    ``ablation`` narrows the tool surface for this arm without changing the twin
    data; it is recorded in the trace and in the result filename.
    """
    ablation = ablation or NO_ABLATION
    proxy = None
    if quiet:
        proxy = _install_thread_aware_stdout()
        proxy.quiet = True

    try:
        scenario = load_scenario(str(scenario_path))
        sc = scenario["scenario"]
        sid = sc["id"]

        # Ensure parallel runs don't share a SQLite path (setup_scenario's default
        # collides on scenario_id only). The ablation is part of the path so
        # concurrent arms don't rebuild the same file underneath each other.
        if db_path is None:
            safe_model = model.replace("/", "_").replace(":", "_")
            db_path = f"/tmp/soc_bench_{sid}__{agent_name}__{safe_model}"
            if not ablation.is_noop:
                db_path = f"{db_path}__{ablation.name}"
            db_path = f"{db_path}.db"

        registry = setup_scenario(
            scenario,
            db_path=db_path,
            company_data=company_data,
            skip_db_build=skip_db_build,
            ablation=ablation,
        )
        try:
            agent_cls = AGENT_CLASSES[agent_name]
            agent = agent_cls(
                model=model,
                registry=registry,
                scenario=scenario,
                max_turns=max_turns,
            )

            start = time.time()
            result = agent.run()
            duration = time.time() - start

            # Evaluation
            eval_dict = None
            if "evaluation" in scenario:
                eval_result = evaluate_investigation(
                    result,
                    scenario,
                    eval_model=eval_model,
                    company_data=company_data,
                    attack_events=attack_events,
                )
                eval_dict = evaluation_to_dict(eval_result)

            trace = {
                "scenario_id": sid,
                "scenario_name": sc["name"],
                "agent_type": agent_name,
                "model": model,
                "ablation": ablation.to_dict(),
                "report": result.report,
                "llm_calls": result.llm_calls,
                "tool_calls": [asdict(tc) for tc in result.tool_calls],
                "messages": result.messages,
                "metadata": result.metadata,
                "evaluation": eval_dict,
                "error": None,
                "duration_seconds": round(duration, 2),
            }
        except Exception as exc:
            trace = {
                "scenario_id": sid,
                "scenario_name": sc["name"],
                "agent_type": agent_name,
                "model": model,
                "ablation": ablation.to_dict(),
                "report": None,
                "llm_calls": 0,
                "tool_calls": [],
                "messages": [],
                "metadata": {},
                "evaluation": None,
                "error": f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}",
                "duration_seconds": 0,
            }
            logger.error("Run failed for %s/%s/%s: %s", sid, agent_name, model, exc)
        finally:
            registry.close()

        # Save trace
        out_path = result_path(output_dir, sid, agent_name, model, ablation.name)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(trace, f, indent=2, default=str)
    finally:
        if proxy is not None:
            proxy.quiet = False

    return trace


def _format_progress(idx: int, total: int, trace: dict) -> str:
    """Format a one-line progress string for a completed run."""
    agent = trace["agent_type"]
    model = trace["model"]
    sid = trace["scenario_id"]
    dur = trace["duration_seconds"]

    if trace["error"]:
        return f"[{idx}/{total}] {agent} | {model} | {sid} — ERROR ({dur:.0f}s)"

    ev = trace.get("evaluation")
    if ev and ev.get("findings"):
        fr = ev["findings"]
        ir = ev["iocs"]
        ev_part = ""
        er = ev.get("events")
        if er:
            ev_part = f" events={er['found_count']}/{er['total_expected']}"
        return (
            f"[{idx}/{total}] {agent} | {model} | {sid} "
            f"— findings={fr['found_count']}/{fr['total_expected']} "
            f"ioc={ir['total_found']}/{ir['total_expected']}{ev_part} ({dur:.0f}s)"
        )

    return f"[{idx}/{total}] {agent} | {model} | {sid} — done ({dur:.0f}s)"


def run_benchmark(
    scenario_paths: List[str],
    agents: List[str],
    models: List[str],
    max_turns: int = 15,
    eval_model: str = "gpt-4o-mini",
    output_dir: str = "results/benchmark",
    resume: bool = False,
    workers: int = 4,
    progress: bool = False,
    ablation: AblationConfig | None = None,
) -> Path:
    """Run the full benchmark and return the output directory path."""
    out_dir = Path(output_dir)
    ablation = ablation or NO_ABLATION

    # Discover scenarios
    scenario_files = discover_scenarios(scenario_paths)
    if not scenario_files:
        print("No scenario files found.")
        return out_dir

    print(f"Discovered {len(scenario_files)} scenario(s)")
    print(f"Agents: {', '.join(agents)}")
    print(f"Models: {', '.join(models)}")
    if not ablation.is_noop:
        print(f"Ablation: {ablation.summary()}")

    # Build run matrix
    matrix = build_run_matrix(scenario_files, agents, models)
    total_before = len(matrix)

    if resume:
        matrix = filter_completed(matrix, out_dir, ablation.name)
        skipped = total_before - len(matrix)
        if skipped:
            print(f"Resuming: skipping {skipped} already-completed run(s)")

    total = len(matrix)
    if total == 0:
        print("All runs already completed. Nothing to do.")
        return out_dir

    print(f"Total runs: {total}  |  Workers: {workers}")
    print("=" * 70)

    print_lock = threading.Lock()
    counter = {"done": 0, "ok": 0, "err": 0}

    def _execute(args):
        scenario_path, agent_name, model = args
        return run_single(
            scenario_path=scenario_path,
            agent_name=agent_name,
            model=model,
            max_turns=max_turns,
            eval_model=eval_model,
            output_dir=out_dir,
            quiet=progress,
            ablation=ablation,
        )

    bar = tqdm(total=total, desc="Runs", unit="run", disable=not progress)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = [ex.submit(_execute, run) for run in matrix]
        for fut in as_completed(futures):
            trace = fut.result()
            with print_lock:
                counter["done"] += 1
                if trace.get("error"):
                    counter["err"] += 1
                else:
                    counter["ok"] += 1
                if progress:
                    bar.update(1)
                    bar.set_postfix(ok=counter["ok"], err=counter["err"])
                else:
                    print(_format_progress(counter["done"], total, trace))
    bar.close()

    print("=" * 70)
    print(f"Benchmark complete. Results saved to {out_dir}/")

    # Generate report
    from bench.report import generate_report

    generate_report(str(out_dir))

    return out_dir


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run SOC investigation benchmark across agents and scenarios",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        required=True,
        help="Scenario YAML files, directories, or glob patterns",
    )
    parser.add_argument(
        "--agents",
        default=",".join(ALL_AGENTS),
        help=f"Comma-separated agent names (default: {','.join(ALL_AGENTS)})",
    )
    parser.add_argument(
        "--models",
        default="gpt-4o",
        help="Comma-separated model names (default: gpt-4o)",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=15,
        help="Max LLM turns per run (default: 15)",
    )
    parser.add_argument(
        "--eval-model",
        default="gpt-4o-mini",
        help="Model for evaluation LLM judge (default: gpt-4o-mini)",
    )
    parser.add_argument(
        "--output-dir",
        default="results/benchmark",
        help="Output directory for results (default: results/benchmark)",
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
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    agents = [a.strip() for a in args.agents.split(",")]
    models = [m.strip() for m in args.models.split(",")]

    for a in agents:
        if a not in AGENT_CLASSES:
            parser.error(f"Unknown agent: {a}. Choose from: {', '.join(ALL_AGENTS)}")

    run_benchmark(
        scenario_paths=args.scenarios,
        agents=agents,
        models=models,
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
