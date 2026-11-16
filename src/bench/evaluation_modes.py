"""
Two-mode evaluation orchestrator for SOC investigation benchmarks.

Mode 1 — Isolated: One attack at a time into clean company data.
    For each scenario, inject 5 times with different victims, investigate each.

Mode 2 — Realistic: Batch attacks at a specified rate, investigate each ticket.
    Multiple attacks coexist in the same company data.

Both modes delegate investigation to bench.runner.run_single().
"""
from __future__ import annotations

import json
import logging
import random
import shutil
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from tqdm import tqdm

from attacks.engine import generate_attack, generate_attacks, extract_attack_events, _primary_email, _select_people_container
from attacks.scenarios import ATTACK_SCENARIOS
from attacks.ticket_generator import generate_ticket, generate_tickets, save_tickets
from bench.runner import run_single, AGENT_CLASSES, result_path, single_results_dir
from soc_tools.ablation import NO_ABLATION, AblationConfig
from twin.generators.json_to_sql import create_database, insert_attack_delta

logger = logging.getLogger(__name__)

# Sentinels for per-run outcomes other than "completed trace returned".
_SKIPPED = object()
_PREP_FAILED = object()


def _select_victims(
    company: Dict[str, Any],
    n: int,
    seed: int,
    scenario_id: str,
) -> List[Dict[str, Any]]:
    """Select n random eligible employees deterministically."""
    rng = random.Random(hash((seed, scenario_id)))
    people, _ = _select_people_container(company)
    eligible = [p for p in people if _primary_email(p) and p.get("id")]
    if not eligible:
        return []
    n = min(n, len(eligible))
    return rng.sample(eligible, n)


def _load_completed_isolated_runs(out_dir: Path) -> set:
    """Scan existing isolated-mode trace JSONs and return the set of
    (base_scenario_id, victim_index, agent, safe_model, ablation) tuples done.

    The on-disk filename embeds a random attack_id suffix, so we identify a
    completed run by reading `base_scenario_id` and `victim_index` from the
    trace itself (saved by `_run_one`) and pairing them with the agent/model
    parsed from the filename.
    """
    results_dir = single_results_dir(out_dir)
    completed: set = set()
    if not results_dir.exists():
        return completed
    for f in results_dir.glob("*.json"):
        # Filename: <scenario_with_atk>__<agent>__<safe_model>[__ablation_<name>]
        # Strip the optional ablation suffix first so the rsplit below still
        # lines up, and key on it so arms sharing a directory resume separately.
        stem = f.stem
        ablation_name = "none"
        if "__ablation_" in stem:
            stem, _, ablation_name = stem.partition("__ablation_")
        # rsplit so a model name containing "__" still parses correctly.
        parts = stem.rsplit("__", 2)
        if len(parts) != 3:
            continue
        _, agent, safe_model = parts
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        sid = data.get("base_scenario_id")
        vidx = data.get("victim_index")
        if sid is None or vidx is None:
            continue
        completed.add((sid, int(vidx), agent, safe_model, ablation_name))
    return completed


def _format_progress(idx: int, total: int, trace: dict) -> str:
    """Format a one-line progress string for a completed run."""
    agent = trace["agent_type"]
    model = trace["model"]
    sid = trace["scenario_id"]
    dur = trace["duration_seconds"]

    if trace.get("error"):
        return f"  [{idx}/{total}] {agent} | {model} | {sid} — ERROR ({dur:.0f}s)"

    ev = trace.get("evaluation")
    if ev and ev.get("findings"):
        fr = ev["findings"]
        ir = ev["iocs"]
        return (
            f"  [{idx}/{total}] {agent} | {model} | {sid} "
            f"— findings={fr['found_count']}/{fr['total_expected']} "
            f"ioc={ir['total_found']}/{ir['total_expected']} ({dur:.0f}s)"
        )

    return f"  [{idx}/{total}] {agent} | {model} | {sid} — done ({dur:.0f}s)"


# ---------------------------------------------------------------------------
# Mode 1: Isolated
# ---------------------------------------------------------------------------

def run_isolated_mode(
    company_path: str,
    *,
    scenario_ids: Optional[List[str]] = None,
    n_victims: int = 5,
    agents: List[str],
    models: List[str],
    seed: int = 42,
    max_turns: int = 15,
    eval_model: str = "gpt-4o-mini",
    output_dir: str = "results/isolated",
    resume: bool = False,
    debug: bool = False,
    workers: int = 4,
    progress: bool = False,
    ablation: Optional[AblationConfig] = None,
) -> Path:
    """
    Isolated evaluation: one attack at a time, fresh company data per run.

    For each scenario, selects *n_victims* random employees and runs each
    attack in isolation. Every attack is forced to succeed so a ticket is
    always generated.

    Returns the output directory Path.
    """
    ablation = ablation or NO_ABLATION
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = out_dir / "_tmp"

    if debug:
        debug_dir = out_dir / "_debug"
        debug_dir.mkdir(exist_ok=True)

    raw_bytes = Path(company_path).read_bytes()

    # Parse once for victim selection (and to build the base SQLite below).
    base_company = json.loads(raw_bytes)

    # In debug mode, maintain a single company with ALL attacks injected
    if debug:
        debug_company = json.loads(raw_bytes)

    # Resolve scenario list
    if scenario_ids is None:
        scenario_ids = list(ATTACK_SCENARIOS.keys())
    else:
        scenario_ids = [s for s in scenario_ids if s in ATTACK_SCENARIOS]

    if not scenario_ids:
        print("No valid scenarios found.")
        return out_dir

    # Pre-select victims per scenario
    victim_assignments: Dict[str, List[Dict[str, Any]]] = {}
    for sid in scenario_ids:
        victims = _select_victims(base_company, n_victims, seed, sid)
        if not victims:
            logger.warning("No eligible victims for scenario %s — skipping", sid)
            continue
        victim_assignments[sid] = victims

    # On resume, scan the output dir once to learn which (sid, vidx, agent, model)
    # tuples already have a trace file. We filter the run plan against this set
    # so prep work (attack generation + per-group DB delta) is also skipped.
    completed_runs: set = _load_completed_isolated_runs(out_dir) if resume else set()

    # Build run plan: (scenario_id, victim_idx, victim, agent, model)
    runs: List[Tuple[str, int, Dict, str, str]] = []
    prefilter_skipped = 0
    for sid, victims in victim_assignments.items():
        for vidx, victim in enumerate(victims):
            for agent_name in agents:
                for model in models:
                    safe_model = model.replace("/", "_").replace(":", "_")
                    if (sid, vidx, agent_name, safe_model, ablation.name) in completed_runs:
                        prefilter_skipped += 1
                        continue
                    runs.append((sid, vidx, victim, agent_name, model))

    total = len(runs)
    if total == 0:
        if prefilter_skipped:
            print(f"All {prefilter_skipped} run(s) already completed. Nothing to do.")
        else:
            print("No runs to execute.")
        return out_dir

    # Build the base SQLite ONCE from the unattacked company. Per-(sid,vidx)
    # groups copy this and append their attack's events as a delta — avoiding
    # the ~4s create_database cost on every run. Built only after the early
    # returns above so a no-op run does not leave _tmp/ behind.
    tmp_dir.mkdir(exist_ok=True)
    base_db_path = tmp_dir / "_base.db"
    if not base_db_path.exists():
        print("Building base SQLite from company data (one-time)...")
        create_database(str(base_db_path), base_company)
        print(f"  base DB: {base_db_path} ({base_db_path.stat().st_size / 1e6:.1f} MB)")

    del base_company  # free memory

    print(f"Isolated mode: {len(victim_assignments)} scenarios × {n_victims} victims")
    print(f"Agents: {', '.join(agents)}  |  Models: {', '.join(models)}")
    if not ablation.is_noop:
        print(f"Ablation: {ablation.summary()}")
    if prefilter_skipped:
        print(f"Resume: skipping {prefilter_skipped} already-completed run(s)")
    print(f"Total runs: {total}  |  Workers: {workers}")
    print("=" * 70)

    debug_lock = threading.Lock() if debug else None

    # Per-(sid, vidx) prep cache. _PREP_FAILED stored if attack/ticket generation
    # fails for that group so we don't retry. Built lazily under per-group lock.
    group_prep: Dict[Tuple[str, int], Any] = {}
    group_prep_lock = threading.Lock()
    per_group_locks: Dict[Tuple[str, int], threading.Lock] = defaultdict(threading.Lock)

    def _prep_group(sid: str, vidx: int, victim: Dict[str, Any]):
        """Build (or reuse) the per-group attack DB + ticket. Thread-safe."""
        key = (sid, vidx)
        with group_prep_lock:
            if key in group_prep:
                return group_prep[key]
            per_lock = per_group_locks[key]

        with per_lock:
            with group_prep_lock:
                if key in group_prep:
                    return group_prep[key]

            attack_seed = seed * 10000 + vidx
            company = json.loads(raw_bytes)

            try:
                generate_attack(
                    company,
                    scenario_id=sid,
                    victim_id=victim["id"],
                    success=True,
                    seed=attack_seed,
                    days_back=5,
                )
            except (ValueError, KeyError) as exc:
                logger.warning("Attack generation failed for %s/%s: %s", sid, victim["id"], exc)
                with group_prep_lock:
                    group_prep[key] = _PREP_FAILED
                return _PREP_FAILED

            if debug:
                with debug_lock:
                    try:
                        generate_attack(
                            debug_company,
                            scenario_id=sid,
                            victim_id=victim["id"],
                            success=True,
                            seed=attack_seed,
                            days_back=5,
                        )
                    except (ValueError, KeyError):
                        pass

            ground_truth = company["_attack_ground_truth"][0]
            attack_id = ground_truth["attack_id"]

            # The ticket's company.data_file is unused at run time when we
            # call run_single with skip_db_build=True.
            ticket = generate_ticket(ground_truth, company, "<unused — skip_db_build>")
            if ticket is None:
                logger.warning("No ticket generated for %s — skipping group", sid)
                with group_prep_lock:
                    group_prep[key] = _PREP_FAILED
                return _PREP_FAILED

            yaml_id = ticket["scenario"]["id"]

            # Copy the base DB and append only this attack's events as a delta.
            group_db_path = tmp_dir / f"group_{yaml_id}.db"
            shutil.copyfile(base_db_path, group_db_path)
            insert_attack_delta(str(group_db_path), company, attack_id)

            ticket_path = tmp_dir / f"ticket_{yaml_id}.yaml"
            with open(ticket_path, "w") as f:
                yaml.dump(ticket, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

            attack_details = {
                "attack_id": attack_id,
                "scenario_id": ground_truth.get("scenario_id"),
                "victim_id": ground_truth.get("victim_id"),
                "victim_email": ground_truth.get("victim_email"),
                "success": ground_truth.get("success"),
                "start_ts": ground_truth.get("start_ts"),
                "compromise_ts": ground_truth.get("compromise_ts"),
                "iocs": ground_truth.get("iocs", {}),
                "expected_findings": ground_truth.get("expected_findings", []),
                "event_ids": ground_truth.get("event_ids", []),
                "events": extract_attack_events(company, attack_id),
            }

            debug_ticket_path = None
            if debug:
                debug_ticket_path = debug_dir / f"{yaml_id}_ticket.yaml"
                shutil.copy(ticket_path, debug_ticket_path)

            del company  # release ~400MB ASAP

            prep = {
                "group_db_path": group_db_path,
                "ticket_path": ticket_path,
                "yaml_id": yaml_id,
                "attack_details": attack_details,
                "debug_ticket_path": debug_ticket_path,
            }
            with group_prep_lock:
                group_prep[key] = prep
            return prep

    def _run_one(args):
        sid, vidx, victim, agent_name, model = args
        prep = _prep_group(sid, vidx, victim)
        if prep is _PREP_FAILED:
            return _PREP_FAILED

        yaml_id = prep["yaml_id"]
        # Must match the path run_single writes to, ablation included — otherwise
        # the enriched trace below lands beside run_single's copy and the report
        # counts the run twice.
        trace_path = result_path(out_dir, yaml_id, agent_name, model, ablation.name)

        # The per-group SQLite is read-only at run time (tools issue SELECTs only),
        # so multiple agent runs share it via independent connections — no per-run
        # copy needed.
        trace = run_single(
            scenario_path=prep["ticket_path"],
            agent_name=agent_name,
            model=model,
            max_turns=max_turns,
            eval_model=eval_model,
            output_dir=out_dir,
            db_path=str(prep["group_db_path"]),
            quiet=progress,
            skip_db_build=True,
            attack_events=prep["attack_details"].get("events"),
            ablation=ablation,
        )

        trace["eval_mode"] = "isolated"
        trace["victim_index"] = vidx
        trace["victim_id"] = victim["id"]
        trace["victim_email"] = _primary_email(victim)
        trace["base_scenario_id"] = sid
        trace["attack_details"] = prep["attack_details"]
        if debug and prep["debug_ticket_path"] is not None:
            trace["debug_company_path"] = str(debug_dir / "company_all_attacks.json")
            trace["debug_ticket_path"] = str(prep["debug_ticket_path"])

        trace_path.parent.mkdir(parents=True, exist_ok=True)
        with open(trace_path, "w") as f:
            json.dump(trace, f, indent=2, default=str)

        return trace

    completed = 0
    skipped = 0
    errors = 0
    prep_failed = 0
    print_lock = threading.Lock()

    bar = tqdm(total=total, desc="Isolated", unit="run", disable=not progress)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = [ex.submit(_run_one, run) for run in runs]
        for fut in as_completed(futures):
            result = fut.result()
            with print_lock:
                if result is _SKIPPED:
                    skipped += 1
                elif result is _PREP_FAILED:
                    prep_failed += 1
                else:
                    completed += 1
                    if result.get("error"):
                        errors += 1
                    if not progress:
                        print(_format_progress(completed + skipped, total, result))
                if progress:
                    bar.update(1)
                    bar.set_postfix(
                        ok=completed - errors,
                        err=errors,
                        skip=skipped,
                        prep_fail=prep_failed,
                    )
    bar.close()

    # Save single debug company with all attacks
    if debug:
        debug_company_path = debug_dir / "company_all_attacks.json"
        with open(debug_company_path, "w") as f:
            json.dump(debug_company, f)
        n_attacks = len(debug_company.get("_attack_ground_truth", []))
        print(f"Debug: saved {debug_company_path} ({n_attacks} attacks)")

    # Clean up the base + per-group SQLite files and tickets in tmp dir (unless
    # debug mode kept the tickets in _debug). Then drop the dir if empty.
    if not debug:
        try:
            shutil.rmtree(tmp_dir)
        except OSError:
            pass
    else:
        try:
            tmp_dir.rmdir()
        except OSError:
            pass

    print("=" * 70)
    if prefilter_skipped:
        print(f"Skipped {prefilter_skipped} already-completed run(s) (resume)")
    print(f"Completed: {completed} | Total: {total}")
    print(f"Results saved to {out_dir}/")

    # Generate report
    try:
        from bench.report import generate_report
        generate_report(str(out_dir))
    except Exception as exc:
        logger.warning("Report generation failed: %s", exc)

    return out_dir


# ---------------------------------------------------------------------------
# Mode 2: Realistic
# ---------------------------------------------------------------------------

def run_realistic_mode(
    company_path: str,
    *,
    attack_rate: float = 0.10,
    scenario_ids: Optional[List[str]] = None,
    agents: List[str],
    models: List[str],
    seed: int = 1337,
    max_turns: int = 15,
    eval_model: str = "gpt-4o-mini",
    output_dir: str = "results/realistic",
    resume: bool = False,
    workers: int = 4,
    progress: bool = False,
    ablation: Optional[AblationConfig] = None,
) -> Path:
    """
    Realistic evaluation: batch attacks at a given rate, then investigate each.

    Attacks coexist in the same company data — the agent investigates one
    ticket at a time but the underlying database contains all attacks.

    Returns the output directory Path.
    """
    ablation = ablation or NO_ABLATION
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load company and inject attacks
    print(f"Loading company data from {company_path}...")
    with open(company_path, "r", encoding="utf-8") as f:
        company = json.load(f)

    print(f"Injecting attacks at rate={attack_rate}...")
    stats = generate_attacks(
        company,
        attack_rate=attack_rate,
        scenario_ids=scenario_ids,
        seed=seed,
    )

    print(f"  Employees targeted: {stats['employees_targeted']}")
    print(f"  Successful: {stats['attacks_successful']}")
    print(f"  Failed: {stats['attacks_failed']}")
    print(f"  By scenario: {stats['by_scenario']}")

    # Save modified company
    modified_company_path = out_dir / "company_realistic.json"
    with open(modified_company_path, "w") as f:
        json.dump(company, f)
    print(f"Modified company saved to {modified_company_path}")

    # Build the shared SQLite DB ONCE. All tickets share the same company,
    # so all runs share the same DB (read-only at run time).
    shared_db_path = out_dir / "company_realistic.db"
    if shared_db_path.exists():
        shared_db_path.unlink()
    print("Building shared SQLite database (one-time)...")
    create_database(str(shared_db_path), company)
    print(f"  shared DB: {shared_db_path} ({shared_db_path.stat().st_size / 1e6:.1f} MB)")

    # Generate tickets for all successful attacks
    tickets = generate_tickets(company, str(modified_company_path))
    if not tickets:
        print("No tickets generated (all attacks may have failed or lack templates).")
        return out_dir

    # Free the company dict — agents read from SQLite from here on.
    del company

    ticket_dir = out_dir / "tickets"
    ticket_paths = save_tickets(tickets, str(ticket_dir))
    print(f"Generated {len(ticket_paths)} ticket(s)")

    # Build run plan
    runs: List[Tuple[Path, str, str]] = []
    for tp in ticket_paths:
        for agent_name in agents:
            for model in models:
                runs.append((tp, agent_name, model))

    total = len(runs)
    print(f"Agents: {', '.join(agents)}  |  Models: {', '.join(models)}")
    if not ablation.is_noop:
        print(f"Ablation: {ablation.summary()}")
    print(f"Total runs: {total}  |  Workers: {workers}")
    print("=" * 70)

    def _run_one(args):
        ticket_path, agent_name, model = args
        with open(ticket_path) as f:
            scenario_data = yaml.safe_load(f)
        yaml_id = scenario_data["scenario"]["id"]
        # Must match run_single's own output path, ablation included.
        trace_path = result_path(out_dir, yaml_id, agent_name, model, ablation.name)
        if resume and trace_path.exists():
            return _SKIPPED

        # All tickets point to the same modified company file. We pre-built
        # the shared SQLite once above, so every run reuses it (read-only).
        trace = run_single(
            scenario_path=ticket_path,
            agent_name=agent_name,
            model=model,
            max_turns=max_turns,
            eval_model=eval_model,
            output_dir=out_dir,
            db_path=str(shared_db_path),
            skip_db_build=True,
            quiet=progress,
            ablation=ablation,
        )

        trace["eval_mode"] = "realistic"
        trace["attack_rate"] = attack_rate

        trace_path.parent.mkdir(parents=True, exist_ok=True)
        with open(trace_path, "w") as f:
            json.dump(trace, f, indent=2, default=str)

        return trace

    completed = 0
    skipped = 0
    errors = 0
    print_lock = threading.Lock()

    bar = tqdm(total=total, desc="Realistic", unit="run", disable=not progress)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = [ex.submit(_run_one, run) for run in runs]
        for fut in as_completed(futures):
            result = fut.result()
            with print_lock:
                if result is _SKIPPED:
                    skipped += 1
                else:
                    completed += 1
                    if result.get("error"):
                        errors += 1
                    if not progress:
                        print(_format_progress(completed + skipped, total, result))
                if progress:
                    bar.update(1)
                    bar.set_postfix(
                        ok=completed - errors,
                        err=errors,
                        skip=skipped,
                    )
    bar.close()

    print("=" * 70)
    if skipped:
        print(f"Skipped {skipped} already-completed run(s)")
    print(f"Completed: {completed} | Total: {total}")
    print(f"Results saved to {out_dir}/")

    # Generate report
    try:
        from bench.report import generate_report
        generate_report(str(out_dir))
    except Exception as exc:
        logger.warning("Report generation failed: %s", exc)

    return out_dir
