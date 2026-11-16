#!/usr/bin/env python3
"""
Generate all single-knob difficulty variations of each company.

For each company config, generates:
  - bench/fixtures/{company}/baseline/          (all defaults)
  - bench/fixtures/{company}/employees_x{N}/    (scaled employee count)
  - bench/fixtures/{company}/event_density_x{N}/ (scaled event multipliers)
  - bench/fixtures/{company}/confounder_rate_x{N}/ (scaled confounder rates)
  - bench/fixtures/{company}/correlation_ratio_{N}/ (absolute correlation ratio)
  - bench/fixtures/{company}/baseline_std_x{N}/  (scaled baseline std devs)

Only one knob is changed at a time; all others stay at defaults.

Usage:
    poetry run python scripts/generate_variations.py
    poetry run python scripts/generate_variations.py --companies nexustech_global brightcart_inc
    poetry run python scripts/generate_variations.py --dry-run
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

def _subprocess_env():
    """Build env dict with PYTHONPATH including src/ and project root."""
    env = os.environ.copy()
    src_dir = str(ROOT / "src")
    root_dir = str(ROOT)
    existing = env.get("PYTHONPATH", "")
    parts = [src_dir, root_dir] + ([existing] if existing else [])
    env["PYTHONPATH"] = os.pathsep.join(parts)
    return env
    
CONFIGS_DIR = ROOT / "src" / "company_generation" / "static" / "configurations" / "static_companies"
FIXTURES_DIR = ROOT / "bench" / "fixtures"

# ── Knob definitions ──────────────────────────────────────────────────────────
# Each knob is a list of non-default values to generate.
# The baseline (all defaults) is always generated separately.

EMPLOYEE_SCALES = [0.5, 2.0, 3.0]
EVENT_DENSITY_SCALES = [0.5, 1.5, 2.0, 3.0]
CONFOUNDER_RATE_SCALES = [0.5, 1.5, 2.0, 3.0]
CORRELATION_RATIOS = [0.1, 0.5, 0.7, 0.9]  # absolute values (default is 0.3)
BASELINE_STD_SCALES = [0.5, 1.5, 2.0, 3.0]

SEED = 1337


def discover_companies(filter_names=None):
    """Find all company YAML configs."""
    configs = sorted(CONFIGS_DIR.glob("*.yaml"))
    if filter_names:
        configs = [c for c in configs if c.stem in filter_names]
    return configs


def run_static_generator(config_path: Path, out_dir: Path, seed: int = SEED):
    """Run the static company generator."""
    cmd = [
        sys.executable, "-m", "company_generation.static.company_static_generator",
        "--config", str(config_path),
        "--out-dir", str(out_dir),
        "--seed", str(seed),
    ]
    subprocess.run(cmd, check=True, cwd=str(ROOT), env=_subprocess_env())


def run_enrichment(company_json: Path, out_path: Path, seed: int = SEED, **kwargs):
    """Run the variable enrichment CLI with given overrides."""
    cmd = [
        sys.executable, "-m", "company_generation.variable.enrich_events_cli",
        "--company", str(company_json),
        "--out", str(out_path),
        "--seed", str(seed),
        "--min-email-scenarios", "8",
        "--email-scenarios", "12"
    ]
    for key, value in kwargs.items():
        flag = f"--{key.replace('_', '-')}"
        cmd.extend([flag, str(value)])
    
    print(f"\n\n=================================================\nRunning command: {' '.join(cmd)}\n=================================================")
    subprocess.run(cmd, check=True, cwd=str(ROOT), env=_subprocess_env())


def generate_static_with_employee_scale(config_path: Path, scale: float, out_dir: Path):
    """Generate static company with scaled employee count (temp config)."""
    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f)

    original_count = cfg.get("overall", {}).get("employees", 1000)
    cfg["overall"]["employees"] = max(50, round(original_count * scale))

    devices_cfg = cfg.get("devices") or {}
    original_devices = devices_cfg.get("count")
    if original_devices is not None:
        devices_cfg["count"] = max(50, round(original_devices * scale))
        cfg["devices"] = devices_cfg

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, dir=str(ROOT / "tmp"),
    ) as tmp:
        yaml.dump(cfg, tmp, default_flow_style=False, allow_unicode=True)
        tmp_path = Path(tmp.name)

    try:
        run_static_generator(tmp_path, out_dir)
    finally:
        tmp_path.unlink(missing_ok=True)


def find_static_json(out_dir: Path, company_id: str) -> Path:
    """Find the company_static.json inside the output directory."""
    # Static generator writes to {out_dir}/{company_id}/company_static.json
    candidate = out_dir / company_id / "company_static.json"
    if candidate.exists():
        return candidate
    # Fallback: search
    for p in out_dir.rglob("company_static.json"):
        return p
    raise FileNotFoundError(f"No company_static.json found under {out_dir}")


def generate_variation(
    config_path: Path,
    company_id: str,
    variation_name: str,
    employee_scale: float = None,
    enrichment_kwargs: dict = None,
    dry_run: bool = False,
):
    """Generate a single variation for a company."""
    variation_dir = FIXTURES_DIR / company_id / variation_name
    print(f"  → {company_id}/{variation_name}", end="")

    if variation_dir.exists():
        print(" [skip, exists]")
        return

    if dry_run:
        print(" [dry-run]")
        return

    variation_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Generate static data
    if employee_scale is not None:
        generate_static_with_employee_scale(config_path, employee_scale, variation_dir)
    else:
        run_static_generator(config_path, variation_dir)

    # Step 2: Enrich with events
    static_json = find_static_json(variation_dir, company_id)
    enriched_path = variation_dir / company_id / "company_enriched.json"
    enrichment_kwargs = enrichment_kwargs or {}
    run_enrichment(static_json, enriched_path, **enrichment_kwargs)

    print(" [done]")


def generate_all_for_company(config_path: Path, dry_run: bool = False):
    """Generate baseline + all single-knob variations for one company."""
    company_id = config_path.stem
    print(f"\n{'='*60}")
    print(f"Company: {company_id}")
    print(f"{'='*60}")

    # 1. Baseline (all defaults)
    generate_variation(config_path, company_id, "baseline", dry_run=dry_run)

    # 2. Employee count variations
    for scale in EMPLOYEE_SCALES:
        name = f"employees_x{scale}"
        generate_variation(
            config_path, company_id, name,
            employee_scale=scale,
            dry_run=dry_run,
        )

    # 3. Event density variations (uniform multiplier across all event types)
    for scale in EVENT_DENSITY_SCALES:
        name = f"event_density_x{scale}"
        generate_variation(
            config_path, company_id, name,
            enrichment_kwargs={
                "logins_multiplier": scale,
                "file_events_multiplier": scale,
                "admin_actions_multiplier": scale,
                "app_events_multiplier": scale,
                "process_events_multiplier": scale,
                "device_events_multiplier": scale,
                "network_events_multiplier": scale,
                "cloud_events_multiplier": scale,
            },
            dry_run=dry_run,
        )

    # 4. Confounder rate variations
    for scale in CONFOUNDER_RATE_SCALES:
        name = f"confounder_rate_x{scale}"
        generate_variation(
            config_path, company_id, name,
            enrichment_kwargs={"confounder_rate_scale": scale},
            dry_run=dry_run,
        )

    # 5. Correlation ratio variations (absolute, not multiplier)
    for ratio in CORRELATION_RATIOS:
        name = f"correlation_ratio_{ratio}"
        generate_variation(
            config_path, company_id, name,
            enrichment_kwargs={"correlation_ratio": ratio},
            dry_run=dry_run,
        )

    # 6. Baseline std variations
    for scale in BASELINE_STD_SCALES:
        name = f"baseline_std_x{scale}"
        generate_variation(
            config_path, company_id, name,
            enrichment_kwargs={"baseline_std_scale": scale},
            dry_run=dry_run,
        )


def main():
    parser = argparse.ArgumentParser(
        description="Generate all single-knob difficulty variations for benchmark companies",
    )
    parser.add_argument(
        "--companies",
        nargs="*",
        help="Company names to generate (default: all). E.g. nexustech_global brightcart_inc",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be generated without running anything",
    )
    args = parser.parse_args()

    # Ensure tmp dir exists for temp YAML configs
    (ROOT / "tmp").mkdir(exist_ok=True)

    configs = discover_companies(args.companies)
    if not configs:
        print("No company configs found!", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(configs)} company configs")
    total_variations = len(configs) * (
        1  # baseline
        + len(EMPLOYEE_SCALES)
        + len(EVENT_DENSITY_SCALES)
        + len(CONFOUNDER_RATE_SCALES)
        + len(CORRELATION_RATIOS)
        + len(BASELINE_STD_SCALES)
    )
    print(f"Total variations to generate: {total_variations}")

    for config_path in configs:
        generate_all_for_company(config_path, dry_run=args.dry_run)

    print(f"\nDone! Variations written to {FIXTURES_DIR}/")


if __name__ == "__main__":
    main()
