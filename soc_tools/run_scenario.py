"""CLI entry point for running SOC investigation scenarios."""

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from twin.generators.json_to_sql import create_database
from soc_tools import ablation as ablation_mod
from soc_tools.ablation import AblationConfig
from soc_tools.tool_registry import ToolRegistry


def load_scenario(scenario_path: str) -> Dict[str, Any]:
    """Load and validate a scenario YAML file."""
    path = Path(scenario_path)
    if not path.exists():
        raise FileNotFoundError(f"Scenario file not found: {path}")
    with open(path, "r") as f:
        return yaml.safe_load(f)


def setup_scenario(
    scenario: Dict[str, Any],
    db_path: str = None,
    company_data: Optional[Dict[str, Any]] = None,
    skip_db_build: bool = False,
    ablation: Optional[AblationConfig] = None,
) -> ToolRegistry:
    """Set up a scenario: load data into SQLite and configure tool registry.

    Args:
        scenario: Parsed scenario YAML.
        db_path: Optional path for the SQLite database. If None, uses a temp path.
        company_data: Pre-parsed company dict. If provided, the JSON file at
            scenario["company"]["data_file"] is NOT read from disk.
        skip_db_build: If True, assume db_path already exists and contains a
            fully populated database — skip parsing the company JSON and the
            create_database call entirely. ``db_path`` is required in this mode.
        ablation: Optional capability restriction for this arm (see
            soc_tools.ablation). None means the full tool surface. The twin
            database is unaffected — only the tools are narrowed.

    Returns:
        Configured ToolRegistry with tools activated.
    """
    if skip_db_build:
        if db_path is None or not Path(db_path).exists():
            raise ValueError("skip_db_build=True requires an existing db_path")
    else:
        if company_data is None:
            data_file = scenario["company"]["data_file"]
            data_path = Path(data_file)
            if not data_path.is_absolute():
                # Try relative to CWD
                if not data_path.exists():
                    raise FileNotFoundError(f"Company data file not found: {data_path}")

            with open(data_path, "r", encoding="utf-8") as f:
                company_data = json.load(f)

        if db_path is None:
            db_path = f"/tmp/soc_bench_{scenario['scenario']['id']}.db"

        # Remove existing DB
        db_file = Path(db_path)
        if db_file.exists():
            db_file.unlink()

        create_database(db_path, company_data)

    registry = ToolRegistry(db_path, ablation=ablation)
    registry.activate_all()

    return registry


def print_scenario_info(scenario: Dict[str, Any], registry: ToolRegistry) -> None:
    """Print scenario information and available tools."""
    sc = scenario["scenario"]
    alert = scenario["alert"]

    print(f"{'=' * 70}")
    print(f"Scenario: {sc['name']}")
    print(f"ID: {sc['id']}  |  Difficulty: {sc.get('difficulty', 'unknown')}  |  Tags: {', '.join(sc.get('tags', []))}")
    print(f"{'=' * 70}")
    print()
    print(f"ALERT: {alert['title']}")
    print(f"Severity: {alert['severity']}  |  Source: {alert['source']}")
    print(f"Description: {alert['description']}")
    print()

    print("Initial Indicators:")
    for indicator in alert.get("initial_indicators", []):
        print(f"  - {indicator.get('type', '?')}: {indicator.get('value', '?')}")
    print()

    if not registry.ablation.is_noop:
        print(f"Ablation: {registry.ablation.summary()}")
        print()

    print("Available Tools:")
    for tool_id in registry.get_active_tool_ids():
        info = registry.get_tool_info(tool_id)
        if info:
            print(f"  [{info['id']}] {info['name']} ({info['category']}) — {info['query_count']} queries")
    print()

    tools = registry.get_llm_tools()
    print(f"Total LLM tool functions: {len(tools)}")
    for t in tools:
        fn = t["function"]
        params = list(fn["parameters"].get("properties", {}).keys())
        print(f"  - {fn['name']}({', '.join(params)})")
    print()


def main() -> None:
    """Main entry point for soc-bench-run-scenario CLI."""
    parser = argparse.ArgumentParser(
        description="Run a SOC investigation benchmark scenario"
    )
    parser.add_argument(
        "scenario",
        help="Path to scenario YAML file",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="Path for the SQLite database (default: /tmp/soc_bench_<id>.db)",
    )
    parser.add_argument(
        "--info-only",
        action="store_true",
        help="Only print scenario info and available tools, then exit",
    )
    parser.add_argument(
        "--output-tools-json",
        default=None,
        help="Write the LLM tool definitions to a JSON file",
    )
    parser.add_argument(
        "--ablation",
        default="none",
        choices=ablation_mod.PRESET_NAMES,
        help="Capability restriction to apply (default: none)",
    )
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    registry = setup_scenario(
        scenario,
        db_path=args.db_path,
        ablation=ablation_mod.resolve(args.ablation),
    )

    print_scenario_info(scenario, registry)

    if args.output_tools_json:
        tools = registry.get_llm_tools()
        out_path = Path(args.output_tools_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(tools, f, indent=2)
        print(f"Tool definitions written to: {out_path}")

    if args.info_only:
        registry.close()
        return

    # Interactive query loop
    print(f"{'=' * 70}")
    print("Interactive Query Mode")
    print("Type a query name and JSON arguments to execute, or 'quit' to exit.")
    print("Example: splunk_search_logs {\"keyword\": \"powershell\"}")
    print(f"{'=' * 70}")

    while True:
        try:
            line = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line or line.lower() in ("quit", "exit", "q"):
            break

        # Parse function name and arguments
        parts = line.split(None, 1)
        func_name = parts[0]
        args_json = parts[1] if len(parts) > 1 else "{}"

        try:
            arguments = json.loads(args_json)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON arguments: {e}")
            continue

        try:
            result = registry.execute(func_name, arguments)
            print(json.dumps(result, indent=2, default=str))
        except Exception as e:
            print(f"Error: {e}")

    registry.close()
    print("Session ended.")


if __name__ == "__main__":
    main()
