#!/usr/bin/env python3
"""
CLI tool to enrich a company fixture with correlated and independent events.

Generates all event types at once: logins (with app), scenario-based emails
(with file correlation), file events, admin actions, app events, process events,
and device events.

All event volume parameters are **multipliers** of the per-person baseline rate
(1.0 = normal, 2.0 = double, 0.5 = half).  Baselines come from each person's
``behavior_baselines`` or from hardcoded role-tier defaults.

Usage:
    python -m company_generation.variable.enrich_events_cli \
        --company bench/fixtures/company.json \
        --seed 1337 \
        --correlation-ratio 0.3 \
        --activity-level normal

    # Or with fine-grained control:
    python -m company_generation.variable.enrich_events_cli \
        --company bench/fixtures/company.json \
        --seed 1337 \
        --correlation-ratio 0.5 \
        --logins-multiplier 2.0 \
        --email-scenarios 4 \
        --file-events-multiplier 1.5 \
        --admin-actions-multiplier 1.0 \
        --app-events-multiplier 1.0 \
        --process-events-multiplier 2.0 \
        --device-events-multiplier 1.0 \
        --network-events-multiplier 1.0
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enrich a company fixture with correlated and independent event logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with defaults
  python -m company_generation.variable.enrich_events_cli --company company.json

  # High activity with 50% correlation
  python -m company_generation.variable.enrich_events_cli \\
      --company company.json \\
      --correlation-ratio 0.5 \\
      --activity-level high

  # Custom multipliers (double file events, half logins)
  python -m company_generation.variable.enrich_events_cli \\
      --company company.json \\
      --logins-multiplier 0.5 --file-events-multiplier 2.0
        """,
    )

    parser.add_argument(
        "--company",
        required=True,
        help="Path to company JSON fixture (will be modified in-place)",
    )
    parser.add_argument(
        "--out",
        help="Output path (defaults to overwriting input file)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1337,
        help="Random seed for deterministic generation (default: 1337)",
    )
    parser.add_argument(
        "--correlation-ratio",
        type=float,
        default=0.3,
        help="Fraction of employees with correlated scenarios, 0.0-1.0 (default: 0.3)",
    )
    parser.add_argument(
        "--activity-level",
        choices=["minimal", "normal", "high"],
        default=None,
        help="Preset activity level (overrides individual multipliers if set)",
    )
    parser.add_argument(
        "--logins-multiplier",
        type=float,
        default=1.0,
        help="Multiplier for baseline login event rate (1.0 = normal, 2.0 = double, default: 1.0)",
    )
    parser.add_argument(
        "--email-scenarios",
        type=int,
        default=4,
        help="Email thread scenarios per employee (default: 4)",
    )
    parser.add_argument(
        "--min-email-scenarios",
        type=int,
        default=2,
        help="Minimum guaranteed email scenarios per employee (default: 2)",
    )
    parser.add_argument(
        "--file-events-multiplier",
        type=float,
        default=1.0,
        help="Multiplier for baseline file event rate (1.0 = normal, 2.0 = double, default: 1.0)",
    )
    parser.add_argument(
        "--admin-actions-multiplier",
        type=float,
        default=1.0,
        help="Multiplier for baseline admin action rate (1.0 = normal, 2.0 = double, default: 1.0)",
    )
    parser.add_argument(
        "--app-events-multiplier",
        type=float,
        default=1.0,
        help="Multiplier for baseline app event rate (1.0 = normal, 2.0 = double, default: 1.0)",
    )
    parser.add_argument(
        "--process-events-multiplier",
        type=float,
        default=1.0,
        help="Multiplier for baseline process event rate (1.0 = normal, 2.0 = double, default: 1.0)",
    )
    parser.add_argument(
        "--device-events-multiplier",
        type=float,
        default=1.0,
        help="Multiplier for baseline device event rate (1.0 = normal, 2.0 = double, default: 1.0)",
    )
    parser.add_argument(
        "--network-events-multiplier",
        type=float,
        default=1.0,
        help="Multiplier for baseline network event rate (1.0 = normal, 2.0 = double, default: 1.0)",
    )
    parser.add_argument(
        "--cloud-events-multiplier",
        type=float,
        default=1.0,
        help="Multiplier for baseline cloud event rate (1.0 = normal, 2.0 = double, default: 1.0)",
    )
    parser.add_argument(
        "--confounder-rate-scale",
        type=float,
        default=1.0,
        help="Multiplier for confounder rates from YAML (2.0 = double probability, default: 1.0)",
    )
    parser.add_argument(
        "--baseline-std-scale",
        type=float,
        default=1.0,
        help="Multiplier for baseline std deviations (2.0 = wider spread, default: 1.0)",
    )
    parser.add_argument(
        "--no-correlations",
        action="store_true",
        help="Skip generating correlated scenarios (only random events)",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        default=True,
        help="Replace existing events (default: True)",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing events instead of replacing",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress output except errors",
    )
    parser.add_argument(
        "--use-baselines",
        action="store_true",
        default=True,
        help="Use role-based behavior baselines for event counts and timing (default: True)",
    )
    parser.add_argument(
        "--no-baselines",
        action="store_true",
        help="Disable baseline-driven generation (use flat event counts)",
    )

    args = parser.parse_args()

    # Validate inputs
    company_path = Path(args.company)
    if not company_path.exists():
        print(f"Error: Company file not found: {company_path}", file=sys.stderr)
        sys.exit(1)

    if args.correlation_ratio < 0 or args.correlation_ratio > 1:
        print("Error: --correlation-ratio must be between 0.0 and 1.0", file=sys.stderr)
        sys.exit(1)

    # Load company
    if not args.quiet:
        print(f"Loading company from {company_path}...")

    with open(company_path, "r", encoding="utf-8") as f:
        company: Dict[str, Any] = json.load(f)

    # Import here to avoid import errors if dependencies missing
    from .event_pipeline import generate_all_events
    from .email_scenario_engine import generate_scenario_based_emails
    from .email_file_correlator import correlate_email_file_events

    # Determine event multipliers
    if args.activity_level:
        presets = {
            "minimal": {
                "login_events_multiplier": 0.5,
                "file_events_multiplier": 0.3,
                "admin_actions_multiplier": 0.3,
                "app_events_multiplier": 0.3,
                "process_events_multiplier": 0.5,
                "device_events_multiplier": 0.3,
                "network_events_multiplier": 0.3,
                "cloud_events_multiplier": 0.3,
                "email_scenarios": 2, "min_email_scenarios": 1,
            },
            "normal": {
                "login_events_multiplier": 1.0,
                "file_events_multiplier": 1.0,
                "admin_actions_multiplier": 1.0,
                "app_events_multiplier": 1.0,
                "process_events_multiplier": 1.0,
                "device_events_multiplier": 1.0,
                "network_events_multiplier": 1.0,
                "cloud_events_multiplier": 1.0,
                "email_scenarios": 4, "min_email_scenarios": 2,
            },
            "high": {
                "login_events_multiplier": 2.5,
                "file_events_multiplier": 2.5,
                "admin_actions_multiplier": 2.5,
                "app_events_multiplier": 2.5,
                "process_events_multiplier": 2.5,
                "device_events_multiplier": 2.5,
                "network_events_multiplier": 2.5,
                "cloud_events_multiplier": 2.5,
                "email_scenarios": 12, "min_email_scenarios": 8,
            },
        }
        counts = presets[args.activity_level]
    else:
        counts = {
            "login_events_multiplier": args.logins_multiplier,
            "file_events_multiplier": args.file_events_multiplier,
            "admin_actions_multiplier": args.admin_actions_multiplier,
            "app_events_multiplier": args.app_events_multiplier,
            "process_events_multiplier": args.process_events_multiplier,
            "device_events_multiplier": args.device_events_multiplier,
            "network_events_multiplier": args.network_events_multiplier,
            "cloud_events_multiplier": args.cloud_events_multiplier,
            "email_scenarios": args.email_scenarios,
            "min_email_scenarios": args.min_email_scenarios,
        }

    # Generate events (emails handled separately via scenarios)
    if not args.quiet:
        print(f"Generating events (seed={args.seed}, correlation_ratio={args.correlation_ratio})...")

    replace_existing = not args.append

    # Resolve generation config: use from company data unless --no-baselines
    gen_cfg = None
    if not args.no_baselines:
        gen_cfg = company.get("_generation_config") or None

    stats = generate_all_events(
        company,
        seed=args.seed,
        scenarios_per_employee=0 if args.no_correlations else args.correlation_ratio,
        login_events_multiplier=counts["login_events_multiplier"],
        email_events_multiplier=0,  # emails handled by scenario engine below
        file_events_multiplier=counts["file_events_multiplier"],
        admin_actions_multiplier=counts["admin_actions_multiplier"],
        app_events_multiplier=counts["app_events_multiplier"],
        process_events_multiplier=counts["process_events_multiplier"],
        device_events_multiplier=counts["device_events_multiplier"],
        network_events_multiplier=counts["network_events_multiplier"],
        cloud_events_multiplier=counts["cloud_events_multiplier"],
        generate_correlations=not args.no_correlations,
        generate_emails=False,  # emails handled by scenario engine below
        replace_existing=replace_existing,
        generation_config=gen_cfg,
        confounder_rate_scale=args.confounder_rate_scale,
        baseline_std_scale=args.baseline_std_scale,
    )

    # Generate scenario-based emails
    if not args.quiet:
        print(f"Generating email scenarios ({counts['email_scenarios']} per employee, min {counts['min_email_scenarios']})...")

    email_stats = generate_scenario_based_emails(
        company,
        seed=args.seed,
        scenarios_per_person=counts["email_scenarios"],
        replace_existing=False,  # Don't replace — pipeline already cleared + injected burst emails
        min_scenarios_guaranteed=counts["min_email_scenarios"],
    )

    # Add correlated file events for email attachments
    if not args.quiet:
        print("Adding correlated file events for email attachments...")

    file_corr_stats = correlate_email_file_events(
        company,
        seed=args.seed,
    )

    # Save output
    out_path = Path(args.out) if args.out else company_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(company, f, indent=2)

    if not args.quiet:
        print(f"\nWrote enriched company to {out_path}")
        print(f"\n=== Generation Statistics ===")
        print(f"Total events generated: {stats['total_events']}")

        if not args.no_correlations:
            corr = stats.get("correlations", {})
            print(f"\nCorrelated scenarios: {corr.get('scenarios_generated', 0)}")
            print(f"Events from scenarios: {corr.get('events_generated', 0)}")
            if corr.get("by_scenario"):
                print("Scenarios by type:")
                for name, count in corr["by_scenario"].items():
                    print(f"  - {name}: {count}")

        print(f"\nRandom events:")
        print(f"  Logins: {stats.get('logins', {}).get('events_added', 0)}")
        print(f"  File events: {stats.get('file_events', {}).get('events_added', 0)}")
        print(f"  Admin actions: {stats.get('admin_actions', {}).get('actions_added', 0)}")
        print(f"  App events: {stats.get('app_events', {}).get('events_added', 0)}")
        print(f"  Process events: {stats.get('process_events', {}).get('events_added', 0)}")
        print(f"  Device events: {stats.get('device_events', {}).get('events_added', 0)}")
        print(f"  Network events: {stats.get('network_events', {}).get('events_added', 0)}")
        cloud_stats = stats.get('cloud_events', {})
        print(f"  Cloud events: {cloud_stats.get('events_added', 0)}")
        if cloud_stats.get('events_added', 0):
            print(f"    Instances with events: {cloud_stats.get('instances_with_events', 0)}")
            print(f"    Sessions: {cloud_stats.get('sessions', 0):,}")
            print(f"    By provider: {cloud_stats.get('events_by_provider', {})}")
            print(f"    Errors: {cloud_stats.get('errors', 0):,}")

        print(f"\nEmail scenarios:")
        print(f"  Scenarios applied: {email_stats.get('scenarios_applied', 0)}")
        print(f"  Emails generated: {email_stats.get('total_emails_generated', 0)}")
        print(f"  Avg scenarios/employee: {email_stats.get('average_scenarios_per_employee', 0)}")
        if email_stats.get("scenarios_by_type"):
            print("  Scenarios by type:")
            for scenario_id, count in sorted(email_stats["scenarios_by_type"].items()):
                print(f"    {scenario_id}: {count}")

        print(f"\nEmail-file correlation:")
        print(f"  Emails with attachments: {file_corr_stats.get('emails_with_file_paths', 0)}")
        print(f"  File events added: {file_corr_stats.get('total_file_events_added', 0)}")

        print(f"\nSorting: {stats.get('sorting', {}).get('event_lists_sorted', 0)} event lists sorted")


if __name__ == "__main__":
    main()
