#!/usr/bin/env python3
"""
Generate company-specific email scenarios and company files using an LLM.

This script reads a company YAML config and generates tailored constants
(email scenarios + company files) for that company, outputting them to
constants/{company_id}/.

Usage:
    # Generate everything for BrightCart
    poetry run python -m company_generation.variable.generate_company_constants \
        --config src/company_generation/static/configurations/static_companies/brightcart_inc.yaml

    # Use a specific model
    poetry run python -m company_generation.variable.generate_company_constants \
        --config path/to/company.yaml --model claude-sonnet-4-20250514

    # Only generate email scenarios (skip files)
    poetry run python -m company_generation.variable.generate_company_constants \
        --config path/to/company.yaml --only-emails

    # Dry run
    poetry run python -m company_generation.variable.generate_company_constants \
        --config path/to/company.yaml --dry-run

Environment Variables:
    OPENAI_API_KEY, ANTHROPIC_API_KEY, etc. as needed by LiteLLM
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    print("Error: pyyaml is required. Install with: pip install pyyaml")
    sys.exit(1)

try:
    import litellm
    from litellm import completion
except ImportError:
    print("Error: litellm is required. Install with: pip install litellm")
    sys.exit(1)

from .generate_company_prompts import (
    CompanyContext,
    build_company_context,
    get_company_department_prompt,
    get_company_cross_department_prompt,
    get_company_urgent_prompt,
    get_company_generic_prompt,
    get_company_files_department_prompt,
    get_company_files_shared_prompt,
)
from .generate_scenarios_llm import (
    extract_json_from_response,
    validate_scenario,
    fix_common_issues,
)


# =============================================================================
# CONFIGURATION
# =============================================================================

CONSTANTS_ROOT = Path(__file__).resolve().parents[3] / "constants"


@dataclass
class CompanyGenerationConfig:
    """Configuration for company-specific generation."""
    model: str = "anthropic/claude-sonnet-4-20250514"
    temperature: float = 0.7
    max_tokens: int = 16000

    # Email scenario settings
    scenarios_per_department: int = 5
    cross_department_count: int = 8
    urgent_count: int = 6
    generic_count: int = 10

    # Company files settings
    shared_files_count: int = 40

    # Output
    output_dir: Path = field(default_factory=lambda: CONSTANTS_ROOT)
    dry_run: bool = False

    # What to generate
    only_emails: bool = False
    only_files: bool = False

    # Rate limiting
    delay_between_calls: float = 1.0


# =============================================================================
# LLM CALLING
# =============================================================================

def call_llm(prompt: str, config: CompanyGenerationConfig) -> str:
    """Call the LLM with the given prompt."""
    messages = [
        {
            "role": "system",
            "content": (
                "You are an expert at generating realistic corporate data for "
                "company simulations. Output only valid JSON arrays, no markdown "
                "formatting or explanation."
            ),
        },
        {"role": "user", "content": prompt},
    ]

    response = completion(
        model=config.model,
        messages=messages,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
    )

    return response.choices[0].message.content


# =============================================================================
# COMPANY FILES VALIDATION
# =============================================================================

VALID_FILE_TYPES = {"regular", "business", "confidential", "unlabeled"}


def validate_company_file(entry: Dict[str, Any]) -> tuple[bool, List[str]]:
    """Validate a single company file entry."""
    issues = []

    required = ["type", "content", "owner role", "created", "path"]
    for f in required:
        if f not in entry:
            issues.append(f"Missing required field: {f}")

    if issues:
        return False, issues

    if entry.get("type") not in VALID_FILE_TYPES:
        issues.append(f"Invalid type: {entry.get('type')} (expected one of {VALID_FILE_TYPES})")

    path = entry.get("path", "")
    if not path.startswith("/"):
        issues.append(f"Path should start with /: {path}")

    created = entry.get("created", "")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", created):
        issues.append(f"Invalid date format: {created} (expected YYYY-MM-DD)")

    owner_role = entry.get("owner role", "")
    if " - " not in owner_role:
        issues.append(f"owner role should be 'Department - Role', got: {owner_role}")

    return len(issues) == 0, issues


def fix_company_file(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Attempt to fix common issues in generated company file entries."""
    entry = dict(entry)

    # Fix type
    file_type = (entry.get("type") or "regular").lower().strip()
    if file_type not in VALID_FILE_TYPES:
        entry["type"] = "regular"
    else:
        entry["type"] = file_type

    # Fix path
    path = entry.get("path", "/shared/document.pdf")
    if not path.startswith("/"):
        path = "/" + path
    entry["path"] = path

    # Fix date
    created = entry.get("created", "2024-01-01")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", created):
        entry["created"] = "2024-01-01"

    # Ensure content is a string
    if not isinstance(entry.get("content"), str):
        entry["content"] = str(entry.get("content", ""))

    return entry


# =============================================================================
# EMAIL SCENARIO GENERATION
# =============================================================================

def generate_email_scenarios(
    ctx: CompanyContext,
    config: CompanyGenerationConfig,
) -> List[Dict[str, Any]]:
    """Generate all email scenarios for a company."""
    all_scenarios: List[Dict[str, Any]] = []
    seen_ids: set = set()

    def add_scenarios(scenarios: List[Dict[str, Any]], source: str) -> None:
        for scenario in scenarios:
            scenario = fix_common_issues(scenario)
            scenario_id = scenario.get("id", "")

            # Ensure uniqueness
            if scenario_id in seen_ids:
                base_id = scenario_id
                counter = 2
                while scenario_id in seen_ids:
                    scenario_id = f"{base_id}_{counter}"
                    counter += 1
                scenario["id"] = scenario_id

            is_valid, issues = validate_scenario(scenario)
            if is_valid:
                seen_ids.add(scenario_id)
                all_scenarios.append(scenario)
            else:
                print(f"    Warning [{source}]: Skipping '{scenario_id}': {issues[:2]}")

    # 1. Per-department scenarios
    for dept in ctx.departments:
        print(f"  Generating scenarios for {dept}...")
        try:
            prompt = get_company_department_prompt(dept, ctx, list(seen_ids) if seen_ids else None)
            response = call_llm(prompt, config)
            scenarios = extract_json_from_response(response)

            # Ensure department is set
            for s in scenarios:
                if not s.get("departments"):
                    s["departments"] = [dept]
                tags = s.get("tags", [])
                if dept.lower() not in [t.lower() for t in tags]:
                    tags.append(dept.lower())
                    s["tags"] = tags

            add_scenarios(scenarios, f"dept:{dept}")
            print(f"    -> {len([s for s in scenarios])} generated, {len(all_scenarios)} total valid")
            time.sleep(config.delay_between_calls)
        except Exception as e:
            print(f"    Error generating {dept} scenarios: {e}")

    # 2. Cross-department scenarios
    print("  Generating cross-department scenarios...")
    try:
        prompt = get_company_cross_department_prompt(ctx, list(seen_ids) if seen_ids else None)
        response = call_llm(prompt, config)
        scenarios = extract_json_from_response(response)

        for s in scenarios:
            s["same_department"] = False
            s["cross_department"] = True
            tags = s.get("tags", [])
            if "cross-department" not in tags:
                tags.append("cross-department")
                s["tags"] = tags

        add_scenarios(scenarios, "cross-dept")
        print(f"    -> {len(all_scenarios)} total valid")
        time.sleep(config.delay_between_calls)
    except Exception as e:
        print(f"    Error generating cross-department scenarios: {e}")

    # 3. Urgent scenarios
    print("  Generating urgent scenarios...")
    try:
        prompt = get_company_urgent_prompt(ctx, list(seen_ids) if seen_ids else None)
        response = call_llm(prompt, config)
        scenarios = extract_json_from_response(response)

        for s in scenarios:
            if s.get("urgency") not in ("high", "critical"):
                s["urgency"] = "high"
            tags = s.get("tags", [])
            if "urgent" not in tags:
                tags.append("urgent")
                s["tags"] = tags

        add_scenarios(scenarios, "urgent")
        print(f"    -> {len(all_scenarios)} total valid")
        time.sleep(config.delay_between_calls)
    except Exception as e:
        print(f"    Error generating urgent scenarios: {e}")

    # 4. Generic scenarios
    print(f"  Generating {config.generic_count} generic scenarios...")
    try:
        prompt = get_company_generic_prompt(config.generic_count, ctx, list(seen_ids) if seen_ids else None)
        response = call_llm(prompt, config)
        scenarios = extract_json_from_response(response)
        add_scenarios(scenarios, "generic")
        print(f"    -> {len(all_scenarios)} total valid")
    except Exception as e:
        print(f"    Error generating generic scenarios: {e}")

    return all_scenarios


# =============================================================================
# COMPANY FILES GENERATION
# =============================================================================

def generate_company_files(
    ctx: CompanyContext,
    config: CompanyGenerationConfig,
) -> List[Dict[str, Any]]:
    """Generate all company files for a company."""
    all_files: List[Dict[str, Any]] = []
    seen_paths: set = set()

    # Calculate target file count (proportional to company size)
    total_target = max(200, int(ctx.employee_count * 1.0))
    dept_target = total_target - config.shared_files_count

    def add_files(files: List[Dict[str, Any]], source: str) -> None:
        for entry in files:
            entry = fix_company_file(entry)
            path = entry.get("path", "")

            # Deduplicate by path
            if path in seen_paths:
                continue

            is_valid, issues = validate_company_file(entry)
            if is_valid:
                seen_paths.add(path)
                all_files.append(entry)
            else:
                print(f"    Warning [{source}]: Skipping '{path}': {issues[:2]}")

    # 1. Department-specific files
    for dept in ctx.departments:
        weight = ctx.department_weights.get(dept, 0)
        count = max(10, int(math.ceil(dept_target * weight)))
        print(f"  Generating {count} files for {dept}...")
        try:
            prompt = get_company_files_department_prompt(
                dept, ctx, count,
                list(seen_paths) if seen_paths else None,
            )
            response = call_llm(prompt, config)
            files = extract_json_from_response(response)
            add_files(files, f"files:{dept}")
            print(f"    -> {len(all_files)} total valid files")
            time.sleep(config.delay_between_calls)
        except Exception as e:
            print(f"    Error generating {dept} files: {e}")

    # 2. Shared/company-wide files
    print(f"  Generating {config.shared_files_count} shared files...")
    try:
        prompt = get_company_files_shared_prompt(
            ctx, config.shared_files_count,
            list(seen_paths) if seen_paths else None,
        )
        response = call_llm(prompt, config)
        files = extract_json_from_response(response)
        add_files(files, "files:shared")
        print(f"    -> {len(all_files)} total valid files")
    except Exception as e:
        print(f"    Error generating shared files: {e}")

    return all_files


# =============================================================================
# OUTPUT
# =============================================================================

def save_output(
    company_id: str,
    scenarios: Optional[List[Dict[str, Any]]],
    files: Optional[List[Dict[str, Any]]],
    config: CompanyGenerationConfig,
) -> None:
    """Save generated data to constants/{company_id}/."""
    output_dir = config.output_dir / company_id
    output_dir.mkdir(parents=True, exist_ok=True)

    if scenarios is not None:
        path = output_dir / "email_scenarios.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(scenarios, f, indent=2)
        print(f"\nSaved {len(scenarios)} email scenarios to {path}")

    if files is not None:
        path = output_dir / "company_files.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(files, f, indent=2)
        print(f"Saved {len(files)} company files to {path}")


def print_summary(
    ctx: CompanyContext,
    scenarios: Optional[List[Dict[str, Any]]],
    files: Optional[List[Dict[str, Any]]],
) -> None:
    """Print a summary of what was generated."""
    print("\n" + "=" * 60)
    print(f"GENERATION SUMMARY: {ctx.name} ({ctx.company_id})")
    print("=" * 60)

    if scenarios is not None:
        print(f"\nEmail Scenarios: {len(scenarios)}")

        by_dept: Dict[str, int] = {}
        for s in scenarios:
            for dept in s.get("departments", ["General"]):
                by_dept[dept] = by_dept.get(dept, 0) + 1
        if by_dept:
            print("  By department:")
            for dept, count in sorted(by_dept.items()):
                print(f"    {dept}: {count}")

        by_urgency: Dict[str, int] = {}
        for s in scenarios:
            u = s.get("urgency", "normal")
            by_urgency[u] = by_urgency.get(u, 0) + 1
        print("  By urgency:")
        for u, count in sorted(by_urgency.items()):
            print(f"    {u}: {count}")

        cross = sum(1 for s in scenarios if s.get("cross_department"))
        print(f"  Cross-department: {cross}")

        total_emails = sum(len(s.get("emails", [])) for s in scenarios)
        print(f"  Total email templates: {total_emails}")

    if files is not None:
        print(f"\nCompany Files: {len(files)}")

        by_type: Dict[str, int] = {}
        for f in files:
            ft = f.get("type", "unknown")
            by_type[ft] = by_type.get(ft, 0) + 1
        print("  By type:")
        for ft, count in sorted(by_type.items()):
            print(f"    {ft}: {count}")

        shared = sum(1 for f in files if f.get("path", "").startswith("/shared/"))
        print(f"  Shared files: {shared}")
        print(f"  Department files: {len(files) - shared}")


# =============================================================================
# CLI
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate company-specific email scenarios and files using an LLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Path to company YAML config file",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="anthropic/claude-sonnet-4-20250514",
        help="LiteLLM model identifier (default: anthropic/claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.7,
        help="Generation temperature (default: 0.7)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output root directory (default: constants/)",
    )
    parser.add_argument(
        "--only-emails",
        action="store_true",
        help="Only generate email scenarios (skip company files)",
    )
    parser.add_argument(
        "--only-files",
        action="store_true",
        help="Only generate company files (skip email scenarios)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print summary without saving",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay between API calls in seconds (default: 1.0)",
    )

    args = parser.parse_args()

    # Load company config
    if not args.config.exists():
        print(f"Error: Config file not found: {args.config}")
        sys.exit(1)

    with args.config.open("r", encoding="utf-8") as f:
        company_config = yaml.safe_load(f)

    ctx = build_company_context(company_config)

    if not ctx.company_id:
        print("Error: Company config missing company.id")
        sys.exit(1)

    # Build generation config
    config = CompanyGenerationConfig(
        model=args.model,
        temperature=args.temperature,
        dry_run=args.dry_run,
        only_emails=args.only_emails,
        only_files=args.only_files,
        delay_between_calls=args.delay,
    )
    if args.output_dir:
        config.output_dir = args.output_dir

    # Print config
    print("=" * 60)
    print(f"GENERATING CONSTANTS FOR: {ctx.name}")
    print("=" * 60)
    print(f"  Company ID: {ctx.company_id}")
    print(f"  Employees: {ctx.employee_count}")
    print(f"  Departments: {len(ctx.departments)}")
    print(f"  Model: {config.model}")
    print(f"  Generate emails: {not config.only_files}")
    print(f"  Generate files: {not config.only_emails}")
    print()

    # Generate
    scenarios = None
    files = None

    if not config.only_files:
        print("--- Email Scenarios ---")
        scenarios = generate_email_scenarios(ctx, config)

    if not config.only_emails:
        print("\n--- Company Files ---")
        files = generate_company_files(ctx, config)

    # Summary
    print_summary(ctx, scenarios, files)

    # Save
    if config.dry_run:
        print("\n[Dry run - nothing saved]")
    else:
        save_output(ctx.company_id, scenarios, files, config)

    print("\nDone!")


if __name__ == "__main__":
    main()
