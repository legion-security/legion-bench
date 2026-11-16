#!/usr/bin/env python3
"""
Generate email scenarios using an LLM via LiteLLM.

This script calls an LLM to generate email scenarios for multiple departments,
cross-department interactions, and urgent situations. The generated scenarios
are validated and saved to constants/email_scenarios.json.

Usage:
    # Generate all scenario types with default model
    python -m company_generation.variable.generate_scenarios_llm

    # Use a specific model
    python -m company_generation.variable.generate_scenarios_llm --model gpt-4o

    # Generate only specific types
    python -m company_generation.variable.generate_scenarios_llm --departments Engineering Sales

    # Dry run (print scenarios without saving)
    python -m company_generation.variable.generate_scenarios_llm --dry-run

    # Append to existing scenarios
    python -m company_generation.variable.generate_scenarios_llm --append

Environment Variables:
    OPENAI_API_KEY, ANTHROPIC_API_KEY, etc. as needed by LiteLLM
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import os

try:
    import litellm
    from litellm import completion
except ImportError:
    print("Error: litellm is required. Install with: pip install litellm")
    sys.exit(1)

from .generate_scenarios_prompts import (
    get_department_prompt,
    get_cross_department_prompt,
    get_urgent_prompt,
    get_generic_prompt,
)

# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class GenerationConfig:
    """Configuration for scenario generation."""
    model: str = "gpt-4o"
    temperature: float = 0.7
    max_tokens: int = 8000

    # What to generate
    departments: List[str] = field(default_factory=lambda: [
        "Engineering", "Sales", "HR", "Finance",
        "Marketing", "IT", "Customer service"
    ])
    include_cross_department: bool = True
    include_urgent: bool = True
    include_generic: bool = True
    generic_count: int = 10

    # Scenarios per department
    scenarios_per_department: int = 5

    # Output
    output_path: Path = field(default_factory=lambda:
        Path(__file__).resolve().parents[3] / "constants" / "email_scenarios.json"
    )
    append: bool = False
    dry_run: bool = False

    # Rate limiting
    delay_between_calls: float = 1.0  # seconds


# =============================================================================
# LLM CALLING
# =============================================================================

def call_llm(prompt: str, config: GenerationConfig) -> str:
    """Call the LLM with the given prompt."""
    messages = [
        {
            "role": "system",
            "content": "You are an expert at generating realistic corporate email scenarios. Output only valid JSON arrays, no markdown formatting or explanation."
        },
        {
            "role": "user",
            "content": prompt
        }
    ]

    response = completion(
        model=config.model,
        messages=messages,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
    )

    return response.choices[0].message.content


def extract_json_from_response(response: str) -> List[Dict[str, Any]]:
    """Extract JSON array from LLM response, handling markdown code blocks."""
    # Remove markdown code blocks if present
    response = response.strip()

    # Try to find JSON in code blocks
    code_block_pattern = r"```(?:json)?\s*([\s\S]*?)```"
    matches = re.findall(code_block_pattern, response)
    if matches:
        response = matches[0].strip()

    # Try to find array bounds
    start_idx = response.find('[')
    end_idx = response.rfind(']')

    if start_idx != -1 and end_idx != -1:
        response = response[start_idx:end_idx + 1]

    try:
        data = json.loads(response)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "scenarios" in data:
            return data["scenarios"]
        else:
            return [data]
    except json.JSONDecodeError as e:
        print(f"  Warning: Failed to parse JSON: {e}")
        return []


# =============================================================================
# SCENARIO VALIDATION
# =============================================================================

def validate_scenario(scenario: Dict[str, Any]) -> tuple[bool, List[str]]:
    """Validate a scenario and return (is_valid, list_of_issues)."""
    issues = []

    # Required fields
    required = ["id", "name", "description", "num_participants", "participant_roles", "emails"]
    for field in required:
        if field not in scenario:
            issues.append(f"Missing required field: {field}")

    if issues:
        return False, issues

    # Validate id format
    if not re.match(r'^[a-z][a-z0-9_]*$', scenario.get("id", "")):
        issues.append(f"Invalid id format: {scenario.get('id')} (should be snake_case)")

    # Validate participant count
    num_participants = scenario.get("num_participants", 0)
    if not isinstance(num_participants, int) or num_participants < 2:
        issues.append(f"num_participants must be >= 2, got {num_participants}")

    # Validate participant_roles matches num_participants
    roles = scenario.get("participant_roles", [])
    if len(roles) != num_participants:
        issues.append(f"participant_roles length ({len(roles)}) != num_participants ({num_participants})")

    # Validate emails
    emails = scenario.get("emails", [])
    if not emails:
        issues.append("emails array is empty")

    for i, email in enumerate(emails):
        email_issues = validate_email(email, i, num_participants)
        issues.extend(email_issues)

    return len(issues) == 0, issues


def validate_email(email: Dict[str, Any], index: int, num_participants: int) -> List[str]:
    """Validate a single email template."""
    issues = []
    prefix = f"emails[{index}]"

    # Required fields
    required = ["offset_hours", "sender_index", "subject_template", "body_template"]
    for field in required:
        if field not in email:
            issues.append(f"{prefix}: Missing required field: {field}")

    # Validate sender_index
    sender_idx = email.get("sender_index", -1)
    if not isinstance(sender_idx, int) or sender_idx < 0 or sender_idx >= num_participants:
        issues.append(f"{prefix}: sender_index {sender_idx} out of range [0, {num_participants-1}]")

    # Validate offset_hours
    offset = email.get("offset_hours", -1)
    if not isinstance(offset, (int, float)) or offset < 0:
        issues.append(f"{prefix}: offset_hours must be >= 0, got {offset}")

    # Validate recipient_indices if present
    recipient_indices = email.get("recipient_indices", [])
    if recipient_indices:
        for idx in recipient_indices:
            if not isinstance(idx, int) or idx < 0 or idx >= num_participants:
                issues.append(f"{prefix}: recipient_indices contains invalid index {idx}")

    return issues


def fix_common_issues(scenario: Dict[str, Any]) -> Dict[str, Any]:
    """Attempt to fix common issues in generated scenarios."""
    # Make a copy
    scenario = dict(scenario)

    # Fix id format (convert to snake_case)
    if "id" in scenario:
        scenario["id"] = re.sub(r'[^a-z0-9]+', '_', scenario["id"].lower()).strip('_')

    # Ensure participant_roles matches num_participants
    num_p = scenario.get("num_participants", 2)
    roles = scenario.get("participant_roles", [])
    if len(roles) < num_p:
        # Add generic roles
        for i in range(len(roles), num_p):
            roles.append(f"participant_{i}")
        scenario["participant_roles"] = roles
    elif len(roles) > num_p:
        scenario["participant_roles"] = roles[:num_p]

    # Fix emails
    emails = scenario.get("emails", [])
    for email in emails:
        # Ensure offset_hours is non-negative
        if email.get("offset_hours", 0) < 0:
            email["offset_hours"] = 0

        # Ensure sender_index is valid
        sender_idx = email.get("sender_index", 0)
        if sender_idx < 0 or sender_idx >= num_p:
            email["sender_index"] = 0

        # Fix recipient_indices
        recipient_indices = email.get("recipient_indices", [])
        if recipient_indices:
            email["recipient_indices"] = [
                idx for idx in recipient_indices
                if isinstance(idx, int) and 0 <= idx < num_p
            ]

    # Set defaults
    scenario.setdefault("same_department", True)
    scenario.setdefault("departments", [])
    scenario.setdefault("requires_manager", False)
    scenario.setdefault("cross_department", False)
    scenario.setdefault("requires_file", False)
    scenario.setdefault("file_types", [])
    scenario.setdefault("tags", [])
    scenario.setdefault("weight", 1.0)
    scenario.setdefault("urgency", "normal")

    return scenario


# =============================================================================
# GENERATION PIPELINE
# =============================================================================

def generate_department_scenarios(
    department: str,
    config: GenerationConfig
) -> List[Dict[str, Any]]:
    """Generate scenarios for a specific department."""
    print(f"  Generating scenarios for {department}...")

    prompt = get_department_prompt(department)
    response = call_llm(prompt, config)
    scenarios = extract_json_from_response(response)

    # Add department tag and validate
    valid_scenarios = []
    for scenario in scenarios:
        scenario = fix_common_issues(scenario)

        # Ensure department is set
        if not scenario.get("departments"):
            scenario["departments"] = [department]

        # Add department to tags
        tags = scenario.get("tags", [])
        if department.lower() not in [t.lower() for t in tags]:
            tags.append(department.lower())
            scenario["tags"] = tags

        is_valid, issues = validate_scenario(scenario)
        if is_valid:
            valid_scenarios.append(scenario)
        else:
            print(f"    Warning: Skipping invalid scenario '{scenario.get('id', 'unknown')}': {issues[:2]}")

    print(f"    Generated {len(valid_scenarios)} valid scenarios")
    return valid_scenarios


def generate_cross_department_scenarios(config: GenerationConfig) -> List[Dict[str, Any]]:
    """Generate cross-department scenarios."""
    print("  Generating cross-department scenarios...")

    prompt = get_cross_department_prompt()

    config.max_tokens = 16000
    response = call_llm(prompt, config)
    scenarios = extract_json_from_response(response)

    valid_scenarios = []
    for scenario in scenarios:
        scenario = fix_common_issues(scenario)

        # Ensure cross-department flags are set
        scenario["same_department"] = False
        scenario["cross_department"] = True

        # Add tag
        tags = scenario.get("tags", [])
        if "cross-department" not in tags:
            tags.append("cross-department")
            scenario["tags"] = tags

        is_valid, issues = validate_scenario(scenario)
        if is_valid:
            valid_scenarios.append(scenario)
        else:
            print(f"    Warning: Skipping invalid scenario '{scenario.get('id', 'unknown')}': {issues[:2]}")

    print(f"    Generated {len(valid_scenarios)} valid scenarios")
    return valid_scenarios


def generate_urgent_scenarios(config: GenerationConfig) -> List[Dict[str, Any]]:
    """Generate urgent/incident scenarios."""
    print("  Generating urgent scenarios...")

    prompt = get_urgent_prompt()
    config.max_tokens = 32000
    response = call_llm(prompt, config)
    scenarios = extract_json_from_response(response)

    valid_scenarios = []
    for scenario in scenarios:
        scenario = fix_common_issues(scenario)

        # Ensure urgency is set
        if scenario.get("urgency") not in ["high", "critical"]:
            scenario["urgency"] = "high"

        # Add tag
        tags = scenario.get("tags", [])
        if "urgent" not in tags:
            tags.append("urgent")
            scenario["tags"] = tags

        is_valid, issues = validate_scenario(scenario)
        if is_valid:
            valid_scenarios.append(scenario)
        else:
            print(f"    Warning: Skipping invalid scenario '{scenario.get('id', 'unknown')}': {issues[:2]}")

    print(f"    Generated {len(valid_scenarios)} valid scenarios")
    return valid_scenarios


def generate_generic_scenarios(config: GenerationConfig) -> List[Dict[str, Any]]:
    """Generate generic diverse scenarios."""
    print(f"  Generating {config.generic_count} generic scenarios...")

    prompt = get_generic_prompt(config.generic_count)
    config.max_tokens = 52000
    response = call_llm(prompt, config)
    scenarios = extract_json_from_response(response)

    valid_scenarios = []
    for scenario in scenarios:
        scenario = fix_common_issues(scenario)

        is_valid, issues = validate_scenario(scenario)
        if is_valid:
            valid_scenarios.append(scenario)
        else:
            print(f"    Warning: Skipping invalid scenario '{scenario.get('id', 'unknown')}': {issues[:2]}")

    print(f"    Generated {len(valid_scenarios)} valid scenarios")
    return valid_scenarios


def generate_all_scenarios(config: GenerationConfig) -> List[Dict[str, Any]]:
    """Generate all scenarios based on config."""
    all_scenarios = []

    # Track generated IDs to avoid duplicates
    seen_ids = set()

    def add_scenarios(scenarios: List[Dict[str, Any]]) -> None:
        for scenario in scenarios:
            scenario_id = scenario.get("id", "")
            if scenario_id in seen_ids:
                # Make ID unique by adding suffix
                base_id = scenario_id
                counter = 2
                while scenario_id in seen_ids:
                    scenario_id = f"{base_id}_{counter}"
                    counter += 1
                scenario["id"] = scenario_id
            seen_ids.add(scenario_id)
            all_scenarios.append(scenario)

    # # Generate department-specific scenarios
    # for department in config.departments:
    #     try:
    #         scenarios = generate_department_scenarios(department, config)
    #         add_scenarios(scenarios)
    #         time.sleep(config.delay_between_calls)
    #     except Exception as e:
    #         print(f"    Error generating {department} scenarios: {e}")

    # Generate cross-department scenarios
    if config.include_cross_department:
        try:
            scenarios = generate_cross_department_scenarios(config)
            add_scenarios(scenarios)
            time.sleep(config.delay_between_calls)
        except Exception as e:
            print(f"    Error generating cross-department scenarios: {e}")

    # Generate urgent scenarios
    if config.include_urgent:
        try:
            scenarios = generate_urgent_scenarios(config)
            add_scenarios(scenarios)
            time.sleep(config.delay_between_calls)
        except Exception as e:
            print(f"    Error generating urgent scenarios: {e}")

    # Generate generic scenarios
    if config.include_generic:
        try:
            scenarios = generate_generic_scenarios(config)
            add_scenarios(scenarios)
        except Exception as e:
            print(f"    Error generating generic scenarios: {e}")

    return all_scenarios


# =============================================================================
# OUTPUT
# =============================================================================

def save_scenarios(scenarios: List[Dict[str, Any]], config: GenerationConfig) -> None:
    """Save scenarios to JSON file."""
    output_path = config.output_path

    if config.append and output_path.exists():
        # Load existing scenarios
        with output_path.open("r", encoding="utf-8") as f:
            existing = json.load(f)
        if isinstance(existing, list):
            # Check for ID conflicts
            existing_ids = {s.get("id") for s in existing}
            for scenario in scenarios:
                if scenario.get("id") in existing_ids:
                    # Generate unique ID
                    base_id = scenario["id"]
                    counter = 2
                    while scenario["id"] in existing_ids:
                        scenario["id"] = f"{base_id}_{counter}"
                        counter += 1
                existing_ids.add(scenario["id"])
            scenarios = existing + scenarios

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(scenarios, f, indent=2)

    print(f"\nSaved {len(scenarios)} scenarios to {output_path}")


def print_summary(scenarios: List[Dict[str, Any]]) -> None:
    """Print a summary of generated scenarios."""
    print("\n" + "=" * 60)
    print("GENERATION SUMMARY")
    print("=" * 60)

    print(f"\nTotal scenarios: {len(scenarios)}")

    # By department
    by_dept: Dict[str, int] = {}
    for s in scenarios:
        for dept in s.get("departments", ["General"]):
            by_dept[dept] = by_dept.get(dept, 0) + 1

    if by_dept:
        print("\nBy department:")
        for dept, count in sorted(by_dept.items()):
            print(f"  {dept}: {count}")

    # By urgency
    by_urgency: Dict[str, int] = {}
    for s in scenarios:
        urgency = s.get("urgency", "normal")
        by_urgency[urgency] = by_urgency.get(urgency, 0) + 1

    print("\nBy urgency:")
    for urgency, count in sorted(by_urgency.items()):
        print(f"  {urgency}: {count}")

    # Cross-department
    cross_dept = sum(1 for s in scenarios if s.get("cross_department"))
    print(f"\nCross-department scenarios: {cross_dept}")

    # With files
    with_files = sum(1 for s in scenarios if s.get("requires_file"))
    print(f"Scenarios requiring files: {with_files}")

    # Email counts
    total_emails = sum(len(s.get("emails", [])) for s in scenarios)
    avg_emails = total_emails / len(scenarios) if scenarios else 0
    print(f"\nTotal email templates: {total_emails}")
    print(f"Average emails per scenario: {avg_emails:.1f}")


# =============================================================================
# CLI
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate email scenarios using an LLM via LiteLLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate all scenarios with default settings
  %(prog)s

  # Use a specific model
  %(prog)s --model claude-3-5-sonnet-20241022

  # Generate only for specific departments
  %(prog)s --departments Engineering Sales Marketing

  # Skip certain types
  %(prog)s --no-urgent --no-generic

  # Dry run (don't save)
  %(prog)s --dry-run

  # Append to existing scenarios
  %(prog)s --append

Environment:
  Set appropriate API keys for your model:
  - OPENAI_API_KEY for OpenAI models
  - ANTHROPIC_API_KEY for Anthropic models
  - etc.
        """,
    )

    parser.add_argument(
        "--model",
        type=str,
        default="gpt-4o",
        help="LiteLLM model identifier (default: gpt-4o)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.7,
        help="Generation temperature (default: 0.7)",
    )
    parser.add_argument(
        "--departments",
        nargs="+",
        default=None,
        help="Departments to generate for (default: all)",
    )
    parser.add_argument(
        "--no-cross-department",
        action="store_true",
        help="Skip cross-department scenarios",
    )
    parser.add_argument(
        "--no-urgent",
        action="store_true",
        help="Skip urgent/incident scenarios",
    )
    parser.add_argument(
        "--no-generic",
        action="store_true",
        help="Skip generic scenarios",
    )
    parser.add_argument(
        "--generic-count",
        type=int,
        default=10,
        help="Number of generic scenarios to generate (default: 10)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Output file path (default: constants/email_scenarios.json)",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing scenarios instead of overwriting",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print scenarios without saving",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay between API calls in seconds (default: 1.0)",
    )

    args = parser.parse_args()

    # Build config
    config = GenerationConfig(
        model=args.model,
        temperature=args.temperature,
        include_cross_department=not args.no_cross_department,
        include_urgent=not args.no_urgent,
        include_generic=not args.no_generic,
        generic_count=args.generic_count,
        append=args.append,
        dry_run=args.dry_run,
        delay_between_calls=args.delay,
    )

    if args.departments:
        config.departments = args.departments

    if args.output:
        config.output_path = args.output

    # Print config
    print("=" * 60)
    print("EMAIL SCENARIO GENERATION")
    print("=" * 60)
    print(f"\nModel: {config.model}")
    print(f"Temperature: {config.temperature}")
    print(f"Departments: {', '.join(config.departments)}")
    print(f"Cross-department: {config.include_cross_department}")
    print(f"Urgent: {config.include_urgent}")
    print(f"Generic: {config.include_generic} ({config.generic_count})")
    print(f"Output: {config.output_path}")
    print(f"Mode: {'append' if config.append else 'overwrite'}")
    print()

    # Generate
    print("Generating scenarios...")
    scenarios = generate_all_scenarios(config)

    if not scenarios:
        print("\nNo scenarios generated!")
        sys.exit(1)

    # Print summary
    print_summary(scenarios)

    # Save or print
    if config.dry_run:
        print("\n[Dry run - scenarios not saved]")
        print("\nGenerated scenarios preview:")
        for s in scenarios[:3]:
            print(f"\n  {s['id']}: {s['name']}")
            print(f"    {s['description'][:60]}...")
        if len(scenarios) > 3:
            print(f"\n  ... and {len(scenarios) - 3} more")
    else:
        save_scenarios(scenarios, config)

    print("\nDone!")


if __name__ == "__main__":
    main()
