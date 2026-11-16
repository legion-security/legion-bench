"""Shared prompt constants and helpers used across all agent types."""

REPORT_FORMAT = """\
**Executive Summary**: One-paragraph overview of what happened, the severity, and immediate risk.

**Findings** (focus on the essential elements that define this attack — be specific and include evidence):
- The specific attack technique or vector used (what makes this attack distinctive)
- Key attacker actions that confirm the attack (e.g., impossible travel, credential replay, privilege escalation)
- Persistence or defense evasion mechanisms (e.g., MFA registration, inbox rules, scheduled tasks, service principals)
- Ultimate impact — what data, systems, or access was compromised
- Any lateral movement to other accounts, hosts, or cloud resources

Prioritize the core narrative of the attack over exhaustive enumeration of every step. \
Focus on the critical evidence that proves the attack happened, identifies the technique, \
and defines its scope and impact.

**Indicators of Compromise (IOCs)** -- list each IOC belonging to the attacker on its own line. The different types of IOCs are: IPs, domains, URLs, emails, hashes, and filenames. Just list the IOCs, no other text. Do not add IoCs that are not related to the attacker.

**Severity Assessment**: Your assessment of the incident severity.\
"""

EMPLOYEE_ID_NOTE = """\
Employee IDs are different from their email addresses. Almost all functions \
require employee IDs and will not work with email addresses. The first step \
needs to be to get the employee ID from the email address.\
"""


def build_initial_message(scenario: dict, tool_summaries: list[dict]) -> str:
    """Build the initial user message presenting the alert to the agent.

    Args:
        scenario: Parsed scenario YAML dict.
        tool_summaries: List of tool info dicts from registry.get_tool_info().

    Returns:
        Formatted initial message string.
    """
    alert = scenario["alert"]
    sc = scenario["scenario"]

    indicators_text = ""
    for ind in alert.get("initial_indicators", []):
        indicators_text += f"  - {ind['type']}: {ind['value']}\n"

    tools_text = ""
    for tool in tool_summaries:
        queries = ", ".join(tool.get("queries", []))
        tools_text += f"  - {tool['name']} ({tool['category']}): {queries}\n"

    return f"""\
## Alert: {alert['title']}

**Scenario**: {sc['name']}
**Severity**: {alert['severity']}
**Source**: {alert['source']}

### Description
{alert['description'].strip()}

### Initial Indicators
{indicators_text.rstrip()}

### Available Tools
{tools_text.rstrip()}

Investigate this alert.\
"""
