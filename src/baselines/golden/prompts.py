"""Prompts for the golden-workflow baseline.

Execution itself is deterministic — no LLM-driven tool calls. The LLM
is invoked exactly once at the end to compose the final report from the
gathered evidence, in the standard ``REPORT_FORMAT`` shared across the
benchmark.
"""
from __future__ import annotations

from agents.prompts import EMPLOYEE_ID_NOTE, REPORT_FORMAT

REPORT_SYSTEM_PROMPT = f"""\
You are a Tier-2 SOC analyst. A deterministic golden-standard playbook \
has already been executed against the alert below; the resulting tool \
call evidence is provided. Your job is to compose the final \
investigation report.

Base every claim on the evidence provided. Do not speculate beyond what \
the tool results show. If a step returned no data, note it briefly \
where relevant. Cite specific IDs, IPs, hashes, timestamps, and \
filenames from the evidence.

{EMPLOYEE_ID_NOTE}\
"""

REPORT_USER_TEMPLATE = """\
## Alert
**Title**: {alert_title}
**Severity**: {alert_severity}
**Source**: {alert_source}
**Workflow**: {workflow}

### Description
{alert_description}

### Initial Indicators
{indicators}

---

## Playbook Evidence

The following tool calls were executed in order (deterministic golden \
workflow, pre-Verdict phases only). Each entry shows the analyst-facing \
step label, the function called, the arguments, and the result.

{evidence}

---

## Output

Write the final investigation report. Use this exact format:

{report_format}
"""


def render_report_user_message(
    alert: dict,
    workflow: str,
    evidence_text: str,
) -> str:
    indicators = ""
    for ind in alert.get("initial_indicators", []) or []:
        indicators += f"  - {ind.get('type', '?')}: {ind.get('value', '?')}\n"
    if not indicators:
        indicators = "  (none)"

    return REPORT_USER_TEMPLATE.format(
        alert_title=alert.get("title", ""),
        alert_severity=alert.get("severity", ""),
        alert_source=alert.get("source", ""),
        workflow=workflow,
        alert_description=(alert.get("description") or "").strip(),
        indicators=indicators.rstrip(),
        evidence=evidence_text,
        report_format=REPORT_FORMAT,
    )
