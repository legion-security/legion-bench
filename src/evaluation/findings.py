"""LLM-based semantic matching for expected findings."""

import json
import logging
import re
from typing import List

import litellm

from evaluation.models import FindingMatch, FindingsResult

logger = logging.getLogger(__name__)


_HEADER_PREFIX = r"(?:[#]{1,6}\s+|\*\*\s*)"
_HEADER_SUFFIX = r"(?:\s*\*\*)?\s*:?\s*$"

_FINDINGS_HEADER_RE = re.compile(
    rf"^\s*{_HEADER_PREFIX}findings\b[^\n]*{_HEADER_SUFFIX}",
    re.IGNORECASE | re.MULTILINE,
)
_NEXT_HEADER_RE = re.compile(
    rf"^\s*{_HEADER_PREFIX}("
    r"indicators? of compromise|iocs?|severity assessment|"
    r"recommendations?|next steps?|executive summary|timeline|"
    r"affected entities|appendix|tool calls? summary|conclusion"
    rf"){_HEADER_SUFFIX[:-1]}[^\n]*$",
    re.IGNORECASE | re.MULTILINE,
)


def extract_findings_section(report: str) -> str:
    """Return only the **Findings** section of a report. Falls back to the
    full report when no Findings header is present (e.g. malformed output)."""
    if not report:
        return report
    match = _FINDINGS_HEADER_RE.search(report)
    if not match:
        return report
    start = match.end()
    tail = report[start:]
    next_match = _NEXT_HEADER_RE.search(tail)
    end = start + next_match.start() if next_match else len(report)
    section = report[match.start():end].strip()
    return section or report

_JUDGE_PROMPT = """\
You are a strict evaluation judge for a SOC (Security Operations Center) investigation benchmark.

You will be given:
1. An investigation report written by an AI agent.
2. A list of expected findings that the agent should have identified.

For each expected finding, determine whether the report contains SPECIFIC, CONCRETE \
information that substantively demonstrates the agent discovered this finding through \
its investigation. Apply these strict rules:

MATCHING RULES:
- The report must show the agent actually IDENTIFIED and INVESTIGATED the finding, \
not merely restated the alert description or ticket information.
- Semantic equivalence is acceptable — the match does NOT need to be verbatim. \
For example, "bulk download of files" matches "mass file download".
- Expected findings describe the essential, high-level elements of the attack (technique, \
key actions, persistence, impact). Match generously on scope — if the expected finding is \
broad (e.g., "data exfiltrated over C2"), the report satisfies it by showing ANY specific \
evidence of that activity (e.g., mentioning the C2 IP and outbound transfer).
- A finding is FOUND only if the report provides specific evidence or details about it \
(e.g., specific IPs, timestamps, user actions, tool outputs).
- A finding is NOT FOUND if:
  * The report only vaguely alludes to it without specifics
  * The report merely repeats information from the initial alert/ticket without adding \
investigation results
  * The information is mentioned in a recommendation section but was never actually confirmed
  * The report speculates about it without evidence from tool queries

Return a JSON object with a single key "results" containing an array with one entry per \
expected finding, in the same order. Each entry must have:
- "index": the 0-based index of the finding
- "found": true/false — whether the report demonstrates the agent discovered this finding
- "evidence": a brief quote or paraphrase from the report that supports your decision \
(or "not found in report" if not found)
- "confidence": a float 0.0–1.0 indicating your confidence in the match

Example output:
{"results": [{"index": 0, "found": true, "evidence": "Report states: Query returned 2847 file download events from SharePoint between March 10-12", "confidence": 0.95}]}

IMPORTANT: Return ONLY valid JSON, no markdown fences or extra text. Be strict — when \
in doubt, mark as not found.\
"""


def evaluate_findings(
    report: str,
    expected_findings: List[str],
    model: str = "gpt-4o-mini",
) -> FindingsResult:
    """Evaluate whether the report covers each expected finding using an LLM judge.

    Args:
        report: The agent's investigation report text.
        expected_findings: List of expected finding descriptions.
        model: LLM model to use for evaluation.

    Returns:
        FindingsResult with per-finding matches and overall recall.
    """
    if not expected_findings:
        return FindingsResult(matches=[], recall=1.0, found_count=0, total_expected=0)

    findings_text = "\n".join(
        f"{i}. {f}" for i, f in enumerate(expected_findings)
    )
    user_message = (
        f"## Investigation Report\n\n{report}\n\n"
        f"## Expected Findings\n\n{findings_text}"
    )

    raw_response = ""
    try:
        response = litellm.completion(
            model=model,
            messages=[
                {"role": "system", "content": _JUDGE_PROMPT},
                {"role": "user", "content": user_message},
            ],
            response_format={"type": "json_object"},
            temperature=0.0,
        )
        raw_response = response.choices[0].message.content
        data = json.loads(raw_response)
        results = data.get("results", data) if isinstance(data, dict) else data

        matches = []
        for item in results:
            idx = item["index"]
            matches.append(
                FindingMatch(
                    finding=expected_findings[idx],
                    found=bool(item["found"]),
                    evidence=item.get("evidence", ""),
                    confidence=float(item.get("confidence", 0.0)),
                )
            )

        # Fill in any findings not returned by the LLM
        returned_indices = {item["index"] for item in results}
        for i, f in enumerate(expected_findings):
            if i not in returned_indices:
                matches.append(
                    FindingMatch(
                        finding=f,
                        found=False,
                        evidence="Not evaluated by judge",
                        confidence=0.0,
                    )
                )

    except Exception as e:
        logger.error("LLM judge failed: %s", e)
        raw_response = f"Judge error: {e}"
        matches = [
            FindingMatch(
                finding=f,
                found=False,
                evidence=f"Judge error: {e}",
                confidence=0.0,
            )
            for f in expected_findings
        ]

    found_count = sum(1 for m in matches if m.found)
    total = len(expected_findings)
    recall = found_count / total if total > 0 else 1.0

    return FindingsResult(
        matches=matches,
        recall=recall,
        found_count=found_count,
        total_expected=total,
        raw_judge_response=raw_response,
    )