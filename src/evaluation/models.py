"""Data models for evaluation results."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Composite score weights: emphasize investigative completeness (findings),
# then concrete evidence extraction (IOCs), then attack coverage (events).
COMPOSITE_ALPHA = 0.5  # findings recall weight
COMPOSITE_BETA = 0.3   # IOC recall weight
COMPOSITE_GAMMA = 0.2  # event recall weight


def f1_score(
    precision: Optional[float],
    recall: Optional[float],
) -> Optional[float]:
    """Harmonic mean of precision and recall. None when either is missing."""
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def composite_score(
    findings_recall: Optional[float],
    ioc_recall: Optional[float],
    event_recall: Optional[float],
) -> Optional[float]:
    """Weighted sum of the three recall metrics.

    Returns None if event_recall is unavailable (no attack events known) — the
    composite is only meaningful when all three components are defined.
    """
    if findings_recall is None or ioc_recall is None or event_recall is None:
        return None
    return (
        COMPOSITE_ALPHA * findings_recall
        + COMPOSITE_BETA * ioc_recall
        + COMPOSITE_GAMMA * event_recall
    )


@dataclass
class FindingMatch:
    """Result of evaluating a single expected finding."""

    finding: str
    found: bool
    evidence: str
    confidence: float


@dataclass
class FindingsResult:
    """Aggregated findings evaluation result."""

    matches: List[FindingMatch]
    recall: float
    found_count: int
    total_expected: int
    raw_judge_response: str = ""


@dataclass
class IOCCategoryResult:
    """Evaluation result for a single IOC category (e.g., IPs, domains)."""

    expected: List[str]
    found: List[str]
    missed: List[str]
    recall: float


@dataclass
class IOCResult:
    """Aggregated IOC evaluation result across all categories."""

    categories: Dict[str, IOCCategoryResult]
    overall_recall: float
    total_found: int
    total_expected: int
    # Precision: of the IOCs the agent listed in the IOC section, how many
    # were real? Populated by ``compute_ioc_precision``. ``neutral_count``
    # captures real attack IoCs outside the 4 evaluated categories (e.g.
    # malware filenames, miner pools) — excluded from both numerator and
    # denominator so they neither help nor hurt precision. Schema:
    #   {"listed_count": int, "matched_count": int, "neutral_count": int,
    #    "unmatched": [str], "precision": Optional[float]}
    precision: Optional[Dict[str, Any]] = None


@dataclass
class EventMatch:
    """Result for a single attack-injected event."""

    event_type: str
    signature: Dict[str, Any]
    found: bool
    matched_in: Optional[str] = None  # tool function name where matched


@dataclass
class EventRecallResult:
    """Aggregated event recall: how many attack events surfaced in tool results."""

    matches: List[EventMatch]
    recall: float
    found_count: int
    total_expected: int
    # Precision: of the tool calls the agent made, how many surfaced at least
    # one attack-injected event? Populated by
    # ``compute_tool_call_attack_precision``. Schema:
    #   {"useful_count": int, "total_count": int,
    #    "precision": Optional[float]}
    tool_call_precision: Optional[Dict[str, Any]] = None


@dataclass
class EvaluationResult:
    """Complete evaluation of an investigation run."""

    findings: FindingsResult
    iocs: IOCResult
    tool_call_count: int
    events: Optional[EventRecallResult] = None
    # Minimum number of (oracle splunk_run_query) calls needed to surface every
    # distinct attack signature — solved as set cover. None when no attack
    # events are available (e.g. non-isolated mode).
    min_tool_calls: Optional[int] = None
    # tool_call_count / min_tool_calls. >= 1.0 means the agent made at least
    # the minimum; higher values indicate more wasted calls. None when
    # min_tool_calls is unavailable or zero.
    tool_call_efficiency: Optional[float] = None

    @property
    def composite_score(self) -> Optional[float]:
        """Weighted summary of findings, IOC, and event recall.

        Score = 0.5*FR + 0.3*IR + 0.2*ER. None when event recall is unavailable.
        """
        return composite_score(
            self.findings.recall if self.findings else None,
            self.iocs.overall_recall if self.iocs else None,
            self.events.recall if self.events else None,
        )
