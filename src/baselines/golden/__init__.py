"""Golden-standard SOC playbook baseline.

Deterministic execution of one of four golden playbooks (mapped from
the source mermaid files), followed by a single GPT-5.5 (or other LLM)
call to produce the final report in the standard ``REPORT_FORMAT``.
"""

from baselines.golden.agent import GoldenWorkflowAgent
from baselines.golden.context import ExecutionContext
from baselines.golden.playbooks import (
    PLAYBOOK_FILES,
    load_playbook_pre_verdict,
)
from baselines.golden.steps import WorkflowStep
from baselines.golden.workflows import WORKFLOWS

__all__ = [
    "GoldenWorkflowAgent",
    "ExecutionContext",
    "WorkflowStep",
    "WORKFLOWS",
    "PLAYBOOK_FILES",
    "load_playbook_pre_verdict",
]
