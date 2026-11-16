"""Concrete deterministic workflows mapped from the golden mermaid playbooks.

Each module here exports a ``STEPS: list[WorkflowStep]`` covering the
pre-Verdict portion of one of the four golden playbooks. ``WORKFLOWS``
indexes them by the router's ``GoldenWorkflow`` name so the agent can
look up the right sequence at run time.
"""
from __future__ import annotations

from baselines.golden.steps import WorkflowStep
from baselines.golden.workflows.account_takeover import STEPS as ATO_STEPS
from baselines.golden.workflows.dlp import STEPS as DLP_STEPS
from baselines.golden.workflows.malware import STEPS as MALWARE_STEPS
from baselines.golden.workflows.phishing import STEPS as PHISHING_STEPS
from baselines.workflow_router import GoldenWorkflow

WORKFLOWS: dict[GoldenWorkflow, list[WorkflowStep]] = {
    "AccountTakeover": ATO_STEPS,
    "Malware": MALWARE_STEPS,
    "DLP": DLP_STEPS,
    "Phishing": PHISHING_STEPS,
}

__all__ = ["WORKFLOWS"]
