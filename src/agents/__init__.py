"""Agent implementations for SOC investigation benchmarks."""

from agents import _reasoning
from agents.base import BaseAgent, InvestigationResult, ToolCallRecord

# No-op unless LEGION_REASONING_EFFORT is set. See agents/_reasoning.py.
_reasoning.install()

from agents.spa import SPAAgent
from agents.direct import DirectAgent
from agents.react import ReActAgent
from agents.reflexion import ReflexionAgent
from agents.multi import MultiAgent

__all__ = [
    "BaseAgent",
    "InvestigationResult",
    "ToolCallRecord",
    "SPAAgent",
    "DirectAgent",
    "ReActAgent",
    "ReflexionAgent",
    "MultiAgent",
]
