"""WorkflowStep — one node in a deterministic golden workflow.

Each step represents one or more nodes from the source mermaid playbook
collapsed onto a single tool function in our SOC tool registry. The
``build_argsets`` callable receives the running ExecutionContext and
returns a list of argument dicts to invoke the function with:

    []          → step is skipped (data unavailable, dependency missing)
    [{...}]     → single tool call
    [{...}, …]  → fan-out (one call per dict, e.g. one TI lookup per IP)

This shape lets workflows express both "look up the user" (single call)
and "for every external IP found in the sign-in logs, check threat
intel" (fan-out, dynamic count) using the same primitive.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from baselines.golden.context import ExecutionContext


ArgsetBuilder = Callable[["ExecutionContext"], list[dict]]


@dataclass(frozen=True)
class WorkflowStep:
    """One deterministic step in a golden workflow."""

    label: str
    """Human-readable name; references the mermaid node(s) it covers."""

    function: str
    """Tool function name as registered in ToolRegistry (e.g.
    ``entra_lookup_user``)."""

    build_argsets: ArgsetBuilder
    """Returns a list of arg dicts. Empty list ⇒ skip the step."""

    covers: tuple[str, ...] = ()
    """Mermaid node IDs this step subsumes (for traceability/audit)."""

    description: str = ""
    """Optional one-line analyst-facing description."""
