"""Abstract base agent and result data classes."""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from soc_tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


# An assistant turn with no tool calls is ambiguous: the model may be narrating
# its reasoning (e.g. the ReAct "**Thought**:" step) rather than concluding.
# Treating that as "done" scores an empty investigation -- gpt-5.6-luna hit this
# on 64/74 react runs, where every collapsed run produced 0 tool calls and a
# findings_recall of 0. Nudge once before accepting an evidence-free finish; if
# the model declines again, respect it and stop.
CONTINUE_NUDGE = (
    "You have not called any tools yet, so no evidence has been gathered. "
    "Continue the investigation: issue your next step as actual tool calls now. "
    "Only write your final report once you have gathered evidence."
)


@dataclass
class ToolCallRecord:
    """Record of a single tool call made during an investigation."""

    function_name: str
    arguments: dict
    result: Any
    error: Optional[str] = None
    ticket_id: Optional[str] = None


@dataclass
class InvestigationResult:
    """Complete result of an agent investigation run."""

    report: str
    tool_calls: List[ToolCallRecord]
    llm_calls: int
    messages: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)


def process_tool_calls(
    registry: ToolRegistry,
    message,
    messages: list[dict],
    tool_call_records: list[ToolCallRecord],
    turn_label: str = "",
    special_handlers: Optional[Dict[str, Callable]] = None,
) -> dict:
    """Process tool calls from an LLM response message.

    Iterates over tool_calls, executes each via the registry (or a special
    handler), appends tool-role messages, and records every call.

    Args:
        registry: Active ToolRegistry for executing queries.
        message: The LLM response message object (must have .tool_calls).
        messages: Conversation history list -- tool results are appended in place.
        tool_call_records: Running list of ToolCallRecord -- new records appended.
        turn_label: Display prefix for logging (e.g. "[Turn 3/15]").
        special_handlers: Optional dict mapping function names to callables.
            Each callable receives (tool_call, args) and must return a
            (content_str, ToolCallRecord) tuple.

    Returns:
        Dict of {handler_name: handler_return_value} for any special handlers
        that were invoked during this turn.
    """
    special_handlers = special_handlers or {}
    special_results: dict = {}

    if message.content:
        print(message.content)

    for tool_call in message.tool_calls:
        func_name = tool_call.function.name
        raw_args = tool_call.function.arguments
        try:
            args = json.loads(raw_args)
        except (json.JSONDecodeError, TypeError) as parse_err:
            logger.warning(
                "Failed to parse tool call arguments for %s: %s — raw: %s",
                func_name, parse_err, raw_args,
            )
            error_msg = f"Tool call argument parsing error: {parse_err}"
            tool_call_records.append(
                ToolCallRecord(func_name, {}, None, error_msg)
            )
            messages.append(
                {"role": "tool", "tool_call_id": tool_call.id,
                 "content": f"Error: Could not parse arguments. Please provide valid JSON arguments. Raw input: {raw_args!r}"}
            )
            print(f"  -> {func_name}() [PARSE ERROR: {parse_err}]")
            continue

        if func_name in special_handlers:
            content, record = special_handlers[func_name](tool_call, args)
            messages.append(
                {"role": "tool", "tool_call_id": tool_call.id, "content": content}
            )
            tool_call_records.append(record)
            special_results[func_name] = (content, record, args)
        else:
            try:
                result = registry.execute(func_name, args)
                error = None
            except Exception as e:
                result = None
                error = str(e)

            tool_call_records.append(ToolCallRecord(func_name, args, result, error))
            content = (
                json.dumps(result, default=str) if result is not None else f"Error: {error}"
            )
            messages.append(
                {"role": "tool", "tool_call_id": tool_call.id, "content": content}
            )

            args_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
            display = content if len(content) <= 500 else content[:500] + "..."
            print(f"  -> {func_name}({args_str})")
            print(f"     {display}")

    return special_results


class BaseAgent(ABC):
    """Abstract base class for SOC investigation agents.

    Subclasses implement different investigation strategies (SPA, ReAct, etc.)
    while sharing the same tool registry and scenario infrastructure.
    """

    def __init__(self, model: str, registry: ToolRegistry, scenario: dict):
        self.model = model
        self.registry = registry
        self.scenario = scenario

    def _get_tool_summaries(self) -> list[dict]:
        """Return tool info dicts for all active platforms."""
        summaries = []
        for tool_id in self.registry.get_active_tool_ids():
            info = self.registry.get_tool_info(tool_id)
            if info:
                summaries.append(info)
        return summaries

    @abstractmethod
    def run(self) -> InvestigationResult:
        """Run the full investigation and return results."""
        ...
