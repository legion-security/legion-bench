"""Direct agent -- vanilla tool-use baseline.

No structural constraints. System prompt + alert + tools, then let the model
run freely until it produces a final report (no tool calls) or hits max_turns.
"""

import logging

import litellm

from agents.base import (
    CONTINUE_NUDGE,
    BaseAgent,
    InvestigationResult,
    ToolCallRecord,
    process_tool_calls,
)
from agents.prompts import build_initial_message
from agents.prompts.direct import SYSTEM_PROMPT

logger = logging.getLogger(__name__)


class DirectAgent(BaseAgent):
    """Vanilla tool-use agent with no imposed methodology."""

    def __init__(self, model: str, registry, scenario: dict, max_turns: int = 15):
        super().__init__(model, registry, scenario)
        self.max_turns = max_turns

    def run(self) -> InvestigationResult:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": build_initial_message(self.scenario, self._get_tool_summaries())
                + "\n\nInvestigate this alert.",
            },
        ]
        tools = self.registry.get_llm_tools()
        tool_call_records: list[ToolCallRecord] = []
        llm_calls = 0
        last_content = ""
        tool_calls_here = 0
        nudged = False

        for turn in range(self.max_turns):
            turn_label = f"[Turn {turn + 1}/{self.max_turns}]"

            response = litellm.completion(
                model=self.model, messages=messages, tools=tools, tool_choice="auto",
            )
            llm_calls += 1
            message = response.choices[0].message
            messages.append(message.model_dump(exclude_none=True))
            last_content = message.content or ""

            if not message.tool_calls:
                # No tool calls = final report, but only once evidence exists.
                if tool_calls_here == 0 and not nudged:
                    nudged = True
                    messages.append({"role": "user", "content": CONTINUE_NUDGE})
                    continue
                break

            tool_calls_here += len(message.tool_calls)
            print(f"\n{turn_label} — {len(message.tool_calls)} tool call(s)")
            print("-" * 50)

            process_tool_calls(
                self.registry, message, messages, tool_call_records, turn_label=turn_label,
            )
        else:
            print(f"\n[!] Agent reached max_turns ({self.max_turns}) without finishing")

        return InvestigationResult(
            report=last_content,
            tool_calls=tool_call_records,
            llm_calls=llm_calls,
            messages=messages,
            metadata={
                "agent_type": "direct",
                "model": self.model,
                "max_turns": self.max_turns,
            },
        )
