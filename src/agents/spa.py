"""SPA (See-Plan-Act) agent implementation.

The SPA agent follows a strict Plan-then-Act cycle:
1. Planning phase: Creates an investigation plan (no tool calls allowed)
2. Execution phase: Executes the plan with tools
3. Agent can request a replan at any time, returning to step 1

Planning and tool execution never happen in the same LLM call.
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
from agents.prompts.spa import (
    SYSTEM_PROMPT,
    EXECUTE_PLAN_PROMPT,
    REPLAN_PROMPT,
)

logger = logging.getLogger(__name__)

REPLAN_TOOL = {
    "type": "function",
    "function": {
        "name": "request_replan",
        "description": "Call this when your investigation findings require a change in direction. This will pause tool execution and let you create a revised investigation plan.",
        "parameters": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Brief explanation of why you need to revise the plan",
                }
            },
            "required": ["reason"],
        },
    },
}


def _handle_replan(tool_call, args):
    """Special handler for the request_replan tool."""
    reason = args.get("reason", "No reason provided")
    print(f"  -> request_replan: {reason}")
    return (
        "Replan request acknowledged. You will now create a revised plan.",
        ToolCallRecord("request_replan", args, "acknowledged", None),
    )


class SPAAgent(BaseAgent):
    """SPA agent that strictly separates planning from execution."""

    def __init__(self, model: str, registry, scenario: dict, max_turns: int = 15):
        super().__init__(model, registry, scenario)
        self.max_turns = max_turns

    def run(self) -> InvestigationResult:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": build_initial_message(self.scenario, self._get_tool_summaries())
                + "\n\nStart by analyzing the indicators and creating your investigation plan.",
            },
        ]
        tools = self.registry.get_llm_tools() + [REPLAN_TOOL]
        tool_call_records: list[ToolCallRecord] = []
        llm_calls = 0
        last_content = ""
        plan_count = 0
        phase = "plan"
        tool_calls_here = 0
        nudged = False

        for turn in range(self.max_turns):
            turn_label = f"[Turn {turn + 1}/{self.max_turns}]"

            if phase == "plan":
                print(f"\n{turn_label} PLANNING (plan #{plan_count + 1})")
                print("-" * 50)

                response = litellm.completion(model=self.model, messages=messages)
                llm_calls += 1
                message = response.choices[0].message
                messages.append(message.model_dump(exclude_none=True))
                last_content = message.content or ""
                plan_count += 1

                print(last_content)

                messages.append({"role": "user", "content": EXECUTE_PLAN_PROMPT})
                phase = "act"

            elif phase == "act":
                response = litellm.completion(
                    model=self.model, messages=messages, tools=tools, tool_choice="auto",
                )
                llm_calls += 1
                message = response.choices[0].message
                messages.append(message.model_dump(exclude_none=True))
                last_content = message.content or ""

                if not message.tool_calls:
                    if tool_calls_here == 0 and not nudged:
                        nudged = True
                        messages.append({"role": "user", "content": CONTINUE_NUDGE})
                        continue
                    break

                tool_calls_here += len(message.tool_calls)
                print(f"\n{turn_label} EXECUTION — {len(message.tool_calls)} tool call(s)")
                print("-" * 50)

                special = process_tool_calls(
                    self.registry,
                    message,
                    messages,
                    tool_call_records,
                    turn_label=turn_label,
                    special_handlers={"request_replan": _handle_replan},
                )

                if "request_replan" in special:
                    _, _, replan_args = special["request_replan"]
                    reason = replan_args.get("reason", "No reason provided")
                    messages.append(
                        {"role": "user", "content": REPLAN_PROMPT.format(reason=reason)}
                    )
                    phase = "plan"
        else:
            print(f"\n[!] Agent reached max_turns ({self.max_turns}) without finishing")

        return InvestigationResult(
            report=last_content,
            tool_calls=tool_call_records,
            llm_calls=llm_calls,
            messages=messages,
            metadata={
                "agent_type": "spa",
                "model": self.model,
                "max_turns": self.max_turns,
                "plan_count": plan_count,
            },
        )
