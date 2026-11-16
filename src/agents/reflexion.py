"""Reflexion agent -- self-critique and second-pass investigation.

Pass 1: Standard investigation loop (like Direct) using half the turn budget.
Critique: A separate "senior analyst" LLM call reviews the draft and identifies gaps.
Pass 2: Second investigation loop addressing the critique, then final report.
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
from agents.prompts.reflexion import (
    INVESTIGATOR_SYSTEM_PROMPT,
    CRITIC_SYSTEM_PROMPT,
    CRITIC_USER_PROMPT,
    PASS2_SYSTEM_PROMPT,
    PASS2_USER_PROMPT,
)

logger = logging.getLogger(__name__)


class ReflexionAgent(BaseAgent):
    """Reflexion agent with self-critique between two investigation passes."""

    def __init__(self, model: str, registry, scenario: dict, max_turns: int = 15):
        super().__init__(model, registry, scenario)
        self.max_turns = max_turns

    def _run_investigation_loop(
        self,
        messages: list[dict],
        tools: list[dict],
        tool_call_records: list[ToolCallRecord],
        max_loop_turns: int,
        label: str,
    ) -> tuple[str, int]:
        """Run a tool-use investigation loop.

        Returns:
            (last_content, llm_calls) -- the final text output and number of LLM calls made.
        """
        llm_calls = 0
        last_content = ""
        # Local to this pass: tool_call_records accumulates across pass 1 and 2,
        # so each pass gets its own evidence check and its own single nudge.
        tool_calls_here = 0
        nudged = False

        for turn in range(max_loop_turns):
            turn_label = f"[{label} Turn {turn + 1}/{max_loop_turns}]"

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
            print(f"\n{turn_label} — {len(message.tool_calls)} tool call(s)")
            print("-" * 50)

            process_tool_calls(
                self.registry, message, messages, tool_call_records, turn_label=turn_label,
            )
        else:
            print(f"\n[!] {label} reached max turns ({max_loop_turns}) without finishing")

        return last_content, llm_calls

    def run(self) -> InvestigationResult:
        tools = self.registry.get_llm_tools()
        tool_call_records: list[ToolCallRecord] = []
        total_llm_calls = 0

        # Budget: split turns between pass 1 and pass 2, reserving 1 for critic
        pass1_turns = (self.max_turns - 1) // 2
        pass2_turns = self.max_turns - 1 - pass1_turns

        alert_summary = self.scenario["alert"]["title"] + "\n" + self.scenario["alert"]["description"]

        # --- Pass 1: Initial investigation ---
        print("\n" + "=" * 70)
        print("PASS 1: Initial Investigation")
        print("=" * 70)

        pass1_messages = [
            {"role": "system", "content": INVESTIGATOR_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": build_initial_message(self.scenario, self._get_tool_summaries())
                + "\n\nInvestigate this alert and produce a draft report.",
            },
        ]

        draft_report, pass1_calls = self._run_investigation_loop(
            pass1_messages, tools, tool_call_records, pass1_turns, "Pass1",
        )
        total_llm_calls += pass1_calls

        print(f"\n{'=' * 70}")
        print("DRAFT REPORT")
        print(f"{'=' * 70}")
        print(draft_report[:1000] + ("..." if len(draft_report) > 1000 else ""))

        # --- Critique ---
        print(f"\n{'=' * 70}")
        print("CRITIQUE PHASE")
        print(f"{'=' * 70}")

        critic_messages = [
            {"role": "system", "content": CRITIC_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": CRITIC_USER_PROMPT.format(
                    alert_summary=alert_summary,
                    draft_report=draft_report,
                ),
            },
        ]

        critic_response = litellm.completion(model=self.model, messages=critic_messages)
        total_llm_calls += 1
        critique = critic_response.choices[0].message.content or ""

        print(critique[:1000] + ("..." if len(critique) > 1000 else ""))

        # --- Pass 2: Follow-up investigation ---
        print(f"\n{'=' * 70}")
        print("PASS 2: Follow-up Investigation")
        print(f"{'=' * 70}")

        pass2_messages = [
            {"role": "system", "content": PASS2_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": PASS2_USER_PROMPT.format(
                    draft_report=draft_report,
                    critique=critique,
                ),
            },
        ]

        final_report, pass2_calls = self._run_investigation_loop(
            pass2_messages, tools, tool_call_records, pass2_turns, "Pass2",
        )
        total_llm_calls += pass2_calls

        # Combine all messages for the trace
        all_messages = (
            pass1_messages
            + [{"role": "system", "content": "--- CRITIC PHASE ---"}]
            + critic_messages
            + [{"role": "assistant", "content": critique}]
            + [{"role": "system", "content": "--- PASS 2 ---"}]
            + pass2_messages
        )

        return InvestigationResult(
            report=final_report,
            tool_calls=tool_call_records,
            llm_calls=total_llm_calls,
            messages=all_messages,
            metadata={
                "agent_type": "reflexion",
                "model": self.model,
                "max_turns": self.max_turns,
                "pass1_turns": pass1_turns,
                "pass2_turns": pass2_turns,
                "draft_report": draft_report,
                "critique": critique,
            },
        )
