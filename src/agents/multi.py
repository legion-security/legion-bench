"""Multi-Agent -- coordinator + domain specialist team.

Coordinator triages the alert and assigns tasks to specialists.
Each specialist investigates their domain with only their category's tools.
Coordinator synthesizes all findings into the final report.
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
from agents.prompts.multi import (
    COORDINATOR_TRIAGE_SYSTEM,
    COORDINATOR_TRIAGE_USER,
    SPECIALIST_SYSTEM,
    SPECIALIST_USER,
    COORDINATOR_SYNTHESIS_SYSTEM,
    COORDINATOR_SYNTHESIS_USER,
)

logger = logging.getLogger(__name__)

# Maps tool-catalog category IDs to specialist role names
CATEGORY_TO_SPECIALIST = {
    "edr": "endpoint",
    "identity": "identity",
    "email_security": "email",
    "siem": "data",
    "dlp": "data",
    "threat_intel": "intel",
    "cnapp": "cloud",
}


def _get_specialist_tools(all_tools: list[dict], category_prefixes: list[str]) -> list[dict]:
    """Filter LLM tool schemas to only those matching the given prefixes."""
    result = []
    for tool in all_tools:
        func_name = tool["function"]["name"]
        if any(func_name.startswith(prefix + "_") for prefix in category_prefixes):
            result.append(tool)
    return result


class MultiAgent(BaseAgent):
    """Multi-agent system with coordinator and domain specialists."""

    def __init__(self, model: str, registry, scenario: dict, max_turns: int = 15):
        super().__init__(model, registry, scenario)
        self.max_turns = max_turns

    def _determine_specialists(self) -> dict[str, list[str]]:
        """Determine which specialists to create based on active platforms.

        Returns:
            Dict mapping specialist role -> list of tool-name prefixes for that role.
        """
        active_platforms = self.registry.get_active_platforms()
        specialists: dict[str, list[str]] = {}

        for category_id, platform_id in active_platforms.items():
            role = CATEGORY_TO_SPECIALIST.get(category_id)
            if not role:
                continue

            # Get the prefix for this platform from the catalog
            cat_data = self.registry._categories.get(category_id, {})
            platforms = cat_data.get("platforms", {})
            platform_def = platforms.get(platform_id, {})
            prefix = platform_def.get("prefix", platform_id)

            if role not in specialists:
                specialists[role] = []
            specialists[role].append(prefix)

        return specialists

    def _run_specialist(
        self,
        role: str,
        prefixes: list[str],
        all_tools: list[dict],
        alert_summary: str,
        assignment: str,
        tool_call_records: list[ToolCallRecord],
        max_spec_turns: int,
    ) -> tuple[str, int, list[dict]]:
        """Run a single specialist investigation.

        Returns:
            (findings_text, llm_calls, messages)
        """
        tools = _get_specialist_tools(all_tools, prefixes)

        if not tools:
            logger.warning(f"Specialist '{role}' has no matching tools, skipping")
            return f"No tools available for {role} domain.", 0, []

        messages = [
            {"role": "system", "content": SPECIALIST_SYSTEM.format(role=role)},
            {
                "role": "user",
                "content": SPECIALIST_USER.format(
                    alert_summary=alert_summary,
                    assignment=assignment,
                ),
            },
        ]

        llm_calls = 0
        last_content = ""
        # Per-specialist: tool_call_records is shared across all specialists.
        tool_calls_here = 0
        nudged = False

        for turn in range(max_spec_turns):
            turn_label = f"[{role.upper()} Turn {turn + 1}/{max_spec_turns}]"

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
            print(f"\n[!] Specialist '{role}' reached max turns ({max_spec_turns})")

        return last_content, llm_calls, messages

    def run(self) -> InvestigationResult:
        tool_call_records: list[ToolCallRecord] = []
        total_llm_calls = 0
        all_tools = self.registry.get_llm_tools()

        alert = self.scenario["alert"]
        sc = self.scenario["scenario"]

        alert_summary = f"{alert['title']}\n{alert['description']}"

        indicators_text = ""
        for ind in alert.get("initial_indicators", []):
            indicators_text += f"  - {ind['type']}: {ind['value']}\n"

        # Determine which specialists are needed
        specialists = self._determine_specialists()
        num_specialists = len(specialists)

        if num_specialists == 0:
            logger.error("No specialists could be created -- no active tool categories")
            return InvestigationResult(
                report="Error: No specialists available for this scenario.",
                tool_calls=[],
                llm_calls=0,
                messages=[],
                metadata={"agent_type": "multi", "error": "no_specialists"},
            )

        # Budget: 1 turn for triage, 1 for synthesis, rest split among specialists.
        # Strict cap: total LLM calls = 1 + num_specialists * per_specialist_turns + 1 <= max_turns.
        per_specialist_turns = (self.max_turns - 2) // num_specialists
        if per_specialist_turns < 1:
            raise ValueError(
                f"max_turns={self.max_turns} too low for {num_specialists} specialists "
                f"(need at least {num_specialists + 2})"
            )

        specialists_text = "\n".join(
            f"  - **{role}**: tools with prefixes {', '.join(prefixes)}"
            for role, prefixes in specialists.items()
        )

        # --- Phase 1: Coordinator triage ---
        print("\n" + "=" * 70)
        print("COORDINATOR: Triage")
        print("=" * 70)

        triage_messages = [
            {"role": "system", "content": COORDINATOR_TRIAGE_SYSTEM},
            {
                "role": "user",
                "content": COORDINATOR_TRIAGE_USER.format(
                    alert_title=alert["title"],
                    severity=alert["severity"],
                    source=alert["source"],
                    description=alert["description"].strip(),
                    indicators=indicators_text.rstrip(),
                    specialists=specialists_text,
                ),
            },
        ]

        triage_response = litellm.completion(model=self.model, messages=triage_messages)
        total_llm_calls += 1
        triage_plan = triage_response.choices[0].message.content or ""

        print(triage_plan[:1500] + ("..." if len(triage_plan) > 1500 else ""))

        # --- Phase 2: Run each specialist ---
        specialist_reports: dict[str, str] = {}
        all_specialist_messages: list[dict] = []

        for role, prefixes in specialists.items():
            print(f"\n{'=' * 70}")
            print(f"SPECIALIST: {role.upper()}")
            print(f"{'=' * 70}")

            # Extract the assignment for this specialist from the triage plan
            assignment = triage_plan  # Give full plan; specialist focuses on their domain

            findings, spec_calls, spec_messages = self._run_specialist(
                role=role,
                prefixes=prefixes,
                all_tools=all_tools,
                alert_summary=alert_summary,
                assignment=assignment,
                tool_call_records=tool_call_records,
                max_spec_turns=per_specialist_turns,
            )
            total_llm_calls += spec_calls
            specialist_reports[role] = findings
            all_specialist_messages.extend(spec_messages)

            print(f"\n--- {role.upper()} findings ---")
            print(findings[:500] + ("..." if len(findings) > 500 else ""))

        # --- Phase 3: Coordinator synthesis ---
        print(f"\n{'=' * 70}")
        print("COORDINATOR: Synthesis")
        print(f"{'=' * 70}")

        reports_text = ""
        for role, report in specialist_reports.items():
            reports_text += f"\n### {role.upper()} Specialist\n{report}\n"

        synthesis_messages = [
            {"role": "system", "content": COORDINATOR_SYNTHESIS_SYSTEM},
            {
                "role": "user",
                "content": COORDINATOR_SYNTHESIS_USER.format(
                    alert_summary=alert_summary,
                    specialist_reports=reports_text,
                ),
            },
        ]

        synthesis_response = litellm.completion(model=self.model, messages=synthesis_messages)
        total_llm_calls += 1
        final_report = synthesis_response.choices[0].message.content or ""

        # Combine all messages for the trace
        combined_messages = (
            triage_messages
            + [{"role": "assistant", "content": triage_plan}]
            + [{"role": "system", "content": "--- SPECIALIST INVESTIGATIONS ---"}]
            + all_specialist_messages
            + [{"role": "system", "content": "--- SYNTHESIS ---"}]
            + synthesis_messages
            + [{"role": "assistant", "content": final_report}]
        )

        return InvestigationResult(
            report=final_report,
            tool_calls=tool_call_records,
            llm_calls=total_llm_calls,
            messages=combined_messages,
            metadata={
                "agent_type": "multi",
                "model": self.model,
                "max_turns": self.max_turns,
                "specialists": list(specialists.keys()),
                "per_specialist_turns": per_specialist_turns,
                "specialist_reports": specialist_reports,
                "triage_plan": triage_plan,
            },
        )
