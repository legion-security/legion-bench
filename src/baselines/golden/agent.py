"""Golden-workflow baseline agent — deterministic execution + LLM report only.

Each of the four golden playbooks (AccountTakeover, Malware, DLP,
Phishing) is encoded as a fixed sequence of ``WorkflowStep`` objects
under ``baselines/golden/workflows``. The agent:

  1. Routes the alert to one of the four workflows (or accepts an
     explicit override from the caller).
  2. Executes every step's tool call(s) deterministically against the
     active ``ToolRegistry``. No LLM is involved here — argument
     resolution comes from the alert and prior tool results, not from a
     model.
  3. Calls GPT-5.5 (or whichever model the user selects) **exactly
     once** with all the gathered evidence and asks it to write the
     final report in the shared ``REPORT_FORMAT``.

This makes the baseline reproducible across runs (same playbook, same
DB, same tool calls every time) while still giving us a high-quality,
human-readable report at the end.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import litellm

from agents.base import BaseAgent, InvestigationResult, ToolCallRecord
from baselines.golden.context import ExecutionContext
from baselines.golden.prompts import REPORT_SYSTEM_PROMPT, render_report_user_message
from baselines.golden.workflows import WORKFLOWS
from baselines.workflow_router import GoldenWorkflow, pick_golden_workflow

logger = logging.getLogger(__name__)

# Truncate per-call result payloads when rendering them into the LLM
# evidence block. The LLM sees a compacted summary that still preserves
# the key fields; the full raw results are persisted in the trace JSON.
_RESULT_TRUNCATE_CHARS = 4_000
_RESULT_TRUNCATE_NOTICE = "  …[truncated]"


def _summarize(value: Any, limit: int = 200) -> str:
    s = json.dumps(value, default=str, ensure_ascii=False)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _format_record_for_evidence(
    step_label: str,
    record: ToolCallRecord,
) -> str:
    args_str = json.dumps(record.arguments, default=str, ensure_ascii=False)
    if record.error:
        body = f"ERROR: {record.error}"
    else:
        body = json.dumps(record.result, default=str, ensure_ascii=False, indent=2)
    if len(body) > _RESULT_TRUNCATE_CHARS:
        body = body[:_RESULT_TRUNCATE_CHARS] + _RESULT_TRUNCATE_NOTICE
    return (
        f"### [{step_label}] {record.function_name}\n"
        f"args: {args_str}\n"
        f"result:\n{body}\n"
    )


def _result_size(value: Any) -> str:
    """Compact size hint for the live console output."""
    if value is None:
        return "null"
    if isinstance(value, list):
        return f"list[{len(value)}]"
    if isinstance(value, dict):
        return f"dict({len(value)} keys)"
    return type(value).__name__


class GoldenWorkflowAgent(BaseAgent):
    """Deterministic golden-playbook executor with LLM-only report writing."""

    def __init__(
        self,
        model: str,
        registry,
        scenario: dict,
        max_turns: int = 0,  # ignored — kept for CLI compatibility
        workflow: GoldenWorkflow | None = None,
    ):
        super().__init__(model, registry, scenario)
        self.workflow: GoldenWorkflow = workflow or pick_golden_workflow(
            scenario.get("alert", {})
        )

    # ------------------------------------------------------------------

    def run(self) -> InvestigationResult:
        steps = WORKFLOWS[self.workflow]
        ctx = ExecutionContext(self.scenario)

        print(f"\n[golden] workflow: {self.workflow}")
        print(f"[golden] steps:    {len(steps)}")
        if ctx.email:
            print(f"[golden] email:    {ctx.email}")
        ts = ctx.alert_ts
        if ts:
            start, end = ctx.time_window()
            print(f"[golden] window:   {start} → {end}\n")

        # --- Stage 1: deterministic tool execution ------------------
        for i, step in enumerate(steps, 1):
            try:
                argsets = step.build_argsets(ctx)
            except Exception as exc:
                logger.warning(
                    "build_argsets failed for step %s: %s", step.label, exc
                )
                argsets = []

            if not argsets:
                print(f"[{i:02d}/{len(steps)}] [skip] {step.label} "
                      f"({step.function}) — no inputs")
                continue

            for args in argsets:
                try:
                    result = self.registry.execute(step.function, args)
                    error = None
                except Exception as exc:  # noqa: BLE001
                    result = None
                    error = str(exc)

                record = ToolCallRecord(
                    function_name=step.function,
                    arguments=args,
                    result=result,
                    error=error,
                )
                ctx.record(step.label, record)

                args_preview = ", ".join(
                    f"{k}={_summarize(v, 60)}" for k, v in args.items()
                )
                if error:
                    print(f"[{i:02d}/{len(steps)}] {step.label}: "
                          f"{step.function}({args_preview}) -> ERROR: {error}")
                else:
                    print(f"[{i:02d}/{len(steps)}] {step.label}: "
                          f"{step.function}({args_preview}) -> {_result_size(result)}")

        # --- Stage 2: single LLM call to write the report -----------
        evidence_blocks = [
            _format_record_for_evidence(label, record)
            for label, record in zip(ctx.step_labels, ctx.results)
        ]
        evidence_text = "\n".join(evidence_blocks) if evidence_blocks else (
            "(no tool calls were executed — alert lacked the indicators "
            "required to start the workflow)"
        )

        user_msg = render_report_user_message(
            ctx.alert, self.workflow, evidence_text
        )
        messages = [
            {"role": "system", "content": REPORT_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ]

        print(f"\n[golden] calling {self.model} for report "
              f"(evidence: {len(evidence_text):,} chars, "
              f"{len(ctx.results)} tool calls)\n")

        response = litellm.completion(model=self.model, messages=messages)
        report_message = response.choices[0].message
        messages.append(report_message.model_dump(exclude_none=True))
        report = report_message.content or ""

        return InvestigationResult(
            report=report,
            tool_calls=ctx.results,
            llm_calls=1,
            messages=messages,
            metadata={
                "agent_type": "golden_workflow",
                "workflow": self.workflow,
                "model": self.model,
                "step_count": len(steps),
                "executed_step_count": len(
                    {label for label in ctx.step_labels}
                ),
                "tool_call_count": len(ctx.results),
            },
        )
