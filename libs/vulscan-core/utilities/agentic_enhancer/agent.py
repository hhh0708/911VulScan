"""
Agentic Context Enhancer

Main agent loop that iteratively explores the codebase to gather
*neutral* structural context. Does not classify exploitability, invent
callers, or mutate the call graph / reachability / verdicts.
"""

from __future__ import annotations

import json
from typing import List, Optional

from ..llm_client import TokenTracker, get_global_tracker, get_shared_llm_client
from ..llm_errors import LLMRateLimitError
from ..model_registry import ModelRole, model_for
from ..rate_limiter import get_rate_limiter
from utilities.enhancement.schema import (
    ENHANCEMENT_PROMPT_VERSION,
    ENHANCEMENT_SCHEMA_VERSION,
    empty_enhancement,
    normalize_enhancement,
)
from .repository_index import RepositoryIndex
from .tools import TOOL_DEFINITIONS, ToolExecutor
from .prompts import SYSTEM_PROMPT, get_user_prompt


AGENT_MODEL = model_for(ModelRole.SECONDARY)
MAX_ITERATIONS = 20
MAX_TOKENS_PER_RESPONSE = 4096


class AgentResult:
    """Neutral enhancement result from the agent."""

    def __init__(
        self,
        enhancement: dict,
        iterations: int,
        total_tokens: int,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
    ):
        self.enhancement = enhancement
        self.iterations = iterations
        self.total_tokens = total_tokens
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cost_usd = cost_usd

    def to_dict(self) -> dict:
        """Return the enhancement payload with agent metadata in provenance."""
        payload = dict(self.enhancement)
        prov = dict(payload.get("provenance") or {})
        prov.update(
            {
                "schema_version": ENHANCEMENT_SCHEMA_VERSION,
                "prompt_version": ENHANCEMENT_PROMPT_VERSION,
                "mode": "agentic",
                "model": AGENT_MODEL,
                "iterations": self.iterations,
                "total_tokens": self.total_tokens,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "cost_usd": self.cost_usd,
            }
        )
        payload["provenance"] = prov
        return payload


class ContextAgent:
    """Agent that gathers neutral context via tool use."""

    def __init__(
        self,
        index: RepositoryIndex,
        tracker: TokenTracker = None,
        verbose: bool = False,
        client=None,
        reachability_status: Optional[str] = None,
        is_structural_root: bool = False,
    ):
        self.index = index
        self.tracker = tracker or get_global_tracker()
        self.verbose = verbose
        self.tool_executor = ToolExecutor(index)
        self.client = client or get_shared_llm_client()
        self.reachability_status = reachability_status
        self.is_structural_root = is_structural_root

    def analyze_unit(
        self,
        unit_id: str,
        unit_type: str,
        primary_code: str,
        static_deps: list[str],
        static_callers: list[str],
    ) -> AgentResult:
        user_prompt = get_user_prompt(
            unit_id=unit_id,
            unit_type=unit_type,
            primary_code=primary_code,
            static_deps=static_deps,
            static_callers=static_callers,
            is_entry_point=self.is_structural_root,
            reachability_status=self.reachability_status,
        )

        messages = [{"role": "user", "content": user_prompt}]
        iterations = 0
        total_input_tokens = 0
        total_output_tokens = 0

        def _incomplete(reason: str, confidence_note: str = "") -> AgentResult:
            payload = empty_enhancement(mode="agentic", model=AGENT_MODEL)
            payload["unknowns"].append({"kind": "incomplete", "detail": reason})
            if confidence_note:
                payload["call_context"]["notes"].append(confidence_note)
            return AgentResult(
                enhancement=payload,
                iterations=iterations,
                total_tokens=total_input_tokens + total_output_tokens,
                input_tokens=total_input_tokens,
                output_tokens=total_output_tokens,
            )

        while iterations < MAX_ITERATIONS:
            iterations += 1
            if self.verbose:
                print(f"  Iteration {iterations}...")

            try:
                get_rate_limiter().wait_if_needed()
                response = self.client.messages.create(
                    model=AGENT_MODEL,
                    max_tokens=MAX_TOKENS_PER_RESPONSE,
                    system=SYSTEM_PROMPT,
                    tools=TOOL_DEFINITIONS,
                    messages=messages,
                )
            except LLMRateLimitError as exc:
                get_rate_limiter().report_rate_limit(exc.retry_after)
                exc.agent_state = {
                    "iteration": iterations,
                    "max_iterations": MAX_ITERATIONS,
                    "tokens_used": total_input_tokens + total_output_tokens,
                    "input_tokens": total_input_tokens,
                    "output_tokens": total_output_tokens,
                }
                raise
            except Exception as exc:
                exc.agent_state = {
                    "iteration": iterations,
                    "max_iterations": MAX_ITERATIONS,
                    "tokens_used": total_input_tokens + total_output_tokens,
                    "input_tokens": total_input_tokens,
                    "output_tokens": total_output_tokens,
                }
                raise

            total_input_tokens += response.usage.input_tokens
            total_output_tokens += response.usage.output_tokens
            assistant_content = response.content
            stop_reason = response.stop_reason

            if stop_reason == "end_turn":
                if self.verbose:
                    print("  Agent ended without calling finish tool")
                return _incomplete("Agent did not complete analysis")

            tool_results = []
            finish_result = None

            for block in assistant_content:
                if block.type == "tool_use":
                    tool_name = block.name
                    tool_input = block.input
                    tool_use_id = block.id
                    if self.verbose:
                        print(f"    Tool: {tool_name}({json.dumps(tool_input)[:100]}...)")
                    result = self.tool_executor.execute(tool_name, tool_input)
                    if tool_name == "finish" and result.get("status") == "complete":
                        finish_result = result.get("result", {})
                        tool_results.append(
                            {
                                "type": "tool_result",
                                "tool_use_id": tool_use_id,
                                "content": json.dumps(result),
                            }
                        )
                        break
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": json.dumps(result),
                        }
                    )

            if finish_result is not None:
                call_record = self.tracker.record_call(
                    model=AGENT_MODEL,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                )
                payload = normalize_enhancement(
                    finish_result, mode="agentic", model=AGENT_MODEL
                )
                # Seed call_context from static metadata when model omitted it.
                if not payload["call_context"].get("direct_calls"):
                    payload["call_context"]["direct_calls"] = list(static_deps or [])
                if not payload["call_context"].get("direct_callers"):
                    payload["call_context"]["direct_callers"] = list(static_callers or [])
                return AgentResult(
                    enhancement=payload,
                    iterations=iterations,
                    total_tokens=total_input_tokens + total_output_tokens,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    cost_usd=call_record.get("cost_usd", 0.0),
                )

            messages.append({"role": "assistant", "content": assistant_content})
            if tool_results:
                messages.append({"role": "user", "content": tool_results})
            else:
                return _incomplete("Agent response had no tool calls")

        call_record = self.tracker.record_call(
            model=AGENT_MODEL,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
        )
        result = _incomplete("Max iterations reached")
        result.cost_usd = call_record.get("cost_usd", 0.0)
        return result


def enhance_unit_with_agent(
    unit: dict,
    index: RepositoryIndex,
    tracker: TokenTracker = None,
    verbose: bool = False,
    client=None,
    reachability_status: Optional[str] = None,
) -> dict:
    """Enhance a unit with neutral context. Does not mutate code or call graph."""
    is_root = bool(unit.get("is_entry_point"))
    status = reachability_status or unit.get("reachability")

    agent = ContextAgent(
        index=index,
        tracker=tracker,
        verbose=verbose,
        client=client,
        reachability_status=status,
        is_structural_root=is_root,
    )

    unit_id = unit.get("id", "unknown")
    unit_type = unit.get("unit_type", "function")
    code_section = unit.get("code", {})
    primary_code = code_section.get("primary_code", "") if isinstance(code_section, dict) else ""
    static_deps = unit.get("metadata", {}).get("direct_calls", [])
    static_callers = unit.get("metadata", {}).get("direct_callers", [])

    result = agent.analyze_unit(
        unit_id=unit_id,
        unit_type=unit_type,
        primary_code=primary_code,
        static_deps=static_deps,
        static_callers=static_callers,
    )

    unit["enhancement"] = result.to_dict()
    # Keep a thin usage mirror for checkpoint/usage aggregation.
    unit["_enhancement_usage"] = {
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "cost_usd": result.cost_usd,
    }
    return unit
