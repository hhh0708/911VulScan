"""Stage 2 candidate verification engine (tool-use state machine)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import anthropic

from core.verification.input_builder import append_tool_evidence
from core.verification.schema import (
    VERIFICATION_PROMPT_VERSION,
    VERIFICATION_SCHEMA_VERSION,
    VERIFICATION_TOOLS_VERSION,
    empty_verification_result,
    normalize_verification_result,
)
from prompts.verification_prompts import (
    get_verification_prompt_from_input,
    get_verification_system_prompt,
)
from utilities.agentic_enhancer.tools import ToolExecutor
from utilities.credentials import safe_exception_message
from utilities.llm_client import TokenTracker, get_global_tracker, get_shared_llm_client
from utilities.llm_errors import LLMRateLimitError
from utilities.model_registry import ModelRole, model_for
from utilities.rate_limiter import get_rate_limiter

VERIFIER_MODEL = model_for(ModelRole.PRIMARY)
MAX_ITERATIONS = 20
MAX_TOKENS_PER_RESPONSE = 4096

FINISH_TOOL = {
    "name": "finish",
    "description": (
        "Complete candidate verification. Return VerificationResult fields only. "
        "decision must be confirmed | rejected | inconclusive. "
        "confirmed requires evidence_roles covering source, propagation, sink, impact. "
        "rejected requires counter_evidence_ids proving path break / guard / unmet precondition. "
        "Do not emit agree, correct_finding, finding, or verdict."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "decision": {
                "type": "string",
                "enum": ["confirmed", "rejected", "inconclusive"],
            },
            "verified_source": {"type": "string"},
            "propagation": {"type": "string"},
            "sink": {"type": "string"},
            "guards": {"type": "array", "items": {}},
            "impact": {"type": "string"},
            "evidence_ids": {
                "type": "array",
                "items": {"type": "string"},
            },
            "counter_evidence_ids": {
                "type": "array",
                "items": {"type": "string"},
            },
            "evidence_roles": {
                "type": "object",
                "description": (
                    "Map role → evidence_id list. Required for confirmed: "
                    "source, propagation, sink, impact."
                ),
            },
            "missing_evidence": {"type": "array", "items": {}},
            "uncertainties": {"type": "array", "items": {}},
            "confidence": {"type": "number"},
            "provenance": {"type": "object"},
        },
        "required": ["decision", "evidence_ids", "counter_evidence_ids", "confidence"],
    },
}

# Reuse exploration tools from agentic enhancer definitions (names only).
from utilities.agentic_enhancer.tools import TOOL_DEFINITIONS as _AGENT_TOOLS

VERIFICATION_TOOLS = [
    t for t in _AGENT_TOOLS if t.get("name") != "finish"
] + [FINISH_TOOL]


class CandidateVerifier:
    """Runs attacker-simulation tool loop for one VerificationInput."""

    def __init__(
        self,
        index,
        tracker: TokenTracker = None,
        app_context=None,
        client=None,
        verbose: bool = False,
    ):
        self.index = index
        self.tracker = tracker or get_global_tracker()
        self.app_context = app_context
        self.client = client or get_shared_llm_client()
        self.tool_executor = ToolExecutor(index)
        self.verbose = verbose

    def verify(self, verification_input: Dict[str, Any]) -> Dict[str, Any]:
        finding_id = verification_input.get("finding_id", "")
        model_id = VERIFIER_MODEL

        # Preconditions
        if not verification_input.get("target_code"):
            return empty_verification_result(
                finding_id,
                execution_state="failed",
                decision="inconclusive",
                reason="missing target code",
                model=model_id,
            )
        if self.index is None:
            return empty_verification_result(
                finding_id,
                execution_state="failed",
                decision="inconclusive",
                reason="missing repository index",
                model=model_id,
            )

        evidence: List[dict] = list(verification_input.get("evidence") or [])
        evidence_ids = {
            e.get("evidence_id")
            for e in evidence
            if isinstance(e, dict) and e.get("evidence_id")
        }

        # Working copy so tool evidence can be appended
        vin = dict(verification_input)
        vin["evidence"] = evidence

        user_prompt = get_verification_prompt_from_input(vin)
        system_prompt = get_verification_system_prompt(self.app_context)
        messages = [{"role": "user", "content": user_prompt}]
        iterations = 0
        total_in = 0
        total_out = 0

        def _failed(reason: str) -> Dict[str, Any]:
            r = empty_verification_result(
                finding_id,
                execution_state="failed",
                decision="inconclusive",
                reason=reason,
                model=model_id,
                evidence=evidence,
            )
            r["provenance"]["iterations"] = iterations
            r["provenance"]["input_tokens"] = total_in
            r["provenance"]["output_tokens"] = total_out
            r["provenance"]["termination_reason"] = reason
            return r

        while iterations < MAX_ITERATIONS:
            iterations += 1
            get_rate_limiter().wait_if_needed()
            try:
                response = self.client.messages.create(
                    model=model_id,
                    max_tokens=MAX_TOKENS_PER_RESPONSE,
                    system=system_prompt,
                    tools=VERIFICATION_TOOLS,
                    messages=messages,
                )
            except (anthropic.RateLimitError, LLMRateLimitError) as exc:
                retry_after = getattr(exc, "retry_after", None)
                if retry_after is None and getattr(exc, "response", None) is not None:
                    retry_after = float(exc.response.headers.get("retry-after", 0))
                get_rate_limiter().report_rate_limit(float(retry_after or 0))
                raise
            except Exception as exc:  # noqa: BLE001
                return _failed(safe_exception_message(exc))

            total_in += response.usage.input_tokens
            total_out += response.usage.output_tokens
            assistant_content = response.content
            stop_reason = response.stop_reason

            if stop_reason == "end_turn":
                self.tracker.record_call(
                    model=model_id, input_tokens=total_in, output_tokens=total_out
                )
                return _failed("end_turn_without_finish")

            tool_results = []
            finish_payload = None

            for block in assistant_content:
                if getattr(block, "type", None) != "tool_use":
                    continue
                tool_name = block.name
                tool_input = block.input
                tool_use_id = block.id

                if tool_name == "finish":
                    finish_payload = tool_input
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": json.dumps({"status": "complete"}),
                        }
                    )
                    break

                result = self.tool_executor.execute(tool_name, tool_input)
                # Register full tool result as evidence (preview is display-only)
                eid = append_tool_evidence(
                    evidence,
                    tool=tool_name,
                    tool_input=tool_input,
                    full_result=result,
                    source=f"stage2.tool.{tool_name}",
                )
                evidence_ids.add(eid)
                vin["evidence"] = evidence
                # Return preview to the model; ID is bound to full content hash
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": json.dumps(
                            {
                                "tool_result_preview": _preview(result),
                                "evidence_id": eid,
                            }
                        ),
                    }
                )

            if finish_payload is not None:
                self.tracker.record_call(
                    model=model_id, input_tokens=total_in, output_tokens=total_out
                )
                result = normalize_verification_result(
                    finish_payload,
                    finding_id=finding_id,
                    evidence_ids=evidence_ids,
                    evidence_table=evidence,
                    model=model_id,
                    execution_state="succeeded",
                )
                result["provenance"]["iterations"] = iterations
                result["provenance"]["input_tokens"] = total_in
                result["provenance"]["output_tokens"] = total_out
                result["provenance"]["schema_version"] = VERIFICATION_SCHEMA_VERSION
                result["provenance"]["prompt_version"] = VERIFICATION_PROMPT_VERSION
                result["provenance"]["tools_version"] = VERIFICATION_TOOLS_VERSION
                return result

            messages.append({"role": "assistant", "content": assistant_content})
            if tool_results:
                messages.append({"role": "user", "content": tool_results})
            else:
                return _failed("no_tool_calls")

        self.tracker.record_call(
            model=model_id, input_tokens=total_in, output_tokens=total_out
        )
        return _failed("max_iterations")


def _preview(result: Any, limit: int = 800) -> Any:
    try:
        text = json.dumps(result, default=str)
    except Exception:  # noqa: BLE001
        text = str(result)
    if len(text) > limit:
        return text[:limit] + "…"
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        return text
