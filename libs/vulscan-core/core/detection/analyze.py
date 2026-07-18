"""Stage 1 candidate discovery — LLM call over DetectionInput."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Optional

from core.detection.schema import (
    DETECTION_PROMPT_VERSION,
    DETECTION_SCHEMA_VERSION,
    empty_detection_result,
    normalize_detection_result,
)
from prompts.vulnerability_analysis import (
    get_detection_prompt,
    get_detection_system_prompt,
)
from utilities.credentials import safe_exception_message
from utilities.llm_client import AnthropicClient
from utilities.model_registry import ModelRole, model_for


def analyze_detection_input(
    client: AnthropicClient,
    detection_input: Dict[str, Any],
    *,
    model: str = "",
) -> Dict[str, Any]:
    """Run Stage 1 candidate discovery. Returns a DetectionResult dict."""
    unit_id = detection_input.get("unit_id", "unknown")
    model_id = model or getattr(client, "model", None) or model_for(ModelRole.PRIMARY)
    evidence_ids = {
        e.get("evidence_id")
        for e in (detection_input.get("evidence") or [])
        if isinstance(e, dict) and e.get("evidence_id")
    }

    user_prompt = get_detection_prompt(detection_input)
    system_prompt = get_detection_system_prompt()

    start = datetime.now()
    try:
        from utilities.llm_json_utils import DEFAULT_JSON_RETRIES

        raw = client.analyze_json_sync(
            user_prompt,
            system=system_prompt,
            context=f"stage1 detection {unit_id}",
            retries=DEFAULT_JSON_RETRIES,
        )
        # Syntax-only JSON path: analyze_json_sync already parses JSON.
        # Do not invent evidence or remap legacy verdicts to candidate.
        result = normalize_detection_result(
            raw, unit_id=unit_id, evidence_ids=evidence_ids, model=model_id
        )
    except Exception as exc:  # noqa: BLE001
        result = empty_detection_result(
            unit_id,
            decision="error",
            reason=safe_exception_message(exc),
            model=model_id,
        )
        result["provenance"]["error"] = {
            "type": "api",
            "message": safe_exception_message(exc),
            "exception_class": type(exc).__name__,
        }

    elapsed = (datetime.now() - start).total_seconds()
    result["provenance"] = {
        **(result.get("provenance") or {}),
        "schema_version": DETECTION_SCHEMA_VERSION,
        "prompt_version": DETECTION_PROMPT_VERSION,
        "model": model_id,
        "elapsed_seconds": elapsed,
    }
    # Pipeline metadata used by Stage 2 for code lookup (not a Stage 1 claim).
    result["route_key"] = unit_id
    return result
