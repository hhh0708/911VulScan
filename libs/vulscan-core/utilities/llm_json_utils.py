"""Shared helpers for JSON-shaped LLM responses across static analysis stages."""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from utilities.llm_errors import LLMEmptyResponseError

# Default: 3 total attempts (initial + 2 retries) for JSON-shaped LLM calls.
DEFAULT_JSON_RETRIES = 2

JSON_ONLY_SYSTEM = (
    "You must respond with exactly one valid JSON object. "
    "Do not include markdown fences, explanations, or any text outside the JSON. "
    "Ensure the JSON is complete and properly closed (all brackets and quotes)."
)

JSON_RETRY_SUFFIX = (
    "\n\nIMPORTANT: Your previous answer was empty or not valid JSON. "
    "Return ONLY one complete JSON object matching the requested schema. "
    "No markdown, no commentary."
)

JSON_TRUNCATED_RETRY_SUFFIX = (
    "\n\nIMPORTANT: Your previous JSON response was truncated or incomplete "
    "(missing closing brackets/quotes). Return a SHORTER but COMPLETE JSON object. "
    "Omit lower-priority items if needed; never cut off mid-object. "
    "Return ONLY valid JSON."
)


def combine_system_prompt(base_system: str | None) -> str:
    """Append JSON-only constraints to any stage system prompt."""
    base = (base_system or "").strip()
    if not base:
        return JSON_ONLY_SYSTEM
    if JSON_ONLY_SYSTEM in base:
        return base
    return f"{base}\n\n{JSON_ONLY_SYSTEM}"


def is_likely_truncated_json(text: str) -> bool:
    """Heuristic: model hit output limit or stopped mid-JSON."""
    if not text or not str(text).strip():
        return False
    cleaned = str(text).strip()
    if extract_json_object(cleaned) is not None:
        return False

    # Unbalanced delimiters strongly suggest truncation.
    braces = cleaned.count("{") - cleaned.count("}")
    brackets = cleaned.count("[") - cleaned.count("]")
    if braces > 0 or brackets > 0:
        return True

    # Starts like JSON but cannot parse.
    if cleaned.lstrip().startswith("{") and extract_json_object(cleaned) is None:
        return True
    return False


def build_json_retry_prompt(
    base_prompt: str,
    attempt: int,
    last_text: str | None,
    last_error: Exception | None,
) -> str:
    """Build prompt for retry attempts after parse failure."""
    if attempt <= 0:
        return base_prompt
    if last_text and is_likely_truncated_json(last_text):
        suffix = JSON_TRUNCATED_RETRY_SUFFIX
    else:
        suffix = JSON_RETRY_SUFFIX
    detail = ""
    if last_error is not None:
        detail = f"\nParse error: {last_error}"
    return base_prompt + suffix + detail


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Best-effort extraction of a JSON object from LLM output."""
    if not text or not str(text).strip():
        return None

    cleaned = str(text).strip()

    fence = re.match(
        r"^```(?:json)?\s*(?P<body>.*?)\s*```\s*$",
        cleaned,
        re.DOTALL | re.IGNORECASE,
    )
    if fence:
        cleaned = fence.group("body").strip()

    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        snippet = cleaned[start : end + 1]
        try:
            parsed = json.loads(snippet)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None


def parse_llm_json_object(text: str, *, context: str = "LLM response") -> dict[str, Any]:
    """Parse LLM output as a JSON object or raise a descriptive error."""
    if not text or not str(text).strip():
        raise LLMEmptyResponseError(f"{context}: model returned empty content")

    parsed = extract_json_object(text)
    if parsed is None:
        preview = str(text).strip().replace("\n", "\\n")[:240]
        hint = " (likely truncated)" if is_likely_truncated_json(text) else ""
        raise ValueError(
            f"Failed to parse {context} as JSON object{hint}. Preview: {preview!r}"
        )
    return parsed


def warn_if_model_alias_normalized(provider: str, requested: str, effective: str) -> None:
    """Log once when a provider model alias is mapped to a supported id."""
    if requested != effective:
        print(
            f"[LLM] Mapped {provider} model {requested!r} -> {effective!r}",
            file=sys.stderr,
        )
