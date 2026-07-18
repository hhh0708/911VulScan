"""Tests for shared LLM JSON helpers."""

import json

import pytest

from utilities.llm_errors import LLMEmptyResponseError
from utilities.llm_json_utils import (
    JSON_ONLY_SYSTEM,
    JSON_TRUNCATED_RETRY_SUFFIX,
    build_json_retry_prompt,
    combine_system_prompt,
    extract_json_object,
    is_likely_truncated_json,
    parse_llm_json_object,
)


def test_extract_json_object_from_markdown_fence():
    text = '```json\n{"signals": []}\n```'
    assert extract_json_object(text) == {"signals": []}


def test_extract_json_object_from_embedded_json():
    text = 'Here is the result:\n{"application_type": "library", "purpose": "x"}'
    parsed = extract_json_object(text)
    assert parsed["application_type"] == "library"


def test_parse_llm_json_object_rejects_empty():
    with pytest.raises(LLMEmptyResponseError):
        parse_llm_json_object("", context="test")


def test_is_likely_truncated_json_unbalanced_braces():
    truncated = '{"signals": [{"unit_id": "a", "kind": "entry_point"'
    assert is_likely_truncated_json(truncated) is True


def test_is_likely_truncated_json_complete_object():
    complete = json.dumps({"signals": []})
    assert is_likely_truncated_json(complete) is False


def test_combine_system_prompt_appends_json_constraint():
    combined = combine_system_prompt("You are a security analyst.")
    assert "You are a security analyst." in combined
    assert JSON_ONLY_SYSTEM in combined


def test_combine_system_prompt_idempotent():
    base = combine_system_prompt("Custom system.")
    again = combine_system_prompt(base)
    assert again.count(JSON_ONLY_SYSTEM) == 1


def test_build_json_retry_prompt_uses_truncation_suffix():
    truncated = '{"signals": ['
    retry = build_json_retry_prompt("base", 1, truncated, ValueError("parse"))
    assert JSON_TRUNCATED_RETRY_SUFFIX in retry
    assert "base" in retry


def test_build_json_retry_prompt_first_attempt_unchanged():
    assert build_json_retry_prompt("base", 0, None, None) == "base"
