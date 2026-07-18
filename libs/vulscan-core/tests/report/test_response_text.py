"""Tests for LLM response text extraction in report generator."""

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

_CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    _stub.RateLimitError = type("RateLimitError", (Exception,), {})
    _stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _stub

from utilities.llm_types import MessageResponse, TextBlock, LLMUsage
from report import generator


def test_extract_response_text_joins_blocks():
    resp = MessageResponse(
        content=[TextBlock(text="hello"), TextBlock(text="world")],
        stop_reason="end_turn",
        usage=LLMUsage(),
    )
    assert generator._extract_response_text(resp) == "hello\nworld"


def test_extract_response_text_raises_when_empty():
    resp = MessageResponse(content=[], stop_reason="end_turn", usage=LLMUsage())
    try:
        generator._extract_response_text(resp)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "no text content" in str(exc)
