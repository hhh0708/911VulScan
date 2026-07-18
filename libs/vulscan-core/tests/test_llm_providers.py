"""Tests for multi-provider LLM configuration and adapters."""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

from utilities.llm_backends.openai_compat_backend import OpenAICompatBackend
from utilities.llm_config import (
    LLMProviderConfig,
    format_active_llm_label,
    resolve_llm_config,
    resolve_model,
)
from utilities.llm_types import ToolUseBlock


def test_default_provider_is_anthropic(monkeypatch):
    monkeypatch.delenv("VULSCAN_LLM_PROVIDER", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = resolve_llm_config()
    assert cfg.provider == "anthropic"
    assert cfg.api_key == "sk-ant-test"


def test_deepseek_provider_uses_openai_compat(monkeypatch):
    monkeypatch.setenv("VULSCAN_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-test")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cfg = resolve_llm_config()
    assert cfg.provider == "deepseek"
    assert cfg.base_url == "https://api.deepseek.com"
    assert cfg.default_model == "deepseek-chat"
    assert cfg.api_key == "sk-deepseek-test"


def test_deepseek_falls_back_to_anthropic_key(monkeypatch):
    monkeypatch.setenv("VULSCAN_LLM_PROVIDER", "deepseek")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-cli")
    cfg = resolve_llm_config()
    assert cfg.api_key == "sk-from-cli"


def test_resolve_model_keeps_claude_when_anthropic(monkeypatch):
    monkeypatch.setenv("VULSCAN_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = resolve_llm_config()
    assert resolve_model("claude-opus-4-6", cfg) == "claude-opus-4-6"


def test_resolve_model_maps_to_provider_default(monkeypatch):
    monkeypatch.setenv("VULSCAN_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-test")
    cfg = resolve_llm_config()
    assert resolve_model("claude-opus-4-6", cfg) == "deepseek-chat"


def test_resolve_model_respects_explicit_env_override(monkeypatch):
    monkeypatch.setenv("VULSCAN_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("VULSCAN_LLM_MODEL", "deepseek-v4-pro")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-test")
    cfg = resolve_llm_config()
    assert cfg.default_model == "deepseek-v4-pro"
    assert resolve_model("claude-opus-4-6", cfg) == "deepseek-v4-pro"


from utilities.llm_pricing import format_cost, calculate_cost, get_model_pricing, resolve_display_currency, get_active_currency


def test_deepseek_v4_pro_pricing_uses_cny(monkeypatch):
    monkeypatch.setenv("VULSCAN_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("VULSCAN_LLM_MODEL", "deepseek-v4-pro")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")

    from utilities.llm_pricing import calculate_cost, get_model_pricing

    # deepseek-v4-pro is the flagship — its own pricing row, not the chat tier.
    pricing = get_model_pricing("deepseek-v4-pro")
    assert pricing["currency"] == "CNY"
    assert pricing["input"] == 3.00
    assert pricing["output"] == 6.00

    amount, currency = calculate_cost("deepseek-v4-pro", 1_000_000, 1_000_000)
    assert currency == "CNY"
    assert amount == round(3.00 + 6.00, 6)


def test_resolve_display_currency_prefers_active_over_stale_usd(monkeypatch):
    monkeypatch.setenv("VULSCAN_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    assert resolve_display_currency("USD") == "CNY"
    assert resolve_display_currency("CNY") == "CNY"


def test_qwen_provider_label_and_pricing(monkeypatch):
    monkeypatch.setenv("VULSCAN_LLM_PROVIDER", "qwen")
    monkeypatch.setenv("VULSCAN_LLM_MODEL", "qwen3-max")
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-qwen-test")
    cfg = resolve_llm_config()
    assert cfg.provider == "qwen"
    assert cfg.default_model == "qwen3-max"
    assert format_active_llm_label("claude-opus-4-6", cfg) == "qwen/qwen3-max"
    assert resolve_model("claude-opus-4-6", cfg) == "qwen3-max"

    pricing = get_model_pricing("qwen3-max")
    assert pricing["currency"] == "CNY"
    amount, currency = calculate_cost("qwen3-max", 1_000_000, 0)
    assert currency == "CNY"
    assert amount == round(2.40, 6)

    assert format_cost(2.5) == "¥2.50"
    assert resolve_display_currency("USD") == "CNY"


def test_openai_compat_uses_usd(monkeypatch):
    monkeypatch.setenv("VULSCAN_LLM_PROVIDER", "openai_compat")
    monkeypatch.setenv("VULSCAN_LLM_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    cfg = resolve_llm_config()
    assert format_active_llm_label("claude-opus-4-6", cfg) == "openai_compat/gpt-4o"
    assert get_active_currency() == "USD"
    assert format_cost(1.0) == "$1.00"


def test_format_cost_cny():
    assert format_cost(1.2345, "CNY") == "¥1.23"
    assert format_cost(0.0012, "CNY") == "¥0.0012"


def test_format_cost_usd():
    assert format_cost(1.2345, "USD") == "$1.23"
    assert format_cost(0.0012, "USD") == "$0.0012"


def test_openai_backend_converts_tool_response():
    cfg = LLMProviderConfig(
        provider="deepseek",
        api_key="sk-test",
        base_url="https://api.deepseek.com",
        default_model="deepseek-chat",
    )
    backend = OpenAICompatBackend(cfg)

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].finish_reason = "tool_calls"
    mock_response.choices[0].message.content = None
    tool_call = MagicMock()
    tool_call.id = "call_123"
    tool_call.function.name = "search_usages"
    tool_call.function.arguments = '{"function_name": "ProcessImage"}'
    mock_response.choices[0].message.tool_calls = [tool_call]
    mock_response.usage.prompt_tokens = 10
    mock_response.usage.completion_tokens = 5

    backend.raw_client = MagicMock()
    backend.raw_client.chat.completions.create.return_value = mock_response

    response = backend.create_message(
        model="claude-opus-4-6",
        max_tokens=100,
        system="test",
        tools=[
            {
                "name": "search_usages",
                "description": "find usages",
                "input_schema": {
                    "type": "object",
                    "properties": {"function_name": {"type": "string"}},
                    "required": ["function_name"],
                },
            }
        ],
        messages=[{"role": "user", "content": "hello"}],
    )

    assert response.stop_reason == "tool_use"
    assert len(response.content) == 1
    block = response.content[0]
    assert isinstance(block, ToolUseBlock)
    assert block.name == "search_usages"
    assert block.input["function_name"] == "ProcessImage"
