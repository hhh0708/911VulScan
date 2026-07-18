"""Tests for the central model configuration (utilities.model_registry).

Covers logical role resolution, env overrides, provider billing defaults, the
configurable pricing table, and the provider-aware billing-tier mapping that
flows through ``llm_pricing``.
"""

from __future__ import annotations

import pytest

from utilities.model_registry import (
    ModelRole,
    model_for,
    pricing_table,
    provider_currency,
    provider_default_model,
)


# --- Logical roles -----------------------------------------------------------

def test_model_for_defaults(monkeypatch):
    for var in ("VULSCAN_MODEL_PRIMARY", "VULSCAN_MODEL_SECONDARY", "VULSCAN_MODEL_PREMIUM"):
        monkeypatch.delenv(var, raising=False)
    assert model_for(ModelRole.PRIMARY) == "claude-opus-4-6"
    assert model_for(ModelRole.SECONDARY) == "claude-sonnet-4-6"
    assert model_for(ModelRole.PREMIUM) == "claude-opus-4-20250514"


def test_model_for_accepts_string_role(monkeypatch):
    monkeypatch.delenv("VULSCAN_MODEL_PRIMARY", raising=False)
    assert model_for("primary") == model_for(ModelRole.PRIMARY)


def test_model_for_honors_env_override(monkeypatch):
    monkeypatch.setenv("VULSCAN_MODEL_PRIMARY", "claude-opus-9")
    monkeypatch.setenv("VULSCAN_MODEL_SECONDARY", "my-cheap-model")
    assert model_for(ModelRole.PRIMARY) == "claude-opus-9"
    assert model_for(ModelRole.SECONDARY) == "my-cheap-model"


def test_model_for_blank_override_falls_back(monkeypatch):
    monkeypatch.setenv("VULSCAN_MODEL_PRIMARY", "   ")
    assert model_for(ModelRole.PRIMARY) == "claude-opus-4-6"


def test_model_for_rejects_unknown_role():
    with pytest.raises(ValueError):
        model_for("does-not-exist")


# --- Provider billing config -------------------------------------------------

def test_provider_currency():
    assert provider_currency("anthropic") == "USD"
    assert provider_currency("deepseek") == "CNY"
    assert provider_currency("qwen") == "CNY"
    assert provider_currency("openai_compat") == "USD"
    assert provider_currency("something-new") == "USD"


def test_provider_default_model(monkeypatch):
    monkeypatch.delenv("VULSCAN_MODEL_PRIMARY", raising=False)
    assert provider_default_model("anthropic") == "claude-opus-4-6"
    assert provider_default_model("deepseek") == "deepseek-chat"
    assert provider_default_model("qwen") == "qwen-plus"
    assert provider_default_model("openai_compat") == "gpt-4o"
    # Unknown providers fall back to the PRIMARY role model.
    assert provider_default_model("mystery") == "claude-opus-4-6"


def test_provider_default_model_follows_primary_override(monkeypatch):
    monkeypatch.setenv("VULSCAN_MODEL_PRIMARY", "claude-opus-9")
    assert provider_default_model("anthropic") == "claude-opus-9"


# --- Pricing table -----------------------------------------------------------

def test_pricing_table_has_core_rows(monkeypatch):
    monkeypatch.delenv("VULSCAN_MODEL_PRICING", raising=False)
    table = pricing_table()
    assert table["claude-opus-4-20250514"]["input"] == 15.00
    assert table["claude-opus-4-20250514"]["output"] == 75.00
    assert table["default"]["currency"] == "USD"
    # deepseek-v4-pro is the flagship and has its own (more expensive) row.
    assert table["deepseek-v4-pro"]["input"] == 3.00
    assert table["deepseek-v4-pro"]["output"] == 6.00
    # Pure aliases are intentionally NOT duplicated in the table.
    assert "qwen3-max" not in table


def test_pricing_table_env_override_merges(monkeypatch):
    monkeypatch.setenv(
        "VULSCAN_MODEL_PRICING",
        '{"claude-opus-4-6": {"input": 99, "output": 88, "currency": "USD"}}',
    )
    table = pricing_table()
    assert table["claude-opus-4-6"]["input"] == 99.0
    assert table["claude-opus-4-6"]["output"] == 88.0
    # Untouched rows keep their defaults.
    assert table["claude-sonnet-4-6"]["input"] == 3.00


def test_pricing_table_ignores_invalid_override(monkeypatch):
    monkeypatch.setenv("VULSCAN_MODEL_PRICING", "{not valid json")
    table = pricing_table()
    # Falls back to the default (opus list price).
    assert table["claude-opus-4-6"]["input"] == 15.00


def test_pricing_table_ignores_malformed_rows(monkeypatch):
    # Missing "output" -> row dropped; valid row kept.
    monkeypatch.setenv(
        "VULSCAN_MODEL_PRICING",
        '{"bad": {"input": 1}, "good-model": {"input": 1, "output": 2, "currency": "USD"}}',
    )
    table = pricing_table()
    assert "bad" not in table
    assert table["good-model"]["output"] == 2.0


# --- Integration with llm_pricing (provider-aware billing tier) --------------

def test_calculate_cost_known_anthropic_model(monkeypatch):
    monkeypatch.delenv("VULSCAN_MODEL_PRICING", raising=False)
    from utilities.llm_pricing import calculate_cost

    amount, currency = calculate_cost("claude-opus-4-20250514", 1_000_000, 1_000_000)
    assert currency == "USD"
    assert amount == 90.0


def test_calculate_cost_honors_pricing_override(monkeypatch):
    monkeypatch.setenv(
        "VULSCAN_MODEL_PRICING",
        '{"claude-opus-4-6": {"input": 30, "output": 30, "currency": "USD"}}',
    )
    from utilities.llm_pricing import calculate_cost

    amount, currency = calculate_cost("claude-opus-4-6", 1_000_000, 1_000_000)
    assert currency == "USD"
    assert amount == 60.0


def test_deepseek_alias_resolves_to_canonical_price(monkeypatch):
    # deepseek-v3 is a pure alias (no own row): it must resolve to deepseek-chat.
    monkeypatch.setenv("VULSCAN_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("VULSCAN_LLM_MODEL", "deepseek-v3")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.delenv("VULSCAN_MODEL_PRICING", raising=False)
    from utilities.llm_pricing import calculate_cost, get_model_pricing

    pricing = get_model_pricing("deepseek-v3")
    assert pricing["currency"] == "CNY"
    assert pricing["input"] == 1.00
    assert pricing["output"] == 2.00

    amount, currency = calculate_cost("deepseek-v3", 1_000_000, 1_000_000)
    assert currency == "CNY"
    assert amount == round(1.00 + 2.00, 6)
