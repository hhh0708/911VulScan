"""LLM cost calculation and currency formatting.

Pricing data and provider billing config are owned by
``utilities.model_registry`` (the single source of truth). This module layers
the resolution, calculation, and display helpers on top of it.
"""

from __future__ import annotations

from typing import Any

from utilities.llm_config import normalize_provider_model, resolve_llm_config
from utilities.model_registry import (
    pricing_table,
    provider_currency,
    provider_default_model,
)

# Back-compat re-export: some callers/tests import ``MODEL_PRICING`` from here.
# It reflects the default table; runtime overrides are read via ``pricing_table()``.
MODEL_PRICING: dict[str, dict[str, Any]] = pricing_table()

_CURRENCY_SYMBOLS = {
    "USD": "$",
    "CNY": "¥",
    "EUR": "€",
}


def get_active_currency() -> str:
    """Return the billing currency for the active LLM provider."""
    try:
        provider = resolve_llm_config().provider
    except ValueError:
        return "USD"
    return provider_currency(provider)


def resolve_pricing_model(model: str) -> str:
    """Map a logical or API model id to a billing row in the pricing table.

    Aliases (e.g. ``deepseek-v4-pro``, ``qwen3-max``) resolve to their canonical
    priced row, so each price is defined exactly once.
    """
    table = pricing_table()
    if model in table:
        return model

    try:
        cfg = resolve_llm_config()
    except ValueError:
        return "default"

    if cfg.provider == "anthropic":
        return "default"

    normalized = normalize_provider_model(cfg.provider, model)
    if normalized in table:
        return normalized

    env_model = normalize_provider_model(cfg.provider, cfg.default_model)
    if env_model in table:
        return env_model

    provider_default = provider_default_model(cfg.provider)
    if provider_default in table:
        return provider_default

    return "default"


def get_model_pricing(model: str) -> dict[str, Any]:
    """Return input/output rates and currency for a model."""
    table = pricing_table()
    resolved = resolve_pricing_model(model)
    pricing = dict(table.get(resolved, table["default"]))
    if resolved == "default":
        try:
            provider = resolve_llm_config().provider
            if provider != "anthropic":
                pricing["currency"] = provider_currency(provider)
        except ValueError:
            pass
    elif "currency" not in pricing:
        pricing["currency"] = get_active_currency()
    return pricing


def calculate_cost(model: str, input_tokens: int, output_tokens: int) -> tuple[float, str]:
    """Calculate call cost and return ``(amount, currency)``."""
    pricing = get_model_pricing(model)
    amount = (
        (input_tokens / 1_000_000) * pricing["input"]
        + (output_tokens / 1_000_000) * pricing["output"]
    )
    return round(amount, 6), pricing["currency"]


def resolve_display_currency(explicit: str | None = None) -> str:
    """Currency for logs and reports.

    Uses *explicit* when set, unless it is stale ``USD`` while the active
    provider bills in another currency (e.g. DeepSeek → CNY).
    """
    active = get_active_currency()
    if explicit and not (explicit == "USD" and active != "USD"):
        return explicit
    return active


def format_cost(amount: float, currency: str | None = None, *, precision: int | None = None) -> str:
    """Format a cost amount with the correct currency symbol."""
    currency = resolve_display_currency(currency)
    symbol = _CURRENCY_SYMBOLS.get(currency)

    if precision is None:
        if currency == "CNY":
            precision = 4 if amount < 0.01 else 2 if amount < 10 else 2
        else:
            precision = 4 if amount < 0.01 else 2 if amount < 10 else 2

    if symbol:
        if amount >= 10 and precision == 2:
            return f"{symbol}{amount:,.2f}"
        return f"{symbol}{amount:.{precision}f}"

    return f"{amount:.{precision}f} {currency}"
