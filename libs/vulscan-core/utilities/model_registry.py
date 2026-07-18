"""Central model configuration for 911VulScan.

This is the single source of truth for everything model-related so that ids and
prices are defined **once** instead of being copy-pasted across ~20 files:

* **Logical model roles** — pipeline code asks for a *role* (PRIMARY /
  SECONDARY / PREMIUM) via :func:`model_for`, not a hardcoded Claude model id.
* **Provider billing defaults** — the model a non-Anthropic provider bills
  under, plus that provider's billing currency.
* **Pricing** — per-model input/output rates and currency.

Everything is overridable via environment variables, so model ids and prices
can change without editing code::

    VULSCAN_MODEL_PRIMARY     override the PRIMARY role model id
    VULSCAN_MODEL_SECONDARY   override the SECONDARY role model id
    VULSCAN_MODEL_PREMIUM     override the PREMIUM role model id
    VULSCAN_MODEL_PRICING     JSON object merged into the pricing table, e.g.
                              '{"claude-opus-4-6": {"input": 15, "output": 75,
                                "currency": "USD"}}'

Layering: this module imports nothing from ``llm_config`` / ``llm_pricing`` so
it stays a dependency-free leaf (both of those import *from* here).
"""

from __future__ import annotations

import json
import os
import sys
from enum import Enum
from typing import Any


class ModelRole(str, Enum):
    """The logical job a model is asked to do.

    Code selects a model by role; the concrete Claude model id for each role is
    defined once in :data:`_DEFAULT_ROLE_MODELS` and overridable per role via
    ``VULSCAN_MODEL_<ROLE>``.
    """

    # Deep reasoning: Stage 1 detection, Stage 2 verification, reachability.
    PRIMARY = "primary"
    # Cost-effective helper: context enhancement/correction, reporting, dynamic tests.
    SECONDARY = "secondary"
    # Highest-capability opus, opt-in (e.g. experiment ``--model opus``).
    PREMIUM = "premium"


_DEFAULT_ROLE_MODELS: dict[ModelRole, str] = {
    ModelRole.PRIMARY: "claude-opus-4-6",
    ModelRole.SECONDARY: "claude-sonnet-4-6",
    ModelRole.PREMIUM: "claude-opus-4-20250514",
}


def model_for(role: ModelRole | str) -> str:
    """Return the Claude model id for a logical *role*.

    Honors ``VULSCAN_MODEL_<ROLE>`` overrides (e.g. ``VULSCAN_MODEL_PRIMARY``).
    """
    role = ModelRole(role)
    override = os.getenv(f"VULSCAN_MODEL_{role.name}", "").strip()
    return override or _DEFAULT_ROLE_MODELS[role]


# --- Provider billing config -------------------------------------------------

# Billing currency each provider invoices in.
PROVIDER_CURRENCY: dict[str, str] = {
    "anthropic": "USD",
    "deepseek": "CNY",
    "qwen": "CNY",
    "openai_compat": "USD",
}

# Model id a non-Anthropic provider bills under when internal code passes a
# generic (Claude role) id. Anthropic is resolved dynamically to the PRIMARY
# role so there is exactly one place that names the default model.
_PROVIDER_DEFAULT_MODEL: dict[str, str] = {
    "deepseek": "deepseek-chat",
    "qwen": "qwen-plus",
    "openai_compat": "gpt-4o",
}


def provider_currency(provider: str) -> str:
    """Billing currency for *provider* (defaults to USD)."""
    return PROVIDER_CURRENCY.get(provider, "USD")


def provider_default_model(provider: str) -> str:
    """Model id *provider* bills under for generic, role-based calls."""
    if provider == "anthropic":
        return model_for(ModelRole.PRIMARY)
    return _PROVIDER_DEFAULT_MODEL.get(provider, model_for(ModelRole.PRIMARY))


# --- Pricing -----------------------------------------------------------------

# Price per 1,000,000 tokens, expressed in the model's billing currency.
#
# Domestic-provider rates are the official list prices (DeepSeek api-docs,
# Aliyun Model Studio) for the *standard, cache-miss, non-thinking, base context
# tier* in China-mainland deployment. Real DeepSeek/Qwen pricing additionally
# varies by cache hit, context-length tier, thinking mode, and Batch discount —
# tune for your exact usage via the ``VULSCAN_MODEL_PRICING`` env override.
#
# NOTE: ids that are pure aliases (e.g. ``qwen3-max`` → ``qwen-max``,
# ``deepseek-v3`` → ``deepseek-chat``) are intentionally NOT duplicated here;
# they resolve to their canonical row via ``llm_pricing.resolve_pricing_model``
# so each price is defined in exactly one place.
_DEFAULT_MODEL_PRICING: dict[str, dict[str, Any]] = {
    # Anthropic (USD)
    "claude-opus-4-20250514": {"input": 15.00, "output": 75.00, "currency": "USD"},
    "claude-opus-4-6": {"input": 15.00, "output": 75.00, "currency": "USD"},
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00, "currency": "USD"},
    # DeepSeek (CNY, cache-miss). deepseek-chat/-reasoner are V4-Flash aliases.
    "deepseek-chat": {"input": 1.00, "output": 2.00, "currency": "CNY"},
    "deepseek-reasoner": {"input": 1.00, "output": 2.00, "currency": "CNY"},
    "deepseek-v4-pro": {"input": 3.00, "output": 6.00, "currency": "CNY"},
    # Qwen (CNY, base context tier, non-thinking)
    "qwen-plus": {"input": 0.80, "output": 2.00, "currency": "CNY"},
    "qwen-max": {"input": 2.40, "output": 9.60, "currency": "CNY"},
    "qwen-turbo": {"input": 0.30, "output": 0.60, "currency": "CNY"},
    "qwen-long": {"input": 0.50, "output": 2.00, "currency": "CNY"},
    # OpenAI-compatible (USD)
    "gpt-4o": {"input": 2.50, "output": 10.00, "currency": "USD"},
    # Fallback for unknown models.
    "default": {"input": 3.00, "output": 15.00, "currency": "USD"},
}


def _normalize_pricing_row(row: Any) -> dict[str, Any] | None:
    """Validate and coerce one override row; return ``None`` if malformed."""
    if not isinstance(row, dict) or "input" not in row or "output" not in row:
        return None
    try:
        return {
            "input": float(row["input"]),
            "output": float(row["output"]),
            "currency": str(row.get("currency", "USD")),
        }
    except (TypeError, ValueError):
        return None


def _load_pricing_overrides() -> dict[str, dict[str, Any]]:
    """Parse ``VULSCAN_MODEL_PRICING`` (JSON object) into pricing rows."""
    raw = os.getenv("VULSCAN_MODEL_PRICING", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError) as exc:
        print(
            f"[model_registry] Ignoring invalid VULSCAN_MODEL_PRICING: {exc}",
            file=sys.stderr,
        )
        return {}
    if not isinstance(data, dict):
        print(
            "[model_registry] VULSCAN_MODEL_PRICING must be a JSON object; ignoring",
            file=sys.stderr,
        )
        return {}
    cleaned: dict[str, dict[str, Any]] = {}
    for model, row in data.items():
        normalized = _normalize_pricing_row(row)
        if normalized is not None:
            cleaned[str(model)] = normalized
    return cleaned


def pricing_table() -> dict[str, dict[str, Any]]:
    """Return the merged pricing table (defaults + ``VULSCAN_MODEL_PRICING``).

    Resolved fresh on each call so environment overrides (and tests that set
    them via monkeypatch) take effect without re-importing the module.
    """
    table = {model: dict(row) for model, row in _DEFAULT_MODEL_PRICING.items()}
    table.update(_load_pricing_overrides())
    return table
