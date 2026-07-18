"""
LLM Client

Wrapper for LLM API calls with built-in token tracking and cost calculation.

Default provider is Anthropic Claude (unchanged when ANTHROPIC_API_KEY is set).
Alternate OpenAI-compatible providers (DeepSeek, Qwen, etc.) are selected via
``VULSCAN_LLM_PROVIDER`` — see ``utilities.llm_config``.

Classes:
    TokenTracker: Tracks token usage and costs across multiple LLM calls
    AnthropicClient: LLM client with automatic token tracking (name kept for compat)

Usage:
    from utilities.llm_client import AnthropicClient, get_global_tracker
    from utilities.model_registry import ModelRole, model_for

    client = AnthropicClient(model=model_for(ModelRole.PRIMARY))
    response = client.analyze_sync("Analyze this code...")

    tracker = get_global_tracker()
    print(f"Total cost: {format_cost(tracker.total_cost_usd, tracker.cost_currency)}")
"""

import json
import os
import threading
from typing import Optional

import anthropic

from .safe_dotenv import load_scan_safe_dotenv

from .llm_backends import create_backend, get_shared_backend
from .llm_config import resolve_llm_config, resolve_model
from .llm_errors import LLMRateLimitError, LLMEmptyResponseError
from .llm_types import TextBlock
from .llm_json_utils import (
    DEFAULT_JSON_RETRIES,
    build_json_retry_prompt,
    combine_system_prompt,
    parse_llm_json_object,
)
from .rate_limiter import get_rate_limiter

from .llm_pricing import MODEL_PRICING, calculate_cost, format_cost, get_active_currency, resolve_display_currency
from .model_registry import ModelRole, model_for


class TokenTracker:
    """
    Tracks token usage and costs across LLM calls.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._thread_local = threading.local()
        self.reset()

    def reset(self):
        """Reset all counters."""
        with self._lock:
            self.calls = []
            self.total_input_tokens = 0
            self.total_output_tokens = 0
            self.total_cost_usd = 0.0
            self.cost_currency = get_active_currency()

    @property
    def total_tokens(self) -> int:
        """Total tokens (input + output)."""
        return self.total_input_tokens + self.total_output_tokens

    def record_call(self, model: str, input_tokens: int, output_tokens: int) -> dict:
        """
        Record a single LLM call.

        Args:
            model: Model identifier
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens

        Returns:
            Dict with call details including cost
        """
        billed_model = _billed_model_id(model)
        total_cost, currency = calculate_cost(billed_model, input_tokens, output_tokens)

        call_record = {
            "model": billed_model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": total_cost,
            "currency": currency,
        }

        with self._lock:
            self.calls.append(call_record)
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_usd += total_cost
            self.cost_currency = currency

        tl = self._thread_local
        if hasattr(tl, "unit_input"):
            tl.unit_input += input_tokens
            tl.unit_output += output_tokens
            tl.unit_cost += total_cost

        return call_record

    def add_prior_usage(
        self,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        currency: str | None = None,
    ):
        """Inject usage from a prior run (e.g. restored checkpoints)."""
        with self._lock:
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_usd += cost_usd
            if currency:
                self.cost_currency = currency
            else:
                self.cost_currency = resolve_display_currency(self.cost_currency)

    def start_unit_tracking(self):
        """Start tracking usage for the current unit on this thread."""
        tl = self._thread_local
        tl.unit_input = 0
        tl.unit_output = 0
        tl.unit_cost = 0.0

    def get_unit_usage(self) -> dict:
        """Return usage accumulated since ``start_unit_tracking()`` on this thread."""
        tl = self._thread_local
        return {
            "input_tokens": getattr(tl, "unit_input", 0),
            "output_tokens": getattr(tl, "unit_output", 0),
            "cost_usd": round(getattr(tl, "unit_cost", 0.0), 6),
        }

    def get_summary(self) -> dict:
        """Get summary of all tracked calls."""
        with self._lock:
            return {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
                "cost_currency": getattr(self, "cost_currency", get_active_currency()),
                "calls": list(self.calls),
            }

    def get_totals(self) -> dict:
        """Get just the totals (without per-call breakdown)."""
        with self._lock:
            return {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
                "cost_currency": getattr(self, "cost_currency", get_active_currency()),
            }


def _billed_model_id(model: str) -> str:
    """Map a (possibly logical) model id to the id actually billed for the
    active provider, so recorded cost and currency match the real invoice.

    Internal code passes Claude role ids (e.g. ``claude-opus-4-6``); for a
    non-Anthropic provider the real call goes to that provider's model, so it
    must be billed there too. Falls back to the given id when the provider can't
    be resolved (e.g. no API key in unit tests). Billing must never crash a run.
    """
    try:
        return resolve_model(model)
    except Exception:  # noqa: BLE001 — advisory billing; never break the pipeline
        return model


_global_tracker = TokenTracker()


def get_global_tracker() -> TokenTracker:
    """Get the global token tracker instance."""
    return _global_tracker


def reset_global_tracker():
    """Reset the global token tracker."""
    _global_tracker.reset()


def _extract_text(response) -> str:
    for block in response.content:
        if isinstance(block, TextBlock):
            return block.text
        if getattr(block, "type", None) == "text":
            return getattr(block, "text", "")
    if response.content:
        first = response.content[0]
        if hasattr(first, "text"):
            return first.text
    return ""


def _handle_rate_limit(exc: Exception) -> None:
    retry_after = 0.0
    response = getattr(exc, "response", None)
    if response is not None:
        retry_after = float(getattr(response, "headers", {}).get("retry-after", 0) or 0)
    get_rate_limiter().report_rate_limit(retry_after)


class AnthropicClient:
    """
    Client for LLM API calls.

    Uses Claude by default. When ``VULSCAN_LLM_PROVIDER`` selects an alternate
    provider, the same interface is preserved via the backend adapter layer.
    """

    def __init__(self, model: str | None = None, tracker: TokenTracker = None):
        load_scan_safe_dotenv()

        self._config = resolve_llm_config()
        self._backend = create_backend(self._config)
        self.model = model or model_for(ModelRole.PREMIUM)
        self.tracker = tracker or _global_tracker
        self.last_call = None

        if self._config.provider == "anthropic":
            if not self._config.api_key:
                raise ValueError(
                    "No API key found for Anthropic. Set ANTHROPIC_API_KEY "
                    "or save a key with `vulscan set-api-key`."
                )
            # Preserve the original attribute for backward compatibility.
            self.client = self._backend.raw_client
        else:
            self.client = self._backend.client

    @property
    def messages(self):
        """Anthropic-shaped messages API (also used by stage1_consistency)."""
        return self._backend.messages

    async def analyze(self, prompt: str, max_tokens: int = 8192) -> str:
        """Send a prompt and get a response."""
        rate_limiter = get_rate_limiter()
        rate_limiter.wait_if_needed()

        try:
            message = self._create_message(
                model=self.model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
        except (anthropic.RateLimitError, LLMRateLimitError) as exc:
            _handle_rate_limit(exc)
            raise

        self.last_call = self.tracker.record_call(
            model=self.model,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
        )

        return _extract_text(message)

    def analyze_sync(
        self,
        prompt: str,
        max_tokens: int = 8192,
        model: str = None,
        system: str = None,
        json_mode: bool = False,
    ) -> str:
        """Synchronous version of analyze."""
        used_model = model or self.model

        kwargs = {
            "model": used_model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        if json_mode and self._config.provider != "anthropic":
            kwargs["json_mode"] = True

        rate_limiter = get_rate_limiter()
        rate_limiter.wait_if_needed()

        try:
            message = self._create_message(**kwargs)
        except (anthropic.RateLimitError, LLMRateLimitError) as exc:
            _handle_rate_limit(exc)
            raise

        billed_model = resolve_model(used_model, self._config)
        self.last_call = self.tracker.record_call(
            model=billed_model,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
        )

        text = _extract_text(message)
        if not text.strip():
            raise LLMEmptyResponseError(
                f"LLM returned empty content (provider={self._config.provider}, "
                f"model={billed_model})"
            )
        return text

    def analyze_json_sync(
        self,
        prompt: str,
        max_tokens: int = 8192,
        model: str = None,
        system: str = None,
        *,
        context: str = "LLM response",
        retries: int = DEFAULT_JSON_RETRIES,
    ) -> dict:
        """Request and parse a JSON object with constraint-aware retries.

        All providers receive JSON-only instructions in the system prompt.
        OpenAI-compatible providers additionally use ``response_format=json_object``.
        Retries append truncation- or parse-specific guidance to the user prompt.
        """
        use_json_mode = self._config.provider != "anthropic"
        effective_system = combine_system_prompt(system)

        last_error: Exception | None = None
        last_text: str | None = None
        for attempt in range(retries + 1):
            attempt_prompt = build_json_retry_prompt(
                prompt, attempt, last_text, last_error
            )
            try:
                text = self.analyze_sync(
                    attempt_prompt,
                    max_tokens=max_tokens,
                    model=model,
                    system=effective_system,
                    json_mode=use_json_mode,
                )
                last_text = text
                return parse_llm_json_object(text, context=context)
            except (LLMEmptyResponseError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt >= retries:
                    break
        raise last_error  # type: ignore[misc]

    def _create_message(self, **kwargs):
        """Create a message using the Anthropic SDK or the adapter backend."""
        json_mode = kwargs.pop("json_mode", False)
        config = getattr(self, "_config", None)
        if config is None or config.provider == "anthropic":
            return self.client.messages.create(**kwargs)
        kwargs["json_mode"] = json_mode
        return self._backend.messages.create(**kwargs)

    def get_last_call(self) -> Optional[dict]:
        """Get details of the last API call."""
        return self.last_call

    def get_session_totals(self) -> dict:
        """Get cumulative totals for this session."""
        return self.tracker.get_totals()

    def get_session_summary(self) -> dict:
        """Get full summary including per-call breakdown."""
        return self.tracker.get_summary()

    def get_usage(self, message) -> dict:
        """Extract token usage from a message response."""
        return {
            "input_tokens": message.usage.input_tokens,
            "output_tokens": message.usage.output_tokens,
        }


def get_shared_llm_client():
    """Return a shared backend for tool-use loops (verifier, agent, etc.)."""
    return get_shared_backend()
