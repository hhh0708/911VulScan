"""Anthropic backend — preserves existing Claude API behaviour."""

from __future__ import annotations

from typing import Any

import anthropic

from utilities.llm_config import LLMProviderConfig, resolve_model
from utilities.llm_errors import LLMRateLimitError
from utilities.llm_types import MessageResponse, normalize_message_response


class AnthropicMessagesAPI:
    def __init__(self, backend: "AnthropicBackend"):
        self._backend = backend

    def create(self, **kwargs: Any) -> MessageResponse:
        return self._backend.create_message(**kwargs)


class AnthropicBackend:
    provider = "anthropic"

    def __init__(self, config: LLMProviderConfig):
        self.config = config
        kwargs: dict[str, Any] = {"api_key": config.api_key, "max_retries": 5}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self.raw_client = anthropic.Anthropic(**kwargs)
        self.messages = AnthropicMessagesAPI(self)

    @property
    def client(self):
        """Backward-compatible alias used by older call sites."""
        return self.raw_client

    def create_message(self, **kwargs: Any) -> MessageResponse:
        model = resolve_model(kwargs.pop("model"), self.config)
        try:
            response = self.raw_client.messages.create(model=model, **kwargs)
        except anthropic.RateLimitError as exc:
            retry_after = float(exc.response.headers.get("retry-after", 0))
            raise LLMRateLimitError(str(exc), retry_after=retry_after, response=exc.response) from exc
        return normalize_message_response(response)
