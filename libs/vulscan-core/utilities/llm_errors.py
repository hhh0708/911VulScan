"""Shared LLM error types used across provider backends."""

from __future__ import annotations


class LLMRateLimitError(Exception):
    """Raised when an LLM provider returns HTTP 429."""

    def __init__(self, message: str, *, retry_after: float = 0.0, response=None):
        super().__init__(message)
        self.retry_after = retry_after
        self.response = response


class LLMEmptyResponseError(Exception):
    """Raised when an LLM provider returns no usable text content."""
