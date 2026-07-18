"""Factory for shared LLM backends."""

from __future__ import annotations

import threading
from typing import Union

from utilities.llm_config import LLMProviderConfig, resolve_llm_config
from utilities.llm_backends.anthropic_backend import AnthropicBackend
from utilities.llm_backends.openai_compat_backend import OpenAICompatBackend

LLMBackend = Union[AnthropicBackend, OpenAICompatBackend]

_backend_lock = threading.Lock()
_shared_backend: LLMBackend | None = None


def create_backend(config: LLMProviderConfig | None = None) -> LLMBackend:
    """Create a provider backend from environment or explicit config."""
    cfg = config or resolve_llm_config()
    if cfg.provider == "anthropic":
        return AnthropicBackend(cfg)
    return OpenAICompatBackend(cfg)


def get_shared_backend() -> LLMBackend:
    """Return a process-wide shared backend (thread-safe singleton)."""
    global _shared_backend
    if _shared_backend is not None:
        return _shared_backend
    with _backend_lock:
        if _shared_backend is None:
            _shared_backend = create_backend()
        return _shared_backend


def reset_shared_backend() -> None:
    """Reset the shared backend (mainly for tests)."""
    global _shared_backend
    with _backend_lock:
        _shared_backend = None
