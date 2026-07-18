"""LLM provider configuration for 911VulScan.

Default behaviour is unchanged: when ``VULSCAN_LLM_PROVIDER`` is unset and
``ANTHROPIC_API_KEY`` is present, the Anthropic SDK is used exactly as before.

To use OpenAI-compatible providers (DeepSeek, Qwen, etc.) set::

    export VULSCAN_LLM_PROVIDER=deepseek   # or qwen, openai_compat
    export VULSCAN_LLM_API_KEY=sk-...      # optional; falls back to ANTHROPIC_API_KEY
    export VULSCAN_LLM_MODEL=deepseek-chat # optional model override

Environment variables
---------------------
VULSCAN_LLM_PROVIDER
    ``anthropic`` (default), ``deepseek``, ``qwen``, or ``openai_compat``.
VULSCAN_LLM_API_KEY
    API key for non-Anthropic providers. If unset, ``ANTHROPIC_API_KEY`` is
    reused so ``vulscan set-api-key`` continues to work.
VULSCAN_LLM_BASE_URL
    Override the provider base URL (required for ``openai_compat`` unless set).
VULSCAN_LLM_MODEL
    Override the model name for all non-Anthropic calls.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from utilities.model_registry import provider_default_model


@dataclass(frozen=True)
class LLMProviderConfig:
    provider: str
    api_key: str
    base_url: str | None
    default_model: str

    def __repr__(self) -> str:
        from utilities.credentials import mask_secret

        return (
            f"LLMProviderConfig(provider={self.provider!r}, "
            f"api_key={mask_secret(self.api_key)!r}, "
            f"base_url={self.base_url!r}, "
            f"default_model={self.default_model!r})"
        )


# Known unofficial / UI names mapped to API model ids.
_PROVIDER_MODEL_ALIASES: dict[str, dict[str, str]] = {
    "deepseek": {
        # deepseek-v4-pro is the distinct flagship model — it has its own
        # pricing row and must NOT be aliased to the cheaper chat/flash tier.
        "deepseek-v4-flash": "deepseek-chat",
        "deepseek-v4": "deepseek-chat",
        "deepseek-v3": "deepseek-chat",
        "deepseek-r1": "deepseek-reasoner",
    },
    "qwen": {
        "qwen-max": "qwen-max",
        "qwen-plus": "qwen-plus",
        "qwen-turbo": "qwen-turbo",
        "qwen-long": "qwen-long",
        "qwen3-max": "qwen-max",
        "qwen3-plus": "qwen-plus",
        "qwen3-turbo": "qwen-turbo",
        "qwen-2.5-72b-instruct": "qwen-max",
        "qwen2.5-72b-instruct": "qwen-max",
    },
    "openai_compat": {},
}


# Provider connection defaults. The default *model* is intentionally NOT stored
# here — it is owned by ``model_registry.provider_default_model`` so there is a
# single source of truth shared with pricing.
_PROVIDER_DEFAULTS: dict[str, dict[str, str]] = {
    "anthropic": {
        "api_key_env": "ANTHROPIC_API_KEY",
        "base_url": "",
    },
    "deepseek": {
        "api_key_env": "DEEPSEEK_API_KEY",
        "base_url": "https://api.deepseek.com",
    },
    "qwen": {
        "api_key_env": "DASHSCOPE_API_KEY",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    },
    "openai_compat": {
        "api_key_env": "OPENAI_API_KEY",
        "base_url": "",
    },
}


def _normalize_provider(raw: str | None) -> str:
    if not raw:
        return "anthropic"
    provider = raw.strip().lower()
    if provider not in _PROVIDER_DEFAULTS:
        supported = ", ".join(sorted(_PROVIDER_DEFAULTS))
        raise ValueError(
            f"Unknown VULSCAN_LLM_PROVIDER={raw!r}. Supported: {supported}"
        )
    return provider


def _resolve_api_key(provider: str) -> str:
    """Resolve API key via CredentialResolver (env or 0600 user config only)."""
    from utilities.credentials import CredentialError, CredentialResolver

    defaults = _PROVIDER_DEFAULTS[provider]
    preferred = defaults["api_key_env"]
    fallbacks = ["VULSCAN_LLM_API_KEY"]
    if provider != "anthropic":
        fallbacks.extend(["OPENAI_API_KEY", "ANTHROPIC_API_KEY"])
    else:
        # preferred already ANTHROPIC_API_KEY; still allow generic override.
        pass

    resolver = CredentialResolver()
    try:
        return resolver.resolve(
            preferred_env=preferred,
            fallback_envs=fallbacks,
            allow_config_file=True,
        ).value
    except CredentialError as exc:
        raise ValueError(str(exc)) from exc


def _validate_base_url(base_url: str | None) -> str | None:
    """Reject plaintext base URLs: the API key rides in the Authorization
    header, so a non-HTTPS endpoint would expose it on the wire.

    ``http://`` is allowed only for loopback hosts (local proxies/dev stacks).
    """
    if not base_url:
        return None
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if scheme == "https":
        return base_url
    if scheme == "http" and host in {"localhost", "127.0.0.1", "::1"}:
        return base_url
    raise ValueError(
        f"Insecure VULSCAN_LLM_BASE_URL={base_url!r}: base URL must use "
        "https:// because the API key is sent in the Authorization header; "
        "http:// is only allowed for localhost/127.0.0.1/::1."
    )


def resolve_llm_config() -> LLMProviderConfig:
    """Resolve the active LLM provider from environment variables."""
    provider = _normalize_provider(os.getenv("VULSCAN_LLM_PROVIDER"))
    defaults = _PROVIDER_DEFAULTS[provider]

    base_url = _validate_base_url(
        os.getenv("VULSCAN_LLM_BASE_URL", defaults["base_url"]).strip() or None
    )
    if provider == "openai_compat" and not base_url:
        raise ValueError(
            "VULSCAN_LLM_BASE_URL is required when VULSCAN_LLM_PROVIDER=openai_compat"
        )

    default_model = os.getenv(
        "VULSCAN_LLM_MODEL", provider_default_model(provider)
    ).strip()
    return LLMProviderConfig(
        provider=provider,
        api_key=_resolve_api_key(provider),
        base_url=base_url,
        default_model=default_model,
    )


def normalize_provider_model(provider: str, model: str) -> str:
    """Map unofficial provider model names to supported API ids."""
    aliases = _PROVIDER_MODEL_ALIASES.get(provider, {})
    return aliases.get(model.strip().lower(), model)


def resolve_model(requested_model: str, config: LLMProviderConfig | None = None) -> str:
    """Map a Claude model id to the configured provider model when needed.

    When ``VULSCAN_LLM_MODEL`` is set, that value is used verbatim — no alias
    rewriting. Aliases in ``_PROVIDER_MODEL_ALIASES`` apply only to
    ``normalize_provider_model()`` for optional callers, not to user env overrides.
    """
    cfg = config or resolve_llm_config()
    if cfg.provider == "anthropic":
        return requested_model

    override = os.getenv("VULSCAN_LLM_MODEL", "").strip()
    if override:
        return override

    # Internal code still passes Claude model ids; substitute provider default.
    if requested_model.startswith("claude-"):
        return cfg.default_model

    return requested_model


def format_active_llm_label(
    requested_model: str | None = None,
    config: LLMProviderConfig | None = None,
) -> str:
    """Human-readable provider/model label for log output."""
    cfg = config or resolve_llm_config()
    effective = resolve_model(requested_model or cfg.default_model, cfg)
    if cfg.provider == "anthropic":
        return effective
    return f"{cfg.provider}/{effective}"
