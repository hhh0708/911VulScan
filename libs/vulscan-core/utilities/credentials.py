"""Unified credential resolution and secret redaction.

Credentials may only come from:
  1. Process environment variables
  2. A user config file with mode ``0600`` (owner read/write only)

Never hardcode API keys. Never log raw secret values — use ``redact_secrets``
or ``mask_secret`` before writing to manifests, checkpoints, exceptions, or
debug output.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# Common LLM / cloud credential environment variables.
CREDENTIAL_ENV_VARS: tuple[str, ...] = (
    "VULSCAN_LLM_API_KEY",
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "DASHSCOPE_API_KEY",
    "OPENAI_API_KEY",
    "GITHUB_TOKEN",
)

# Patterns that look like secrets in free-form text (values never logged).
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(sk-[a-z0-9_-]{16,})\b"),
    re.compile(r"(?i)\b(ghp_[a-z0-9]{20,})\b"),
    re.compile(r"(?i)\b(gho_[a-z0-9]{20,})\b"),
    re.compile(r"(?i)\b(xox[baprs]-[a-z0-9-]{10,})\b"),
    re.compile(
        r"(?i)(api[_-]?key|authorization|bearer|token)\s*[:=]\s*['\"]?([^\s'\"]{8,})"
    ),
)

_REDACTED = "***REDACTED***"


class CredentialError(ValueError):
    """Raised when no usable credential can be resolved."""


@dataclass(frozen=True)
class ResolvedCredential:
    """A resolved credential with metadata suitable for safe logging."""

    value: str
    source: str  # e.g. "env:DEEPSEEK_API_KEY" or "config:~/.config/vulscan/config.json"
    env_name: str | None = None

    def masked(self) -> str:
        return mask_secret(self.value)

    def __repr__(self) -> str:
        return f"ResolvedCredential(source={self.source!r}, value={_REDACTED!r})"


def mask_secret(value: str | None, *, head: int = 4, tail: int = 4) -> str:
    """Return a masked preview that never includes the full secret."""
    if not value:
        return "(not set)"
    if len(value) <= head + tail + 3:
        return "***"
    return f"{value[:head]}...{value[-tail:]}"


def redact_secrets(
    text: str,
    extra_secrets: Iterable[str] | None = None,
) -> str:
    """Redact secret-looking substrings from ``text`` for safe logging."""
    if not text:
        return text

    out = text
    extras = [s for s in (extra_secrets or ()) if s and len(s) >= 6]
    # Longest first so partial overlaps redact cleanly.
    for secret in sorted(extras, key=len, reverse=True):
        out = out.replace(secret, _REDACTED)

    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 2:
            out = pattern.sub(
                lambda m: f"{m.group(1)}={_REDACTED}",
                out,
            )
        else:
            out = pattern.sub(_REDACTED, out)
    return out


def _config_path_candidates() -> list[Path]:
    """Candidate user config files that may hold an api_key (0600 required)."""
    paths: list[Path] = []
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    home = Path.home()
    if xdg:
        paths.append(Path(xdg) / "vulscan" / "config.json")
    paths.append(home / ".config" / "vulscan" / "config.json")
    # Windows APPDATA layout used by the Go CLI.
    appdata = os.environ.get("APPDATA", "").strip()
    if appdata:
        paths.append(Path(appdata) / "vulscan" / "config.json")
    return paths


def _file_mode_is_owner_only(path: Path) -> bool:
    """Return True if ``path`` is owner-readable only (approx. 0600).

    On Windows, POSIX mode bits are approximate; we still require that the
    file is not world/group-writable when the platform exposes mode bits.
    """
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    # Reject group/other read or write bits when present.
    if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
        return False
    return True


def _read_api_key_from_config(path: Path) -> str | None:
    """Read ``api_key`` from a JSON config file if permissions are safe."""
    if not path.is_file():
        return None
    if os.name != "nt" and not _file_mode_is_owner_only(path):
        raise CredentialError(
            f"Refusing to read credentials from {path}: "
            "file permissions must be 0600 (owner read/write only)."
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(data, dict):
        return None
    key = data.get("api_key")
    if isinstance(key, str) and key.strip():
        return key.strip()
    return None


class CredentialResolver:
    """Resolve LLM credentials from environment or a locked-down config file."""

    def __init__(
        self,
        *,
        env: dict[str, str] | None = None,
        config_paths: Iterable[Path] | None = None,
    ) -> None:
        self._env = env if env is not None else os.environ
        self._config_paths = list(config_paths) if config_paths is not None else _config_path_candidates()

    def get_env(self, name: str) -> str:
        return (self._env.get(name) or "").strip()

    def resolve(
        self,
        *,
        preferred_env: str | None = None,
        fallback_envs: Iterable[str] = (),
        allow_config_file: bool = True,
    ) -> ResolvedCredential:
        """Resolve a credential value.

        Order:
          1. ``preferred_env``
          2. each name in ``fallback_envs``
          3. (optional) 0600 user config ``api_key``
        """
        ordered: list[str] = []
        if preferred_env:
            ordered.append(preferred_env)
        for name in fallback_envs:
            if name and name not in ordered:
                ordered.append(name)

        for name in ordered:
            value = self.get_env(name)
            if value:
                return ResolvedCredential(
                    value=value,
                    source=f"env:{name}",
                    env_name=name,
                )

        if allow_config_file:
            for path in self._config_paths:
                value = _read_api_key_from_config(path)
                if value:
                    return ResolvedCredential(
                        value=value,
                        source=f"config:{path}",
                        env_name=None,
                    )

        tried = ", ".join(ordered) if ordered else "(none)"
        raise CredentialError(
            f"No API key found. Set one of: {tried}, "
            "or save a key with `vulscan set-api-key` "
            "(stored in ~/.config/vulscan/config.json with mode 0600)."
        )

    def collect_known_secrets(self) -> list[str]:
        """Return currently available secret values for redaction (never log these)."""
        secrets: list[str] = []
        for name in CREDENTIAL_ENV_VARS:
            value = self.get_env(name)
            if value:
                secrets.append(value)
        for path in self._config_paths:
            try:
                value = _read_api_key_from_config(path)
            except CredentialError:
                continue
            if value:
                secrets.append(value)
        return secrets


def safe_exception_message(exc: BaseException) -> str:
    """Format an exception for logs with secrets redacted."""
    resolver = CredentialResolver()
    return redact_secrets(str(exc), resolver.collect_known_secrets())
