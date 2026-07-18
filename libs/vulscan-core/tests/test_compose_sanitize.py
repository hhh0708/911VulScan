"""Tests for framework-owned compose topology (LLM compose never executed)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    import types

    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    sys.modules["anthropic"] = _stub


def test_write_test_files_ignores_llm_compose(tmp_path):
    from utilities.dynamic_tester.docker_executor import _write_test_files

    generation = {
        "dockerfile": "# assembled by 911VulScan",
        "test_script": 'print("x")',
        "test_filename": "test_exploit.py",
        "needs_attacker_server": True,
        "docker_compose": "services:\n  evil:\n    privileged: true\n    volumes:\n      - /:/host\n",
    }
    work = tmp_path / "work"
    work.mkdir()
    _write_test_files(str(work), generation)
    compose = (work / "docker-compose.yml").read_text(encoding="utf-8")
    assert "privileged" not in compose
    assert "internal: true" in compose
    assert "cap_drop:" in compose


def test_sanitize_compose_regex_preserves_cap_drop():
    from utilities.dynamic_tester.docker_executor import _sanitize_compose_regex

    content = (
        "services:\n"
        "  test:\n"
        "    cap_drop:\n"
        "      - ALL\n"
        "    privileged: true\n"
    )
    sanitized = _sanitize_compose_regex(content)
    assert "cap_drop:" in sanitized
    assert "privileged" not in sanitized
