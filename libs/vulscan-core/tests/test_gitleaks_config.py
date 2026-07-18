"""Verify .gitleaks.toml detects real-looking keys and ignores exact placeholders.

Never prints secret values — assertions only check finding counts / rule IDs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
GITLEAKS_CONFIG = REPO_ROOT / ".gitleaks.toml"


def _find_gitleaks() -> str | None:
    found = shutil.which("gitleaks")
    if found:
        return found
    # Common local install locations used by CI / developers.
    candidates = [
        Path("/usr/local/bin/gitleaks"),
        Path.home() / "bin" / "gitleaks",
        Path.home() / "bin" / "gitleaks.exe",
        REPO_ROOT / "tools" / "gitleaks" / "gitleaks",
        REPO_ROOT / "tools" / "gitleaks" / "gitleaks.exe",
    ]
    for path in candidates:
        if path.is_file():
            return str(path)
    return None


GITLEAKS = _find_gitleaks()
pytestmark = pytest.mark.skipif(
    GITLEAKS is None,
    reason="gitleaks binary not found on PATH (install to run these tests)",
)


def _synthetic_real_key() -> str:
    """Build a real-format-looking key at runtime (not stored as one literal)."""
    return "sk-ant-api03-" + ("A1b2C3d4E5f6G7h8" * 5)


def _run_gitleaks_dir(source: Path) -> subprocess.CompletedProcess[str]:
    assert GITLEAKS is not None
    report = source / "gitleaks-report.json"
    return subprocess.run(
        [
            GITLEAKS,
            "detect",
            "--no-git",
            "--source",
            str(source),
            "--config",
            str(GITLEAKS_CONFIG),
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--exit-code",
            "0",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _load_findings(source: Path) -> list[dict]:
    report = source / "gitleaks-report.json"
    if not report.is_file() or report.stat().st_size == 0:
        return []
    data = json.loads(report.read_text(encoding="utf-8"))
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return []


def test_gitleaks_detects_real_format_key_in_markdown(tmp_path):
    key = _synthetic_real_key()
    (tmp_path / "notes.md").write_text(
        f"# setup\n\nexport ANTHROPIC_API_KEY={key}\n",
        encoding="utf-8",
    )
    proc = _run_gitleaks_dir(tmp_path)
    assert proc.returncode == 0, proc.stderr
    findings = _load_findings(tmp_path)
    assert findings, "expected gitleaks to flag a real-format key in Markdown"
    # Never assert on the raw secret value.
    assert all("Secret" in f or "RuleID" in f for f in findings)


def test_gitleaks_detects_real_format_key_in_test_file(tmp_path):
    key = _synthetic_real_key()
    (tmp_path / "test_sample.py").write_text(
        f'API_KEY = "{key}"\n',
        encoding="utf-8",
    )
    proc = _run_gitleaks_dir(tmp_path)
    assert proc.returncode == 0, proc.stderr
    findings = _load_findings(tmp_path)
    assert findings, "expected gitleaks to flag a real-format key in a test file"


def test_gitleaks_allows_exact_test_placeholders(tmp_path):
    placeholders = [
        "sk-test",
        "sk-ant-test",
        "sk-deepseek-test",
        "sk-qwen-test",
        "sk-from-cli",
        "sk-test-key",
        "sk-good-key",
        "sk-bad-key",
        "sk-test-123",
        "sk-test-bad-key",
        "sk-test-redact",
        "sk-test-mask",
        "sk-deepseek",
        "sk-from-env",
        "sk-from-env-xx",
        "sk-from-flag",
        "sk-from-file",
    ]
    body = "\n".join(f'KEY_{i} = "{p}"' for i, p in enumerate(placeholders))
    (tmp_path / "test_placeholders.py").write_text(body + "\n", encoding="utf-8")
    (tmp_path / "placeholders.md").write_text(
        "Placeholders only:\n\n" + "\n".join(f"- `{p}`" for p in placeholders) + "\n",
        encoding="utf-8",
    )
    proc = _run_gitleaks_dir(tmp_path)
    assert proc.returncode == 0, proc.stderr
    findings = _load_findings(tmp_path)
    assert findings == [], (
        f"exact test placeholders must not false-positive; got {len(findings)} finding(s)"
    )


def test_gitleaks_config_rejects_broad_exemptions():
    text = GITLEAKS_CONFIG.read_text(encoding="utf-8")
    allowlist = text.split("[allowlist]")[1].split("[[rules]]")[0]
    assert "libs/vulscan-core/tests" not in allowlist
    assert r".*\.md$" not in allowlist
    assert "'''(^|/).*" not in allowlist  # no catch-all path globs
    # Only the local (gitignored) gitleaks tool extract may be path-allowlisted.
    if "paths" in allowlist:
        assert "tools/gitleaks" in allowlist
