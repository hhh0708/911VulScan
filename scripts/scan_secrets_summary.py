"""Run gitleaks and print finding counts only (never secret values)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    gitleaks = root / "tools" / "gitleaks" / "gitleaks.exe"
    if not gitleaks.is_file():
        gitleaks = Path(shutil_which("gitleaks") or "")
    if not gitleaks or not Path(gitleaks).is_file():
        print("gitleaks_binary=missing", file=sys.stderr)
        return 2

    mode = sys.argv[1] if len(sys.argv) > 1 else "workdir"
    # Whitelist: an unknown mode would silently degrade to a full-history scan,
    # and `mode` is interpolated into the report filename (path traversal).
    if mode not in {"workdir", "history"}:
        print(f"error: invalid mode {mode!r} — expected 'workdir' or 'history'", file=sys.stderr)
        return 2
    report = root / "tools" / "gitleaks" / f"report-{mode}.json"
    report.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(gitleaks),
        "detect",
        "--source",
        str(root),
        "--config",
        str(root / ".gitleaks.toml"),
        "--report-format",
        "json",
        "--report-path",
        str(report),
        "--exit-code",
        "0",
    ]
    if mode == "workdir":
        cmd.append("--no-git")
    # mode == history: full git history (default gitleaks behavior)

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    findings: list[dict] = []
    if report.is_file() and report.stat().st_size:
        raw = json.loads(report.read_text(encoding="utf-8") or "[]")
        if isinstance(raw, list):
            findings = raw

    by_rule = Counter(f.get("RuleID", "?") for f in findings)
    by_file = Counter(Path(f.get("File", "?")).name for f in findings)

    print(f"mode={mode}")
    print(f"exit_code={proc.returncode}")
    print(f"findings={len(findings)}")
    print("by_rule=" + ",".join(f"{k}:{v}" for k, v in sorted(by_rule.items())) if by_rule else "by_rule=")
    print("by_file=" + ",".join(f"{k}:{v}" for k, v in sorted(by_file.items())[:20]) if by_file else "by_file=")
    # Intentionally omit Secret / Match / line content.
    return 1 if findings else 0


def shutil_which(name: str) -> str | None:
    from shutil import which

    return which(name)


if __name__ == "__main__":
    raise SystemExit(main())
