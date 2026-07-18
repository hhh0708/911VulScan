"""Export 911VulScan scan artifacts to a human-friendly results tree.

Layout (default root: ``<workspace>/911VulScan_Scan_Results``, sibling to ``911VulScan/``)::

    911VulScan_Scan_Results/
      local/cjson/c/
        INDEX.md
        static/
          SUMMARY_REPORT.md
          disclosures/
          results.json
          ...
        dynamic/
          DYNAMIC_TEST_RESULTS.md
          dynamic_test_results.json
          ...

Override root with env ``911VULSCAN_SCAN_RESULTS_ROOT``.
"""

from __future__ import annotations

import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

# Any character outside this set is replaced with "_" in a path component.
_UNSAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]")


def _safe_component(name: str) -> str:
    """Sanitize a single path segment so it cannot traverse or escape.

    ``project_name``/``language`` originate from user-controlled init input, so
    a value like ``../../.ssh`` must not be allowed to write outside the
    results root. Dotted-only segments ("", ".", "..") are rejected.
    """
    cleaned = _UNSAFE_COMPONENT_RE.sub("_", (name or "").strip())
    if not cleaned or set(cleaned) <= {"."}:
        return ""
    return cleaned

# Files copied into static/ (machine + human-readable summaries).
_STATIC_FILES = (
    "results.json",
    "results_verified.json",
    "pipeline_output.json",
    "dataset.json",
    "dataset_enhanced.json",
    "scan.report.json",
    "parse.report.json",
    "enhance.report.json",
    "analyze.report.json",
    "verify.report.json",
    "build-output.report.json",
    "report.report.json",
    "diff_filter.report.json",
    "diff_manifest.json",
)

# Files copied into dynamic/.
_DYNAMIC_FILES = (
    "dynamic_test_results.json",
    "DYNAMIC_TEST_RESULTS.md",
    "dynamic-test.report.json",
)


def default_scan_results_root() -> Path:
    """Return ``911VulScan_Scan_Results`` next to the ``911VulScan`` package directory."""
    env = os.environ.get("911VULSCAN_SCAN_RESULTS_ROOT", "").strip()
    if env:
        return Path(env).expanduser().resolve()

    # vulscan-core → 911VulScan/libs/vulscan-core → 911VulScan → workspace
    core_root = Path(__file__).resolve().parents[1]
    vulscan_dir = core_root.parent.parent
    workspace = vulscan_dir.parent
    return workspace / "911VulScan_Scan_Results"


def project_results_dir(
    project_name: str,
    language: str | None = None,
    root: Path | None = None,
) -> Path:
    """``911VulScan_Scan_Results/<org>/<repo>/<language>/`` from ``local/cjson`` + ``c``."""
    base = (root or default_scan_results_root()).resolve()
    parts = [c for c in (_safe_component(p) for p in (project_name or "unknown").split("/")) if c]
    path = base.joinpath(*parts) if parts else base / "unknown"
    if language:
        lang = _safe_component(language.lower())
        if lang:
            path = path / lang
    # Defense in depth: never resolve outside the results root.
    resolved = path.resolve()
    if resolved != base and base not in resolved.parents:
        return base / "unknown"
    return resolved


def _copy_if_exists(src: Path, dst: Path) -> bool:
    if not src.is_file():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def _copy_tree_if_exists(src_dir: Path, dst_dir: Path) -> bool:
    if not src_dir.is_dir():
        return False
    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    shutil.copytree(src_dir, dst_dir)
    return True


def export_static_results(
    scan_dir: str | Path,
    project_name: str,
    language: str | None = None,
    root: Path | None = None,
) -> Path:
    """Mirror static analysis outputs into ``.../<project>/<lang>/static/``."""
    scan = Path(scan_dir).resolve()
    dest = project_results_dir(project_name, language, root) / "static"
    dest.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    for name in _STATIC_FILES:
        if _copy_if_exists(scan / name, dest / name):
            copied.append(name)

    report_dir = scan / "report"
    if report_dir.is_dir():
        if _copy_if_exists(report_dir / "SUMMARY_REPORT.md", dest / "SUMMARY_REPORT.md"):
            copied.append("SUMMARY_REPORT.md")
        _copy_tree_if_exists(report_dir / "disclosures", dest / "disclosures")
        if (dest / "disclosures").is_dir():
            copied.append("disclosures/")

    _write_index(
        project_results_dir(project_name, language, root),
        project_name=project_name,
        language=language,
        scan_dir=scan,
        static_dest=dest,
        dynamic_dest=None,
        static_files=copied,
        dynamic_files=[],
    )
    print(f"[911VulScan] Static results exported to {dest}", file=__import__("sys").stderr)
    return dest


def export_dynamic_results(
    scan_dir: str | Path,
    project_name: str,
    language: str | None = None,
    root: Path | None = None,
) -> Path:
    """Mirror dynamic test outputs into ``.../<project>/<lang>/dynamic/``."""
    scan = Path(scan_dir).resolve()
    dest = project_results_dir(project_name, language, root) / "dynamic"
    dest.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    for name in _DYNAMIC_FILES:
        if _copy_if_exists(scan / name, dest / name):
            copied.append(name)

    if _copy_tree_if_exists(scan / "disclosures", dest / "disclosures"):
        copied.append("disclosures/")

    base = project_results_dir(project_name, language, root)
    _write_index(
        base,
        project_name=project_name,
        language=language,
        scan_dir=scan,
        static_dest=base / "static" if (base / "static").is_dir() else None,
        dynamic_dest=dest,
        static_files=[],
        dynamic_files=copied,
    )
    print(f"[911VulScan] Dynamic results exported to {dest}", file=__import__("sys").stderr)
    return dest


def export_all_results(
    scan_dir: str | Path,
    project_name: str,
    language: str | None = None,
    *,
    include_static: bool = True,
    include_dynamic: bool = True,
    root: Path | None = None,
) -> Path:
    """Export static and/or dynamic trees; returns project language directory."""
    base = project_results_dir(project_name, language, root)
    if include_static:
        export_static_results(scan_dir, project_name, language, root=root)
    if include_dynamic:
        export_dynamic_results(scan_dir, project_name, language, root=root)
    return base


def _write_index(
    base: Path,
    *,
    project_name: str,
    language: str | None,
    scan_dir: Path,
    static_dest: Path | None,
    dynamic_dest: Path | None,
    static_files: list[str],
    dynamic_files: list[str],
) -> None:
    index_path = base / "INDEX.md"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    static_dir = base / "static"
    dynamic_dir = base / "dynamic"

    lines = [
        f"# 911VulScan Scan Results — {project_name}",
        "",
        f"- **Language:** {language or '(unspecified)'}",
        f"- **Exported:** {now}",
        f"- **Internal scan dir:** `{scan_dir}`",
        "",
        "## Layout",
        "",
        "| Directory | Contents |",
        "|-----------|----------|",
        "| `static/` | Stage 1/2 静态分析、pipeline_output、摘要与披露文档 |",
        "| `dynamic/` | Docker 动态测试结果与动态验证说明 |",
        "",
    ]

    if static_dir.is_dir():
        files = static_files or sorted(
            p.name for p in static_dir.iterdir() if p.is_file()
        )
        lines.extend(["## Static (`static/`)", ""])
        for name in files:
            lines.append(f"- `{name}`")
        if (static_dir / "disclosures").is_dir():
            lines.append("- `disclosures/`")
        lines.append("")

    if dynamic_dir.is_dir():
        files = dynamic_files or sorted(
            p.name for p in dynamic_dir.iterdir() if p.is_file()
        )
        lines.extend(["## Dynamic (`dynamic/`)", ""])
        for name in files:
            lines.append(f"- `{name}`")
        if (dynamic_dir / "disclosures").is_dir():
            lines.append("- `disclosures/`")
        lines.append("")

    base.mkdir(parents=True, exist_ok=True)
    index_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
