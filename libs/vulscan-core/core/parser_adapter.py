"""
Unified parser interface.

Wraps language-specific parsers (Python, JavaScript, Go, C/C++) with
a single function signature that accepts a repo path and returns dataset +
analyzer output.

Each parser is invoked as a subprocess to avoid import conflicts with
sys.path hacks in the original code.
"""

import contextlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from core.pipeline_config import (
    PipelineConfigError,
    SUPPORTED_LANGUAGES,
    normalize_language,
    normalize_scope,
)
from core.schemas import ParseResult
from utilities.file_io import open_utf8, read_json, write_json

# Root of vulscan-core (where parsers/ lives)
_CORE_ROOT = Path(__file__).parent.parent

# JS parser directory (holds its own package.json / node_modules)
_JS_PARSER_DIR = _CORE_ROOT / "parsers" / "javascript"

# Shared language detection config (single source of truth: config/languages.json)
_LANGUAGES_CONFIG = Path(__file__).parent.parent.parent.parent / "config" / "languages.json"


def _load_language_config() -> dict:
    return read_json(_LANGUAGES_CONFIG)


def detect_language(repo_path: str) -> str:
    """Auto-detect the primary language of a repository.

    Counts source files by extension and returns the dominant language.
    Extension mappings and skip directories are loaded from config/languages.json.

    Returns:
        One of: "python", "javascript", "go", "c"
    """
    config = _load_language_config()
    skip_dirs = set(config["skip_dirs"])
    extensions = config["extensions"]

    repo = Path(repo_path)
    counts: dict[str, int] = {}

    for f in repo.rglob("*"):
        if not f.is_file():
            continue
        # Skip configured non-source dirs
        if any(p in skip_dirs for p in f.parts):
            continue

        suffix = f.suffix.lower()
        if suffix in extensions:
            lang = extensions[suffix]
            if lang not in SUPPORTED_LANGUAGES:
                continue
            counts[lang] = counts.get(lang, 0) + 1

    if not counts:
        raise ValueError(
            f"No supported source files found in {repo_path}. "
            "Supported languages: Python, JavaScript/TypeScript, Go, C/C++."
        )

    return max(counts, key=counts.get)


def parse_repository(
    repo_path: str,
    output_dir: str,
    language: str = "auto",
    scope: str = "reachable",
    skip_tests: bool = True,
    name: str = None,
    diff_manifest: str | None = None,
    supplemental_manifest: str | None = None,
) -> ParseResult:
    """Parse a repository into an 911VulScan dataset.

    Delegates to the appropriate language-specific parser. Each parser is
    invoked as a subprocess to avoid import path conflicts.

    Args:
        repo_path: Absolute path to the repository to parse.
        output_dir: Directory where dataset.json and analyzer_output.json will be written.
        language: "auto", "python", "javascript", "typescript", "go", or "c".
        scope: "all" or "reachable".
        skip_tests: If True, exclude test files from parsing (default: True).
        name: Dataset name override (default: derived from repo path basename).

    Returns:
        ParseResult with paths to generated files and stats.

    Raises:
        ValueError / PipelineConfigError: If language can't be detected or is unsupported.
        RuntimeError: If the parser subprocess fails.
    """
    repo_path = os.path.abspath(repo_path)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    scope = normalize_scope(scope)

    # Detect / normalize language
    if language == "auto":
        language = detect_language(repo_path)
        print(f"  Auto-detected language: {language}", file=sys.stderr)
    else:
        language = normalize_language(language)

    # Language parsers still accept --processing-level all|reachable.
    parser_level = scope

    # Dispatch to the right parser
    if language == "python":
        result = _parse_python(repo_path, output_dir, parser_level, skip_tests, name)
    elif language == "javascript":
        result = _parse_javascript(repo_path, output_dir, parser_level, skip_tests, name)
    elif language == "go":
        result = _parse_go(repo_path, output_dir, parser_level, skip_tests, name)
    elif language == "c":
        result = _parse_c(
            repo_path, output_dir, parser_level, skip_tests, name,
            supplemental_manifest=supplemental_manifest,
        )
    else:
        raise PipelineConfigError(
            f"Unsupported language: {language}. "
            f"Supported: {', '.join(sorted(SUPPORTED_LANGUAGES))}."
        )

    # Normalize result metadata to the new scope field.
    result.scope = scope
    result.language = language

    _maybe_apply_diff_filter(result, output_dir, diff_manifest)
    return result


def _maybe_apply_diff_filter(
    result: ParseResult,
    output_dir: str,
    diff_manifest: str | None,
) -> None:
    """Apply the diff filter to the dataset on disk if a manifest is provided.

    Annotates every unit with `diff_selected: bool` and rewrites dataset.json.
    Writes stats to {output_dir}/diff_filter.report.json for the step report
    (picked up alongside parse.report.json). If `diff_manifest` is None and
    no default manifest exists in output_dir, this is a no-op so legacy runs
    behave exactly as before.
    """
    # Resolve manifest path: explicit arg wins, else look for the default.
    if diff_manifest is None:
        default = os.path.join(output_dir, "diff_manifest.json")
        if os.path.exists(default):
            diff_manifest = default
    if not diff_manifest:
        return

    from core.diff_filter import apply_diff_filter, load_manifest

    print(f"\n[Diff Filter] Loading manifest from {diff_manifest}", file=sys.stderr)
    manifest = load_manifest(diff_manifest)

    if not os.path.exists(result.dataset_path):
        print(
            f"  [Warning] dataset {result.dataset_path} not found; skipping diff filter",
            file=sys.stderr,
        )
        return

    dataset = read_json(result.dataset_path)
    # Dataset may be a dict with "units" or a raw list.
    if isinstance(dataset, dict):
        units = dataset.get("units", [])
    else:
        units = dataset

    stats = apply_diff_filter(units, manifest)

    write_json(result.dataset_path, dataset)
    # Expose stats on the ParseResult via a side-channel file; the parse
    # step_context reads this when assembling parse.report.json.
    diff_report_path = os.path.join(output_dir, "diff_filter.report.json")
    write_json(diff_report_path, stats.to_dict())

    print(
        f"  Diff filter ({stats.scope}): {stats.selected}/{stats.total} units selected"
        + (f" ({stats.callers_added} added as callers)" if stats.callers_added else "")
        + (f", {stats.fallback_file_match} fell back to file-level" if stats.fallback_file_match else ""),
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Reachability filter (shared by Python path; JS/Go handle it internally)
# ---------------------------------------------------------------------------

def apply_reachability_filter(
    dataset: dict,
    output_dir: str,
    processing_level: str,
) -> dict:
    """Filter dataset units using three-state reachability.

    Keeps ``reachable`` and ``unknown`` units; drops only proven
    ``unreachable``. Roots come exclusively from ``structural_roots``.

    If ``call_graph.json`` is missing, corrupt, or schema-invalid, every
    unit is marked ``unknown`` and retained — scanning continues.
    """
    from utilities.call_graph.reachability import (
        ReachabilityStatus,
        all_unknown,
        compute_reachability,
        filter_keep_ids,
    )
    from utilities.call_graph.schema import load_call_graph, write_call_graph
    from utilities.call_graph.structural_roots import structural_root_ids

    call_graph_path = os.path.join(output_dir, "call_graph.json")
    language = (
        dataset.get("language")
        or dataset.get("metadata", {}).get("language")
        or "unknown"
    )

    print(f"\n[Reachability Filter] Filtering to {processing_level} units...", file=sys.stderr)

    units = dataset.get("units", [])
    original_count = len(units)
    unit_ids = [u.get("id", "") for u in units if u.get("id")]

    call_graph_data = None
    load_error = None
    if not os.path.exists(call_graph_path):
        load_error = "missing"
    else:
        call_graph_data, load_error = load_call_graph(call_graph_path, language=language)

    if call_graph_data is None:
        print(
            f"  [Warning] call_graph.json unusable ({load_error}) — "
            "marking all units unknown and continuing",
            file=sys.stderr,
        )
        status_map = all_unknown(unit_ids)
        roots: list = []
        root_ids: set = set()
        unresolved_count = 0
    else:
        roots = list(call_graph_data.get("structural_roots") or [])
        root_ids = structural_root_ids(roots)
        status_map = compute_reachability(
            call_graph_data.get("nodes") or {},
            call_graph_data.get("resolved_edges") or [],
            call_graph_data.get("unresolved_edges") or [],
            roots,
            language=language,
        )
        for uid in unit_ids:
            if uid not in status_map:
                status_map[uid] = ReachabilityStatus.UNKNOWN.value
        unresolved_count = len(call_graph_data.get("unresolved_edges") or [])
        try:
            write_call_graph(call_graph_path, call_graph_data, language=language)
        except OSError:
            pass

    keep_ids = filter_keep_ids(status_map)
    root_reason = {
        r["id"]: f"structural_root:{r.get('kind', 'unknown')}"
        for r in roots
        if isinstance(r, dict) and r.get("id")
    }

    filtered_units = []
    status_counts = {
        ReachabilityStatus.REACHABLE.value: 0,
        ReachabilityStatus.UNKNOWN.value: 0,
        ReachabilityStatus.UNREACHABLE.value: 0,
    }
    for u in units:
        unit_id = u.get("id", "")
        st = status_map.get(unit_id, ReachabilityStatus.UNKNOWN.value)
        status_counts[st] = status_counts.get(st, 0) + 1
        u["reachability"] = st
        # Roots only from structural_roots — never preserve external promotion.
        u["is_entry_point"] = unit_id in root_ids
        if unit_id in root_ids:
            u["entry_point_reason"] = root_reason.get(unit_id, "structural_root")
        elif str(u.get("entry_point_reason", "")).startswith("llm_reachability"):
            u.pop("entry_point_reason", None)
        if unit_id in keep_ids:
            u["reachable"] = st == ReachabilityStatus.REACHABLE.value
            filtered_units.append(u)

    dataset["units"] = filtered_units

    reduction_pct = (
        round((1 - len(filtered_units) / original_count) * 100, 1)
        if original_count > 0
        else 0
    )
    dataset.setdefault("metadata", {})["reachability_filter"] = {
        "original_units": original_count,
        "structural_roots": len(root_ids),
        "entry_points": len(root_ids),
        "reachable_units": status_counts.get(ReachabilityStatus.REACHABLE.value, 0),
        "unknown_units": status_counts.get(ReachabilityStatus.UNKNOWN.value, 0),
        "unreachable_units": status_counts.get(ReachabilityStatus.UNREACHABLE.value, 0),
        "kept_units": len(filtered_units),
        "filtered_out": original_count - len(filtered_units),
        "reduction_percentage": reduction_pct,
        "unresolved_edges": unresolved_count,
        "call_graph_error": load_error,
    }

    print(f"  Structural roots: {len(root_ids)}", file=sys.stderr)
    print(
        f"  Reachability: reachable={status_counts.get('reachable', 0)} "
        f"unknown={status_counts.get('unknown', 0)} "
        f"unreachable={status_counts.get('unreachable', 0)}",
        file=sys.stderr,
    )
    print(
        f"  Units kept (reachable+unknown): {original_count} -> {len(filtered_units)} "
        f"({reduction_pct}% reduction)",
        file=sys.stderr,
    )

    if processing_level == "codeql":
        print(
            "  [Warning] CodeQL filter not yet wired into the Python parser path. "
            "Returning reachable+unknown units only.",
            file=sys.stderr,
        )
    elif processing_level == "exploitable":
        print(
            "  [Warning] Exploitable filter (CodeQL + LLM classification) not yet "
            "wired into the Python parser path. Returning reachable+unknown units only.",
            file=sys.stderr,
        )

    return dataset


# Private alias kept for the Python parser path which calls it directly.
_apply_reachability_filter = apply_reachability_filter


# ---------------------------------------------------------------------------
# Python parser
# ---------------------------------------------------------------------------

def _parse_python(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the Python parser.

    The Python parser has a clean `parse_repository()` function that we can
    call directly (it's the best-structured of the three).
    """
    print("[Parser] Running Python parser...", file=sys.stderr)

    # Import and call directly — the Python parser is well-structured
    parser_dir = str(_CORE_ROOT / "parsers" / "python")
    if parser_dir not in sys.path:
        sys.path.insert(0, parser_dir)

    from parsers.python.parse_repository import parse_repository as _py_parse

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    options = {
        "dataset_name": name or Path(repo_path).name,
        "output_dir": output_dir,  # For intermediate files
        "skip_tests": skip_tests,
    }

    dataset, analyzer_output = _py_parse(repo_path, options)

    # Apply reachability filter if processing_level requires it
    if processing_level != "all":
        dataset = _apply_reachability_filter(dataset, output_dir, processing_level)

    # Write outputs
    write_json(dataset_path, dataset)
    write_json(analyzer_output_path, analyzer_output)
    units_count = len(dataset.get("units", []))
    print(f"  Python parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path,
        units_count=units_count,
        language="python",
        scope=processing_level,
    )


# ---------------------------------------------------------------------------
# JavaScript/TypeScript parser
# ---------------------------------------------------------------------------

def _js_deps_installed() -> bool:
    """Return True only if a *complete* npm install has previously succeeded.

    Checking that ``node_modules/`` exists is not enough: a prior install that
    was killed (Ctrl+C, OOM, disk full) leaves a partial directory. npm writes
    ``node_modules/.package-lock.json`` at the *end* of a successful install,
    so we use that as the completion sentinel.
    """
    return (_JS_PARSER_DIR / "node_modules" / ".package-lock.json").is_file()


def _ensure_js_parser_dependencies() -> None:
    """Install the JS parser's Node dependencies on first use.

    Mirrors the Go CLI's venv bootstrap (apps/vulscan-cli/internal/python/runtime.go):
    the first invocation installs, subsequent invocations are a no-op. Runs only
    when a JS repo is actually being parsed, so Python/Go-only users never need npm.

    Concurrency: uses a lockfile so two parallel parses don't both run
    ``npm install`` in the same directory (which can corrupt node_modules).
    """
    if _js_deps_installed():
        return

    if not (_JS_PARSER_DIR / "package.json").is_file():
        raise RuntimeError(
            f"JS parser package.json not found at {_JS_PARSER_DIR / 'package.json'}. "
            "The vulscan-core install may be incomplete."
        )

    npm = shutil.which("npm")
    if npm is None:
        raise RuntimeError(
            "JavaScript parser dependencies are not installed and `npm` is not on PATH. "
            f"Install Node.js/npm, then run: npm install (from {_JS_PARSER_DIR})"
        )

    # Serialize concurrent bootstraps. The lockfile lives next to package.json so
    # it's always on the same filesystem as the install target.
    lock_path = _JS_PARSER_DIR / ".vulscan-npm-install.lock"
    with _file_lock(lock_path):
        # Re-check under the lock: another process may have finished while we waited.
        if _js_deps_installed():
            return

        print(
            "[Parser] Installing JS parser dependencies (first run, this may take a minute)...",
            file=sys.stderr,
        )
        result = subprocess.run(
            [npm, "install"],
            cwd=str(_JS_PARSER_DIR),
            stdout=sys.stderr,
            stderr=sys.stderr,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"`npm install` failed in {_JS_PARSER_DIR} with exit code "
                f"{result.returncode}. See npm output above for details; you can "
                f"reproduce with: npm install (from {_JS_PARSER_DIR})"
            )


@contextlib.contextmanager
def _file_lock(lock_path: Path):
    """Cross-platform exclusive file lock as a context manager.

    Uses ``msvcrt`` on Windows and ``fcntl`` elsewhere. Blocks until the lock is
    acquired, releases on exit. The lockfile itself is left in place; only the
    OS-level lock matters for mutual exclusion.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    # "w" (not "a+") so the file pointer is at byte 0 — msvcrt.locking locks a
    # range starting at the *current* file position, so different positions
    # would mean non-overlapping (i.e. non-exclusive) locks.
    f = open_utf8(lock_path, "w")
    try:
        if os.name == "nt":
            import msvcrt

            f.seek(0)
            # LK_LOCK blocks (with retries) until the byte range is exclusive.
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    finally:
        f.close()


def _parse_javascript(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the JavaScript/TypeScript parser.

    The JS parser is a PipelineTest class that runs Node.js subprocesses.
    We invoke it via subprocess to avoid the sys.path hacks.
    """
    _ensure_js_parser_dependencies()

    print("[Parser] Running JavaScript parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "javascript" / "test_pipeline.py"

    # Build command — analyzer-path now defaults to co-located file in the parser
    cmd = [
        sys.executable, str(parser_script),
        repo_path,
        "--output", output_dir,
        "--processing-level", processing_level,
    ]

    if name:
        cmd.extend(["--name", name])
    if skip_tests:
        cmd.append("--skip-tests")

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,
    )

    if result.returncode != 0:
        raise RuntimeError(f"JavaScript parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  JavaScript parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="javascript",
        scope=processing_level,
    )


# ---------------------------------------------------------------------------
# Go parser
# ---------------------------------------------------------------------------

def _parse_go(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the Go parser.

    The Go parser is a PipelineTest class that calls a compiled Go binary.
    We invoke it via subprocess.
    """
    print("[Parser] Running Go parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "go" / "test_pipeline.py"

    cmd = [
        sys.executable, str(parser_script),
        repo_path,
        "--output", output_dir,
        "--processing-level", processing_level,
    ]

    if name:
        cmd.extend(["--name", name])
    if skip_tests:
        cmd.append("--skip-tests")

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Go parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  Go parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="go",
        scope=processing_level,
    )


# ---------------------------------------------------------------------------
# C/C++ parser
# ---------------------------------------------------------------------------

def _parse_c(
    repo_path: str,
    output_dir: str,
    processing_level: str,
    skip_tests: bool = True,
    name: str = None,
    supplemental_manifest: str | None = None,
) -> ParseResult:
    """Invoke the C/C++ parser.

    The C parser uses tree-sitter for function extraction and call graph
    building.  Invoked via subprocess (same pattern as Go/JS parsers).

    Requires: tree-sitter, tree-sitter-c, tree-sitter-cpp
    """
    print("[Parser] Running C/C++ parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "c" / "test_pipeline.py"

    cmd = [
        sys.executable, str(parser_script),
        repo_path,
        "--output", output_dir,
        "--processing-level", processing_level,
    ]

    if name:
        cmd.extend(["--name", name])
    if skip_tests:
        cmd.append("--skip-tests")
    if supplemental_manifest and os.path.exists(supplemental_manifest):
        cmd.extend(["--supplemental-manifest", supplemental_manifest])

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,  # 30 min timeout (C repos can be large)
    )

    if result.returncode != 0:
        raise RuntimeError(f"C/C++ parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  C/C++ parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="c",
        scope=processing_level,
    )


# ---------------------------------------------------------------------------
# Ruby parser
# ---------------------------------------------------------------------------

def _parse_ruby(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the Ruby parser.

    The Ruby parser uses tree-sitter for function extraction and call graph
    building.  Invoked via subprocess (same pattern as other parsers).

    Requires: tree-sitter, tree-sitter-ruby
    """
    print("[Parser] Running Ruby parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "ruby" / "test_pipeline.py"

    cmd = [
        sys.executable, str(parser_script),
        repo_path,
        "--output", output_dir,
        "--processing-level", processing_level,
    ]

    if name:
        cmd.extend(["--name", name])
    if skip_tests:
        cmd.append("--skip-tests")

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Ruby parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  Ruby parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="ruby",
        scope=processing_level,
    )


# ---------------------------------------------------------------------------
# PHP parser
# ---------------------------------------------------------------------------

def _parse_php(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the PHP parser.

    The PHP parser uses tree-sitter for function extraction and call graph
    building.  Invoked via subprocess (same pattern as other parsers).

    Requires: tree-sitter, tree-sitter-php
    """
    print("[Parser] Running PHP parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "php" / "test_pipeline.py"

    cmd = [
        sys.executable, str(parser_script),
        repo_path,
        "--output", output_dir,
        "--processing-level", processing_level,
    ]

    if name:
        cmd.extend(["--name", name])
    if skip_tests:
        cmd.append("--skip-tests")

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,
    )

    if result.returncode != 0:
        raise RuntimeError(f"PHP parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  PHP parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="php",
        scope=processing_level,
    )


# ---------------------------------------------------------------------------
# Zig parser
# ---------------------------------------------------------------------------

def _parse_zig(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the Zig parser.

    The Zig parser uses tree-sitter for function extraction and call graph
    building.  Invoked via subprocess (same pattern as other parsers).

    Requires: tree-sitter, tree-sitter-zig
    """
    print("[Parser] Running Zig parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "zig" / "test_pipeline.py"

    cmd = [
        sys.executable, str(parser_script),
        repo_path,
        "--output", output_dir,
        "--processing-level", processing_level,
    ]

    if name:
        cmd.extend(["--name", name])
    if skip_tests:
        cmd.append("--skip-tests")

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Zig parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  Zig parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="zig",
        scope=processing_level,
    )
