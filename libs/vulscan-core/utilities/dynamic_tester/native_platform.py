"""Resolve native (C/C++) dynamic-test sources across platforms.

Linux dynamic tests run in gcc/g++ containers. Findings under Windows harness
paths often reference DLL entry points whose implementation lives in a separate
Linux port of the same vulnerable logic. This module maps those findings to
testable Linux sources instead of failing at Docker build time.
"""

from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field

from utilities.dynamic_tester.native_harness import build_linked_harness_notes
from utilities.dynamic_tester.native_symbols import (
    extract_entry_symbol,
    implementation_symbol,
)
from utilities.dynamic_tester.staging_limits import resolve_repo_file
from utilities.dynamic_tester.windows_runtime import (
    windows_container_guidance,
    windows_containers_supported,
)

_WINDOWS_PATH_MARKERS = ("windows/", "win32/", "win64/", "msvc/", "visualstudio/")

_DEFINE_SYMBOL_RE = re.compile(
    r"\b(?:int|void|static\s+int|static\s+void|unsigned\s+int)\s+{symbol}\s*\("
)

# Preferred basenames when multiple Linux implementations exist.
_IMPL_BASENAME_SCORES = {
    "imgread.c": 10,
    "dvcp.c": 10,
    "imgreadlib.c": 8,
    "imgread_replication.c": 6,
}


@dataclass
class NativeTestSource:
    """Primary source file and metadata for a native dynamic test."""

    source_path: str | None = None
    source_basename: str | None = None
    staged_basenames: list[str] = field(default_factory=list)
    platform_notes: str = ""
    harness_notes: str = ""
    runtime: str = "linux"  # linux | windows
    blocked: bool = False
    blocked_reason: str = ""


def _normalize_rel(path: str) -> str:
    return path.replace("\\", "/").lower()


def is_windows_only_path(rel_path: str) -> bool:
    """Return True when a finding path looks Windows-specific."""
    norm = _normalize_rel(rel_path)
    return any(marker in norm for marker in _WINDOWS_PATH_MARKERS)


def _file_defines_symbol(path: str, symbol: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(120_000)
    except OSError:
        return False
    pattern = _DEFINE_SYMBOL_RE.pattern.format(symbol=re.escape(symbol))
    return bool(re.search(pattern, text))


def _score_linux_candidate(rel_path: str, basename: str) -> int:
    rel = _normalize_rel(rel_path)
    score = _IMPL_BASENAME_SCORES.get(basename.lower(), 0)
    if "/linux/" in rel or rel.startswith("linux/"):
        score += 5
    if "replication" in rel:
        score += 2
    if "patched" in rel:
        score -= 6
    if "libfuzzer" in rel or "socket" in rel:
        score += 1
    if "shmem" in rel:
        score += 1
    return score


_IMPL_GLOB_PATTERNS = (
    "**/imgRead.c",
    "**/imgReadlib.c",
    "**/imgRead_replication.c",
    "**/imgRead_socket.c",
    "**/dvcp.c",
)


def find_linux_implementation(repo_path: str, symbol: str) -> str | None:
    """Find a non-Windows translation unit that defines *symbol*."""
    candidates: list[tuple[int, str]] = []

    for pattern in _IMPL_GLOB_PATTERNS:
        for path in glob.glob(os.path.join(repo_path, pattern), recursive=True):
            rel = os.path.relpath(path, repo_path).replace("\\", "/")
            if is_windows_only_path(rel):
                continue
            if not _file_defines_symbol(path, symbol):
                continue
            candidates.append((_score_linux_candidate(rel, os.path.basename(path)), path))

    if candidates:
        candidates.sort(key=lambda item: (-item[0], len(item[1])))
        return candidates[0][1]

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d not in {"node_modules", "__pycache__"}
        ]
        rel_root = os.path.relpath(root, repo_path).replace("\\", "/")
        if is_windows_only_path(rel_root):
            continue

        for name in files:
            if not name.endswith((".c", ".cpp", ".cc", ".cxx")):
                continue
            path = os.path.join(root, name)
            if not _file_defines_symbol(path, symbol):
                continue
            rel = os.path.relpath(path, repo_path).replace("\\", "/")
            candidates.append((_score_linux_candidate(rel, name), path))

    if not candidates:
        return None

    candidates.sort(key=lambda item: (-item[0], len(item[1])))
    return candidates[0][1]


def stage_files_from_source_path(
    source_path: str,
    repo_path: str | None = None,
) -> tuple[str, list[str]]:
    """Return (basename, staged basenames) for a source file and project headers."""
    from utilities.dynamic_tester.native_stage import enumerate_stage_artifacts

    basename, staged, _paths = enumerate_stage_artifacts(source_path, repo_path)
    return basename, staged


def _is_companion_translation_unit(entry: str, primary_basename: str) -> bool:
    """Sibling .c required when linking split library TUs (e.g. cJSON.c + cJSON_Utils.c)."""
    if entry == primary_basename:
        return False
    primary_stem, _ = os.path.splitext(primary_basename)
    entry_stem, _ = os.path.splitext(entry)
    if primary_stem.endswith("_Utils") and entry_stem == primary_stem[: -len("_Utils")]:
        return True
    if entry_stem.endswith("_Utils") and primary_stem == entry_stem[: -len("_Utils")]:
        return True
    return False


def resolve_native_test_source(finding: dict, repo_path: str | None) -> NativeTestSource:
    """Choose the source file that should be staged for dynamic testing."""
    if not repo_path:
        return NativeTestSource()

    loc = finding.get("location", {})
    rel_path = loc.get("file", "") if isinstance(loc, dict) else ""
    if not rel_path:
        return NativeTestSource()

    original_path = resolve_repo_file(rel_path, repo_path)
    if not original_path:
        return NativeTestSource()

    if not is_windows_only_path(rel_path):
        basename, staged = stage_files_from_source_path(original_path, repo_path)
        harness_notes = build_linked_harness_notes(finding, basename, original_path)
        return NativeTestSource(
            source_path=original_path,
            source_basename=basename,
            staged_basenames=staged,
            harness_notes=harness_notes,
        )

    entry_symbol = extract_entry_symbol(finding)
    impl_symbol = implementation_symbol(entry_symbol)
    linux_impl = find_linux_implementation(repo_path, impl_symbol)

    if linux_impl:
        basename, staged = stage_files_from_source_path(linux_impl, repo_path)
        rel_impl = os.path.relpath(linux_impl, repo_path).replace("\\", "/")
        platform_notes = (
            f"This finding is located in Windows-only harness `{rel_path}`. "
            f"Dynamic tests run on Linux and will exercise `{rel_impl}` instead, "
            f"which implements `{impl_symbol}()` with the same vulnerable logic."
        )
        harness_notes = build_linked_harness_notes(finding, basename, linux_impl)
        return NativeTestSource(
            source_path=linux_impl,
            source_basename=basename,
            staged_basenames=staged,
            platform_notes=platform_notes,
            harness_notes=harness_notes,
        )

    if windows_containers_supported():
        basename, staged = stage_files_from_source_path(original_path, repo_path)
        platform_notes = (
            f"No Linux implementation of `{impl_symbol}()` was found. "
            f"Using experimental Windows container runtime for `{rel_path}`."
        )
        harness_notes = build_linked_harness_notes(finding, basename, original_path)
        return NativeTestSource(
            source_path=original_path,
            source_basename=basename,
            staged_basenames=staged,
            platform_notes=platform_notes,
            harness_notes=harness_notes,
            runtime="windows",
        )

    return NativeTestSource(
        blocked=True,
        blocked_reason=windows_container_guidance(rel_path, impl_symbol),
    )


def list_staged_files_for_finding(
    finding: dict,
    repo_path: str | None,
) -> tuple[str | None, list[str]]:
    """Return staged file basenames, applying platform resolution when needed."""
    resolution = resolve_native_test_source(finding, repo_path)
    if resolution.blocked:
        return None, []
    if resolution.source_basename:
        return resolution.source_basename, list(resolution.staged_basenames)

    loc = finding.get("location", {})
    rel_path = loc.get("file", "") if isinstance(loc, dict) else ""
    if not rel_path or not repo_path:
        return None, []

    source_path = resolve_repo_file(rel_path, repo_path)
    if not source_path:
        return None, []

    basename, staged = stage_files_from_source_path(source_path, repo_path)
    return basename, staged
