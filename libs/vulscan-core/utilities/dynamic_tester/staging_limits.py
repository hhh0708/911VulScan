"""Shared bounds for dynamic-test source staging."""

from __future__ import annotations

import os

MAX_STAGE_FILES = 500
MAX_STAGE_BYTES = 50 * 1024 * 1024  # 50 MiB

_SKIP_DIR_NAMES = frozenset({
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    ".vulscan-objects",
    "vendor",
})


def within_repo(path: str, repo_path: str | None) -> bool:
    if not repo_path:
        return True
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(repo_path)]) == os.path.abspath(
            repo_path
        )
    except ValueError:
        return False


def resolve_repo_file(rel_path: str, repo_path: str | None) -> str | None:
    """Resolve an LLM-controlled ``location.file`` path inside *repo_path*.

    Rejects absolute paths, ``..`` traversal and symlink escapes by requiring
    the realpath to stay within the repo realpath. Returns None on any
    failure — callers must treat that exactly like "file not found" and fall
    back to their existing no-source path (no new exception types).
    """
    if not rel_path or not repo_path or os.path.isabs(rel_path):
        return None
    from core.dynamic_verification.staging import resolve_repo_source_path

    real, err = resolve_repo_source_path(rel_path, repo_path)
    if err or not real:
        return None
    return real


def check_staging_bounds(
    files: list[tuple[str, str]],
) -> tuple[bool, str]:
    """Validate planned staging file list as (rel_path, abs_path) pairs."""
    if len(files) > MAX_STAGE_FILES:
        return False, f"staging exceeds file limit ({len(files)} > {MAX_STAGE_FILES})"
    total = 0
    for _rel, abs_path in files:
        try:
            total += os.path.getsize(abs_path)
        except OSError:
            continue
        if total > MAX_STAGE_BYTES:
            return False, f"staging exceeds size limit ({total} > {MAX_STAGE_BYTES} bytes)"
    return True, ""
