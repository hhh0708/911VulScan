"""Safe source-path resolution and staging verification for dynamic tests."""

from __future__ import annotations

import os
from typing import Optional, Tuple


def resolve_repo_source_path(
    relative_or_abs: str,
    repo_path: str,
) -> Tuple[Optional[str], str]:
    """Resolve a source path under *repo_path* with symlink/escape rejection.

    Returns (realpath, error). On success error is "".
    """
    if not relative_or_abs or not str(relative_or_abs).strip():
        return None, "empty_source_path"
    if not repo_path or not os.path.isdir(repo_path):
        return None, "repo_path_missing"

    try:
        repo_real = os.path.realpath(repo_path)
    except OSError as exc:
        return None, f"repo_realpath_failed:{exc}"

    candidate = relative_or_abs
    if not os.path.isabs(candidate):
        candidate = os.path.join(repo_real, candidate)

    # Reject obvious traversal before realpath
    norm = os.path.normpath(candidate)
    if ".." in norm.split(os.sep):
        # still allow if final realpath stays inside — but check after realpath
        pass

    try:
        real = os.path.realpath(norm)
    except OSError as exc:
        return None, f"source_realpath_failed:{exc}"

    try:
        common = os.path.commonpath([real, repo_real])
    except ValueError:
        return None, "path_escape_rejected"
    if common != repo_real:
        return None, "path_escape_rejected"

    # Symlink escape: if any parent of the path (before realpath of file) left the repo
    # realpath already collapses symlinks; ensure the resolved file is a regular file.
    if not os.path.isfile(real):
        return None, "source_not_a_file"

    # Extra: reject if relative path contained .. that escapes even after join
    rel_try = os.path.relpath(real, repo_real)
    if rel_try.startswith(".."):
        return None, "path_escape_rejected"

    return real, ""


def verify_staged_source(
    work_dir: str,
    expected_basename: str,
    *,
    min_bytes: int = 1,
) -> Tuple[bool, str]:
    """Confirm staged target source exists in the Docker build context."""
    if not expected_basename:
        return False, "missing_staged_basename"
    path = os.path.join(work_dir, expected_basename)
    if not os.path.isfile(path):
        # Also accept nested relative path under work_dir
        nested = os.path.normpath(os.path.join(work_dir, expected_basename))
        try:
            common = os.path.commonpath(
                [os.path.realpath(nested), os.path.realpath(work_dir)]
            )
        except (ValueError, OSError):
            return False, "staged_source_missing"
        if common != os.path.realpath(work_dir) or not os.path.isfile(nested):
            return False, "staged_source_missing"
        path = nested
    try:
        if os.path.getsize(path) < min_bytes:
            return False, "staged_source_empty"
    except OSError:
        return False, "staged_source_unreadable"
    return True, ""
