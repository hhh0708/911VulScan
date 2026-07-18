"""Stage Python project trees for dynamic exploit tests."""

from __future__ import annotations

import os
import shutil

from utilities.dynamic_tester.staging_limits import (
    _SKIP_DIR_NAMES,
    check_staging_bounds,
    within_repo,
)

_PYTHON_ROOT_MARKERS = frozenset({
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "requirements-dev.txt",
})
_PYTHON_SOURCE_SUFFIXES = (".py",)
_PYTHON_META_FILES = frozenset({
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "requirements-dev.txt",
    "MANIFEST.in",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
})


def find_python_project_root(source_path: str, repo_path: str | None = None) -> str | None:
    """Return the nearest directory that looks like a Python project root."""
    if not source_path:
        return None
    start = os.path.abspath(source_path)
    current = start if os.path.isdir(start) else os.path.dirname(start)
    repo_root = os.path.abspath(repo_path) if repo_path else None

    while True:
        names = set(os.listdir(current)) if os.path.isdir(current) else set()
        if names & _PYTHON_ROOT_MARKERS:
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        if repo_root is not None and not within_repo(parent, repo_root):
            return None
        current = parent


def _should_stage_python_file(name: str) -> bool:
    return name in _PYTHON_META_FILES or name.endswith(_PYTHON_SOURCE_SUFFIXES)


def plan_python_staged_files(
    source_path: str,
    repo_path: str | None = None,
) -> tuple[list[str], str | None, str]:
    """Return (relative staged paths, project root abs path, blocked_reason)."""
    project_root = find_python_project_root(source_path, repo_path)
    if not project_root:
        return [], None, "no Python project root (pyproject.toml/setup.py/requirements*.txt) found"

    pairs: list[tuple[str, str]] = []
    for root, dirs, files in os.walk(project_root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIR_NAMES)
        rel_root = os.path.relpath(root, project_root)
        for name in sorted(files):
            if not _should_stage_python_file(name):
                continue
            abs_path = os.path.join(root, name)
            if not within_repo(abs_path, repo_path):
                continue
            if rel_root == ".":
                rel_path = name
            else:
                rel_path = f"{rel_root}/{name}".replace("\\", "/")
            pairs.append((rel_path, abs_path))

    ok, reason = check_staging_bounds(pairs)
    if not ok:
        return [], project_root, reason
    return [rel for rel, _ in pairs], project_root, ""


def stage_python_project(
    work_dir: str,
    source_path: str,
    repo_path: str | None = None,
) -> tuple[str | None, list[str], str]:
    """Copy a bounded Python project tree into *work_dir*."""
    staged_rel, project_root, blocked = plan_python_staged_files(source_path, repo_path)
    if blocked:
        return None, [], blocked
    if not staged_rel:
        return None, [], "no Python files to stage"

    staged: list[str] = []
    for rel in staged_rel:
        src = os.path.join(project_root, rel)
        dest = os.path.join(work_dir, rel)
        os.makedirs(os.path.dirname(dest) or work_dir, exist_ok=True)
        shutil.copy2(src, dest)
        staged.append(rel)

    source_basename = os.path.basename(source_path)
    return source_basename, sorted(staged), ""
