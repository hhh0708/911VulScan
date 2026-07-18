"""Stage Go module trees for dynamic exploit tests."""

from __future__ import annotations

import os
import re
import shutil

_GO_MOD_MODULE_RE = re.compile(r"^\s*module\s+(\S+)", re.MULTILINE)
_SKIP_DIR_NAMES = frozenset({
    ".git",
    "vendor",
    "node_modules",
    "__pycache__",
    ".vulscan-objects",
})
_MODULE_STAGE_DIR = "module"
_GO_STAGE_SUFFIXES = (".go",)
_GO_STAGE_FILES = frozenset({"go.mod", "go.sum"})


def find_go_module_root(source_path: str, repo_path: str | None = None) -> str | None:
    """Return the directory containing go.mod for *source_path*, if any."""
    if not source_path:
        return None

    start = os.path.abspath(source_path)
    current = start if os.path.isdir(start) else os.path.dirname(start)
    repo_root = os.path.abspath(repo_path) if repo_path else None

    while True:
        if os.path.isfile(os.path.join(current, "go.mod")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        if repo_root is not None:
            try:
                inside = os.path.commonpath([current, repo_root]) == repo_root
            except ValueError:
                inside = False
            if not inside:
                return None
        current = parent


def read_go_module_path(module_root: str) -> str | None:
    """Parse the module path from go.mod."""
    go_mod = os.path.join(module_root, "go.mod")
    try:
        with open(go_mod, "r", encoding="utf-8") as handle:
            content = handle.read()
    except OSError:
        return None
    match = _GO_MOD_MODULE_RE.search(content)
    return match.group(1) if match else None


def _should_stage_go_file(name: str) -> bool:
    return name in _GO_STAGE_FILES or name.endswith(_GO_STAGE_SUFFIXES)


def stage_go_module(
    work_dir: str,
    source_file: str,
    repo_path: str | None = None,
) -> tuple[str | None, list[str], str | None]:
    """Copy a Go module tree into work_dir/module/.

    Returns:
        (source_basename, staged relative paths, module import path)
    """
    module_root = find_go_module_root(source_file, repo_path)
    if not module_root:
        return None, [], None

    module_import = read_go_module_path(module_root)
    if not module_import:
        return None, [], None

    module_dest = os.path.join(work_dir, _MODULE_STAGE_DIR)
    staged: list[str] = []

    for root, dirs, files in os.walk(module_root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIR_NAMES)
        rel_root = os.path.relpath(root, module_root)
        for name in sorted(files):
            if not _should_stage_go_file(name):
                continue
            src = os.path.join(root, name)
            if rel_root == ".":
                rel_path = f"{_MODULE_STAGE_DIR}/{name}"
                dest = os.path.join(module_dest, name)
            else:
                rel_path = f"{_MODULE_STAGE_DIR}/{rel_root}/{name}".replace("\\", "/")
                dest = os.path.join(module_dest, rel_root, name)
            os.makedirs(os.path.dirname(dest) or module_dest, exist_ok=True)
            shutil.copy2(src, dest)
            staged.append(rel_path)

    source_basename = os.path.basename(source_file)
    return source_basename, sorted(staged), module_import


def plan_go_staged_files(
    source_file: str,
    repo_path: str | None = None,
) -> tuple[list[str], str | None]:
    """Return staged relative paths and module import path without copying files."""
    module_root = find_go_module_root(source_file, repo_path)
    if not module_root:
        return [], None

    module_import = read_go_module_path(module_root)
    if not module_import:
        return [], None

    staged: list[str] = []
    for root, dirs, files in os.walk(module_root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIR_NAMES)
        rel_root = os.path.relpath(root, module_root)
        for name in sorted(files):
            if not _should_stage_go_file(name):
                continue
            if rel_root == ".":
                staged.append(f"{_MODULE_STAGE_DIR}/{name}")
            else:
                staged.append(
                    f"{_MODULE_STAGE_DIR}/{rel_root}/{name}".replace("\\", "/")
                )

    return sorted(staged), module_import
