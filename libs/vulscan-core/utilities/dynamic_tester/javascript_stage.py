"""Stage JavaScript/TypeScript project trees for dynamic exploit tests."""

from __future__ import annotations

import json
import os
import shutil

from utilities.dynamic_tester.staging_limits import (
    _SKIP_DIR_NAMES,
    check_staging_bounds,
    within_repo,
)

_JS_ROOT_MARKERS = frozenset({"package.json"})
_JS_SOURCE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
_JS_META_FILES = frozenset({
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "tsconfig.json",
    "tsconfig.build.json",
    "jsconfig.json",
})


def find_javascript_project_root(source_path: str, repo_path: str | None = None) -> str | None:
    """Return the nearest directory containing package.json."""
    if not source_path:
        return None
    start = os.path.abspath(source_path)
    current = start if os.path.isdir(start) else os.path.dirname(start)
    repo_root = os.path.abspath(repo_path) if repo_path else None

    while True:
        if os.path.isfile(os.path.join(current, "package.json")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        if repo_root is not None and not within_repo(parent, repo_root):
            return None
        current = parent


def _should_stage_js_file(name: str) -> bool:
    return name in _JS_META_FILES or name.endswith(_JS_SOURCE_SUFFIXES)


def _package_source_dirs(project_root: str) -> list[str]:
    """Return relative directories declared in package.json (main/module/types)."""
    pkg_path = os.path.join(project_root, "package.json")
    try:
        with open(pkg_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []

    dirs: set[str] = set()
    for key in ("main", "module", "types", "typings", "browser"):
        val = data.get(key)
        if isinstance(val, str) and not val.startswith("node:"):
            parent = os.path.dirname(val)
            if parent and parent != ".":
                dirs.add(parent)
    return sorted(dirs)


def plan_javascript_staged_files(
    source_path: str,
    repo_path: str | None = None,
) -> tuple[list[str], str | None, str]:
    """Return (relative staged paths, project root abs path, blocked_reason)."""
    project_root = find_javascript_project_root(source_path, repo_path)
    if not project_root:
        return [], None, "no JavaScript project root (package.json) found"

    preferred_dirs = set(_package_source_dirs(project_root))
    pairs: list[tuple[str, str]] = []

    for root, dirs, files in os.walk(project_root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIR_NAMES)
        rel_root = os.path.relpath(root, project_root)
        if rel_root != "." and preferred_dirs:
            top = rel_root.split(os.sep)[0]
            if top not in preferred_dirs and rel_root not in preferred_dirs:
                # Still allow meta files at project root
                if rel_root != ".":
                    dirs.clear()
                    continue
        for name in sorted(files):
            if not _should_stage_js_file(name):
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


def stage_javascript_project(
    work_dir: str,
    source_path: str,
    repo_path: str | None = None,
) -> tuple[str | None, list[str], str]:
    """Copy a bounded JS/TS project tree into *work_dir*."""
    staged_rel, project_root, blocked = plan_javascript_staged_files(source_path, repo_path)
    if blocked:
        return None, [], blocked
    if not staged_rel:
        return None, [], "no JavaScript/TypeScript files to stage"

    staged: list[str] = []
    for rel in staged_rel:
        src = os.path.join(project_root, rel)
        dest = os.path.join(work_dir, rel)
        os.makedirs(os.path.dirname(dest) or work_dir, exist_ok=True)
        shutil.copy2(src, dest)
        staged.append(rel)

    source_basename = os.path.basename(source_path)
    return source_basename, sorted(staged), ""
