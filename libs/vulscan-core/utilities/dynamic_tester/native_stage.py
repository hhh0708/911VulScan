"""Discover native source/header artifacts to stage for dynamic Docker builds."""

from __future__ import annotations

import os
import re

_INCLUDE_RE = re.compile(r'#\s*include\s+"([^"]+)"')

_MAIN_SOURCE_NAMES = frozenset({"main.c", "main.cpp", "main.cc", "main.cxx"})

_HEADER_SUFFIXES = (".h", ".hpp", ".hh", ".hxx")

_SOURCE_SUFFIXES = (".c", ".cpp", ".cxx", ".cc")


def quoted_includes_in_file(path: str, limit: int = 200_000) -> list[str]:
    """Return quoted #include names from a source or header file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(limit)
    except OSError:
        return []
    return _INCLUDE_RE.findall(text)


def include_search_directories(repo_path: str | None, source_path: str) -> list[str]:
    """Candidate directories for resolving #include \"header.h\"."""
    source_dir = os.path.dirname(os.path.abspath(source_path))
    dirs: list[str] = [source_dir]

    parent = os.path.dirname(source_dir)
    for sub in ("include", "inc"):
        candidate = os.path.join(parent, sub)
        if os.path.isdir(candidate):
            dirs.append(candidate)

    if repo_path:
        repo_root = os.path.abspath(repo_path)
        for sub in ("include", "inc", "src", "public", "headers"):
            candidate = os.path.join(repo_root, sub)
            if os.path.isdir(candidate):
                dirs.append(candidate)

    seen: set[str] = set()
    ordered: list[str] = []
    for entry in dirs:
        norm = os.path.normpath(entry)
        if norm not in seen:
            seen.add(norm)
            ordered.append(norm)
    return ordered


def resolve_quoted_include(header: str, search_dirs: list[str]) -> str | None:
    """Resolve a quoted include to an absolute path, if present."""
    for directory in search_dirs:
        candidate = os.path.join(directory, header)
        if os.path.isfile(candidate):
            return candidate
        basename = os.path.basename(header)
        if basename != header:
            candidate = os.path.join(directory, basename)
            if os.path.isfile(candidate):
                return candidate
    return None


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


def _co_located_artifacts(source_path: str) -> dict[str, str]:
    """Headers and split-library companions in the same directory as *source_path*."""
    source_basename = os.path.basename(source_path)
    source_dir = os.path.dirname(os.path.abspath(source_path))
    artifacts: dict[str, str] = {source_basename: source_path}

    try:
        entries = os.listdir(source_dir)
    except OSError:
        return artifacts

    for entry in entries:
        if entry == source_basename:
            continue
        full = os.path.join(source_dir, entry)
        if not os.path.isfile(full):
            continue
        if entry.endswith(_HEADER_SUFFIXES):
            artifacts[entry] = full
        elif entry.endswith(_SOURCE_SUFFIXES) and _is_companion_translation_unit(
            entry, source_basename
        ):
            artifacts[entry] = full
    return artifacts


def _external_project_headers(source_path: str, repo_path: str | None) -> list[str]:
    """Project headers included by *source_path* that live outside its directory."""
    source_dir = os.path.dirname(os.path.abspath(source_path))
    search_dirs = include_search_directories(repo_path, source_path)
    external: list[str] = []
    for header in quoted_includes_in_file(source_path):
        resolved = resolve_quoted_include(header, search_dirs)
        if not resolved:
            continue
        if os.path.dirname(os.path.abspath(resolved)) != source_dir:
            external.append(header)
    return external


def needs_module_link_bundle(source_path: str, repo_path: str | None) -> bool:
    """True when the TU dispatches into multiple sibling translation units."""
    external = _external_project_headers(source_path, repo_path)
    source_stem = os.path.splitext(os.path.basename(source_path))[0]
    foreign = [
        header
        for header in external
        if os.path.splitext(os.path.basename(header))[0] != source_stem
    ]
    return len(foreign) >= 2


def _impl_basename_for_header(header_basename: str) -> str | None:
    """Map foo.h -> foo.c (or foo.hpp -> foo.cpp) for link companion discovery."""
    lower = header_basename.lower()
    if lower.endswith(".hpp"):
        return header_basename[:-4] + ".cpp"
    if lower.endswith((".hh", ".hxx")):
        return header_basename[:-4] + ".cpp"
    if lower.endswith(".h"):
        return header_basename[:-2] + ".c"
    return None


def _stage_impl_units_for_headers(
    path_by_basename: dict[str, str],
    search_dirs: list[str],
) -> None:
    """Stage .c/.cpp files that implement staged project headers (e.g. dictionary.h -> dictionary.c)."""
    for basename in list(path_by_basename.keys()):
        if not basename.endswith(_HEADER_SUFFIXES):
            continue
        impl_basename = _impl_basename_for_header(basename)
        if not impl_basename or impl_basename in path_by_basename:
            continue

        header_path = path_by_basename[basename]
        header_dir = os.path.dirname(os.path.abspath(header_path))
        same_dir = os.path.join(header_dir, impl_basename)
        if os.path.isfile(same_dir):
            path_by_basename.setdefault(impl_basename, same_dir)
            continue

        resolved = resolve_quoted_include(impl_basename, search_dirs)
        if resolved:
            path_by_basename.setdefault(impl_basename, resolved)


def sibling_module_sources(source_path: str) -> dict[str, str]:
    """Other module .c/.cpp files in the same directory (excluding program entry)."""
    source_dir = os.path.dirname(os.path.abspath(source_path))
    source_basename = os.path.basename(source_path)
    primary_is_cpp = source_basename.lower().endswith((".cpp", ".cxx", ".cc"))
    companions: dict[str, str] = {}

    try:
        entries = os.listdir(source_dir)
    except OSError:
        return companions

    for entry in entries:
        if entry == source_basename or entry in _MAIN_SOURCE_NAMES:
            continue
        if not entry.endswith(_SOURCE_SUFFIXES):
            continue
        entry_is_cpp = entry.lower().endswith((".cpp", ".cxx", ".cc"))
        if entry_is_cpp != primary_is_cpp:
            continue
        companions[entry] = os.path.join(source_dir, entry)
    return companions


def enumerate_stage_artifacts(
    source_path: str,
    repo_path: str | None = None,
) -> tuple[str, list[str], dict[str, str]]:
    """Return staged basenames and absolute paths for a native finding source.

    Returns:
        (source_basename, staged_basenames, path_by_basename)
    """
    source_path = os.path.abspath(source_path)
    source_basename = os.path.basename(source_path)
    path_by_basename = _co_located_artifacts(source_path)

    search_dirs = include_search_directories(repo_path, source_path)
    pending_headers = list(quoted_includes_in_file(source_path))
    seen_headers: set[str] = set()

    while pending_headers:
        header = pending_headers.pop(0)
        if header in seen_headers:
            continue
        seen_headers.add(header)

        resolved = resolve_quoted_include(header, search_dirs)
        if not resolved:
            continue

        basename = os.path.basename(resolved)
        path_by_basename.setdefault(basename, resolved)

        for nested in quoted_includes_in_file(resolved):
            if nested not in seen_headers:
                pending_headers.append(nested)

    _stage_impl_units_for_headers(path_by_basename, search_dirs)

    if needs_module_link_bundle(source_path, repo_path):
        for basename, full_path in sibling_module_sources(source_path).items():
            path_by_basename.setdefault(basename, full_path)

    staged_basenames = sorted(path_by_basename.keys(), key=lambda name: (name != source_basename, name))
    return source_basename, staged_basenames, path_by_basename


def stage_data_directory(
    work_dir: str,
    repo_path: str | None,
    staged_basenames: list[str],
) -> list[str]:
    """Copy repo data/ into the build context when path helpers are staged."""
    if not repo_path or "path_traversal.c" not in staged_basenames:
        return []

    data_src = os.path.join(os.path.abspath(repo_path), "data")
    if not os.path.isdir(data_src):
        return []

    import shutil

    data_dst = os.path.join(work_dir, "data")
    if os.path.isdir(data_dst):
        shutil.rmtree(data_dst, ignore_errors=True)
    shutil.copytree(data_src, data_dst)

    staged: list[str] = []
    for root, _, files in os.walk(data_dst):
        for name in files:
            rel = os.path.relpath(os.path.join(root, name), work_dir).replace("\\", "/")
            staged.append(rel)
    return staged
