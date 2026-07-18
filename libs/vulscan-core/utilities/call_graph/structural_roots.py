"""Structural root detection from language structure only.

Roots are NEVER derived from framework names, decorator regexes,
HTTP request patterns, or vulnerability source/sink rules.

Allowed root kinds:
  - program_entry: language program entry (e.g. main, __main__)
  - module_init: module/package initialization (e.g. Go init, module-level)
  - exported_symbol: exported or language-public symbols
"""

from __future__ import annotations

from typing import Any, Dict, List


def detect_structural_roots(
    nodes: Dict[str, Dict[str, Any]],
    *,
    language: str = "unknown",
) -> List[Dict[str, str]]:
    """Return structural roots as ``[{id, kind}, ...]``."""
    roots: List[Dict[str, str]] = []
    seen = set()

    def _add(node_id: str, kind: str) -> None:
        if node_id in seen or node_id not in nodes:
            return
        seen.add(node_id)
        roots.append({"id": node_id, "kind": kind})

    lang = (language or "unknown").lower()

    for node_id, node in nodes.items():
        name = node.get("name") or ""
        kind = (node.get("kind") or node.get("unit_type") or "").lower()
        file_path = (node.get("file_path") or "").replace("\\", "/")
        is_exported = bool(node.get("is_exported"))
        visibility = (node.get("visibility") or "").lower()
        package = node.get("package") or ""

        # --- program entry ---
        if name == "main":
            if lang == "go":
                if package == "main" or file_path.endswith("main.go") or "/main.go" in file_path:
                    _add(node_id, "program_entry")
            else:
                _add(node_id, "program_entry")
            continue

        if lang == "python" and (
            name == "__main__"
            or kind == "module_level"
            and ("__name__" in (node.get("code") or "") and "__main__" in (node.get("code") or ""))
        ):
            if name == "__main__" or kind == "module_level":
                # Module-level with __main__ guard is program entry; plain module_level is init.
                code = node.get("code") or ""
                if "__main__" in code:
                    _add(node_id, "program_entry")
                    continue

        # --- module / package initialization ---
        if lang == "go" and name == "init":
            _add(node_id, "module_init")
            continue

        if kind in ("module_level", "module_init", "package_init"):
            _add(node_id, "module_init")
            continue

        # --- exported / public symbols ---
        if is_exported or visibility == "public":
            # Nested/lambda/private helpers marked exported by mistake stay excluded by name.
            if name.startswith("_") and not name.startswith("__"):
                continue
            if kind in ("lambda", "nested_function", "closure") and not is_exported:
                continue
            _add(node_id, "exported_symbol")

    return roots


def structural_root_ids(roots: List[Dict[str, str]]) -> set:
    return {r["id"] for r in roots if r.get("id")}
