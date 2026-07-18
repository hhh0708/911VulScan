"""Conservative language inference from unit metadata and source syntax.

Not a vulnerability heuristic — used only so Stage 1 prompts receive a
language label when the parser omitted one.
"""

from __future__ import annotations

import re


def normalize_language(language: str | None) -> str:
    value = (language or "").strip().lower()
    aliases = {
        "c++": "cpp",
        "cxx": "cpp",
        "py": "python",
        "golang": "go",
        "js": "javascript",
        "ts": "typescript",
        "node": "javascript",
    }
    return aliases.get(value, value or "unknown")


def infer_language(language: str | None, route: str, code: str) -> str:
    """Infer a supported language conservatively from metadata and syntax."""
    explicit = normalize_language(language)
    if explicit != "unknown":
        return explicit
    path = (route or "").split(":", 1)[0].lower()
    suffix_map = {
        ".c": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".py": "python",
        ".go": "go",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
    }
    for suffix, inferred in suffix_map.items():
        if path.endswith(suffix):
            return inferred
    if re.search(r"^\s*package\s+\w+", code, re.MULTILINE):
        return "go"
    if re.search(r"^\s*(?:def|class)\s+\w+", code, re.MULTILINE):
        return "python"
    if re.search(r"\b(?:const|let|var)\s+\w+|=>|require\s*\(", code):
        return "javascript"
    if re.search(r"#\s*include|std::|(?:^|\s)(?:char|void|int)\s+\w+\s*\(", code):
        return "cpp" if "std::" in code else "c"
    return "unknown"
