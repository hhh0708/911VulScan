"""Extract compiler diagnostics and repair native test harnesses after build failures."""

from __future__ import annotations

import copy
import re

from utilities.dynamic_tester.dockerfile_builder import normalize_language
from utilities.dynamic_tester.native_link_mode import sanitize_native_test_script

_COMPILER_LINE_RE = re.compile(
    r".*\.(?:c|cpp|cc|cxx|h|hpp):\d+:\d+:\s*(?:error|fatal error|note):",
    re.IGNORECASE,
)
_LINKER_ERROR_RE = re.compile(
    r"(?:undefined reference to|collect2: error|ld returned \d+ exit status)",
    re.IGNORECASE,
)
_C_PREPROCESSOR_LINE_RE = re.compile(
    r"^\s*#\s*(?:include|define|ifdef|ifndef|pragma|endif)\b",
    re.MULTILINE,
)
_NATIVE_LANGS = frozenset({"c", "cpp", "c++"})


def is_native_test_script(
    test_script: str,
    test_filename: str | None = None,
    language: str | None = None,
) -> bool:
    """Return True when deterministic C/C++ compile fixes apply to this harness."""
    lang = normalize_language(language or "")
    if lang in _NATIVE_LANGS:
        return True
    fn = (test_filename or "").lower()
    return fn.endswith((".c", ".cpp", ".cc", ".cxx"))


def strip_c_preprocessor_lines(test_script: str) -> str:
    """Remove C preprocessor directives (often mistaken LLM output in JS/Python)."""
    if not test_script:
        return test_script
    kept = [
        line
        for line in test_script.splitlines()
        if not _C_PREPROCESSOR_LINE_RE.match(line)
    ]
    return "\n".join(kept).strip("\n") + ("\n" if kept else "")


def sanitize_high_level_test_script(
    test_script: str,
    language: str | None = None,
    test_filename: str | None = None,
) -> str:
    """Normalize non-native harness scripts (strip accidental C directives)."""
    if is_native_test_script(test_script, test_filename, language):
        return test_script
    return strip_c_preprocessor_lines(test_script)


def script_has_c_preprocessor(test_script: str) -> bool:
    return bool(_C_PREPROCESSOR_LINE_RE.search(test_script or ""))


def extract_compiler_diagnostics(raw: str, max_chars: int = 5000) -> str:
    """Return the most relevant gcc/clang/linker lines from a Docker build log."""
    if not raw:
        return ""

    picked: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if _COMPILER_LINE_RE.search(stripped):
            picked.append(stripped)
            continue
        if _LINKER_ERROR_RE.search(stripped):
            picked.append(stripped)

    if picked:
        text = "\n".join(picked[-48:])
        return text[:max_chars]

    text = raw.strip()
    if len(text) > max_chars:
        return "...(truncated)...\n" + text[-max_chars:]
    return text


def apply_deterministic_compile_fixes(
    test_script: str,
    language: str | None = None,
    test_filename: str | None = None,
) -> str:
    """Apply local fixes for frequent LLM C harness mistakes (no LLM call)."""
    if not is_native_test_script(test_script, test_filename, language):
        return sanitize_high_level_test_script(
            test_script, language=language, test_filename=test_filename
        )

    script = sanitize_native_test_script(test_script or "")

    script = re.sub(
        r"\bstruct\s+vulscan_child_capture\b",
        "vulscan_child_capture",
        script,
    )

    needs = {
        "#include <stdio.h>": re.compile(
            r"\b(?:stderr|stdout|stdin|printf|fprintf|snprintf|setvbuf|fopen|fclose|fgets)\b"
        ),
        "#include <string.h>": re.compile(
            r"\b(?:strcpy|strncpy|strlen|memcpy|memset|strcmp|strncmp)\b"
        ),
        "#include <stdlib.h>": re.compile(
            r"\b(?:malloc|free|calloc|realloc|atoi)\b|(?<![.\w])exit\s*\("
        ),
        "#include <stddef.h>": re.compile(r"\bsize_t\b"),
        '#include "vulscan_native_compat.h"': re.compile(r"\bvulscan_\w+"),
    }

    for header, pattern in needs.items():
        if pattern.search(script) and header not in script:
            script = header + "\n" + script

    return script


def deterministic_repair_generation(
    generation: dict | None,
    language: str | None = None,
) -> dict | None:
    """Return a copy of *generation* with a locally repaired test_script, or None."""
    if not generation or not generation.get("test_script"):
        return None

    lang = language or generation.get("_language")
    test_filename = generation.get("test_filename")
    fixed = apply_deterministic_compile_fixes(
        str(generation["test_script"]),
        language=lang,
        test_filename=test_filename,
    )
    if fixed == generation.get("test_script"):
        return None

    out = copy.deepcopy(generation)
    out["test_script"] = fixed
    return out
