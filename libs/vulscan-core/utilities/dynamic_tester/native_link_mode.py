"""Native dynamic-test link strategy: library API vs linked symbol vs local reimplementation."""

from __future__ import annotations

import enum
import os
import re

from utilities.dynamic_tester.native_symbols import (
    extract_entry_symbol,
    implementation_symbol,
)

_INCLUDE_RE = re.compile(r'#\s*include\s+"([^"]+)"')

_STATIC_DEF_RE = re.compile(
    r"\bstatic\s+(?:inline\s+)?(?:const\s+)?(?:unsigned\s+)?(?:int|void|char|size_t|cJSON_bool)\s+{symbol}\s*\(",
    re.MULTILINE,
)

_FUNC_DEF_RE = re.compile(
    r"(?:^|\n)\s*(?:static\s+)?(?:inline\s+)?"
    r"(?:CJSON_PUBLIC\s+)?(?:const\s+)?(?:unsigned\s+)?"
    r"(?:int|void|char|size_t|cJSON\s*\*|cJSON_bool)\s+(\w+)\s*\([^;]*\)\s*\{",
    re.MULTILINE,
)

_PRINTF_JSON_STATUS_RE = re.compile(
    r'printf\s*\(\s*["\']\s*\{\s*["\']?\s*status',
    re.IGNORECASE,
)

_PUBLIC_DECL_RE = re.compile(
    r"(?:CJSON_PUBLIC|extern)\s+[^;]*\b(\w+)\s*\([^;]*\)\s*;",
    re.MULTILINE,
)


class NativeLinkMode(str, enum.Enum):
    """How the harness is expected to reach the vulnerable code."""

    LIBRARY_API = "library_api"
    LINKED_SYMBOL = "linked_symbol"
    SELF_CONTAINED = "self_contained"


def _read_source(path: str | None, limit: int = 200_000) -> str:
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def symbol_is_static_in_source(source_path: str | None, symbol: str) -> bool:
    """True when *symbol* is defined static in the staged translation unit."""
    if not symbol:
        return False
    text = _read_source(source_path)
    if not text:
        return False
    pattern = _STATIC_DEF_RE.pattern.format(symbol=re.escape(symbol))
    return bool(re.search(pattern, text))


def test_defines_function(test_script: str, symbol: str) -> bool:
    """True when the harness defines a function named *symbol*."""
    if not symbol or not test_script:
        return False
    pattern = re.compile(
        rf"(?:^|\n)\s*(?:static\s+)?(?:inline\s+)?"
        rf"(?:const\s+)?(?:unsigned\s+)?(?:int|void|char|size_t|cJSON\s*\*|cJSON_bool)\s+"
        rf"{re.escape(symbol)}\s*\([^;]*\)\s*\{{",
        re.MULTILINE,
    )
    return bool(pattern.search(test_script))


def includes_project_headers(test_script: str, staged_headers: list[str]) -> bool:
    includes = set(_INCLUDE_RE.findall(test_script or ""))
    staged = set(staged_headers or [])
    return bool(includes & staged)


def find_public_callers_of_symbol(source_path: str | None, symbol: str) -> list[str]:
    """Non-static functions in *source_path* whose bodies call *symbol*."""
    text = _read_source(source_path)
    if not text or not symbol:
        return []

    callers: list[str] = []
    for match in _FUNC_DEF_RE.finditer(text):
        name = match.group(1)
        if name == symbol:
            continue
        body_start = match.end()
        next_fn = _FUNC_DEF_RE.search(text, body_start)
        body_end = next_fn.start() if next_fn else len(text)
        body = text[body_start:body_end]
        if re.search(rf"\b{re.escape(symbol)}\s*\(", body):
            callers.append(name)
    return callers


def public_api_declarations_near_source(source_path: str | None) -> list[str]:
    """Exported symbols declared in headers co-located with the source file."""
    if not source_path:
        return []
    source_dir = os.path.dirname(os.path.abspath(source_path))
    names: list[str] = []
    try:
        entries = os.listdir(source_dir)
    except OSError:
        return names

    for entry in entries:
        if not entry.endswith((".h", ".hpp")):
            continue
        header_path = os.path.join(source_dir, entry)
        text = _read_source(header_path, limit=80_000)
        for match in _PUBLIC_DECL_RE.finditer(text):
            name = match.group(1)
            if name not in names:
                names.append(name)
    return names


def infer_library_api_targets(
    source_path: str | None,
    target_symbol: str,
) -> list[str]:
    """Suggest public entry points that exercise a static helper."""
    callers = find_public_callers_of_symbol(source_path, target_symbol)
    if callers:
        return callers[:6]

    decls = public_api_declarations_near_source(source_path)
    stem = os.path.splitext(os.path.basename(source_path or ""))[0]
    scored: list[tuple[int, str]] = []
    for name in decls:
        score = 0
        if stem and stem.replace("_", "") in name.replace("_", ""):
            score += 2
        if "Utils" in name or "Get" in name or "Apply" in name or "Patch" in name:
            score += 1
        if name.lower().startswith("cjson"):
            score += 1
        scored.append((score, name))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [name for score, name in scored if score > 0][:6]


def detect_link_mode(
    *,
    test_script: str,
    source_path: str | None,
    source_basename: str | None,
    target_symbol: str,
    staged_files: list[str] | None = None,
) -> NativeLinkMode:
    """Classify how the generated harness reaches the bug."""
    staged = staged_files or []
    staged_headers = [f for f in staged if f.endswith((".h", ".hpp", ".hh", ".hxx"))]

    if test_defines_function(test_script, target_symbol):
        return NativeLinkMode.SELF_CONTAINED

    if includes_project_headers(test_script, staged_headers):
        if symbol_is_static_in_source(source_path, target_symbol):
            return NativeLinkMode.LIBRARY_API
        return NativeLinkMode.LINKED_SYMBOL

    if symbol_is_static_in_source(source_path, target_symbol):
        return NativeLinkMode.SELF_CONTAINED

    if source_basename and source_basename.endswith((".c", ".cpp", ".cc", ".cxx")):
        return NativeLinkMode.LINKED_SYMBOL

    return NativeLinkMode.SELF_CONTAINED


def should_compile_finding_source(
    test_script: str,
    source_basename: str | None,
    source_path: str | None,
    target_symbol: str,
    staged_files: list[str] | None = None,
) -> bool:
    """Whether the finding's .c file should be compiled into test_exploit."""
    if not source_basename or not source_basename.endswith(_SOURCE_SUFFIXES):
        return False
    mode = detect_link_mode(
        test_script=test_script,
        source_path=source_path,
        source_basename=source_basename,
        target_symbol=target_symbol,
        staged_files=staged_files,
    )
    if mode == NativeLinkMode.SELF_CONTAINED:
        return False
    if test_defines_function(test_script, target_symbol):
        return False
    return True


_SOURCE_SUFFIXES = (".c", ".cpp", ".cxx", ".cc")


def build_library_api_harness_notes(
    finding: dict,
    source_basename: str | None,
    source_path: str | None,
) -> str:
    """Extra prompt notes when the vulnerable symbol is static/internal."""
    entry = extract_entry_symbol(finding)
    target = implementation_symbol(entry)
    if not target or not symbol_is_static_in_source(source_path, target):
        return ""

    header_stem = os.path.splitext(source_basename or "")[0]
    header_name = f"{header_stem}.h" if header_stem else "module.h"
    api_targets = infer_library_api_targets(source_path, target)

    lines = [
        "STATIC HELPER — USE PUBLIC LIBRARY API (mandatory when possible):",
        f"- `{target}()` is static in `{source_basename}`; do NOT reimplement it in test_exploit.c.",
        f'- #include "{header_name}" and link the real library translation units.',
        "- The framework links matching .c files when you include project headers.",
    ]
    if api_targets:
        lines.append(
            "- Prefer calling one of these public entry points that reach the helper: "
            + ", ".join(f"`{name}()`" for name in api_targets[:4])
        )
    lines.extend([
        "- Build a minimal JSON/document fixture and invoke the public API in "
        "vulscan_run_asan_child_void/ptr().",
        "- Report INCONCLUSIVE (not CONFIRMED) if you can only reproduce via a "
        "local copy of the vulnerable logic.",
    ])
    return "\n".join(lines)


def is_logic_only_reproduction(
    generation: dict | None,
    finding: dict,
    *,
    source_path: str | None = None,
) -> bool:
    """True when CONFIRMED evidence likely comes from harness-local reimplementation."""
    if not generation:
        return False
    test_script = str(generation.get("test_script", ""))
    target = implementation_symbol(extract_entry_symbol(finding))
    if not target:
        return False

    if test_defines_function(test_script, target):
        return True

    mode = detect_link_mode(
        test_script=test_script,
        source_path=source_path,
        source_basename=None,
        target_symbol=target,
        staged_files=None,
    )
    return mode == NativeLinkMode.SELF_CONTAINED and symbol_is_static_in_source(
        source_path, target
    )


def sanitize_native_test_script(test_script: str) -> str:
    """Fix common LLM C harness mistakes before Docker build."""
    script = test_script or ""

    script = re.sub(
        r"\bstrncopy\s*\(",
        "strncpy(",
        script,
        flags=re.IGNORECASE,
    )

    script = re.sub(
        r"\bstruct\s+vulscan_child_capture\b",
        "vulscan_child_capture",
        script,
    )

    if _PRINTF_JSON_STATUS_RE.search(script) and "vulscan_emit_result_json" not in script:
        script = script.rstrip() + (
            "\n\n/* vulscan: replaced invalid printf(JSON) — use emit helper */\n"
            "#include \"vulscan_native_compat.h\"\n"
        )

    return script


def link_mode_for_finding(
    finding: dict,
    test_script: str,
    *,
    source_path: str | None = None,
    source_basename: str | None = None,
    staged_files: list[str] | None = None,
) -> NativeLinkMode:
    target = implementation_symbol(extract_entry_symbol(finding))
    return detect_link_mode(
        test_script=test_script,
        source_path=source_path,
        source_basename=source_basename,
        target_symbol=target,
        staged_files=staged_files,
    )
