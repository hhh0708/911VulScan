"""Helpers for correct C/C++ dynamic-test harness generation.

The native builder links the staged vulnerable source into /work/test_exploit.
Validation rules and prompt instructions live in native_test_plan.py.
"""

from __future__ import annotations

import os
import re

from utilities.dynamic_tester.native_symbols import (
    extract_entry_symbol,
    implementation_symbol,
)
from utilities.dynamic_tester.native_link_mode import (
    build_library_api_harness_notes,
    symbol_is_static_in_source,
)
from utilities.dynamic_tester.native_test_plan import (
    NativeTestPlan,
    validate_native_test_script,
)


def extract_symbol_declaration(source_path: str | None, symbol: str) -> str | None:
    """Return a single-line declaration for *symbol* from *source_path*."""
    if not source_path or not os.path.isfile(source_path):
        return None
    try:
        with open(source_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(80_000)
    except OSError:
        return None

    pattern = re.compile(
        r"((?:extern\s+)?(?:\"C\"\s+)?"
        rf"(?:int|void|unsigned\s+int|size_t)\s+"
        rf"{re.escape(symbol)}\s*\([^;{{]*\)\s*;?)",
        re.MULTILINE,
    )
    match = pattern.search(text)
    if not match:
        return None
    decl = " ".join(match.group(1).split())
    if not decl.endswith(";"):
        decl += ";"
    return decl


def build_linked_harness_notes(
    finding: dict,
    source_basename: str | None,
    source_path: str | None,
) -> str:
    """Return mandatory instructions for linked native dynamic tests."""
    if not source_basename:
        return ""

    entry_symbol = extract_entry_symbol(finding)
    target_symbol = implementation_symbol(entry_symbol)
    stem = os.path.splitext(source_basename)[0]
    decl = extract_symbol_declaration(source_path, target_symbol)
    decl_line = f"- Use this declaration in the test harness: `{decl}`\n" if decl else ""

    notes = (
        "LINKED NATIVE BUILD (mandatory):\n"
        f"- The framework compiles `{source_basename}` and links it into `/work/test_exploit`.\n"
        f"- `/work/test_exploit` is the ONLY executable produced by the Docker build.\n"
    )
    if symbol_is_static_in_source(source_path, target_symbol):
        notes += (
            f"- `{target_symbol}()` is static — call a public library API from the module "
            f"header instead of reimplementing the helper.\n"
        )
    else:
        notes += (
            f"- Call `{target_symbol}(...)` directly from your test code.\n"
            f"{decl_line}"
        )
    notes += (
        f"- NEVER execl()/execv()/system() `/work/{stem}` or any path other than "
        f"`/work/test_exploit` — separate `{stem}` binaries are NOT built.\n"
        f"- Use vulscan_run_asan_child_void/ptr() from vulscan_native_compat.h "
        f"to invoke the target in a child — do NOT hand-roll fork/pipe/waitpid.\n"
        f"- Do NOT redirect stderr to /dev/null or call fclose(stderr)."
    )

    api_notes = build_library_api_harness_notes(finding, source_basename, source_path)
    if api_notes:
        notes += "\n" + api_notes
    return notes


def native_test_script_errors(
    test_script: str,
    source_basename: str | None = None,
    plan: NativeTestPlan | None = None,
) -> list[str]:
    """Return validation errors for a generated native test harness."""
    return validate_native_test_script(
        test_script,
        source_basename=source_basename,
        plan=plan,
    )
