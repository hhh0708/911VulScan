"""Shared symbol extraction helpers for native dynamic tests."""

from __future__ import annotations

import re

_SYMBOL_FROM_LOCATION_RE = re.compile(r":(\w+)\s*$")

# Thin Windows harness symbols that delegate to a core implementation elsewhere.
_HARNESS_SYMBOLS = {"fuzzme", "main", "dllmain", "wmain"}


def extract_entry_symbol(finding: dict) -> str | None:
    """Best-effort symbol name from finding location metadata."""
    loc = finding.get("location", {})
    if not isinstance(loc, dict):
        return None

    func = loc.get("function", "")
    if isinstance(func, str) and func:
        match = _SYMBOL_FROM_LOCATION_RE.search(func.strip())
        if match:
            return match.group(1)
        if ":" not in func:
            token = func.split(".")[-1].strip()
            if token:
                return token

    description = finding.get("description", "") or ""
    for symbol in ("ProcessImage", "LLVMFuzzerTestOneInput", "FuzzMe"):
        if symbol in description:
            return symbol
    return None


def implementation_symbol(entry_symbol: str | None) -> str:
    """Map a harness entry symbol to the function that holds the bug."""
    if entry_symbol and entry_symbol.lower() in _HARNESS_SYMBOLS:
        return "ProcessImage"
    return entry_symbol or "ProcessImage"
