"""Native (C/C++) dynamic test planning — single source of truth.

Encapsulates test strategy selection, sanitizer flags, struct layout extraction,
payload hints, harness validation rules, and sanitizer output detection markers.
The LLM generates exploit logic; the framework owns IO patterns, layouts, and
classification semantics.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from utilities.dynamic_tester.native_symbols import (
    extract_entry_symbol,
    implementation_symbol,
)

# ---------------------------------------------------------------------------
# Detection markers (shared with result_collector)
# ---------------------------------------------------------------------------

SANITIZER_CONFIRMATION_MARKERS: tuple[str, ...] = (
    "ERROR: AddressSanitizer",
    "AddressSanitizer:",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "stack-buffer-underflow",
    "heap-use-after-free",
    "double-free",
    "attempting free on address which was not malloc",
    "allocation-size-too-big",
    "negative-size-param",
    "runtime error: signed integer overflow",
    "runtime error: unsigned integer overflow",
    "runtime error: division by zero",
    "runtime error: null pointer passed",
    "FPE",
    "SIGSEGV",
    "SIGABRT",
    "SEGV on unknown address",
)

HARNESS_FAILURE_MARKERS: tuple[str, ...] = (
    "exit code 127",
    "exit=127",
    "exit code: 127",
    "execl:",
    "execv:",
    "execve:",
    "no such file or directory",
    "cannot execute",
    "command not found",
    "child signaled 13",
    "signal 13",
    "sigpipe",
)

# ---------------------------------------------------------------------------
# Test strategies
# ---------------------------------------------------------------------------

class NativeTestStrategy(str, Enum):
    """How a native finding should be dynamically verified."""

    ASAN_CRASH = "asan_crash"
    DIFFERENTIAL_OUTPUT = "differential_output"
    ASAN_AND_DIFFERENTIAL = "asan_and_differential"


# CWE → default strategy
_CWE_STRATEGY: dict[int, NativeTestStrategy] = {
    125: NativeTestStrategy.ASAN_AND_DIFFERENTIAL,  # OOB read
    200: NativeTestStrategy.DIFFERENTIAL_OUTPUT,      # info exposure
    787: NativeTestStrategy.ASAN_CRASH,             # OOB write
    788: NativeTestStrategy.ASAN_CRASH,             # heap overflow
    121: NativeTestStrategy.ASAN_CRASH,
    122: NativeTestStrategy.ASAN_CRASH,
    190: NativeTestStrategy.ASAN_CRASH,             # integer overflow
    191: NativeTestStrategy.ASAN_CRASH,
    415: NativeTestStrategy.ASAN_CRASH,             # double free
    416: NativeTestStrategy.ASAN_CRASH,             # UAF
}

# Base sanitizer flags per strategy
_STRATEGY_SANITIZERS: dict[NativeTestStrategy, str] = {
    NativeTestStrategy.ASAN_CRASH: (
        "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O0"
    ),
    NativeTestStrategy.DIFFERENTIAL_OUTPUT: (
        "-fsanitize=undefined -fno-omit-frame-pointer -g -O0"
    ),
    NativeTestStrategy.ASAN_AND_DIFFERENTIAL: (
        "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O0"
    ),
}

DEFAULT_SANITIZER_FLAGS = _STRATEGY_SANITIZERS[NativeTestStrategy.ASAN_CRASH]

# ---------------------------------------------------------------------------
# Struct layout extraction
# ---------------------------------------------------------------------------

_STRUCT_RE = re.compile(
    r"struct\s+(\w+)\s*\{([^}]*)\}",
    re.MULTILINE,
)

_FIELD_ARRAY_RE = re.compile(
    r"(?:unsigned\s+)?(?:signed\s+)?char\s+(\w+)\s*\[(\d+)\]",
)
_FIELD_SCALAR_RE = re.compile(
    r"(?:unsigned\s+)?(?:signed\s+)?(?:int|long|short|size_t)\s+(\w+)\s*;",
)

_SCALAR_SIZE = 4  # 32/64-bit int on Linux x86_64 for planning purposes


@dataclass(frozen=True)
class StructField:
    name: str
    size_bytes: int
    declaration: str


@dataclass(frozen=True)
class StructLayout:
    name: str
    fields: tuple[StructField, ...]
    body: str

    @property
    def estimated_size(self) -> int:
        return sum(f.size_bytes for f in self.fields)


def extract_struct_layouts(source_text: str) -> list[StructLayout]:
    """Extract top-level struct definitions from C/C++ source text."""
    layouts: list[StructLayout] = []
    for match in _STRUCT_RE.finditer(source_text or ""):
        name = match.group(1)
        body = match.group(2)
        fields: list[StructField] = []
        for fm in _FIELD_ARRAY_RE.finditer(body):
            fields.append(StructField(
                name=fm.group(1),
                size_bytes=int(fm.group(2)),
                declaration=fm.group(0).strip(),
            ))
        for fm in _FIELD_SCALAR_RE.finditer(body):
            fields.append(StructField(
                name=fm.group(1),
                size_bytes=_SCALAR_SIZE,
                declaration=fm.group(0).strip(),
            ))
        if fields:
            layouts.append(StructLayout(name=name, fields=tuple(fields), body=body.strip()))
    return layouts


def format_struct_layout_section(layouts: list[StructLayout]) -> str:
    """Human-readable struct layout block for LLM prompts."""
    if not layouts:
        return ""
    lines = [
        "STRUCT LAYOUT (from staged source — use exactly, do NOT invent partial headers):",
    ]
    for layout in layouts:
        lines.append(f"  struct {layout.name} {{ ... }}  estimated sizeof = {layout.estimated_size} bytes")
        for fld in layout.fields:
            lines.append(f"    - {fld.declaration}  ({fld.size_bytes} bytes)")
        lines.append(
            f"  Write payloads with fwrite(&instance, sizeof(struct {layout.name}), 1, fp)."
        )
    return "\n".join(lines)


def build_struct_layout_header(layouts: list[StructLayout]) -> list[str]:
    """Generate C header lines injected into the Docker build."""
    if not layouts:
        return []
    lines = [
        "/* Auto-generated struct layout reference — do not edit. */",
        "#ifndef VULSCAN_STRUCT_LAYOUT_H",
        "#define VULSCAN_STRUCT_LAYOUT_H",
    ]
    for layout in layouts:
        macro = f"VULSCAN_SIZEOF_{layout.name.upper()}"
        lines.append(f"#define {macro} {layout.estimated_size}")
        lines.append(f"/* struct {layout.name} estimated {layout.estimated_size} bytes */")
    lines.append("#endif")
    return lines


# ---------------------------------------------------------------------------
# Payload hints from static analysis text
# ---------------------------------------------------------------------------

_PAYLOAD_KV_RE = re.compile(
    r"\b(width|height|size|length|count)\s*=\s*(0x[0-9a-fA-F]+|-?\d+)\b",
    re.IGNORECASE,
)

_FWRITE_SIZE_RE = re.compile(
    r"fwrite\s*\([^,]+,\s*(?:sizeof\s*\([^)]+\)|(\d+))\s*,",
    re.IGNORECASE,
)


def extract_payload_hints(*texts: str | None) -> dict[str, str]:
    """Extract width/height/size hints from finding description or steps."""
    hints: dict[str, str] = {}
    combined = "\n".join(t for t in texts if t)
    for match in _PAYLOAD_KV_RE.finditer(combined):
        key = match.group(1).lower()
        if key not in hints:
            hints[key] = match.group(2)
    return hints


def format_payload_hints_section(hints: dict[str, str]) -> str:
    if not hints:
        return ""
    pairs = ", ".join(f"{k}={v}" for k, v in sorted(hints.items()))
    return (
        "RECOMMENDED PAYLOAD (from static analysis — try these BEFORE weaker values):\n"
        f"  {pairs}"
    )


# ---------------------------------------------------------------------------
# Proven exploit registry (batch learning)
# ---------------------------------------------------------------------------

@dataclass
class ProvenExploit:
    finding_id: str
    source_basename: str
    target_symbol: str
    payload_snippet: str


class ProvenExploitRegistry:
    """Collect CONFIRMED exploits within a batch for sibling findings."""

    def __init__(self) -> None:
        self._entries: list[ProvenExploit] = []

    def register(
        self,
        finding_id: str,
        source_basename: str,
        target_symbol: str,
        test_script: str,
    ) -> None:
        snippet = _extract_payload_snippet(test_script)
        if not snippet:
            return
        self._entries.append(ProvenExploit(
            finding_id=finding_id,
            source_basename=source_basename,
            target_symbol=target_symbol,
            payload_snippet=snippet,
        ))

    def hints_for(self, source_basename: str, target_symbol: str) -> str:
        matches = [
            e for e in self._entries
            if e.source_basename == source_basename
            and e.target_symbol == target_symbol
        ]
        if not matches:
            return ""
        lines = ["PROVEN PAYLOAD (CONFIRMED on sibling finding in this batch):"]
        for entry in matches[-2:]:
            lines.append(f"  From {entry.finding_id}:")
            lines.append(f"```c\n{entry.payload_snippet}\n```")
        lines.append(
            "Reuse this struct layout and field values unless your finding "
            "targets a clearly different code path."
        )
        return "\n".join(lines)


def _extract_payload_snippet(test_script: str, max_lines: int = 40) -> str:
    """Extract payload-construction portion from a generated test script."""
    if not test_script:
        return ""
    keywords = ("struct ", "fwrite", "memcpy", "payload", "width", "height", "header")
    lines = test_script.splitlines()
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if any(kw in line for kw in keywords):
            current.append(line)
        elif current:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)
    if not blocks:
        return ""
    best = max(blocks, key=len)
    return "\n".join(best[:max_lines])


# ---------------------------------------------------------------------------
# Native test plan
# ---------------------------------------------------------------------------

@dataclass
class NativeTestPlan:
    """Complete native test configuration for one finding."""

    cwe_id: int
    strategy: NativeTestStrategy
    sanitizer_flags: str
    struct_layouts: list[StructLayout] = field(default_factory=list)
    payload_hints: dict[str, str] = field(default_factory=dict)
    target_symbol: str = ""
    source_basename: str = ""
    finding_source_path: str | None = None
    prompt_sections: list[str] = field(default_factory=list)

    @property
    def primary_struct_size(self) -> int | None:
        if not self.struct_layouts:
            return None
        return max(layout.estimated_size for layout in self.struct_layouts)

    def struct_layout_header_lines(self) -> list[str]:
        return build_struct_layout_header(self.struct_layouts)


def strategy_for_cwe(cwe_id: int) -> NativeTestStrategy:
    return _CWE_STRATEGY.get(cwe_id, NativeTestStrategy.ASAN_CRASH)


def build_native_test_plan(
    finding: dict,
    *,
    repo_path: str | None = None,
    source_path: str | None = None,
    source_basename: str | None = None,
    registry: ProvenExploitRegistry | None = None,
) -> NativeTestPlan | None:
    """Build a native test plan when the finding targets C/C++ code."""
    cwe_id = int(finding.get("cwe_id") or 0)
    strategy = strategy_for_cwe(cwe_id)
    sanitizer_flags = _STRATEGY_SANITIZERS[strategy]

    entry_symbol = extract_entry_symbol(finding)
    target_symbol = implementation_symbol(entry_symbol)

    struct_layouts: list[StructLayout] = []
    if source_path and os.path.isfile(source_path):
        try:
            with open(source_path, "r", encoding="utf-8", errors="replace") as handle:
                struct_layouts = extract_struct_layouts(handle.read(160_000))
        except OSError:
            pass

    payload_hints = extract_payload_hints(
        finding.get("description"),
        finding.get("steps_to_reproduce"),
        finding.get("vulnerable_code"),
    )

    sections: list[str] = [_strategy_instructions(strategy, cwe_id)]

    struct_section = format_struct_layout_section(struct_layouts)
    if struct_section:
        sections.append(struct_section)

    hint_section = format_payload_hints_section(payload_hints)
    if hint_section:
        sections.append(hint_section)

    if registry and source_basename:
        proven = registry.hints_for(source_basename, target_symbol)
        if proven:
            sections.append(proven)

    sections.append(_runtime_api_instructions())

    from utilities.dynamic_tester.native_link_mode import build_library_api_harness_notes

    api_notes = build_library_api_harness_notes(
        finding, source_basename, source_path
    )
    if api_notes:
        sections.append(api_notes)

    return NativeTestPlan(
        cwe_id=cwe_id,
        strategy=strategy,
        sanitizer_flags=sanitizer_flags,
        struct_layouts=struct_layouts,
        payload_hints=payload_hints,
        target_symbol=target_symbol,
        source_basename=source_basename or "",
        finding_source_path=source_path,
        prompt_sections=sections,
    )


def _strategy_instructions(strategy: NativeTestStrategy, cwe_id: int) -> str:
    lines = [f"NATIVE TEST STRATEGY: {strategy.value} (CWE-{cwe_id or 'unknown'})"]
    if strategy in {NativeTestStrategy.ASAN_CRASH, NativeTestStrategy.ASAN_AND_DIFFERENTIAL}:
        lines.extend([
            "- Invoke the target in a child process using vulscan_run_asan_child() "
            "from vulscan_native_compat.h (do NOT hand-roll fork/pipe/waitpid).",
            "- CONFIRMED when stderr contains AddressSanitizer/UBSan output, "
            "the child exits non-zero, or the child is killed by SIGABRT/SIGSEGV.",
        ])
    if strategy in {
        NativeTestStrategy.DIFFERENTIAL_OUTPUT,
        NativeTestStrategy.ASAN_AND_DIFFERENTIAL,
    }:
        lines.extend([
            "- For non-crashing vulnerabilities (OOB read / info leak): run TWO payloads.",
            "  1) baseline: strings terminated with \\0 within declared bounds",
            "  2) malicious: same layout but NO \\0 in fixed char[] fields",
            "- CONFIRMED when malicious stdout is longer or contains bytes absent "
            "from baseline output (attach both outputs as evidence).",
            "- Do NOT rely solely on field-length parsing of tab-separated printf output.",
        ])
    return "\n".join(lines)


def _runtime_api_instructions() -> str:
    return (
        "FRAMEWORK RUNTIME API (vulscan_native_compat.h):\n"
        "- vulscan_child_capture vulscan_run_asan_child_void(void (*fn)(void));\n"
        "- vulscan_child_capture vulscan_run_asan_child_ptr(void (*fn)(void*), void *arg);\n"
        "- int vulscan_has_sanitizer_evidence(const char *buf);\n"
        "- int vulscan_has_differential_leak(const char *baseline, const char *malicious, "
        "size_t field_limit);\n"
        "- Fields in vulscan_child_capture: exit_code, signaled, signal_num, buf[], len.\n"
        "- Parent MUST use these helpers — they wait for the child before reading stderr "
        "(avoids SIGPIPE false positives)."
    )


# ---------------------------------------------------------------------------
# Harness validation (used by native_harness.py)
# ---------------------------------------------------------------------------

_EXEC_CALL_RE = re.compile(
    r"\b(?:execl|execle|execlp|execv|execve|execvp|system)\s*\(",
    re.IGNORECASE,
)

_WORK_BINARY_RE = re.compile(
    r"""['"]/?work/(?!test_exploit)[^'"]+['"]""",
    re.IGNORECASE,
)

_STDERR_DEVNULL_RE = re.compile(
    r'freopen\s*\(\s*["\']/dev/null["\']\s*,\s*["\']w["\']\s*,\s*stderr\s*\)',
    re.IGNORECASE,
)

_FCLOSE_STDERR_RE = re.compile(r"\bfclose\s*\(\s*stderr\s*\)", re.IGNORECASE)


def validate_native_test_script(
    test_script: str,
    *,
    source_basename: str | None = None,
    plan: NativeTestPlan | None = None,
) -> list[str]:
    """Return validation errors for a generated native harness."""
    script = test_script or ""
    errors: list[str] = []

    if _EXEC_CALL_RE.search(script):
        errors.append(
            "uses execl/execv/system(); call the linked vulnerable function directly"
        )

    if _WORK_BINARY_RE.search(script):
        errors.append("references a /work/* binary other than /work/test_exploit")

    if source_basename:
        stem = os.path.splitext(source_basename)[0]
        if re.search(rf'["\']/?work/{re.escape(stem)}["\']', script, re.IGNORECASE):
            errors.append(f"tries to execute /work/{stem}, which is not built")

    if _STDERR_DEVNULL_RE.search(script):
        errors.append("redirects stderr to /dev/null (hides sanitizer output)")

    if _FCLOSE_STDERR_RE.search(script):
        errors.append("calls fclose(stderr) (loses sanitizer output / causes SIGPIPE)")

    if re.search(
        r'printf\s*\(\s*["\']\s*\{\s*["\']?\s*status',
        script,
        re.IGNORECASE,
    ):
        errors.append(
            "uses printf with literal JSON template; call vulscan_emit_result_json() instead"
        )

    if re.search(r"\bstrncopy\s*\(", script, re.IGNORECASE):
        errors.append("typo strncopy — use strncpy")

    if plan and plan.primary_struct_size:
        expected = plan.primary_struct_size
        for match in _FWRITE_SIZE_RE.finditer(script):
            literal = match.group(1)
            if literal and int(literal) < expected:
                errors.append(
                    f"fwrite size {literal} bytes is smaller than expected "
                    f"struct size {expected} bytes"
                )
        if re.search(r"struct\s+\w+\s*\{[^}]*\}\s*\w+\s*;", script):
            if "sizeof" not in script and "fwrite" in script:
                errors.append(
                    "defines inline struct for payload but never uses sizeof(); "
                    "include staged struct layout instead"
                )

    return errors


def get_cwe_guidance(cwe_id: int) -> str:
    """CWE-specific guidance for dynamic test generation prompts."""
    guidance = {
        22: (
            "Path Traversal: read /etc/passwd or a file outside the intended directory. "
            "Evidence should show inaccessible file contents."
        ),
        78: (
            "OS Command Injection: inject `id` or `echo PWNED`. "
            "Evidence should show command output."
        ),
        79: "XSS: inject script tag or event handler; evidence shows unescaped output.",
        89: (
            "SQL Injection: UNION SELECT or boolean-based injection; "
            "evidence shows unexpected data or behavior change."
        ),
        94: (
            "Code Injection: inject code that creates a marker file or prints a secret."
        ),
        125: (
            "Out-of-bounds Read: run baseline (null-terminated) AND malicious "
            "(no null in fixed char[]) payloads. Compare captured stdout lengths/content. "
            "Also try vulscan_run_asan_child — some reads trigger ASan READ reports."
        ),
        134: "Format String: inject %s or {0}; evidence shows format interpretation.",
        190: (
            "Integer Overflow: use width/height values from static analysis that wrap "
            "size calculations (e.g. 0x7FFFFFFF + 2). UBSan may report signed overflow."
        ),
        200: (
            "Information Exposure: differential test — restricted data must appear "
            "in malicious run output but not baseline."
        ),
        502: (
            "Deserialization: inject malicious serialized object; "
            "evidence shows code execution or unexpected behavior."
        ),
        918: (
            "SSRF: request attacker capture server at http://attacker:9999; "
            "check /logs for captured requests."
        ),
    }
    return guidance.get(cwe_id, "")


def uses_native_sanitizer(dockerfile: str) -> bool:
    """True when the Dockerfile compiles with any -fsanitize flag."""
    return "-fsanitize=" in (dockerfile or "")
