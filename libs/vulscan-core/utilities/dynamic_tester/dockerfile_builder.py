"""Deterministic Dockerfile assembly and validation for dynamic tests.

The LLM generates exploit test logic; this module owns Dockerfile correctness.
For C/C++ findings with staged source files, the framework always emits a
canonical Dockerfile (COPY staged artifacts, compile, run) instead of trusting
model-generated Docker syntax (which often breaks on multi-line RUN heredocs).

For other languages, LLM Dockerfiles are kept but must pass structural validation.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field

from utilities.dynamic_tester.native_platform import list_staged_files_for_finding
from utilities.dynamic_tester.native_link_mode import should_compile_finding_source
from utilities.dynamic_tester.php_dockerfile import finalize_php_dockerfile
from utilities.dynamic_tester.native_test_plan import (
    DEFAULT_SANITIZER_FLAGS,
    NativeTestPlan,
)

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))

# Dockerfile instructions recognized by the parser (uppercase).
_DOCKER_INSTRUCTIONS = frozenset({
    "ADD", "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV", "EXPOSE", "FROM",
    "HEALTHCHECK", "LABEL", "MAINTAINER", "ONBUILD", "RUN", "SHELL",
    "STOPSIGNAL", "USER", "VOLUME", "WORKDIR",
})

_NATIVE_LANGUAGES = frozenset({"c", "cpp", "c++"})
_GO_LANGUAGES = frozenset({"go", "golang"})
_PYTHON_LANGUAGES = frozenset({"python", "py"})
_JS_LANGUAGES = frozenset({"javascript", "js", "typescript", "ts"})

_HEADER_SUFFIXES = (".h", ".hpp", ".hh", ".hxx")

_SOURCE_SUFFIXES = (".c", ".cpp", ".cxx", ".cc")

_INCLUDE_RE = re.compile(r'#\s*include\s+"([^"]+)"')

_COMPAT_HEADER = "vulscan_native_compat.h"
_COMPAT_SOURCE = "vulscan_native_compat.c"

_COMPAT_HEADER_LINES = [
    "#ifndef VULSCAN_NATIVE_COMPAT_H",
    "#define VULSCAN_NATIVE_COMPAT_H",
    "#include <stddef.h>",
    "#include <stdint.h>",
    "#ifndef __declspec",
    "#define __declspec(x)",
    "#endif",
    "#ifndef __stdcall",
    "#define __stdcall",
    "#endif",
    "#ifndef __cdecl",
    "#define __cdecl",
    "#endif",
    "#ifndef __fastcall",
    "#define __fastcall",
    "#endif",
    "#ifndef WINAPI",
    "#define WINAPI",
    "#endif",
    "#ifndef CALLBACK",
    "#define CALLBACK",
    "#endif",
    "#ifndef TRUE",
    "#define TRUE 1",
    "#endif",
    "#ifndef FALSE",
    "#define FALSE 0",
    "#endif",
    "#ifdef __cplusplus",
    'extern "C" {',
    "#endif",
    "extern unsigned char vulscan_afl_testcase_buf[1048576];",
    "extern unsigned int __afl_fuzz_len;",
    "#ifndef __AFL_FUZZ_INIT",
    "#define __AFL_FUZZ_INIT()",
    "#endif",
    "#ifndef __AFL_FUZZ_TESTCASE_BUF",
    "#define __AFL_FUZZ_TESTCASE_BUF vulscan_afl_testcase_buf",
    "#endif",
    "#ifndef __AFL_FUZZ_TESTCASE_LEN",
    "#define __AFL_FUZZ_TESTCASE_LEN __afl_fuzz_len",
    "#endif",
    "typedef struct {",
    "    int exit_code;",
    "    int signaled;",
    "    int signal_num;",
    "    char buf[65536];",
    "    size_t len;",
    "} vulscan_child_capture;",
    "vulscan_child_capture vulscan_run_asan_child_void(void (*fn)(void));",
    "vulscan_child_capture vulscan_run_asan_child_ptr(void (*fn)(void *), void *arg);",
    "int vulscan_has_sanitizer_evidence(const char *buf);",
    "int vulscan_has_differential_leak(const char *baseline, const char *malicious, size_t field_limit);",
    "void vulscan_emit_result_json(const char *status, const char *details, const char *evidence_content);",
    "#ifdef __cplusplus",
    "}",
    "#endif",
    "#endif",
]

_STRUCT_LAYOUT_HEADER = "vulscan_struct_layout.h"

_COMPAT_SOURCE_LINES = [
    f'#include "{_COMPAT_HEADER}"',
    "unsigned char vulscan_afl_testcase_buf[1048576];",
    "unsigned int __afl_fuzz_len;",
]


def _runtime_source_lines() -> list[str]:
    """Load the shared ASan child-process runtime linked into every native test."""
    path = os.path.join(_MODULE_DIR, "native_compat_runtime.c")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().splitlines()
    except OSError:
        return []


@dataclass
class StagedBuildContext:
    """Files and metadata available in the Docker build context."""

    language: str
    test_filename: str
    test_script: str
    staged_files: list[str] = field(default_factory=list)
    source_basename: str | None = None
    workdir: str = "/work"
    image: str = "gcc:13"
    runtime: str = "linux"
    sanitizer_flags: str = DEFAULT_SANITIZER_FLAGS
    struct_layout_header_lines: list[str] | None = None
    target_symbol: str = ""
    finding_source_path: str | None = None
    go_module_path: str | None = None

    @property
    def is_native(self) -> bool:
        return normalize_language(self.language) in _NATIVE_LANGUAGES

    @property
    def binary_path(self) -> str:
        return f"{self.workdir}/test_exploit"


def normalize_language(language: str) -> str:
    """Normalize repository language strings to a canonical token."""
    lang = (language or "").strip().lower()
    if lang in {"c++", "cxx"}:
        return "cpp"
    return lang


def infer_language_from_test_filename(test_filename: str) -> str | None:
    """Infer language from the generated test filename extension."""
    name = (test_filename or "").lower()
    if name.endswith((".cpp", ".cxx", ".cc")):
        return "cpp"
    if name.endswith(".c"):
        return "c"
    if name.endswith(".go"):
        return "go"
    return None


def collect_staged_files(work_dir: str) -> list[str]:
    """List regular files in the build context directory (excluding Dockerfile)."""
    if not os.path.isdir(work_dir):
        return []

    names: list[str] = []
    skip_dirs = {"attacker-server", ".vulscan-objects"}

    def walk_dir(base: str, prefix: str) -> None:
        for entry in sorted(os.listdir(base)):
            if entry in {"Dockerfile", "docker-compose.yml"}:
                continue
            path = os.path.join(base, entry)
            rel = f"{prefix}/{entry}" if prefix else entry
            if os.path.isfile(path):
                names.append(rel.replace("\\", "/"))
                continue
            if os.path.isdir(path) and entry not in skip_dirs:
                walk_dir(path, rel)

    walk_dir(work_dir, "")
    return names


def _includes_in_test(test_script: str) -> set[str]:
    return set(_INCLUDE_RE.findall(test_script or ""))


def _companion_translation_units(primary: str, staged_files: list[str]) -> list[str]:
    """Other staged .c files required to link *primary* (split library TUs)."""
    primary_stem = os.path.splitext(os.path.basename(primary))[0]
    companions: list[str] = []
    for name in staged_files:
        if not name.endswith((".c", ".cc", ".cpp", ".cxx")) or name == primary:
            continue
        entry_stem = os.path.splitext(os.path.basename(name))[0]
        if primary_stem.endswith("_Utils") and entry_stem == primary_stem[: -len("_Utils")]:
            companions.append(name)
    return companions


def _impl_unit_for_header(header: str) -> str | None:
    """Map #include \"foo.h\" to implementation filename foo.c / foo.cpp."""
    lower = header.lower()
    if lower.endswith(".hpp"):
        return header[:-4] + ".cpp"
    if lower.endswith((".hh", ".hxx")):
        return header[:-4] + ".cpp"
    if lower.endswith(".h"):
        return header[:-2] + ".c"
    return None


def _impl_units_for_header_includes(test_script: str, staged_files: list[str]) -> list[str]:
    """Link staged .c files that back headers included by the harness (e.g. cJSON.h -> cJSON.c)."""
    staged = set(staged_files)
    units: list[str] = []
    for hdr in _includes_in_test(test_script):
        impl = _impl_unit_for_header(hdr)
        if impl and impl in staged and impl not in units:
            units.append(impl)
    return units


def _copy_instruction(name: str) -> str:
    """Return a Dockerfile COPY line for a staged build-context path."""
    if "/" in name:
        dest_dir = os.path.dirname(name) or "."
        return f"COPY {name} {dest_dir}/"
    return f"COPY {name} ."


def _compile_sources(ctx: StagedBuildContext) -> list[str]:
    """Determine which translation units to pass to the compiler.

    Self-contained harnesses (static copy of a helper in test_exploit.c, no library
    headers) link only test_exploit.c. Harnesses that #include project headers get
    the matching .c from the build context (and split-library companions).
    """
    includes = _includes_in_test(ctx.test_script)
    sources: list[str] = []

    def add(path: str) -> None:
        if path and path not in sources:
            sources.append(path)

    def add_with_companions(path: str) -> None:
        add(path)
        for companion in _companion_translation_units(path, ctx.staged_files):
            add(companion)

    add(ctx.test_filename)

    for name in _impl_units_for_header_includes(ctx.test_script, ctx.staged_files):
        add_with_companions(name)

    for name in ctx.staged_files:
        if not name.endswith(_SOURCE_SUFFIXES):
            continue
        if name == ctx.test_filename:
            continue
        if name not in includes:
            continue
        add_with_companions(name)

    if (
        ctx.source_basename
        and ctx.source_basename != ctx.test_filename
        and should_compile_finding_source(
            ctx.test_script,
            ctx.source_basename,
            ctx.finding_source_path,
            ctx.target_symbol,
            ctx.staged_files,
        )
    ):
        add_with_companions(ctx.source_basename)

    _MAIN_EXCLUDE = frozenset({"main.c", "main.cpp", "main.cc", "main.cxx"})
    module_sources = [
        name
        for name in ctx.staged_files
        if name.endswith(_SOURCE_SUFFIXES)
        and name != ctx.test_filename
        and os.path.basename(name) not in _MAIN_EXCLUDE
    ]
    if len(module_sources) >= 2:
        for name in module_sources:
            add_with_companions(name)

    return sources


def _object_name_for_source(source_name: str) -> str:
    """Return a deterministic object filename for a staged source file."""
    stem = os.path.splitext(os.path.basename(source_name))[0]
    safe_stem = re.sub(r"[^A-Za-z0-9_]", "_", stem).strip("_") or "source"
    digest = hashlib.sha1(source_name.encode("utf-8")).hexdigest()[:8]
    return f"{safe_stem}_{digest}.o"


def _main_symbol_for_source(source_name: str) -> str:
    """Return a per-source replacement symbol for C/C++ main()."""
    stem = os.path.splitext(os.path.basename(source_name))[0]
    safe_stem = re.sub(r"[^A-Za-z0-9_]", "_", stem).strip("_") or "source"
    digest = hashlib.sha1(source_name.encode("utf-8")).hexdigest()[:8]
    return f"vulscan_target_main_{safe_stem}_{digest}"


def _shell_quote(value: str) -> str:
    """Single-quote a value for POSIX shell usage in generated Dockerfiles."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _printf_file_command(path: str, lines: list[str]) -> str:
    """Return a Docker RUN command that writes a small support file."""
    quoted_lines = " ".join(_shell_quote(line) for line in lines)
    return f"RUN printf '%s\\n' {quoted_lines} > {path}"


def build_windows_native_dockerfile(ctx: StagedBuildContext) -> str:
    """Build a Windows-container Dockerfile for native tests (experimental).

    Requires VULSCAN_WINDOWS_BUILDER_IMAGE pointing to an image that already
    contains a C/C++ toolchain (for example VS Build Tools or LLVM on Windows).
    There is no official lightweight gcc:13 equivalent for Windows containers.
    """
    from utilities.dynamic_tester.windows_runtime import (
        WINDOWS_NATIVE_IMAGE,
        windows_builder_image,
    )

    builder_image = windows_builder_image() or WINDOWS_NATIVE_IMAGE
    if not ctx.staged_files:
        raise ValueError("build_windows_native_dockerfile requires staged_files")

    copy_lines = "\n".join(_copy_instruction(name) for name in sorted(ctx.staged_files))
    binary = "C:/work/test_exploit.exe"
    test_file = ctx.test_filename.replace("/", "\\")

    return (
        f"# escape=`\n"
        f"FROM {builder_image}\n"
        f"WORKDIR C:/work\n"
        f"{copy_lines}\n"
        f"RUN cl /Fe:{binary} /EHsc /Zi {test_file}\n"
        f'CMD ["{binary}"]\n'
    )


def _is_cpp_source(name: str) -> bool:
    return name.lower().endswith((".cpp", ".cxx", ".cc"))


def _compiler_for_source(name: str, *, harness_is_cpp: bool) -> str:
    if _is_cpp_source(name):
        return "g++"
    if harness_is_cpp:
        return "g++"
    return "gcc"


def build_native_dockerfile(ctx: StagedBuildContext) -> str:
    """Build a canonical, parser-safe Dockerfile for C/C++ dynamic tests."""
    if not ctx.staged_files:
        raise ValueError("build_native_dockerfile requires staged_files")

    lang = normalize_language(ctx.language)
    harness_is_cpp = lang == "cpp" or _is_cpp_source(ctx.test_filename)
    sources = _compile_sources(ctx)
    target_sources = [source for source in sources if source != ctx.test_filename]
    has_cpp_objects = any(_is_cpp_source(source) for source in target_sources)
    link_compiler = "g++" if harness_is_cpp or has_cpp_objects else "gcc"
    harness_compiler = "g++" if harness_is_cpp else "gcc"

    copy_lines = "\n".join(_copy_instruction(name) for name in sorted(ctx.staged_files))
    binary = ctx.binary_path
    object_dir = f"{ctx.workdir}/.vulscan-objects"
    compat_header = f"{ctx.workdir}/{_COMPAT_HEADER}"
    compat_source = f"{ctx.workdir}/{_COMPAT_SOURCE}"
    compat_object = f"{object_dir}/vulscan_native_compat.o"
    runtime_source = f"{ctx.workdir}/vulscan_native_runtime.c"
    runtime_object = f"{object_dir}/vulscan_native_runtime.o"
    base_flags = ctx.sanitizer_flags
    harness_flags = base_flags + (" -fpermissive" if harness_is_cpp else "")
    link_flags = base_flags + (" -fpermissive" if link_compiler == "g++" else "")

    setup_lines: list[str] = [
        _printf_file_command(compat_header, _COMPAT_HEADER_LINES),
        _printf_file_command(compat_source, _COMPAT_SOURCE_LINES),
    ]
    runtime_lines = _runtime_source_lines()
    if runtime_lines:
        setup_lines.append(_printf_file_command(runtime_source, runtime_lines))
    if ctx.struct_layout_header_lines:
        layout_header = f"{ctx.workdir}/{_STRUCT_LAYOUT_HEADER}"
        setup_lines.append(
            _printf_file_command(layout_header, ctx.struct_layout_header_lines)
        )

    setup_lines.extend([
        f"RUN mkdir -p {object_dir}",
        f"RUN gcc {base_flags} -c {compat_source} -o {compat_object}",
    ])
    if runtime_lines:
        setup_lines.append(
            f"RUN gcc {base_flags} -c {runtime_source} -o {runtime_object}"
        )

    object_args: list[str] = [compat_object]
    if runtime_lines:
        object_args.append(runtime_object)
    if target_sources:
        for source in target_sources:
            obj_path = f"{object_dir}/{_object_name_for_source(source)}"
            object_args.append(obj_path)
            src_compiler = _compiler_for_source(source, harness_is_cpp=False)
            src_flags = base_flags + (" -fpermissive" if src_compiler == "g++" else "")
            setup_lines.append(
                f"RUN {src_compiler} {src_flags} -include {compat_header} "
                f"-Dmain={_main_symbol_for_source(source)} "
                f"-c {source} -o {obj_path}"
            )

    link_args = " ".join([ctx.test_filename] + object_args)
    if link_compiler == "g++" and ctx.test_filename.endswith(".c"):
        link_args = f"-x c {ctx.test_filename} -x none " + " ".join(object_args)
    setup = "\n".join(setup_lines)
    if setup:
        setup += "\n"

    return (
        f"FROM {ctx.image}\n"
        f"WORKDIR {ctx.workdir}\n"
        f"{copy_lines}\n"
        f"{setup}"
        f"RUN {link_compiler} {link_flags} -include {compat_header} "
        f"-o {binary} {link_args} -lm -pthread\n"
        f"RUN test -x {binary}\n"
        f'CMD ["{binary}"]\n'
    )


def build_go_dockerfile(ctx: StagedBuildContext) -> str:
    """Assemble a canonical Go Dockerfile with a staged local module replace."""
    module_path = ctx.go_module_path or "local/module"
    binary = ctx.binary_path
    vendor_copy = ""
    vendor_build = ""
    if "module/vendor/modules.txt" in ctx.staged_files:
        vendor_copy = "COPY module/vendor/ /module/vendor/\n"
        vendor_build = " -mod=vendor"
    return (
        f"FROM golang:1.25-alpine\n"
        f"WORKDIR {ctx.workdir}/test\n"
        f"ENV GOCACHE=/tmp/.gocache GOMODCACHE=/tmp/.gomodcache\n"
        f"COPY module/ /module/\n"
        f"{vendor_copy}"
        f"COPY {ctx.test_filename} .\n"
        f"RUN go mod init vulscan-test && "
        f"go mod edit -replace={module_path}=/module && "
        f"go mod tidy && "
        f"go build{vendor_build} -o {binary} .\n"
        f"RUN test -x {binary}\n"
        f'CMD ["{binary}"]\n'
    )


def build_python_dockerfile(ctx: StagedBuildContext) -> str:
    """Assemble a canonical Python Dockerfile from staged project files."""
    test_filename = ctx.test_filename
    req_name = "requirements.txt"
    for candidate in ("requirements.txt", "requirements-dev.txt"):
        if candidate in ctx.staged_files:
            req_name = candidate
            break

    install_lines = [
        f"RUN if [ -f {req_name} ]; then pip install --no-cache-dir -r {req_name}; fi",
        "RUN if [ -f pyproject.toml ]; then pip install --no-cache-dir .; "
        "elif [ -f setup.py ]; then pip install --no-cache-dir .; fi",
    ]
    return (
        "FROM python:3.11-slim\n"
        f"WORKDIR {ctx.workdir}\n"
        "COPY . .\n"
        + "\n".join(install_lines)
        + "\n"
        f'CMD ["python", "{test_filename}"]\n'
    )


def build_javascript_dockerfile(ctx: StagedBuildContext) -> str:
    """Assemble a canonical Node.js Dockerfile from staged project files."""
    test_filename = ctx.test_filename
    is_typescript = test_filename.endswith(".ts")
    npm_install = (
        "RUN if [ -f package-lock.json ]; then npm ci --omit=dev; "
        "elif [ -f package.json ]; then npm install --omit=dev; fi"
    )
    if is_typescript:
        npm_install += (
            "\nRUN npm install --no-save typescript ts-node @types/node"
        )
        cmd = f'CMD ["npx", "ts-node", "{test_filename}"]'
    else:
        cmd = f'CMD ["node", "{test_filename}"]'

    return (
        "FROM node:20-slim\n"
        f"WORKDIR {ctx.workdir}\n"
        "COPY . .\n"
        f"{npm_install}\n"
        f"{cmd}\n"
    )


def validate_dockerfile(dockerfile: str) -> list[str]:
    """Return human-readable validation errors; empty list means structurally OK."""
    if not dockerfile or not dockerfile.strip():
        return ["Dockerfile is empty"]

    errors: list[str] = []
    lines = dockerfile.splitlines()

    for line_no, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            continue

        instr_match = re.match(r"^([A-Za-z][A-Za-z0-9_]*)\b", stripped)
        if not instr_match:
            if _looks_like_embedded_source(stripped):
                errors.append(
                    f"Line {line_no}: content outside a Dockerfile instruction "
                    f"(likely a broken multi-line RUN): {stripped[:60]}"
                )
            continue

        instr = instr_match.group(1).upper()
        if instr not in _DOCKER_INSTRUCTIONS:
            errors.append(
                f"Line {line_no}: unknown Dockerfile instruction '{instr_match.group(1)}'"
            )
            continue

        if instr == "RUN" and _run_uses_unsafe_shell_heredoc(stripped):
            errors.append(
                f"Line {line_no}: RUN uses shell heredoc (<<); Docker parses following "
                "lines as separate instructions — use COPY for files instead"
            )

    if "from " not in dockerfile.lower():
        errors.append("Dockerfile missing FROM instruction")

    return errors


def _looks_like_embedded_source(line: str) -> bool:
    return bool(
        re.match(
            r"^(extern|#include|#pragma|#define|#ifdef|#ifndef|#endif|typedef|"
            r"void|int|char|struct|class|namespace)\b",
            line,
        )
    )


def _run_uses_unsafe_shell_heredoc(run_line: str) -> bool:
    """Detect `RUN cat > file << 'EOF'` without Docker BuildKit heredoc form."""
    if "<<" not in run_line:
        return False
    # BuildKit heredoc: RUN <<EOF (instruction-level heredoc)
    if re.match(r"^RUN\s+<<", run_line, re.IGNORECASE):
        return False
    return bool(re.search(r"<<\s*['\"]?\w+", run_line))


def should_use_python_builder(language: str, test_filename: str) -> bool:
    lang = normalize_language(language)
    if lang in _PYTHON_LANGUAGES:
        return True
    return (test_filename or "").lower().endswith(".py")


def should_use_javascript_builder(language: str, test_filename: str) -> bool:
    lang = normalize_language(language)
    if lang in _JS_LANGUAGES:
        return True
    name = (test_filename or "").lower()
    return name.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"))


def should_use_go_builder(
    language: str,
    test_filename: str,
    staged_files: list[str],
) -> bool:
    """Whether the framework should assemble the Go Dockerfile."""
    lang = normalize_language(language)
    if lang not in _GO_LANGUAGES:
        inferred = infer_language_from_test_filename(test_filename)
        if inferred != "go":
            return False
    return "module/go.mod" in staged_files


def should_use_native_builder(
    language: str,
    test_filename: str,
    staged_files: list[str],
) -> bool:
    """Whether the framework should assemble the Dockerfile instead of the LLM."""
    if not staged_files:
        return False
    lang = normalize_language(language)
    if lang in _NATIVE_LANGUAGES:
        return True
    inferred = infer_language_from_test_filename(test_filename)
    return inferred in _NATIVE_LANGUAGES


def should_use_framework_builder(
    language: str,
    test_filename: str,
    staged_files: list[str],
) -> bool:
    """Whether the framework owns Dockerfile generation for this language."""
    if should_use_native_builder(language, test_filename, staged_files):
        return True
    if should_use_go_builder(language, test_filename, staged_files):
        return True
    if should_use_python_builder(language, test_filename):
        return True
    if should_use_javascript_builder(language, test_filename):
        return True
    return False


def finalize_dockerfile(
    llm_dockerfile: str,
    *,
    language: str,
    test_filename: str,
    test_script: str,
    staged_files: list[str],
    source_basename: str | None = None,
    runtime: str = "linux",
    native_plan: NativeTestPlan | None = None,
    go_module_path: str | None = None,
) -> str:
    """Produce the Dockerfile that will actually be written to the build context."""
    if should_use_go_builder(language, test_filename, staged_files):
        lang = normalize_language(language)
        inferred = infer_language_from_test_filename(test_filename)
        effective_lang = lang if lang in _GO_LANGUAGES else (inferred or lang)
        ctx = StagedBuildContext(
            language=effective_lang,
            test_filename=test_filename,
            test_script=test_script,
            staged_files=sorted(set(staged_files)),
            source_basename=source_basename,
            runtime=runtime,
            go_module_path=go_module_path,
            image="golang:1.25-alpine",
        )
        return build_go_dockerfile(ctx)

    if should_use_native_builder(language, test_filename, staged_files):
        lang = normalize_language(language)
        inferred = infer_language_from_test_filename(test_filename)
        effective_lang = lang if lang in _NATIVE_LANGUAGES else (inferred or lang)
        ctx = StagedBuildContext(
            language=effective_lang,
            test_filename=test_filename,
            test_script=test_script,
            staged_files=sorted(set(staged_files)),
            source_basename=source_basename,
            runtime=runtime,
            sanitizer_flags=(
                native_plan.sanitizer_flags if native_plan else DEFAULT_SANITIZER_FLAGS
            ),
            struct_layout_header_lines=(
                native_plan.struct_layout_header_lines() if native_plan else None
            ),
            target_symbol=native_plan.target_symbol if native_plan else "",
            finding_source_path=(
                native_plan.finding_source_path if native_plan else None
            ),
        )
        if runtime == "windows":
            return build_windows_native_dockerfile(ctx)
        return build_native_dockerfile(ctx)

    if should_use_python_builder(language, test_filename):
        ctx = StagedBuildContext(
            language=normalize_language(language) or "python",
            test_filename=test_filename,
            test_script=test_script,
            staged_files=sorted(set(staged_files)),
            source_basename=source_basename,
            runtime=runtime,
            workdir="/work",
            image="python:3.11-slim",
        )
        return build_python_dockerfile(ctx)

    if should_use_javascript_builder(language, test_filename):
        ctx = StagedBuildContext(
            language=normalize_language(language) or "javascript",
            test_filename=test_filename,
            test_script=test_script,
            staged_files=sorted(set(staged_files)),
            source_basename=source_basename,
            runtime=runtime,
            workdir="/work",
            image="node:20-slim",
        )
        return build_javascript_dockerfile(ctx)

    errors = validate_dockerfile(llm_dockerfile)
    if errors:
        # Non-native: return LLM output; docker build will fail with a clear error.
        return llm_dockerfile
    lang_norm = normalize_language(language)
    if lang_norm == "php":
        return finalize_php_dockerfile(llm_dockerfile)
    return llm_dockerfile


def apply_dockerfile_finalization(
    generation: dict,
    *,
    staged_files: list[str] | None = None,
    source_basename: str | None = None,
    language: str | None = None,
    runtime: str = "linux",
    native_plan: NativeTestPlan | None = None,
    go_module_path: str | None = None,
) -> dict:
    """Return a copy of *generation* with a finalized Dockerfile."""
    test_filename = generation.get("test_filename", "test_exploit.py")
    test_script = generation.get("test_script", "")
    lang = language or generation.get("_language") or infer_language_from_test_filename(
        test_filename
    ) or "python"

    dockerfile = finalize_dockerfile(
        generation.get("dockerfile", ""),
        language=lang,
        test_filename=test_filename,
        test_script=test_script,
        staged_files=staged_files or [],
        source_basename=source_basename,
        runtime=runtime,
        native_plan=native_plan,
        go_module_path=go_module_path,
    )
    out = dict(generation)
    out["dockerfile"] = dockerfile

    req_name = (generation.get("requirements_filename") or "").lower()
    if normalize_language(lang) == "php" and req_name == "composer.json" and generation.get("requirements"):
        from utilities.dynamic_tester.php_dockerfile import sanitize_composer_json_text
        out["requirements"] = sanitize_composer_json_text(generation["requirements"])

    return out
