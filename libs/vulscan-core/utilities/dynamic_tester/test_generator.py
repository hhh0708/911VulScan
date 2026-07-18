"""LLM-based dynamic test generation using Claude Sonnet.

For each finding, generates:
- A Dockerfile that installs the target library/app at the correct version
- A test script that attempts the exploit and prints structured JSON results
- A docker-compose.yml if the test needs multiple services (e.g., attacker capture server)
"""

import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from utilities.dynamic_tester.dockerfile_builder import (
    apply_dockerfile_finalization,
    list_staged_files_for_finding,
    normalize_language,
    should_use_go_builder,
    should_use_native_builder,
    validate_dockerfile,
)
from utilities.dynamic_tester.native_platform import resolve_native_test_source
from utilities.dynamic_tester.staging_limits import resolve_repo_file
from utilities.dynamic_tester.native_harness import (
    build_linked_harness_notes,
    native_test_script_errors,
)
from utilities.dynamic_tester.native_link_mode import sanitize_native_test_script
from utilities.dynamic_tester.compile_error_repair import (
    apply_deterministic_compile_fixes,
    deterministic_repair_generation,
    extract_compiler_diagnostics,
    is_native_test_script,
    script_has_c_preprocessor,
    sanitize_high_level_test_script,
)
from utilities.dynamic_tester.native_test_plan import (
    NativeTestPlan,
    ProvenExploitRegistry,
    build_native_test_plan,
    get_cwe_guidance,
)
from utilities.llm_client import AnthropicClient, TokenTracker
from utilities.llm_pricing import format_cost
from utilities.model_registry import ModelRole, model_for

# Model used for dynamic exploit-test generation. Historically this constant was
# named SONNET_MODEL but pointed at the opus (PRIMARY) id; the role mapping keeps
# that exact behavior while removing the misleading name.
TEST_GENERATION_MODEL = model_for(ModelRole.PRIMARY)

# Map language strings to Dockerfile template names
LANGUAGE_MAP = {
    "python": "python",
    "javascript": "node",
    "typescript": "node",
    "js": "node",
    "ts": "node",
    "go": "go",
    "golang": "go",
}

SYSTEM_PROMPT = """\
You are an expert security researcher generating dynamic exploit tests.

You will receive one vulnerability finding from a static analysis pipeline. Your job is to generate
a self-contained Docker-based test that attempts to reproduce the vulnerability.

GENERAL RULES:
1. The test MUST run inside a Docker container. Never assume host access.
2. The test MUST be minimal and focused on the specific vulnerability.
3. The test MUST finish within 60 seconds.
4. The test MUST print exactly ONE JSON object to stdout as its final output, with this schema:
   {"status": "CONFIRMED|NOT_REPRODUCED|BLOCKED|INCONCLUSIVE|ERROR", "details": "...", "evidence": [{"type": "file_read|http_response|command_output|network_capture", "content": "..."}]}
5. Do NOT print anything else to stdout. Use stderr for debug logging.
6. If the vulnerability cannot be reproduced automatically, return a test that prints INCONCLUSIVE or NOT_REPRODUCED.
7. Do NOT return analysis prose, markdown, or multiple candidate JSON objects.
8. Immediately before invoking the target function/endpoint, print
   `TARGET_REACHED:<target>` to stderr. Do not print this marker if the
   target was not actually invoked.
9. Every payload MUST satisfy all REPRO CHECKS from the finding. If the
   checks cannot be satisfied through the stated entry point, emit
   INCONCLUSIVE rather than constructing an unrelated local reproduction.

OUTPUT FORMAT:
Return exactly ONE valid JSON object with these keys:
- "dockerfile": string — complete Dockerfile content
- "test_script": string — complete test script content
- "test_filename": string — filename for the test script
- "requirements": string — dependency file content, or empty string
- "requirements_filename": string — dependency filename, or "requirements.txt"
- "docker_compose": string | null — docker-compose.yml content if multi-service, null if single container
- "needs_attacker_server": boolean — whether the test needs the attacker capture server

STRICT JSON RULES:
- Return ONLY one JSON object.
- Do NOT include explanations before or after the JSON.
- Do NOT wrap the JSON in markdown fences.
- Do NOT return multiple JSON objects.
- Escape all newlines inside JSON strings as \n.
- Escape all quotes inside JSON strings correctly.
- The JSON object must be parseable by json.loads.

COMMON DOCKER RULES:
- The repository source file mentioned in the prompt is already staged in the Docker build context.
- If the prompt says "Source file: X", the Dockerfile MUST use COPY X .
- The Dockerfile MUST copy the generated test script using COPY <test_filename> .
- Use /work or /test as the directory for source files, generated test files, and compiled binaries.
- Do NOT use /tmp as WORKDIR.
- Do NOT put the main executable or test script under /tmp.
- /tmp may be mounted as a fresh writable tmpfs at runtime, which can hide files copied into /tmp during image build.
- Use /tmp only for runtime temporary files, caches, and logs created after the container starts.
- Do NOT write files to $HOME, /root, /app/data, or other persistent locations at runtime.
- Avoid network access during test execution unless the finding requires it.
- Use build-time dependency installation only in the Dockerfile.
- The final CMD must run the generated test script or compiled test binary outside /tmp.
- If using a compiler or package manager, install only minimal dependencies.
- Docker build commands MUST fail fast. Do NOT hide build errors.
- Never use `|| true`, `|| echo BUILD FAILED`, `|| echo`, or any fallback that lets Docker build continue after compiler failure.
- Never write `gcc ... && echo BUILD OK || echo BUILD FAILED`.
- If compilation is required, the Dockerfile MUST include a direct failing compile command, followed by an executable check.
- Good pattern:
  RUN gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 -o /work/test_exploit test_exploit.c
  RUN test -x /work/test_exploit
- Bad pattern:
  RUN gcc ... && echo BUILD OK || echo BUILD FAILED
- NEVER embed source or header file contents inside the Dockerfile.
- NEVER use shell heredoc in RUN (e.g. RUN cat > file.h << 'EOF'). Docker treats each following line as a new instruction unless every line ends with \\.
- ALWAYS use COPY for files that are already in the build context.
- Each logical step must be its own Dockerfile instruction (FROM, WORKDIR, COPY, RUN, CMD).

LANGUAGE-SPECIFIC RULES:

Python:
- Use "test_filename": "test_exploit.py".
- Use a Python base image, such as python:3.12-slim.
- Put Python dependencies in "requirements" and use "requirements_filename": "requirements.txt".
- If no dependencies are needed, set "requirements" to "" and still set "requirements_filename": "requirements.txt".
- Set PYTHONDONTWRITEBYTECODE=1.
- The Python script must print exactly one JSON object to stdout at the end.

JavaScript:
- Use "test_filename": "test_exploit.js".
- Use a Node.js base image, such as node:22-slim.
- Put dependencies in "requirements" as package.json content and use "requirements_filename": "package.json".
- If no dependencies are needed, package.json can contain a minimal package with "type": "commonjs".
- The Dockerfile should run npm install only if package.json declares dependencies.
- The JS script must print exactly one JSON object to stdout at the end.

TypeScript:
- Use "test_filename": "test_exploit.ts".
- Use a Node.js base image, such as node:22-slim.
- Put dependencies in "requirements" as package.json content and use "requirements_filename": "package.json".
- Include tsx or ts-node in devDependencies if needed.
- The Dockerfile should run npm install and then run the test using npx tsx test_exploit.ts or npx ts-node test_exploit.ts.
- The TypeScript script must print exactly one JSON object to stdout at the end.

Go:
- Use "test_filename": "test_exploit.go".
- Put the complete Go test harness in "test_script". Focus your effort on correct exploit logic.
- For "dockerfile", return a one-line placeholder comment (e.g. "# assembled by 911VulScan").
- Do NOT write COPY/RUN/go mod lines for Go — the framework stages the full Go module (go.mod + sources) and emits a canonical Dockerfile with a local module replace.
- Import the project's real module path from go.mod (for example github.com/emicklei/go-restful/v3). Do NOT invent /work/repo, /restful, or ../lib paths in the test code.
- Do NOT return go.mod or go.sum in "requirements".
- Set "requirements" to "" and "requirements_filename" to "requirements.txt".
- The Go program must print exactly one JSON object to stdout at the end.

C/C++:
- Use "test_filename": "test_exploit.c" for C findings or "test_exploit.cpp" for C++ findings.
- Set "requirements" to "" and "requirements_filename" to "requirements.txt".
- Put the complete C/C++ test harness in "test_script". Focus your effort on correct exploit logic.
- Do NOT require a second script file. This schema supports only one generated test script.
- Do NOT reference test_exploit.py for C/C++ projects.
- The 911VulScan framework assembles the Dockerfile automatically from staged source and headers.
- For "dockerfile", you may return a one-line placeholder comment (e.g. "# assembled by 911VulScan").
- Do NOT write COPY/RUN/gcc lines for C/C++ — the framework emits a canonical build.
- The scaffold stages the vulnerable source file and same-directory .h/.hpp headers into the build context.
- If test_exploit.c includes the implementation via #include "foo.c", the framework will not compile foo.c twice.
- If you #include a project header (e.g. "cJSON.h"), the framework automatically links the matching staged .c (cJSON.c) and any split-library companion (cJSON.c when linking cJSON_Utils.c). Do NOT call cJSON_* APIs unless you include the real header or you provide your own stubs.
- To test a static helper in isolation, copy only that function into test_exploit.c as static, avoid #include "cJSON.h", and do not call library APIs — the framework will link only test_exploit.c.
- main() must be valid C: every opening brace must match; do not split printf/JSON printing across lines in a way that leaves stray `} else {` at file scope.
- The prompt may include source/header excerpts. Use the REAL struct layout, function signatures, and argument mutability from those excerpts. Do not guess header/data sizes.
- Runtime files should be written under /tmp unless the test explicitly needs another path.
- The native scaffold provides a compatibility shim for AFL shared-memory symbols:
  `vulscan_afl_testcase_buf`, `__afl_fuzz_len`, `__AFL_FUZZ_TESTCASE_BUF`, and `__AFL_FUZZ_INIT`.
  For AFL-style sources, fill `vulscan_afl_testcase_buf`, set `__afl_fuzz_len`, and call the real target function.
- If AFL-style code calls `strlen(__AFL_FUZZ_TESTCASE_BUF)` before parsing, make sure the first bytes of the crafted testcase contain no `\0` before the length check threshold. Choose width/height byte values with non-zero little-endian bytes, or call the exposed parser function directly when that is the only reliable way to reach the vulnerable code.
- For socket/server code, prefer direct calls to functions like `ProcessImage(buffer, size)` when available. If testing the server entry point is required, fork the server, connect to localhost, send the payload, then kill/wait with a timeout.
- For libFuzzer code, call `LLVMFuzzerTestOneInput(payload, size)` directly in a child process.
- For Windows-derived C/C++ code compiled on Linux, the scaffold neutralizes `__declspec`/calling-convention macros. Still pass mutable `char *` buffers to functions declared as `char *`; do not pass `const char *` where the target expects mutable input.
- Prefer exercising the original target function/source. Only reimplement the vulnerable logic if the original source cannot be compiled or called, and report INCONCLUSIVE rather than CONFIRMED when relying on a reimplementation.
- NEVER call execl()/execv()/system() on binaries that the framework does not build. Link against the staged source and call the vulnerable function directly (for example ProcessImage()).
- NEVER redirect stderr to /dev/null in AddressSanitizer tests. Capture stderr with a pipe or leave it attached so ASan diagnostics are visible.
- In fork()+waitpid() harnesses, treat child non-zero exit under ASan as CONFIRMED unless the exit is clearly from harness setup (missing binary, exit 127).
- For `%s` out-of-bounds reads from fixed-size char arrays, do not rely only on a crash. Disable buffering or flush output, wait for the child to exit, then inspect captured stdout for bytes printed past the declared field length.
- In ASan-instrumented native tests, a child process exiting non-zero after invoking the target with a crafted payload should normally be reported as CONFIRMED unless the non-zero exit is clearly from the harness setup itself.
- The C/C++ test program must print exactly one JSON object to stdout at the end.
- In C/C++, you MUST call vulscan_emit_result_json(status, details, evidence_content) from vulscan_native_compat.h as the final stdout output. Do NOT use printf with a literal JSON template like printf("{\"status\":...") — unescaped quotes break compilation.
- Example: vulscan_emit_result_json(confirmed ? "CONFIRMED" : "NOT_REPRODUCED", "reason text", cap.buf);

PHP:
- Use "test_filename": "test_exploit.php".
- Use a PHP base image already present when possible (php:8.3-cli).
- If the Dockerfile runs composer install/require, you MUST make composer available first, e.g.:
  COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
- Do NOT require ext-grpc in composer.json for ProtosetConverter path-traversal tests; google/protobuf (or pecl protobuf) is enough.
- Stage library source with PSR-4 layout (src/..., composer.json) or copy vendor/ if present.
- Put composer.json in "requirements" with "requirements_filename": "composer.json" when dependencies are needed.
- The PHP script must print exactly one JSON object to stdout at the end.

Ruby:
- Use "test_filename": "test_exploit.rb".
- Use a Ruby base image, such as ruby:3.3-slim.
- Set "requirements" to "" and "requirements_filename" to "requirements.txt" unless gems are needed.
- If gems are needed, put Gemfile content in "requirements" and use "requirements_filename": "Gemfile".
- The Ruby script must print exactly one JSON object to stdout at the end.

ATTACKER CAPTURE SERVER:
- Only use docker_compose if the finding needs SSRF, callback, webhook, or exfiltration testing.
- The attacker server is provided locally and listens on port 9999.
- In docker-compose, reference it as http://attacker:9999 from the test container.
- Do NOT include a docker-compose "version:" key.
- The attacker service MUST use build: ./attacker-server.
- The test service should be named test and use build: .
- Use a bridge network named testnet.

Return ONLY the JSON object, no markdown fences or explanations.
"""


def _build_finding_prompt(
    finding: dict,
    repo_info: dict,
    repo_path: str | None = None,
    native_plan: NativeTestPlan | None = None,
) -> str:
    """Build the prompt for generating a test for a single finding."""
    language = repo_info.get("language", "Python")

    source_basename = ""
    staged_headers: list[str] = []
    loc = finding.get("location", {})
    platform_notes = repo_info.get("platform_notes", "")
    harness_notes = repo_info.get("harness_notes", "")
    resolution = resolve_native_test_source(finding, repo_path)
    if resolution.platform_notes:
        platform_notes = resolution.platform_notes
    if resolution.harness_notes:
        harness_notes = resolution.harness_notes
    elif resolution.source_basename and resolution.source_path:
        harness_notes = build_linked_harness_notes(
            finding, resolution.source_basename, resolution.source_path
        )
    if isinstance(loc, dict) and loc.get("file"):
        source_basename = os.path.basename(loc["file"])
        _src, staged = list_staged_files_for_finding(finding, repo_path)
        if _src:
            source_basename = _src
        staged_headers = [f for f in staged if f != source_basename]

    parts = [
        f"Generate a dynamic exploit test for the following vulnerability.",
        "",
        f"Repository: {repo_info.get('name', 'unknown')}",
        f"Language: {language}",
        f"Application Type: {repo_info.get('application_type', 'unknown')}",
        "",
        "FINDING:",
        f"  ID: {finding.get('id', 'unknown')}",
        f"  Name: {finding.get('name', 'unknown')}",
        f"  CWE: {finding.get('cwe_id', 0)} - {finding.get('cwe_name', 'Unknown')}",
        f"  Location: {json.dumps(loc, indent=4)}",
        f"  Stage 1 Verdict: {finding.get('stage1_verdict', 'unknown')}",
        f"  Stage 2 Verdict: {finding.get('stage2_verdict', 'unknown')}",
    ]

    if source_basename:
        parts.extend([
            "",
            f"  Source file (pre-staged in Docker build context): {source_basename}",
        ])
        if staged_headers:
            parts.append(
                f"  Pre-staged headers: {', '.join(sorted(staged_headers))}"
            )
        lang_norm = normalize_language(language)
        if lang_norm in {"c", "cpp", "c++"} or should_use_native_builder(
            lang_norm, "test_exploit.c", [source_basename] + staged_headers
        ):
            parts.extend([
                "  The framework will assemble the Dockerfile (COPY, compile, CMD).",
                "  Focus on test_script exploit logic only.",
            ])
        elif lang_norm in {"go", "golang"}:
            from utilities.dynamic_tester.go_stage import plan_go_staged_files

            source_path = _resolve_finding_source_path(finding, repo_path, resolution)
            _, module_import = (
                plan_go_staged_files(source_path, repo_path)
                if source_path
                else ([], None)
            )
            module_hint = (
                f"  Go module path (import this in test_script): {module_import}"
                if module_import
                else "  Import the project's real Go module path from go.mod."
            )
            parts.extend([
                "  The framework stages the full Go module under module/ and assembles the Dockerfile.",
                "  Focus on test_script exploit logic only.",
                module_hint,
            ])
        else:
            parts.append(
                f"  Your Dockerfile MUST use `COPY {source_basename} .` — the file is already there."
            )

        source_context = _source_context_for_prompt(finding, repo_path)
        if source_context:
            parts.extend(["", "SOURCE CONTEXT:", source_context])

    if finding.get("description"):
        parts.extend(["", f"  Description: {finding['description']}"])
    if finding.get("vulnerable_code"):
        parts.extend(["", f"  Vulnerable Code:\n{finding['vulnerable_code']}"])
    if finding.get("impact"):
        parts.extend(["", f"  Impact: {finding['impact']}"])
    if finding.get("steps_to_reproduce"):
        parts.extend(["", f"  Steps to Reproduce: {finding['steps_to_reproduce']}"])
    repro_checks = (
        finding.get("repro_checks")
        or finding.get("trigger_constraints")
        or []
    )
    if repro_checks:
        parts.extend(["", "REPRO CHECKS (all must be respected):"])
        for check in repro_checks:
            if isinstance(check, dict):
                parts.append(
                    "- "
                    + str(
                        check.get("description")
                        or check.get("expression")
                        or check
                    )
                )
                literals = check.get("required_literals") or []
                if literals:
                    parts.append(
                        f"  Required payload literals/bytes: {', '.join(map(str, literals))}"
                    )
                if check.get("target_symbol"):
                    parts.append(
                        f"  Target symbol: {check['target_symbol']}"
                    )
            else:
                parts.append(f"- {check}")
        parts.append(
            "Emit TARGET_REACHED:<target> to stderr immediately before the real target call."
        )

    if platform_notes:
        parts.extend(["", "PLATFORM NOTES:", platform_notes])
    if harness_notes:
        parts.extend(["", harness_notes])
    if native_plan and native_plan.prompt_sections:
        parts.extend(["", *native_plan.prompt_sections])

    # Add CWE-specific guidance
    cwe_id = finding.get("cwe_id", 0)
    guidance = get_cwe_guidance(cwe_id)
    if guidance:
        parts.extend(["", "CWE-SPECIFIC GUIDANCE:", guidance])

    return "\n".join(parts)


def _read_text_limited(path: str, limit: int) -> str:
    """Read a small source excerpt for dynamic test generation prompts."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read(limit + 1)
    except OSError:
        return ""
    if len(data) > limit:
        return data[:limit] + "\n/* ... truncated ... */"
    return data


def _source_context_for_prompt(finding: dict, repo_path: str | None) -> str:
    """Return bounded source/header context so C/C++ tests use real layouts."""
    if not repo_path:
        return ""

    loc = finding.get("location", {})
    rel_path = loc.get("file", "") if isinstance(loc, dict) else ""
    if not rel_path:
        return ""

    source_path = resolve_repo_file(rel_path, repo_path)
    if not source_path:
        return ""

    chunks: list[str] = []
    source_text = _read_text_limited(source_path, 16000)
    if source_text:
        chunks.append(f"Source file {os.path.basename(source_path)}:\n```c\n{source_text}\n```")

    source_dir = os.path.dirname(os.path.abspath(source_path))
    try:
        entries = sorted(os.listdir(source_dir))
    except OSError:
        entries = []

    for entry in entries:
        if not entry.endswith((".h", ".hpp", ".hh", ".hxx")):
            continue
        header_path = os.path.join(source_dir, entry)
        if not os.path.isfile(header_path):
            continue
        header_text = _read_text_limited(header_path, 6000)
        if header_text:
            chunks.append(f"Header file {entry}:\n```c\n{header_text}\n```")

    return "\n\n".join(chunks)


def _resolve_native_plan(
    finding: dict,
    repo_path: str | None,
    registry: ProvenExploitRegistry | None,
) -> NativeTestPlan | None:
    """Build a native test plan when the finding has staged C/C++ source."""
    resolution = resolve_native_test_source(finding, repo_path)
    source_path = resolution.source_path
    source_basename = resolution.source_basename
    if not source_path and not source_basename:
        loc = finding.get("location", {})
        rel = loc.get("file", "") if isinstance(loc, dict) else ""
        if repo_path and rel:
            candidate = resolve_repo_file(rel, repo_path)
            if candidate:
                source_path = candidate
                source_basename = os.path.basename(candidate)
    if not source_basename:
        return None
    return build_native_test_plan(
        finding,
        repo_path=repo_path,
        source_path=source_path,
        source_basename=source_basename,
        registry=registry,
    )


def _reject_invalid_generation(
    parsed: dict,
    repo_info: dict,
    finding: dict | None = None,
    repo_path: str | None = None,
    native_plan: NativeTestPlan | None = None,
) -> bool:
    """Return True if the parsed LLM output should be rejected before finalize."""
    lang = str(repo_info.get("language", "")).lower()
    filename = str(parsed.get("test_filename", "")).lower()
    dockerfile_l = str(parsed.get("dockerfile", "")).lower()
    test_script = str(parsed.get("test_script", ""))

    if lang in {"c", "cpp", "c++"}:
        if not filename.endswith((".c", ".cpp", ".cc", ".cxx")):
            return True
        if "python3" in dockerfile_l or "test_exploit.py" in dockerfile_l:
            return True
        resolution = resolve_native_test_source(finding, repo_path) if finding else None
        source_basename = resolution.source_basename if resolution else None
        if native_test_script_errors(test_script, source_basename, plan=native_plan):
            return True
    elif lang in {"python", "py"} and not filename.endswith(".py"):
        return True
    elif lang in {"javascript", "js"} and not filename.endswith(".js"):
        return True
    elif lang in {"typescript", "ts"} and not filename.endswith(".ts"):
        return True
    elif lang in {"go", "golang"} and not filename.endswith(".go"):
        return True
    elif lang == "php" and not filename.endswith(".php"):
        return True
    elif lang == "ruby" and not filename.endswith(".rb"):
        return True

    if not is_native_test_script(test_script, filename, lang) and script_has_c_preprocessor(
        test_script
    ):
        return True

    forbidden = (
        "|| true", "|| echo", "echo build failed", "echo build ok",
        "2>/dev/null ||", "2>&1 ||",
    )
    if any(pat in dockerfile_l for pat in forbidden):
        return True
    if "/tmp/work" in dockerfile_l or "workdir /tmp" in dockerfile_l:
        return True
    if 'cmd ["/tmp/' in dockerfile_l:
        return True
    return False


def _resolve_finding_source_path(
    finding: dict,
    repo_path: str | None,
    resolution,
) -> str | None:
    if resolution and resolution.source_path:
        return resolution.source_path
    if not repo_path:
        return None
    rel_path = finding.get("location", {}).get("file", "")
    if not rel_path:
        return None
    return resolve_repo_file(rel_path, repo_path)


def _go_finalize_staging(
    finding: dict,
    repo_path: str | None,
    resolution,
    staged_for_finalize: list[str],
) -> tuple[list[str], str | None]:
    from utilities.dynamic_tester.go_stage import plan_go_staged_files

    source_path = _resolve_finding_source_path(finding, repo_path, resolution)
    if not source_path:
        return staged_for_finalize, None

    go_staged, module_import = plan_go_staged_files(source_path, repo_path)
    if not go_staged:
        return staged_for_finalize, None

    return sorted(set(staged_for_finalize) | set(go_staged)), module_import


def _finalize_generation(
    parsed: dict,
    finding: dict,
    repo_info: dict,
    repo_path: str | None,
    native_plan: NativeTestPlan | None = None,
) -> dict | None:
    """Validate LLM generation output without assembling Dockerfile (deferred to executor)."""
    language = repo_info.get("language", "Python")
    parsed = dict(parsed)
    parsed["_language"] = language

    if parsed.get("dockerfile") and not str(parsed.get("dockerfile", "")).startswith("# assembled"):
        print(
            "[DynamicTest] warning: LLM dockerfile ignored; framework assembles Dockerfile",
            file=sys.stderr,
        )
        parsed["dockerfile"] = "# assembled by 911VulScan"

    if parsed.get("docker_compose"):
        print(
            "[DynamicTest] warning: LLM docker_compose ignored; framework generates compose topology",
            file=sys.stderr,
        )
        parsed["docker_compose"] = None

    resolution = resolve_native_test_source(finding, repo_path)
    runtime = resolution.runtime or "linux"
    parsed["_runtime"] = runtime
    parsed["_native_plan"] = native_plan
    repro_checks = list(
        finding.get("repro_checks") or finding.get("trigger_constraints") or []
    )
    parsed["_repro_checks"] = repro_checks
    parsed["_requires_target_evidence"] = bool(repro_checks)
    parsed["_target_symbol"] = finding.get("location", {}).get("function", "")
    if resolution.source_path:
        parsed["_finding_source_path"] = resolution.source_path

    if parsed.get("test_script"):
        parsed["test_script"] = apply_deterministic_compile_fixes(
            parsed["test_script"],
            language=language,
            test_filename=parsed.get("test_filename", ""),
        )

    return parsed


def _parse_generation_response(raw: str) -> dict:
    """Parse the LLM response into structured test generation output.

    The model may accidentally return prose, markdown fences, or multiple JSON
    attempts. This parser first tries direct JSON, then scans all balanced JSON
    objects and returns the last valid object with the required 911VulScan fields.
    """
    text = raw.strip()

    required = {"dockerfile", "test_script", "test_filename"}

    def valid(obj):
        return isinstance(obj, dict) and required.issubset(obj.keys())

    # Remove simple whole-response markdown fences.
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [line for line in lines if not line.strip().startswith("```")]
        text = "\n".join(lines).strip()

    # Direct parse.
    try:
        obj = json.loads(text)
        if valid(obj):
            return obj
    except json.JSONDecodeError:
        pass

    # Scan balanced JSON objects while respecting string escapes.
    candidates = []
    stack = []
    start_idx = None
    in_string = False
    escape = False

    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "{":
            if not stack:
                start_idx = i
            stack.append(ch)
        elif ch == "}":
            if stack:
                stack.pop()
                if not stack and start_idx is not None:
                    candidates.append(text[start_idx:i + 1])
                    start_idx = None

    # Prefer the last valid candidate because the model often revises itself.
    for cand in reversed(candidates):
        try:
            obj = json.loads(cand)
            if valid(obj):
                return obj
        except json.JSONDecodeError:
            continue

    return None

def generate_test(
    finding: dict,
    repo_info: dict,
    tracker: TokenTracker = None,
    repo_path: str | None = None,
    exploit_registry: ProvenExploitRegistry | None = None,
) -> dict | None:
    """Generate a dynamic test for a single finding.

    Args:
        finding: Finding dict from pipeline_output.json
        repo_info: Repository info (name, language, application_type)
        tracker: Optional TokenTracker for cost tracking

    Returns:
        Dict with dockerfile, test_script, test_filename, requirements,
        requirements_filename, docker_compose, needs_attacker_server.
        None if generation fails.
    """
    tracker = tracker or TokenTracker()
    client = AnthropicClient(model=TEST_GENERATION_MODEL, tracker=tracker)

    native_plan = _resolve_native_plan(finding, repo_path, exploit_registry)
    prompt = _build_finding_prompt(
        finding, repo_info, repo_path=repo_path, native_plan=native_plan
    )
    from utilities.llm_json_utils import DEFAULT_JSON_RETRIES

    try:
        parsed = client.analyze_json_sync(
            prompt,
            max_tokens=8192,
            system=SYSTEM_PROMPT,
            context="dynamic test generation",
            retries=DEFAULT_JSON_RETRIES,
        )
    except Exception:
        parsed = None

    # DEBUG: save raw LLM response for dynamic test generation
    if parsed is not None:
        try:
            from pathlib import Path as _Path
            _Path("/tmp/vulscan_dynamic_raw_response.txt").write_text(
                json.dumps(parsed, indent=2), encoding="utf-8"
            )
        except Exception:
            pass
    if not parsed:
        return None

    # Validate required fields
    required = ["dockerfile", "test_script", "test_filename"]
    if not all(k in parsed for k in required):
        return None

    # Normalize optional fields.
    parsed.setdefault("requirements", "")
    parsed.setdefault("requirements_filename", "requirements.txt")
    parsed.setdefault("docker_compose", None)
    parsed.setdefault("needs_attacker_server", False)

    if _reject_invalid_generation(
        parsed, repo_info, finding=finding, repo_path=repo_path, native_plan=native_plan
    ):
        return None

    return _finalize_generation(
        parsed, finding, repo_info, repo_path, native_plan=native_plan
    )


COMPILE_REPAIR_SYSTEM_PROMPT = """You fix compile errors in C/C++ dynamic exploit test harnesses for 911VulScan.

Return ONLY a JSON object with these keys:
  dockerfile, test_script, test_filename, requirements, requirements_filename

Rules:
- Change ONLY test_script unless test_filename must stay the same as given.
- For C/C++ native tests set dockerfile to "# assembled by 911VulScan".
- vulscan_child_capture is a typedef — NEVER write struct vulscan_child_capture.
- When using vulscan_run_asan_child_* / vulscan_emit_result_json / vulscan_has_sanitizer_evidence,
  #include "vulscan_native_compat.h" (injected via -include, but explicit include is OK).
- Add #include <stdio.h> for stderr/stdout/printf/setvbuf; <string.h> for strcpy/strlen; <stdlib.h> for malloc/free.
- Preserve the exploit intent; fix syntax/types/includes only.
- End main() with vulscan_emit_result_json(...) — never hand-roll JSON printf templates.
- Do NOT redirect stderr to /dev/null.
"""


def repair_test_from_compile_errors(
    finding: dict,
    repo_info: dict,
    previous_generation: dict,
    build_error: str,
    tracker: TokenTracker = None,
    repo_path: str | None = None,
    exploit_registry: ProvenExploitRegistry | None = None,
) -> dict | None:
    """Ask the LLM to fix test_script given compiler diagnostics (focused repair)."""
    test_filename = previous_generation.get("test_filename", "test_exploit.c")
    test_script = previous_generation.get("test_script", "")
    lang_norm = normalize_language(repo_info.get("language", ""))
    if not is_native_test_script(test_script, test_filename, lang_norm):
        return None

    tracker = tracker or TokenTracker()
    client = AnthropicClient(model=TEST_GENERATION_MODEL, tracker=tracker)

    native_plan = _resolve_native_plan(finding, repo_path, exploit_registry)
    diagnostics = extract_compiler_diagnostics(build_error)

    repair_prompt = (
        "The following native test harness failed to compile inside Docker.\n"
        "Fix ALL compiler/linker errors in test_script.\n\n"
        f"test_filename: {test_filename}\n\n"
        f"Current test_script:\n```c\n{test_script}\n```\n\n"
        f"Compiler / linker diagnostics:\n```\n{diagnostics}\n```\n\n"
        "Return the corrected full test_script in JSON. "
        "Keep test_filename unchanged unless switching .c/.cpp is required."
    )

    from utilities.llm_json_utils import DEFAULT_JSON_RETRIES

    try:
        parsed = client.analyze_json_sync(
            repair_prompt,
            max_tokens=8192,
            system=COMPILE_REPAIR_SYSTEM_PROMPT,
            context="dynamic test compile repair",
            retries=DEFAULT_JSON_RETRIES,
        )
    except Exception:
        parsed = None
    if not parsed:
        return None

    required = ["dockerfile", "test_script", "test_filename"]
    if not all(k in parsed for k in required):
        return None

    merged = dict(previous_generation)
    merged.update(parsed)
    if not merged.get("test_filename"):
        merged["test_filename"] = test_filename

    if _reject_invalid_generation(
        merged, repo_info, finding=finding, repo_path=repo_path, native_plan=native_plan
    ):
        return None

    return _finalize_generation(
        merged, finding, repo_info, repo_path, native_plan=native_plan
    )


def apply_local_compile_repairs(
    generation: dict,
    finding: dict,
    repo_info: dict,
    repo_path: str | None = None,
    exploit_registry: ProvenExploitRegistry | None = None,
) -> dict | None:
    """Apply deterministic compile fixes and re-finalize the Docker build context."""
    repaired = deterministic_repair_generation(
        generation,
        language=repo_info.get("language"),
    )
    if repaired is None:
        return None
    native_plan = _resolve_native_plan(finding, repo_path, exploit_registry)
    return _finalize_generation(
        repaired, finding, repo_info, repo_path, native_plan=native_plan
    )


def regenerate_test(
    finding: dict,
    repo_info: dict,
    previous_generation: dict,
    error_message: str,
    tracker: TokenTracker = None,
    repo_path: str | None = None,
    exploit_registry: ProvenExploitRegistry | None = None,
) -> dict | None:
    """Regenerate a test after a build/run failure, feeding the error back to the LLM.

    Args:
        finding: Finding dict from pipeline_output.json
        repo_info: Repository info
        previous_generation: The generation that failed
        error_message: The Docker build/run error message
        tracker: Optional TokenTracker

    Returns:
        New generation dict, or None if regeneration fails.
    """
    tracker = tracker or TokenTracker()
    client = AnthropicClient(model=TEST_GENERATION_MODEL, tracker=tracker)

    native_plan = _resolve_native_plan(finding, repo_path, exploit_registry)
    original_prompt = _build_finding_prompt(
        finding, repo_info, repo_path=repo_path, native_plan=native_plan
    )

    test_filename = previous_generation.get('test_filename', 'test_exploit.py')
    test_script = previous_generation.get('test_script', '')
    lang_norm = normalize_language(repo_info.get("language", ""))
    is_native = is_native_test_script(test_script, test_filename, lang_norm)
    if is_native:
        error_excerpt = extract_compiler_diagnostics(error_message)
    else:
        error_excerpt = error_message.strip()[:5000]

    common_fixes = (
        "- Missing directories: use `mkdir -p` before writing files\n"
        "- Dependency conflicts: don't pin exact versions, use >= or no pin\n"
        "- Missing packages: install only the sub-package you need\n"
        "- Connection errors: ensure service names match docker-compose service names\n"
        "- Missing abstract methods: implement all required abstract methods on mock/stub classes\n"
        "- Application-level errors: check the error details and fix the test logic\n"
        "- Read-only filesystem/runtime file errors: write generated inputs under /tmp\n"
    )
    native_fixes = (
        "- Docker parse error 'unknown instruction' (e.g. extern, #include): never embed C/source "
        "in Dockerfile; for C/C++ only fix test_script — Dockerfile is assembled by 911VulScan\n"
        "- Compile/link errors: ensure symbols are declared; if using #include \"file.c\" do not "
        "also expect separate compilation of that file\n"
        "- const-correctness errors: if the target expects char*, use a mutable char array, not const char*\n"
        "- AFL macro errors: use the provided vulscan_afl_testcase_buf/__afl_fuzz_len compatibility symbols\n"
        "- Socket tests: prefer direct ProcessImage(buffer, size) calls when the vulnerable parser is exposed\n"
        "- NEVER execl()/execv()/system() /work/<source> binaries; only /work/test_exploit exists. "
        "Call the linked vulnerable function directly.\n"
        "- Do NOT redirect stderr to /dev/null in AddressSanitizer tests\n"
        "- Use vulscan_run_asan_child_void/ptr() from vulscan_native_compat.h "
        "instead of hand-rolled fork/pipe/waitpid\n"
        "- vulscan_child_capture is a typedef — do NOT write struct vulscan_child_capture\n"
        "- Add #include <stdio.h> when using stderr/stdout/printf/setvbuf\n"
        "- C JSON output: end main() with vulscan_emit_result_json(status, details, evidence); "
        "never printf(\"{\\\"status\\\":\") — raw {\" in a C string is a syntax error\n"
    )
    js_fixes = (
        "- This is a Node.js test: use require()/import only — NEVER use #include, #define, or other C preprocessor directives\n"
        "- Use process.exit() for early exit; do not add C headers\n"
        "- Print exactly one JSON object to stdout with console.log(JSON.stringify(...))\n"
        "- COPY lodash.js and require('./lodash.js') relative to /work\n"
    )

    retry_prompt = (
        f"{original_prompt}\n\n"
        f"IMPORTANT: A previous attempt to generate this test FAILED.\n\n"
        f"Previous Dockerfile:\n```\n{previous_generation.get('dockerfile', '')}\n```\n\n"
        f"Previous requirements:\n```\n{previous_generation.get('requirements', '')}\n```\n\n"
        f"Previous test script ({test_filename}):\n```\n{test_script}\n```\n\n"
        f"Error message:\n```\n{error_excerpt}\n```\n\n"
        f"Fix the issue and regenerate. Common fixes:\n"
        f"{common_fixes}"
    )
    if is_native:
        retry_prompt += native_fixes
    elif lang_norm in {"javascript", "js", "typescript", "ts"}:
        retry_prompt += js_fixes

    if lang_norm in {"c", "cpp", "c++"}:
        retry_prompt += (
            "\n\nFor this C/C++ finding, return a minimal dockerfile placeholder and put all "
            "fixes in test_script. Do NOT regenerate COPY/RUN/gcc instructions."
        )

    from utilities.llm_json_utils import DEFAULT_JSON_RETRIES

    try:
        parsed = client.analyze_json_sync(
            retry_prompt,
            max_tokens=8192,
            system=SYSTEM_PROMPT,
            context="dynamic test regeneration",
            retries=DEFAULT_JSON_RETRIES,
        )
    except Exception:
        parsed = None
    if not parsed:
        return None

    required = ["dockerfile", "test_script", "test_filename"]
    if not all(k in parsed for k in required):
        return None

    if _reject_invalid_generation(
        parsed, repo_info, finding=finding, repo_path=repo_path, native_plan=native_plan
    ):
        return None

    return _finalize_generation(
        parsed, finding, repo_info, repo_path, native_plan=native_plan
    )


def _generate_one(finding, repo_info, tracker, repo_path=None):
    """Generate a test for a single finding, tracking cost."""
    cost_before = tracker.total_cost_usd
    result = generate_test(finding, repo_info, tracker, repo_path=repo_path)
    cost_after = tracker.total_cost_usd
    cost = cost_after - cost_before
    worker = threading.current_thread().name
    return finding, result, cost, worker


def generate_tests_batch(
    findings: list[dict],
    repo_info: dict,
    tracker: TokenTracker = None,
    workers: int = 10,
    repo_path: str | None = None,
) -> list[tuple[dict, dict | None, float]]:
    """Generate tests for multiple findings.

    Uses ThreadPoolExecutor for parallel generation when workers > 1.

    Args:
        findings: List of finding dicts
        repo_info: Repository info
        tracker: Optional TokenTracker
        workers: Number of parallel workers (default: 10).

    Returns:
        List of (finding, generation_result_or_None, cost_usd) tuples
    """
    tracker = tracker or TokenTracker()
    total = len(findings)

    mode = "sequential" if workers <= 1 else f"parallel ({workers} workers)"
    print(f"[DynamicTest] Generating tests for {total} findings, mode: {mode}", file=sys.stderr, flush=True)

    if workers <= 1:
        results = []
        for i, finding in enumerate(findings):
            _finding, result, cost, _worker = _generate_one(
                finding, repo_info, tracker, repo_path=repo_path
            )
            print(f"[DynamicTest] {i+1}/{total}  {format_cost(cost)}", file=sys.stderr, flush=True)
            results.append((_finding, result, cost))
        return results

    # Parallel mode
    results = []
    completed = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_generate_one, finding, repo_info, tracker, repo_path)
            for finding in findings
        ]
        for future in as_completed(futures):
            _finding, result, cost, worker = future.result()
            completed += 1
            print(f"[DynamicTest] {completed}/{total}  {format_cost(cost)}  [{worker}]", file=sys.stderr, flush=True)
            results.append((_finding, result, cost))

    return results
