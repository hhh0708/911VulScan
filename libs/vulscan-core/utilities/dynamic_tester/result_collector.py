"""Parse container output and classify dynamic test results.

Each test container is expected to print a single JSON object to stdout:
{
    "status": "CONFIRMED|NOT_REPRODUCED|BLOCKED|INCONCLUSIVE|ERROR",
    "details": "Human-readable explanation",
    "evidence": [{"type": "file_read|http_response|command_output|network_capture", "content": "..."}]
}
"""

import json
import re

from utilities.dynamic_tester.models import DynamicTestResult, TestEvidence, VALID_STATUSES
from utilities.dynamic_tester.docker_executor import DockerExecutionResult
from utilities.dynamic_tester.native_link_mode import is_logic_only_reproduction
from utilities.dynamic_tester.native_test_plan import (
    HARNESS_FAILURE_MARKERS,
    SANITIZER_CONFIRMATION_MARKERS,
    uses_native_sanitizer,
)

_CONFIRMATION_MARKERS = SANITIZER_CONFIRMATION_MARKERS

_HARNESS_FAILURE_MARKERS = HARNESS_FAILURE_MARKERS

_SIGPIPE_HARNESS_RE = re.compile(
    r"(child\s+signaled\s+13|signal\s+13|sigpipe)",
    re.IGNORECASE,
)

_NONZERO_CHILD_EXIT_RE = re.compile(
    r"(child|process|target)[^\n]{0,80}"
    r"(exited|exit|terminated)[^\n]{0,80}"
    r"(code|status)[^\n]{0,20}([1-9][0-9]*)",
    re.IGNORECASE,
)

_EXIT_CODE_EVIDENCE_RE = re.compile(
    r"exit(?:\s+code)?\s*[:=]\s*([1-9][0-9]*)",
    re.IGNORECASE,
)


def collect_result(
    finding: dict,
    generation: dict | None,
    execution: DockerExecutionResult | None,
    generation_cost: float = 0.0,
) -> DynamicTestResult:
    """Parse container output into a DynamicTestResult.

    Args:
        finding: Original finding dict from pipeline_output.json
        generation: Test generation output (or None if generation failed)
        execution: Docker execution result (or None if not run)
        generation_cost: Cost of LLM test generation in USD

    Returns:
        DynamicTestResult with parsed status and evidence
    """
    finding_id = finding.get("id", "unknown")

    # Generation failed
    if generation is None:
        return DynamicTestResult(
            finding_id=finding_id,
            status="ERROR",
            details="Test generation failed — LLM did not return valid test code",
            generation_cost_usd=generation_cost,
        )

    # Execution not attempted
    if execution is None:
        return DynamicTestResult(
            finding_id=finding_id,
            status="ERROR",
            details="Docker execution was not attempted",
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            generation_cost_usd=generation_cost,
        )

    # Build failure
    if execution.build_error:
        return DynamicTestResult(
            finding_id=finding_id,
            status="ERROR",
            details=f"Docker build failed: {execution.build_error[:2000]}",
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    # Timeout
    if execution.timed_out:
        return DynamicTestResult(
            finding_id=finding_id,
            status="INCONCLUSIVE",
            details="Container execution timed out",
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    combined_output = "\n".join(
        part for part in (execution.stdout, execution.stderr) if part
    )

    confirmed_output = _detect_confirming_output(execution.stdout, execution.stderr)
    if confirmed_output and not _looks_like_harness_failure(confirmed_output, generation):
        status = "CONFIRMED"
        details = "Container output contains sanitizer/crash evidence"
        source_path = generation.get("_finding_source_path")
        if is_logic_only_reproduction(generation, finding, source_path=source_path):
            status = "INCONCLUSIVE"
            details = (
                "Sanitizer output observed in a harness-local reimplementation of a "
                "static helper — not verified through the staged library translation "
                "units. Prefer #include project headers and public API entry points."
            )
        elif generation.get("_requires_target_evidence") and not _target_reached(
            execution.stderr
        ):
            status = "INCONCLUSIVE"
            details = (
                "Crash/sanitizer evidence was observed, but the harness did not "
                "prove that it reached the requested target."
            )
        return DynamicTestResult(
            finding_id=finding_id,
            status=status,
            details=details,
            evidence=[TestEvidence(type="command_output", content=confirmed_output[:5000])],
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    # Parse stdout for the JSON result
    parsed = _parse_container_output(execution.stdout)

    if parsed is None:
        parsed = _repair_container_output(execution.stdout)

    if parsed is None:
        return DynamicTestResult(
            finding_id=finding_id,
            status="ERROR",
            details=f"Container did not produce valid JSON output. "
                    f"Exit code: {execution.exit_code}. "
                    f"Stderr: {execution.stderr[:300]}",
            evidence=[TestEvidence(type="command_output", content=execution.stdout[:2000])],
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    # Valid JSON output
    status = parsed.get("status", "ERROR")
    if status not in VALID_STATUSES:
        status = "INCONCLUSIVE"

    parsed_evidence_text = "\n".join(
        str(e.get("content", "")) for e in (parsed.get("evidence") or [])
        if isinstance(e, dict)
    )
    confirming_evidence = _detect_confirming_output(parsed_evidence_text, "")
    if confirming_evidence and status in {"NOT_REPRODUCED", "INCONCLUSIVE", "ERROR"}:
        status = "CONFIRMED"
        parsed["details"] = (
            parsed.get("details")
            or "Evidence contains sanitizer/crash output despite test status"
        )

    classification_text = "\n".join(
        [
            str(parsed.get("details", "")),
            parsed_evidence_text,
            combined_output,
        ]
    )
    if status == "CONFIRMED" and _looks_like_harness_failure(classification_text, generation):
        status = "INCONCLUSIVE"
        parsed["details"] = (
            "Test harness could not invoke the linked target "
            "(missing binary, exec failure, or exit 127)"
        )
    elif status == "CONFIRMED" and is_logic_only_reproduction(
        generation,
        finding,
        source_path=generation.get("_finding_source_path"),
    ):
        status = "INCONCLUSIVE"
        parsed["details"] = (
            "Test reported CONFIRMED via local reimplementation of a static helper; "
            "re-run with staged library headers and public API calls."
        )
    elif status in {"NOT_REPRODUCED", "INCONCLUSIVE"}:
        status = _apply_status_adjustments(status, generation, classification_text)
        if status == "INCONCLUSIVE" and _looks_like_sigpipe_harness_failure(
            classification_text
        ):
            status = "INCONCLUSIVE"
            parsed["details"] = (
                "Test harness IO failure (SIGPIPE) — stderr capture order is wrong; "
                "use vulscan_run_asan_child_* from vulscan_native_compat.h"
            )

    if status == "CONFIRMED" and generation.get("_requires_target_evidence"):
        if not _target_reached(execution.stderr):
            status = "INCONCLUSIVE"
            parsed["details"] = (
                "The test claimed CONFIRMED without emitting target-reach evidence "
                "immediately before the requested target invocation."
            )

    evidence = []
    for e in (parsed.get("evidence") or []):
        if isinstance(e, dict) and "type" in e and "content" in e:
            evidence.append(TestEvidence(type=e["type"], content=str(e["content"])[:5000]))

    return DynamicTestResult(
        finding_id=finding_id,
        status=status,
        details=parsed.get("details", ""),
        evidence=evidence,
        test_code=generation.get("test_script", ""),
        dockerfile=generation.get("dockerfile", ""),
        docker_compose=generation.get("docker_compose", ""),
        elapsed_seconds=execution.elapsed_seconds,
        generation_cost_usd=generation_cost,
    )


def _target_reached(stderr: str) -> bool:
    """Target reachability is an explicit runtime observation, not LLM prose."""
    return bool(
        re.search(
            r"(?m)^(?:TARGET_REACHED|VULSCAN_TARGET_REACHED):[^\r\n]+$",
            stderr or "",
        )
    )


def _parse_container_output(stdout: str) -> dict | None:
    """Extract the JSON result object from container stdout.

    The container may print debug info before the JSON. We look for the
    last valid JSON object in the output.
    """
    if not stdout.strip():
        return None

    # Try parsing the entire output as JSON
    try:
        return json.loads(stdout.strip())
    except json.JSONDecodeError:
        pass

    # Try each line from the end (last JSON object wins)
    lines = stdout.strip().split("\n")
    for line in reversed(lines):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue

    for candidate in reversed(_balanced_json_objects(stdout)):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    return None


def _balanced_json_objects(text: str) -> list[str]:
    """Extract balanced JSON object candidates from arbitrary output."""
    candidates: list[str] = []
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

    return candidates


def _detect_confirming_output(stdout: str, stderr: str) -> str:
    """Return sanitizer/crash output when it clearly confirms reproduction."""
    text = "\n".join(part for part in (stdout, stderr) if part)
    if not text:
        return ""
    if any(marker in text for marker in _CONFIRMATION_MARKERS):
        return text
    return ""


def is_harness_failure_result(
    result: DynamicTestResult,
    execution: DockerExecutionResult | None = None,
    generation: dict | None = None,
) -> bool:
    """True when the container failed before reaching the vulnerable code path."""
    text = result.details or ""
    if result.evidence:
        text = "\n".join([text] + [e.content for e in result.evidence])
    if execution is not None:
        text = "\n".join([
            text,
            execution.stdout or "",
            execution.stderr or "",
        ])
    return _looks_like_harness_failure(text, generation)


_PYTHON_HARNESS_MARKERS = (
    "traceback (most recent call last)",
    "modulenotfounderror",
    "importerror:",
    "syntaxerror:",
)

_GO_HARNESS_MARKERS = (
    "panic:",
    "runtime error:",
    "fatal error:",
)

_JS_HARNESS_MARKERS = (
    "unhandledpromiserejection",
    "unhandled promise rejection",
    "referenceerror:",
    "typeerror: cannot read propert",
)


def _language_harness_markers(generation: dict | None) -> tuple[str, ...]:
    if not generation:
        return ()
    lang = str(generation.get("_language", "")).lower()
    if lang in {"python", "py"}:
        return _PYTHON_HARNESS_MARKERS
    if lang in {"go", "golang"}:
        return _GO_HARNESS_MARKERS
    if lang in {"javascript", "js", "typescript", "ts"}:
        return _JS_HARNESS_MARKERS
    return ()


def _looks_like_harness_failure(text: str, generation: dict | None = None) -> bool:
    """Detect exec/execl failures and other harness setup errors."""
    lowered = (text or "").lower()
    if any(marker in lowered for marker in _HARNESS_FAILURE_MARKERS):
        return True
    if any(marker in lowered for marker in _language_harness_markers(generation)):
        return True
    if re.search(r"\bexit(?:ed|s)?\s+(?:normally\s+)?with\s+(?:code|status)\s+127\b", lowered):
        return True
    if re.search(r"\bexit(?:\s+code)?\s*[:=]\s*127\b", lowered):
        return True
    return False


def _looks_like_sanitizer_nonzero_child_exit(generation: dict, text: str) -> bool:
    """Detect generated harnesses that mislabel ASan child exit as not reproduced."""
    if not uses_native_sanitizer(str(generation.get("dockerfile", ""))):
        return False
    test_script = str(generation.get("test_script", ""))
    if "waitpid" not in test_script or "fork" not in test_script:
        return False

    if _NONZERO_CHILD_EXIT_RE.search(text or ""):
        return True
    if _EXIT_CODE_EVIDENCE_RE.search(text or ""):
        return True
    return False


def _apply_status_adjustments(status: str, generation: dict, text: str) -> str:
    """Promote weak NOT_REPRODUCED/INCONCLUSIVE results when ASan evidence exists."""
    if status == "NOT_REPRODUCED" and _looks_like_sanitizer_nonzero_child_exit(
        generation, text
    ):
        return "CONFIRMED"
    return status


def _looks_like_sigpipe_harness_failure(text: str) -> bool:
    """True when SIGPIPE likely comes from broken stderr pipe handling."""
    if not text:
        return False
    if not _SIGPIPE_HARNESS_RE.search(text):
        return False
    if _detect_confirming_output(text, ""):
        return False
    return True


def _repair_container_output(stdout: str) -> dict | None:
    """Best-effort repair for near-JSON container output.

    The dynamic test harness expects the container to print one JSON object,
    but C/C++ test programs occasionally forget to escape evidence text.
    This fallback salvages the fixed 911VulScan schema when the output is close
    enough to the expected shape to be unambiguously repaired.
    """
    text = stdout.strip()
    if not text:
        return None

    start = text.rfind('{"status"')
    if start == -1:
        start = text.find('{')
    end = text.rfind('}')
    if start == -1 or end == -1 or end <= start:
        return None

    body = text[start:end + 1]

    status_match = re.search(r'"status"\s*:\s*"([^"]+)"', body)
    details_match = re.search(r'"details"\s*:\s*"(.*)"\s*,\s*"evidence"\s*:\s*\[', body, re.S)
    type_match = re.search(r'"type"\s*:\s*"([^"]+)"', body)

    if not status_match or not details_match or not type_match:
        return None

    content_key = body.find('"content": "')
    if content_key == -1:
        return None
    content_start = content_key + len('"content": "')
    content_end = body.rfind('"}]}')
    if content_end == -1 or content_end <= content_start:
        return None

    return {
        "status": status_match.group(1),
        "details": details_match.group(1),
        "evidence": [{
            "type": type_match.group(1),
            "content": body[content_start:content_end],
        }],
    }
