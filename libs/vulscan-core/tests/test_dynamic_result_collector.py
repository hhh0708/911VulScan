"""Tests for dynamic test result collection."""

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    _stub.RateLimitError = type("RateLimitError", (Exception,), {})
    _stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _stub


def test_collect_result_confirms_raw_asan_output():
    from utilities.dynamic_tester.docker_executor import DockerExecutionResult
    from utilities.dynamic_tester.result_collector import collect_result

    execution = DockerExecutionResult()
    execution.stdout = "=================================================================\n"
    execution.stderr = "ERROR: AddressSanitizer: heap-buffer-overflow\nSUMMARY: AddressSanitizer\n"
    execution.exit_code = 1

    result = collect_result(
        {"id": "VULN-TEST"},
        {"test_script": "int main(void){return 0;}", "dockerfile": "FROM gcc:13"},
        execution,
    )

    assert result.status == "CONFIRMED"
    assert "sanitizer" in result.details.lower()


def test_collect_result_overrides_misclassified_asan_evidence():
    from utilities.dynamic_tester.docker_executor import DockerExecutionResult
    from utilities.dynamic_tester.result_collector import collect_result

    execution = DockerExecutionResult()
    execution.stdout = (
        '{"status":"NOT_REPRODUCED","details":"missed",'
        '"evidence":[{"type":"command_output",'
        '"content":"ERROR: AddressSanitizer: stack-buffer-overflow"}]}'
    )

    result = collect_result(
        {"id": "VULN-TEST"},
        {"test_script": "int main(void){return 0;}", "dockerfile": "FROM gcc:13"},
        execution,
    )

    assert result.status == "CONFIRMED"


def test_collect_result_overrides_asan_child_nonzero_not_reproduced():
    from utilities.dynamic_tester.docker_executor import DockerExecutionResult
    from utilities.dynamic_tester.result_collector import collect_result

    execution = DockerExecutionResult()
    execution.stdout = (
        '{"status":"NOT_REPRODUCED",'
        '"details":"Process exited normally with code 1",'
        '"evidence":[{"type":"command_output","content":"Exit code: 1"}]}'
    )

    result = collect_result(
        {"id": "VULN-TEST"},
        {
            "test_script": "int main(void){ if (fork() == 0) return 1; waitpid(0,0,0); }",
            "dockerfile": "RUN gcc -fsanitize=address -o /work/test_exploit test_exploit.c",
        },
        execution,
    )

    assert result.status == "CONFIRMED"


def test_collect_result_rejects_exit_127_harness_failure():
    from utilities.dynamic_tester.docker_executor import DockerExecutionResult
    from utilities.dynamic_tester.result_collector import collect_result

    execution = DockerExecutionResult()
    execution.stdout = (
        '{"status":"CONFIRMED",'
        '"details":"Process exited abnormally (exit code 127)",'
        '"evidence":[{"type":"command_output","content":"execl: No such file or directory\\n"}]}'
    )

    result = collect_result(
        {"id": "VULN-TEST"},
        {
            "test_script": "int main(void){ execl(\"/missing\", \"missing\", 0); }",
            "dockerfile": "RUN gcc -fsanitize=address -o /work/test_exploit test_exploit.c",
        },
        execution,
    )

    assert result.status == "INCONCLUSIVE"
    assert "harness" in result.details.lower() or "127" in result.details


def test_collect_result_parses_multiline_json_after_debug_output():
    from utilities.dynamic_tester.docker_executor import DockerExecutionResult
    from utilities.dynamic_tester.result_collector import collect_result

    execution = DockerExecutionResult()
    execution.stdout = """debug line
{
  "status": "INCONCLUSIVE",
  "details": "multi-line json",
  "evidence": []
}
"""

    result = collect_result(
        {"id": "VULN-TEST"},
        {"test_script": "int main(void){return 0;}", "dockerfile": "FROM gcc:13"},
        execution,
    )

    assert result.status == "INCONCLUSIVE"
    assert result.details == "multi-line json"


def test_collect_result_detects_python_traceback_harness_failure():
    from utilities.dynamic_tester.docker_executor import DockerExecutionResult
    from utilities.dynamic_tester.result_collector import collect_result

    execution = DockerExecutionResult()
    execution.stderr = (
        "Traceback (most recent call last):\n"
        '  File "test_exploit.py", line 1, in <module>\n'
        "ModuleNotFoundError: No module named 'missing'\n"
    )
    execution.exit_code = 1

    generation = {"test_script": "import missing", "dockerfile": "FROM python:3.11-slim", "_language": "python"}
    result = collect_result({"id": "PY-ERR"}, generation, execution)
    assert result.status in {"ERROR", "INCONCLUSIVE"}


def test_looks_like_harness_failure_go_panic():
    from utilities.dynamic_tester.result_collector import _looks_like_harness_failure

    text = "panic: runtime error: index out of range"
    assert _looks_like_harness_failure(text, {"_language": "go"})


def test_looks_like_harness_failure_js_rejection():
    from utilities.dynamic_tester.result_collector import _looks_like_harness_failure

    text = "UnhandledPromiseRejectionWarning: ReferenceError: foo is not defined"
    assert _looks_like_harness_failure(text, {"_language": "javascript"})

