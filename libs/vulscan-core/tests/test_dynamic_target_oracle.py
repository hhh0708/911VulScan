"""Dynamic oracle: CONFIRMED requires target-reach evidence when checked."""

from __future__ import annotations

from utilities.dynamic_tester.docker_executor import DockerExecutionResult
from utilities.dynamic_tester.result_collector import collect_result


def _execution(stdout: str, stderr: str = "", exit_code: int = 0) -> DockerExecutionResult:
    result = DockerExecutionResult()
    result.stdout = stdout
    result.stderr = stderr
    result.exit_code = exit_code
    result.elapsed_seconds = 0.1
    return result


def test_confirmed_without_target_marker_becomes_inconclusive():
    finding = {
        "id": "VULN-001",
        "repro_checks": [
            {"description": "must reach GetCharacterRef", "target_symbol": "GetCharacterRef"}
        ],
        "location": {"function": "GetCharacterRef"},
    }
    generation = {
        "test_script": "int main(){return 0;}",
        "dockerfile": "# assembled",
        "_requires_target_evidence": True,
        "_repro_checks": finding["repro_checks"],
    }
    result = collect_result(
        finding,
        generation,
        _execution(
            '{"status":"CONFIRMED","details":"crash","evidence":[{"type":"command_output","content":"AddressSanitizer: heap-buffer-overflow"}]}',
            stderr="asan report",
        ),
    )
    assert result.status == "INCONCLUSIVE"
    assert "target" in result.details.lower()


def test_confirmed_with_target_marker_stays_confirmed():
    finding = {
        "id": "VULN-002",
        "repro_checks": [{"description": "reach sink"}],
        "location": {"function": "sink"},
    }
    generation = {
        "test_script": "int main(){return 0;}",
        "dockerfile": "# assembled",
        "_requires_target_evidence": True,
    }
    result = collect_result(
        finding,
        generation,
        _execution(
            '{"status":"CONFIRMED","details":"ok","evidence":[{"type":"command_output","content":"AddressSanitizer: heap-buffer-overflow"}]}',
            stderr="TARGET_REACHED:sink\n",
        ),
    )
    assert result.status == "CONFIRMED"
