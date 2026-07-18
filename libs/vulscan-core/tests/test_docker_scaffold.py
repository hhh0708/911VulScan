"""Regression tests for Dockerfile scaffold pre-staging.

The dynamic-test scaffold must stage the vulnerable source file into the
Docker build context BEFORE asking the LLM to write the Dockerfile, so
`COPY VulnerablePythonScript.py .` works on the first try.
"""

import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    _stub.RateLimitError = type("RateLimitError", (Exception,), {})
    _stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _stub


def _canonical_stage2(finding_id: str) -> dict:
    """Canonical Stage 2 record required by `is_testable_finding` (Phase 10b+):
    succeeded + confirmed with finding_id and resolvable evidence."""
    return {
        "finding_id": finding_id,
        "execution_state": "succeeded",
        "decision": "confirmed",
        "evidence_ids": ["ev1"],
        "evidence": [{"evidence_id": "ev1", "kind": "obs", "content": {}}],
    }


def test_write_test_files_stages_source(tmp_path):
    """_write_test_files must copy the vulnerable source into the work dir."""
    from utilities.dynamic_tester.docker_executor import _write_test_files

    # Create a fake source file to stage. Current staging contract: Python
    # sources are staged as a bounded project tree, which requires a project
    # root marker (pyproject.toml/setup.py/requirements*.txt).
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "requirements.txt").write_text("flask\n", encoding="utf-8")
    source = repo_dir / "app.py"
    source.write_text("def vuln(): pass", encoding="utf-8")

    generation = {
        "dockerfile": "FROM python:3.11\nCOPY app.py .\nCMD python app.py",
        "test_script": "print('test')",
        "test_filename": "test_exploit.py",
        "requirements": "flask",
    }

    finding = {
        "location": {"file": "app.py", "function": "app.py:vuln"},
    }

    work_dir = str(tmp_path / "work")
    os.makedirs(work_dir)

    _write_test_files(work_dir, generation, source_file=str(source))

    staged = os.path.join(work_dir, "app.py")
    assert os.path.exists(staged), "source file must be staged into work_dir"
    assert open(staged, encoding="utf-8").read() == "def vuln(): pass"


def test_write_test_files_stages_same_directory_headers(tmp_path):
    """_write_test_files must copy same-directory headers into the work dir."""
    from utilities.dynamic_tester.docker_executor import _write_test_files

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    source = repo_dir / "app.c"
    source.write_text('#include "app.h"\n#include "app.hpp"\nint main(void) { return 0; }')
    (repo_dir / "app.h").write_text("#define APP_H 1")
    (repo_dir / "app.hpp").write_text("inline int answer() { return 42; }")

    generation = {
        "dockerfile": "FROM gcc:13\nCOPY app.c .\nCOPY app.h .\nCOPY app.hpp .\nCMD echo hi",
        "test_script": "print('test')",
        "test_filename": "test_exploit.py",
    }

    work_dir = str(tmp_path / "work")
    os.makedirs(work_dir)

    _write_test_files(work_dir, generation, source_file=str(source))

    staged_h = os.path.join(work_dir, "app.h")
    staged_hpp = os.path.join(work_dir, "app.hpp")
    assert os.path.exists(staged_h), "same-directory header must be staged into work_dir"
    assert os.path.exists(staged_hpp), "same-directory C++ header must be staged into work_dir"
    assert open(staged_h).read() == "#define APP_H 1"
    assert open(staged_hpp).read() == "inline int answer() { return 42; }"


def test_write_test_files_works_without_source(tmp_path):
    """Backward compat: _write_test_files must not fail when no source_file is given."""
    from utilities.dynamic_tester.docker_executor import _write_test_files

    generation = {
        "dockerfile": "FROM python:3.11\nCMD echo hi",
        "test_script": "print('test')",
        "test_filename": "test_exploit.py",
    }

    work_dir = str(tmp_path / "work")
    os.makedirs(work_dir)

    # Must not raise
    _write_test_files(work_dir, generation)


# ---------------------------------------------------------------------------
# Link 3: orchestrator resolves source_file and passes it to run_single_container
# ---------------------------------------------------------------------------

def test_orchestrator_passes_source_file(tmp_path, monkeypatch):
    """run_dynamic_tests must resolve source_file from repo_path + finding.location.file
    and pass it through to run_single_container."""
    import json

    # Create a fake repo with a source file
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def vuln(): pass")

    # Create a minimal pipeline_output.json
    po = {
        "repository": {"name": "test", "language": "python"},
        "application_type": "web_app",
        "findings": [{
            "id": "VULN-001",
            "name": "test vuln",
            "short_name": "vuln",
            "location": {"file": "app.py", "function": "app.py:vuln"},
            "cwe_id": 79,
            "cwe_name": "XSS",
            "stage2_verification": _canonical_stage2("VULN-001"),
        }],
    }
    po_path = tmp_path / "pipeline_output.json"
    po_path.write_text(json.dumps(po), encoding="utf-8")

    # Track what run_single_container receives
    captured_kwargs = {}

    def mock_generate_test(finding, repo_info, tracker, repo_path=None, **kwargs):
        return {
            "dockerfile": "FROM python:3.11\nCMD echo hi",
            "test_script": "print('ok')",
            "test_filename": "test_exploit.py",
        }

    def mock_run_single_container(generation, finding_id, source_file=None, **kwargs):
        captured_kwargs["source_file"] = source_file
        from utilities.dynamic_tester.docker_executor import DockerExecutionResult
        result = DockerExecutionResult()
        result.stdout = '{"status": "CONFIRMED", "details": "test", "evidence": []}'
        result.exit_code = 0
        return result

    monkeypatch.setattr("utilities.dynamic_tester.generate_test", mock_generate_test)
    monkeypatch.setattr("utilities.dynamic_tester.run_single_container", mock_run_single_container)

    from utilities.dynamic_tester import run_dynamic_tests
    run_dynamic_tests(
        pipeline_output_path=str(po_path),
        output_dir=str(tmp_path / "out"),
        max_retries=0,
        repo_path=str(repo),
    )

    assert captured_kwargs.get("source_file") is not None, (
        "orchestrator must pass source_file to run_single_container"
    )
    assert captured_kwargs["source_file"].endswith("app.py")
    assert os.path.isfile(captured_kwargs["source_file"])


def test_orchestrator_works_without_repo_path(tmp_path, monkeypatch):
    """Backward compat: when repo_path is None, source_file should be None."""
    import json

    po = {
        "repository": {"name": "test", "language": "python"},
        "application_type": "web_app",
        "findings": [{
            "id": "VULN-001",
            "name": "test",
            "short_name": "vuln",
            "location": {"file": "app.py", "function": "app.py:vuln"},
            "cwe_id": 79,
            "cwe_name": "XSS",
            "stage2_verification": _canonical_stage2("VULN-001"),
        }],
    }
    po_path = tmp_path / "pipeline_output.json"
    po_path.write_text(json.dumps(po), encoding="utf-8")

    captured_kwargs = {}

    def mock_generate_test(finding, repo_info, tracker, repo_path=None, **kwargs):
        return {
            "dockerfile": "FROM python:3.11\nCMD echo hi",
            "test_script": "print('ok')",
            "test_filename": "test_exploit.py",
        }

    def mock_run_single_container(generation, finding_id, source_file=None, **kwargs):
        captured_kwargs["source_file"] = source_file
        from utilities.dynamic_tester.docker_executor import DockerExecutionResult
        result = DockerExecutionResult()
        result.stdout = '{"status": "CONFIRMED", "details": "test", "evidence": []}'
        result.exit_code = 0
        return result

    monkeypatch.setattr("utilities.dynamic_tester.generate_test", mock_generate_test)
    monkeypatch.setattr("utilities.dynamic_tester.run_single_container", mock_run_single_container)

    from utilities.dynamic_tester import run_dynamic_tests
    run_dynamic_tests(
        pipeline_output_path=str(po_path),
        output_dir=str(tmp_path / "out"),
        max_retries=0,
    )

    assert captured_kwargs.get("source_file") is None, (
        "without repo_path, source_file must be None (backward compat)"
    )


def test_orchestrator_filters_non_testable_findings(tmp_path, monkeypatch):
    """run_dynamic_tests should test only Stage 2-confirmed findings."""
    import json

    po = {
        "repository": {"name": "test", "language": "python"},
        "application_type": "web_app",
        "findings": [
            {
                "id": "VULN-001",
                "name": "confirmed",
                "location": {"file": "app.py"},
                "stage2_verification": _canonical_stage2("VULN-001"),
            },
            {
                "id": "VULN-002",
                "name": "rejected",
                "location": {"file": "app.py"},
                "stage2_verdict": "rejected",
            },
        ],
    }
    po_path = tmp_path / "pipeline_output.json"
    po_path.write_text(json.dumps(po), encoding="utf-8")

    tested_ids = []

    def mock_generate_test(finding, repo_info, tracker, repo_path=None, **kwargs):
        tested_ids.append(finding["id"])
        return {
            "dockerfile": "FROM python:3.11\nCMD echo hi",
            "test_script": "print('ok')",
            "test_filename": "test_exploit.py",
        }

    def mock_run_single_container(generation, finding_id, source_file=None, **kwargs):
        from utilities.dynamic_tester.docker_executor import DockerExecutionResult
        result = DockerExecutionResult()
        result.stdout = '{"status": "CONFIRMED", "details": "test", "evidence": []}'
        result.exit_code = 0
        return result

    monkeypatch.setattr("utilities.dynamic_tester.generate_test", mock_generate_test)
    monkeypatch.setattr("utilities.dynamic_tester.run_single_container", mock_run_single_container)

    from utilities.dynamic_tester import run_dynamic_tests
    results = run_dynamic_tests(
        pipeline_output_path=str(po_path),
        output_dir=str(tmp_path / "out"),
        max_retries=0,
    )

    assert tested_ids == ["VULN-001"]
    assert [r.finding_id for r in results] == ["VULN-001"]
    results_json = json.loads((tmp_path / "out" / "dynamic_test_results.json").read_text(encoding="utf-8"))
    assert results_json["total_findings"] == 2
    assert results_json["findings_tested"] == 1


# ---------------------------------------------------------------------------
# Link 4 + prompt: existing tests
# ---------------------------------------------------------------------------

def test_finding_prompt_includes_source_basename():
    """_build_finding_prompt must tell the LLM the staged filename."""
    from utilities.dynamic_tester.test_generator import _build_finding_prompt

    finding = {
        "id": "VULN-001",
        "name": "Command Injection",
        "cwe_id": 78,
        "cwe_name": "Command Injection",
        "location": {"file": "VulnerablePythonScript.py", "function": "ping"},
        "stage1_verdict": "vulnerable",
        "stage2_verdict": "agreed",
        "vulnerable_code": "def ping(): ...",
    }
    repo_info = {"name": "test", "language": "python", "application_type": "web_app"}

    prompt = _build_finding_prompt(finding, repo_info)
    assert "VulnerablePythonScript.py" in prompt, (
        "prompt must mention the staged source filename so the LLM references it in COPY"
    )
