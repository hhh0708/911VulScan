"""Optional real-Docker smoke tests for dynamic verification."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_CORE_ROOT))

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="Docker not available",
)


def test_python_fixture_builds_and_runs(tmp_path):
    from utilities.dynamic_tester.docker_executor import run_single_container

    fixtures = _CORE_ROOT / "tests" / "fixtures" / "dynamic" / "python_minimal"
    generation = {
        "dockerfile": "# assembled by 911VulScan",
        "test_script": (
            'import json\n'
            'print(json.dumps({"status": "NOT_REPRODUCED", "details": "smoke", "evidence": []}))\n'
        ),
        "test_filename": "test_exploit.py",
        "requirements": "",
        "requirements_filename": "requirements.txt",
        "_language": "python",
    }
    finding = {"id": "SMOKE-PY", "location": {"file": "vuln.py"}}
    repo_info = {"language": "python", "name": "smoke"}

    result = run_single_container(
        generation,
        "SMOKE-PY",
        source_file=str(fixtures / "vuln.py"),
        language="python",
        repo_path=str(fixtures),
        batch_run_id="smokepy01",
        finding=finding,
        repo_info=repo_info,
        build_timeout=300,
        container_timeout=120,
    )
    if result.build_error and "DeadlineExceeded" in (result.build_error or ""):
        pytest.skip("Docker registry unreachable")
    assert result.build_error is None, result.build_error
    assert "NOT_REPRODUCED" in (result.stdout or "")
