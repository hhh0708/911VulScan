"""Tests for Python dynamic staging."""

from __future__ import annotations

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

FIXTURES = _CORE_ROOT / "tests" / "fixtures" / "dynamic" / "python_minimal"


def test_plan_python_staged_files():
    from utilities.dynamic_tester.python_stage import plan_python_staged_files

    source = FIXTURES / "vuln.py"
    staged, root, blocked = plan_python_staged_files(str(source), repo_path=str(FIXTURES))
    assert not blocked
    assert root == str(FIXTURES)
    assert "vuln.py" in staged
    assert "requirements.txt" in staged


def test_stage_python_project(tmp_path):
    from utilities.dynamic_tester.python_stage import stage_python_project

    work = tmp_path / "work"
    work.mkdir()
    source = FIXTURES / "vuln.py"
    basename, staged, blocked = stage_python_project(str(work), str(source), repo_path=str(FIXTURES))
    assert not blocked
    assert basename == "vuln.py"
    assert (work / "vuln.py").is_file()


def test_build_python_dockerfile():
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        build_python_dockerfile,
    )

    ctx = StagedBuildContext(
        language="python",
        test_filename="test_exploit.py",
        test_script="print('x')",
        staged_files=["vuln.py", "requirements.txt", "test_exploit.py"],
    )
    dockerfile = build_python_dockerfile(ctx)
    assert "FROM python:3.11-slim" in dockerfile
    assert "pip install" in dockerfile
    assert 'CMD ["python", "test_exploit.py"]' in dockerfile
