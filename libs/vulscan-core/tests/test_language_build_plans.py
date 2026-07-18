"""Tests for BuildPlan and language registry."""

from __future__ import annotations

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

FIXTURES = _CORE_ROOT / "tests" / "fixtures" / "dynamic"


def test_resource_scope_unique_names():
    from utilities.dynamic_tester.build_plan import ResourceScope

    a = ResourceScope.create("VULN-001", batch_run_id="abc12345")
    b = ResourceScope.create("VULN-001", batch_run_id="def67890")
    assert a.image_tag != b.image_tag
    assert a.compose_project != b.compose_project
    assert a.docker_labels()["vulscan.run_id"] == "abc12345"


def test_materialize_python_build_plan(tmp_path):
    from utilities.dynamic_tester.language_registry import materialize_build_plan

    repo = FIXTURES / "python_minimal"
    finding = {"id": "PY-1", "location": {"file": "vuln.py"}}
    generation = {
        "dockerfile": "FROM evil",
        "test_script": 'print("ok")',
        "test_filename": "test_exploit.py",
    }
    plan = materialize_build_plan(
        generation,
        finding,
        {"language": "python"},
        repo_path=str(repo),
    )
    assert not plan.blocked
    assert "vuln.py" in plan.staged_files
    assert plan.execution_mode == "single"


def test_materialize_go_blocked_without_mod(tmp_path):
    from utilities.dynamic_tester.language_registry import materialize_build_plan

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.go").write_text("package main\nfunc main() {}\n")
    finding = {"id": "GO-1", "location": {"file": "main.go"}}
    generation = {
        "dockerfile": "# assembled",
        "test_script": "package main\nfunc main() {}",
        "test_filename": "test_exploit.go",
    }
    plan = materialize_build_plan(
        generation,
        finding,
        {"language": "go"},
        repo_path=str(repo),
    )
    assert plan.blocked
    assert "go.mod" in plan.blocked_reason.lower()


def test_framework_compose_topology():
    from utilities.dynamic_tester.compose_builder import build_compose_yaml

    content = build_compose_yaml()
    assert "internal: true" in content
    assert "cap_drop:" in content
    assert "no-new-privileges" in content
    assert "attacker:" in content
    assert "test:" in content
