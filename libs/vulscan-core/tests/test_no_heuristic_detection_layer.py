"""Architecture tests: old heuristic detection layer must stay out of production."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = CORE_ROOT.parents[1]

REMOVED_MODULES = (
    "real_world",
    "core.code_evidence",
    "utilities.evidence_rules",
)

FORBIDDEN_IMPORT_ROOTS = (
    "real_world",
    "core.code_evidence",
    "utilities.evidence_rules",
)

# Production packages that must not reintroduce the heuristic layer.
PRODUCTION_DIRS = (
    CORE_ROOT / "core",
    CORE_ROOT / "utilities",
    CORE_ROOT / "prompts",
    CORE_ROOT / "vulscan",
    CORE_ROOT / "context",
    CORE_ROOT / "report",
    CORE_ROOT / "parsers",
)

FORBIDDEN_TERMS = (
    "strip_real_world_fields",
    "collect_code_evidence",
    "reconcile_stage1_verdict",
    "apply_stage1_static_backstop",
    "FAMILY_RULES",
    "SUPPORT_MATRIX",
    "miss_diagnosis",
    "risk_backstop",
    "format_real_world_for_prompt",
)


def test_removed_packages_are_not_importable():
    for mod in REMOVED_MODULES:
        try:
            spec = importlib.util.find_spec(mod)
        except ModuleNotFoundError:
            spec = None
        assert spec is None, f"{mod} must not be importable"


def test_real_world_directory_deleted():
    assert not (CORE_ROOT / "real_world").exists()
    assert not (CORE_ROOT / "core" / "code_evidence.py").exists()
    assert not (CORE_ROOT / "utilities" / "evidence_rules.py").exists()


def _iter_production_py_files():
    for directory in PRODUCTION_DIRS:
        if not directory.is_dir():
            continue
        for path in directory.rglob("*.py"):
            if "tests" in path.parts or path.name.startswith("test_"):
                continue
            yield path
    # Thin deprecation stub only (research harness is under research/)
    stub = CORE_ROOT / "experiment.py"
    if stub.is_file():
        yield stub


def test_production_code_has_no_forbidden_imports():
    offenders: list[str] = []
    for path in _iter_production_py_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if alias.name in FORBIDDEN_IMPORT_ROOTS or root == "real_world":
                        offenders.append(f"{path.relative_to(REPO_ROOT)}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                mod = node.module
                if mod == "real_world" or mod.startswith("real_world."):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: from {mod}")
                if mod in {"core.code_evidence", "utilities.evidence_rules"}:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: from {mod}")
    assert offenders == [], "forbidden imports:\n" + "\n".join(offenders)


def test_production_code_has_no_forbidden_heuristic_terms():
    offenders: list[str] = []
    for path in _iter_production_py_files():
        text = path.read_text(encoding="utf-8")
        for term in FORBIDDEN_TERMS:
            if term in text:
                # Allow comments that explicitly say the layer was removed.
                for i, line in enumerate(text.splitlines(), 1):
                    if term in line and not line.lstrip().startswith("#"):
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}:{i}: {term}"
                        )
    assert offenders == [], "forbidden terms in production code:\n" + "\n".join(offenders)


def test_stage1_analyze_unit_has_no_verdict_reconcile():
    src = (CORE_ROOT / "core" / "analyzer.py").read_text(encoding="utf-8")
    assert "reconcile_stage1_verdict" not in src
    assert "apply_stage1_static_backstop" not in src
    assert "collect_code_evidence" not in src
    assert "from experiment" not in src
    assert "import experiment" not in src


def test_stage2_uses_candidate_gate_only():
    src = (CORE_ROOT / "core" / "verifier.py").read_text(encoding="utf-8")
    assert "needs_stage2_review" not in src
    assert "evidence_rules" not in src
    assert '== "candidate"' in src
    assert "get_consistency_check_prompt" not in src
    assert "correct_finding" not in src
