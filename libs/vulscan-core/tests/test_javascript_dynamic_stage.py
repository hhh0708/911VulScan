"""Tests for JavaScript dynamic staging."""

from __future__ import annotations

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

FIXTURES = _CORE_ROOT / "tests" / "fixtures" / "dynamic" / "js_minimal"


def test_plan_javascript_staged_files():
    from utilities.dynamic_tester.javascript_stage import plan_javascript_staged_files

    source = FIXTURES / "lib.js"
    staged, root, blocked = plan_javascript_staged_files(str(source), repo_path=str(FIXTURES))
    assert not blocked
    assert "package.json" in staged
    assert "lib.js" in staged


def test_build_javascript_dockerfile():
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        build_javascript_dockerfile,
    )

    ctx = StagedBuildContext(
        language="javascript",
        test_filename="test_exploit.js",
        test_script="console.log('x')",
        staged_files=["package.json", "lib.js", "test_exploit.js"],
    )
    dockerfile = build_javascript_dockerfile(ctx)
    assert "FROM node:20-slim" in dockerfile
    assert "npm" in dockerfile
    assert 'CMD ["node", "test_exploit.js"]' in dockerfile
