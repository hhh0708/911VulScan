"""Tests for bundled library export extraction (lodash IIFE pattern)."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest


PARSERS_JS_DIR = Path(__file__).parent.parent.parent.parent / "parsers" / "javascript"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"
LODASH_REPO = (
    Path(__file__).parent.parent.parent.parent.parent.parent
    / "Project_for_911VulScan"
    / "lodash-4.0.0"
)

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def _run_analyzer(repo_path, file_path):
    cmd = ["node", str(PARSERS_JS_DIR / "typescript_analyzer.js"), str(repo_path), str(file_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_lodash_template_extracted_from_iife_bundle(tmp_path):
    """lodash.template = template must resolve the nested template() function."""
    if not LODASH_REPO.is_dir():
        pytest.skip("lodash-4.0.0 fixture repo not available")

    lodash_js = LODASH_REPO / "lodash.js"
    out = _run_analyzer(LODASH_REPO, lodash_js)

    template_id = "lodash.js:template"
    assert template_id in out["functions"], (
        f"expected {template_id}; keys sample={list(out['functions'])[:10]}"
    )
    data = out["functions"][template_id]
    assert data["isExported"] is True
    assert data["libraryExport"] == "template"
    assert "Function(" in data["code"]
    assert "options.variable" in data["code"]
    assert template_id in out["callGraph"]


def test_minimal_iife_library_fixture(tmp_path):
    repo = tmp_path / "lib"
    repo.mkdir()
    lib = repo / "bundle.js"
    lib.write_text(
        """
;(function() {
  function template(string, options) {
    var source = 'function(obj) { return __p; }';
    return Function('return ' + source)();
  }
  lodash.template = template;
}).call(this);
"""
    )
    out = _run_analyzer(repo, lib)
    assert "bundle.js:template" in out["functions"]
    assert out["functions"]["bundle.js:template"]["isExported"] is True

