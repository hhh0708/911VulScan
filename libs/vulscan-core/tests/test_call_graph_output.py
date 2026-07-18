"""Tests that each parser writes call_graph.json to the output directory.

The call_graph.json file is required by apply_reachability_filter (and the
post-LLM re-filter path) so it must be present regardless of processing_level,
including when --llm-reachability causes a parse with scope="all".

Structure expected by apply_reachability_filter (unified schema + legacy):
    {
        "nodes": {...},
        "resolved_edges": [...],
        "unresolved_edges": [...],
        "structural_roots": [...],
        "provenance": {...},
        "functions": {<id>: {<metadata>}, ...},
        "call_graph": {<id>: [<callee_id>, ...], ...},
        "reverse_call_graph": {<id>: [<caller_id>, ...], ...},
    }

Parser availability gates (identical to patterns used in test_js_parser.py):
- Python: always available
- JavaScript: requires Node.js + parsers/javascript/node_modules
- Go: requires parsers/go/go_parser/go_parser binary
- C: requires tree_sitter_c Python package
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from core.parser_adapter import apply_reachability_filter, parse_repository

TESTS_DIR = Path(__file__).parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
PARSERS_DIR = Path(__file__).parent.parent / "parsers"

# ---------------------------------------------------------------------------
# Availability checks (used by skipif marks)
# ---------------------------------------------------------------------------

def _node_available() -> bool:
    return bool(shutil.which("node")) and (PARSERS_DIR / "javascript" / "node_modules").exists()

def _go_parser_available() -> bool:
    go_dir = PARSERS_DIR / "go" / "go_parser"
    # Check both Unix and Windows binary names.
    candidates = [go_dir / "go_parser", go_dir / "go_parser.exe"]
    binary = next((p for p in candidates if p.exists() and p.stat().st_size > 0), None)
    if binary is None:
        return False
    import subprocess
    try:
        subprocess.run([str(binary), "--help"], capture_output=True, timeout=5)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False

def _ts_c_available() -> bool:
    try:
        import tree_sitter_c  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CANONICAL_KEYS = {
    "nodes",
    "resolved_edges",
    "unresolved_edges",
    "structural_roots",
    "provenance",
}
_LEGACY_KEYS = {"functions", "call_graph", "reverse_call_graph"}


def _assert_call_graph_valid(output_dir: str) -> dict:
    """Load call_graph.json and assert the on-disk file is canonical-only."""
    cg_path = Path(output_dir) / "call_graph.json"
    assert cg_path.exists(), f"call_graph.json not found in {output_dir}"
    with open(cg_path) as f:
        data = json.load(f)
    assert _CANONICAL_KEYS <= data.keys(), (
        f"call_graph.json missing keys: {_CANONICAL_KEYS - data.keys()}"
    )
    # Legacy dual-source fields must not be persisted on disk.
    assert not (_LEGACY_KEYS & data.keys()), (
        f"canonical call_graph.json must not contain legacy keys: "
        f"{_LEGACY_KEYS & data.keys()}"
    )
    assert isinstance(data["nodes"], dict)
    assert isinstance(data["resolved_edges"], list)
    assert isinstance(data["unresolved_edges"], list)
    assert isinstance(data["structural_roots"], list)
    assert isinstance(data["provenance"], dict)
    return data


# ---------------------------------------------------------------------------
# apply_reachability_filter unit tests (always run — no external deps)
# ---------------------------------------------------------------------------


class TestApplyReachabilityFilterPublicAPI:
    """apply_reachability_filter is the consumer of call_graph.json.
    These tests verify it works correctly with a synthetic fixture."""

    def _make_call_graph_json(self, tmp_path: Path) -> None:
        """Write a minimal call_graph.json that apply_reachability_filter can parse.

        ``main`` is a structural program_entry root; ``_orphan`` is private.
        """
        cg = {
            "language": "python",
            "functions": {
                "app.py:main": {
                    "name": "main",
                    "filePath": "app.py",
                    "file_path": "app.py",
                    "unitType": "function",
                    "isExported": False,
                    "decorators": [],
                },
                "app.py:_helper": {
                    "name": "_helper",
                    "filePath": "app.py",
                    "file_path": "app.py",
                    "unitType": "private_function",
                    "isExported": False,
                    "decorators": [],
                },
                "app.py:_orphan": {
                    "name": "_orphan",
                    "filePath": "app.py",
                    "file_path": "app.py",
                    "unitType": "private_function",
                    "isExported": False,
                    "decorators": [],
                },
            },
            "call_graph": {
                "app.py:main": ["app.py:_helper"],
            },
            "reverse_call_graph": {
                "app.py:_helper": ["app.py:main"],
            },
        }
        (tmp_path / "call_graph.json").write_text(json.dumps(cg))

    def _make_dataset(self, unit_ids: list[str]) -> dict:
        return {
            "language": "python",
            "units": [
                {"id": uid, "code": {"primary_code": "pass"}, "unit_type": "function"}
                for uid in unit_ids
            ]
        }

    def test_filters_to_reachable_units(self, tmp_path):
        self._make_call_graph_json(tmp_path)
        dataset = self._make_dataset(
            ["app.py:main", "app.py:_helper", "app.py:_orphan"]
        )
        result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
        unit_ids = {u["id"] for u in result["units"]}
        assert "app.py:main" in unit_ids
        assert "app.py:_helper" in unit_ids
        assert "app.py:_orphan" not in unit_ids

    def test_non_structural_root_cannot_be_injected(self, tmp_path):
        import inspect

        self._make_call_graph_json(tmp_path)
        dataset = self._make_dataset(
            ["app.py:main", "app.py:_helper", "app.py:_orphan"]
        )
        dataset["units"][2]["is_entry_point"] = True
        dataset["units"][2]["entry_point_reason"] = "llm_reachability: fake"
        sig = inspect.signature(apply_reachability_filter)
        assert "extra_entry_points" not in sig.parameters
        result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
        unit_ids = {u["id"] for u in result["units"]}
        assert "app.py:_orphan" not in unit_ids

    def test_is_entry_point_set_on_structural_entry_points(self, tmp_path):
        self._make_call_graph_json(tmp_path)
        dataset = self._make_dataset(["app.py:main", "app.py:_helper"])
        result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
        by_id = {u["id"]: u for u in result["units"]}
        assert by_id["app.py:main"]["is_entry_point"] is True
        assert by_id["app.py:_helper"]["is_entry_point"] is False

    def test_llm_promoted_flag_is_cleared_for_non_roots(self, tmp_path):
        self._make_call_graph_json(tmp_path)
        dataset = self._make_dataset(["app.py:main", "app.py:_helper"])
        dataset["units"][1]["is_entry_point"] = True
        dataset["units"][1]["entry_point_reason"] = "llm_reachability: fake"
        result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
        by_id = {u["id"]: u for u in result["units"]}
        assert by_id["app.py:_helper"]["is_entry_point"] is False

    def test_missing_call_graph_marks_all_unknown(self, tmp_path):
        dataset = self._make_dataset(["app.py:main", "app.py:_orphan"])
        result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
        assert len(result["units"]) == 2
        assert all(u["reachability"] == "unknown" for u in result["units"])
        assert result["metadata"]["reachability_filter"]["call_graph_error"] == "missing"


# ---------------------------------------------------------------------------
# Python parser — always runs
# ---------------------------------------------------------------------------


class TestPythonCallGraphOutput:
    def test_call_graph_json_written(self, sample_python_repo, tmp_output_dir):
        parse_repository(
            repo_path=sample_python_repo,
            output_dir=tmp_output_dir,
            language="python",
            scope="all",
        )
        _assert_call_graph_valid(tmp_output_dir)

    def test_call_graph_json_written_with_reachable_level(
        self, sample_python_repo, tmp_output_dir
    ):
        parse_repository(
            repo_path=sample_python_repo,
            output_dir=tmp_output_dir,
            language="python",
            scope="reachable",
        )
        _assert_call_graph_valid(tmp_output_dir)


# ---------------------------------------------------------------------------
# JavaScript parser
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _node_available(), reason="Node.js or JS parser npm deps not available")
class TestJavaScriptCallGraphOutput:
    def test_call_graph_json_written(self, sample_js_repo, tmp_output_dir):
        parse_repository(
            repo_path=sample_js_repo,
            output_dir=tmp_output_dir,
            language="javascript",
            scope="all",
        )
        _assert_call_graph_valid(tmp_output_dir)

    def test_call_graph_json_written_with_reachable_level(
        self, sample_js_repo, tmp_output_dir
    ):
        parse_repository(
            repo_path=sample_js_repo,
            output_dir=tmp_output_dir,
            language="javascript",
            scope="reachable",
        )
        _assert_call_graph_valid(tmp_output_dir)


# ---------------------------------------------------------------------------
# Go parser
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_go_repo(tmp_path):
    """Minimal Go repository fixture."""
    repo = tmp_path / "go_repo"
    repo.mkdir()
    (repo / "go.mod").write_text("module example.com/myapp\n\ngo 1.21\n")
    (repo / "main.go").write_text(
        'package main\n\nimport "fmt"\n\n'
        "func main() {\n\tgreet()\n}\n\n"
        'func greet() {\n\tfmt.Println("hello")\n}\n'
    )
    return str(repo)


@pytest.mark.skipif(not _go_parser_available(), reason="go_parser binary not available")
class TestGoCallGraphOutput:
    def test_call_graph_json_written(self, sample_go_repo, tmp_output_dir):
        parse_repository(
            repo_path=sample_go_repo,
            output_dir=tmp_output_dir,
            language="go",
            scope="all",
        )
        _assert_call_graph_valid(tmp_output_dir)

    def test_call_graph_json_written_with_reachable_level(
        self, sample_go_repo, tmp_output_dir
    ):
        parse_repository(
            repo_path=sample_go_repo,
            output_dir=tmp_output_dir,
            language="go",
            scope="reachable",
        )
        _assert_call_graph_valid(tmp_output_dir)


# ---------------------------------------------------------------------------
# C parser
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_c_repo(tmp_path):
    """Minimal C repository fixture."""
    repo = tmp_path / "c_repo"
    repo.mkdir()
    (repo / "main.c").write_text(
        "#include <stdio.h>\n\nvoid greet() {\n    printf(\"hello\\n\");\n}\n\n"
        "int main() {\n    greet();\n    return 0;\n}\n"
    )
    return str(repo)


@pytest.mark.skipif(not _ts_c_available(), reason="tree_sitter_c not installed")
class TestCCallGraphOutput:
    def test_call_graph_json_written(self, sample_c_repo, tmp_output_dir):
        parse_repository(
            repo_path=sample_c_repo,
            output_dir=tmp_output_dir,
            language="c",
            scope="all",
        )
        _assert_call_graph_valid(tmp_output_dir)

    def test_call_graph_json_written_with_reachable_level(
        self, sample_c_repo, tmp_output_dir
    ):
        parse_repository(
            repo_path=sample_c_repo,
            output_dir=tmp_output_dir,
            language="c",
            scope="reachable",
        )
        _assert_call_graph_valid(tmp_output_dir)


# ---------------------------------------------------------------------------
# Ruby parser
# ---------------------------------------------------------------------------


class TestRemovedLanguagesRejected:
    """Ruby/PHP/Zig CLI and auto-detect entry points were removed in Phase 1."""

    @pytest.mark.parametrize("lang", ["ruby", "php", "zig"])
    def test_parse_rejects_removed_language(self, lang, tmp_path, tmp_output_dir):
        from core.pipeline_config import PipelineConfigError

        repo = tmp_path / f"{lang}_repo"
        repo.mkdir()
        (repo / "x.txt").write_text("placeholder")
        with pytest.raises(PipelineConfigError, match="no longer supported"):
            parse_repository(
                repo_path=str(repo),
                output_dir=tmp_output_dir,
                language=lang,
                scope="all",
            )
