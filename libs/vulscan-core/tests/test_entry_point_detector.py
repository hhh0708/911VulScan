"""Tests for structural roots (replaces EntryPointDetector facade).

Framework unit types / decorator regexes are no longer entry points.
"""
from utilities.call_graph.schema import finalize_call_graph
from utilities.call_graph.structural_roots import detect_structural_roots, structural_root_ids


def test_framework_unit_types_are_not_automatic_roots():
    functions = {
        "server.js:fn": {
            "name": "fn",
            "unit_type": "route_handler",
            "isExported": False,
            "code": "async (req, res, next) => { next(); }",
        }
    }
    doc = finalize_call_graph(
        {"functions": functions, "call_graph": {}}, language="javascript"
    )
    roots = structural_root_ids(doc["structural_roots"])
    assert "server.js:fn" not in roots


def test_exported_symbol_is_structural_root():
    functions = {
        "lib.js:api": {
            "name": "api",
            "unit_type": "function",
            "isExported": True,
            "code": "export function api() {}",
        }
    }
    doc = finalize_call_graph(
        {"functions": functions, "call_graph": {}}, language="javascript"
    )
    roots = structural_root_ids(doc["structural_roots"])
    assert "lib.js:api" in roots
    kinds = {r["id"]: r["kind"] for r in doc["structural_roots"]}
    assert kinds["lib.js:api"] == "exported_symbol"


def test_main_is_program_entry():
    functions = {
        "app.py:main": {
            "name": "main",
            "unit_type": "function",
            "file_path": "app.py",
            "code": "def main():\n    pass\n",
        }
    }
    doc = finalize_call_graph(
        {"functions": functions, "call_graph": {}}, language="python"
    )
    roots = structural_root_ids(detect_structural_roots(doc["nodes"], language="python"))
    assert "app.py:main" in roots
