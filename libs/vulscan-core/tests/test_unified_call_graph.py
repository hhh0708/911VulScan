"""Cross-language consistency tests for the unified call-graph layer.

Covers:
  - Correct call edges must exist
  - Same-name wrong edges must not exist
  - No structural roots must not empty the dataset
  - New schema fields present; unresolved stats available
  - scope=reachable keeps reachable + unknown
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.parser_adapter import apply_reachability_filter
from utilities.call_graph.reachability import (
    ReachabilityStatus,
    compute_reachability,
    filter_keep_ids,
)
from utilities.call_graph.schema import (
    SCHEMA_VERSION,
    finalize_call_graph,
    load_call_graph,
    to_legacy_export,
    unresolved_stats,
    write_call_graph,
)
from utilities.call_graph.structural_roots import detect_structural_roots


REQUIRED_KEYS = {
    "nodes",
    "resolved_edges",
    "unresolved_edges",
    "structural_roots",
    "provenance",
}


def test_schema_normalize_emits_required_keys():
    raw = {
        "language": "python",
        "functions": {
            "a.py:main": {
                "name": "main",
                "file_path": "a.py",
                "unit_type": "function",
                "code": "def main():\n    helper()\n",
            },
            "a.py:helper": {
                "name": "helper",
                "file_path": "a.py",
                "unit_type": "function",
                "code": "def helper():\n    pass\n",
            },
            "a.py:_orphan": {
                "name": "_orphan",
                "file_path": "a.py",
                "unit_type": "private_function",
                "code": "def _orphan():\n    pass\n",
            },
        },
        "call_graph": {"a.py:main": ["a.py:helper"]},
        "unresolved_edges": [],
    }
    doc = finalize_call_graph(raw, language="python")
    assert REQUIRED_KEYS <= set(doc.keys())
    assert doc["schema_version"] == SCHEMA_VERSION
    assert "a.py:main" in doc["nodes"]
    assert any(e["caller"] == "a.py:main" and e["callee"] == "a.py:helper" for e in doc["resolved_edges"])
    root_ids = {r["id"] for r in doc["structural_roots"]}
    assert "a.py:main" in root_ids
    assert "a.py:_orphan" not in root_ids
    stats = unresolved_stats(doc)
    assert stats["total"] == 0


def test_same_name_ambiguous_not_resolved_in_python_builder(tmp_path):
    """Two files define helper(); cross-file call without import must not guess."""
    from parsers.python.call_graph_builder import CallGraphBuilder

    extractor = {
        "repository": str(tmp_path),
        "functions": {
            "a.py:caller": {
                "name": "caller",
                "file_path": "a.py",
                "code": "def caller():\n    helper()\n",
                "class_name": None,
            },
            "a.py:other": {
                "name": "other",
                "file_path": "a.py",
                "code": "def other():\n    pass\n",
                "class_name": None,
            },
            "b.py:helper": {
                "name": "helper",
                "file_path": "b.py",
                "code": "def helper():\n    pass\n",
                "class_name": None,
            },
            "c.py:helper": {
                "name": "helper",
                "file_path": "c.py",
                "code": "def helper():\n    pass\n",
                "class_name": None,
            },
        },
        "classes": {},
        "imports": {"a.py": {}},
    }
    builder = CallGraphBuilder(extractor)
    builder.build_call_graph()
    # Must not create a.py:caller -> either helper
    assert "b.py:helper" not in builder.call_graph.get("a.py:caller", [])
    assert "c.py:helper" not in builder.call_graph.get("a.py:caller", [])
    # Ambiguous/unresolved edge recorded
    assert any(
        e["caller"] == "a.py:caller" and e["callee_name"] == "helper"
        for e in builder.unresolved_edges
    )


def test_correct_same_file_edge_exists():
    from parsers.python.call_graph_builder import CallGraphBuilder

    extractor = {
        "repository": ".",
        "functions": {
            "a.py:main": {
                "name": "main",
                "file_path": "a.py",
                "code": "def main():\n    helper()\n",
                "class_name": None,
            },
            "a.py:helper": {
                "name": "helper",
                "file_path": "a.py",
                "code": "def helper():\n    pass\n",
                "class_name": None,
            },
        },
        "classes": {},
        "imports": {},
    }
    builder = CallGraphBuilder(extractor)
    builder.build_call_graph()
    assert "a.py:helper" in builder.call_graph.get("a.py:main", [])


def test_method_not_linked_by_variable_name():
    from parsers.python.call_graph_builder import CallGraphBuilder

    extractor = {
        "repository": ".",
        "functions": {
            "a.py:run": {
                "name": "run",
                "file_path": "a.py",
                "code": "def run(svc):\n    svc.save()\n",
                "class_name": None,
            },
            "a.py:User.save": {
                "name": "save",
                "file_path": "a.py",
                "code": "def save(self):\n    pass\n",
                "class_name": "User",
            },
            "a.py:Order.save": {
                "name": "save",
                "file_path": "a.py",
                "code": "def save(self):\n    pass\n",
                "class_name": "Order",
            },
        },
        "classes": {},
        "imports": {},
    }
    builder = CallGraphBuilder(extractor)
    builder.build_call_graph()
    callees = builder.call_graph.get("a.py:run", [])
    assert "a.py:User.save" not in callees
    assert "a.py:Order.save" not in callees


def test_typed_receiver_resolves_method():
    from parsers.python.call_graph_builder import CallGraphBuilder

    extractor = {
        "repository": ".",
        "functions": {
            "a.py:run": {
                "name": "run",
                "file_path": "a.py",
                "code": "def run():\n    svc: User = User()\n    svc.save()\n",
                "class_name": None,
            },
            "a.py:User.save": {
                "name": "save",
                "file_path": "a.py",
                "code": "def save(self):\n    pass\n",
                "class_name": "User",
            },
            "a.py:Order.save": {
                "name": "save",
                "file_path": "a.py",
                "code": "def save(self):\n    pass\n",
                "class_name": "Order",
            },
        },
        "classes": {},
        "imports": {},
    }
    builder = CallGraphBuilder(extractor)
    builder.build_call_graph()
    assert "a.py:User.save" in builder.call_graph.get("a.py:run", [])
    assert "a.py:Order.save" not in builder.call_graph.get("a.py:run", [])


def test_no_roots_keeps_all_as_unknown(tmp_path):
    cg = {
        "language": "python",
        "functions": {
            "lib.py:_internal": {
                "name": "_internal",
                "file_path": "lib.py",
                "unit_type": "private_function",
                "is_exported": False,
            },
            "lib.py:_other": {
                "name": "_other",
                "file_path": "lib.py",
                "unit_type": "private_function",
                "is_exported": False,
            },
        },
        "call_graph": {"lib.py:_internal": ["lib.py:_other"]},
        "structural_roots": [],
    }
    # Force empty roots after normalize by using only private nodes
    doc = finalize_call_graph(cg, language="python")
    # Private-only library may still get no roots
    if not doc["structural_roots"]:
        status = compute_reachability(
            doc["nodes"], doc["resolved_edges"], doc["unresolved_edges"], []
        )
        assert all(s == ReachabilityStatus.UNKNOWN.value for s in status.values())
        keep = filter_keep_ids(status)
        assert keep == set(doc["nodes"])

    (tmp_path / "call_graph.json").write_text(json.dumps(doc))
    dataset = {
        "language": "python",
        "units": [
            {"id": "lib.py:_internal", "code": {"primary_code": "pass"}},
            {"id": "lib.py:_other", "code": {"primary_code": "pass"}},
        ],
    }
    # Clear roots in written file to simulate no-entry library
    doc["structural_roots"] = []
    (tmp_path / "call_graph.json").write_text(json.dumps(doc))
    result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
    assert len(result["units"]) == 2, "no roots must not empty the dataset"


def test_reachable_filter_drops_only_unreachable(tmp_path):
    cg = {
        "language": "python",
        "functions": {
            "app.py:main": {
                "name": "main",
                "file_path": "app.py",
                "unit_type": "function",
                "code": "def main():\n    helper()\n",
            },
            "app.py:helper": {
                "name": "helper",
                "file_path": "app.py",
                "unit_type": "function",
                "code": "def helper():\n    pass\n",
            },
            "app.py:_orphan": {
                "name": "_orphan",
                "file_path": "app.py",
                "unit_type": "private_function",
                "code": "def _orphan():\n    pass\n",
            },
        },
        "call_graph": {"app.py:main": ["app.py:helper"]},
        "unresolved_edges": [
            {
                "caller": "app.py:main",
                "callee_name": "dyn",
                "reason": "dynamic",
                "candidates": ["app.py:_orphan"],
            }
        ],
    }
    doc = finalize_call_graph(cg, language="python")
    (tmp_path / "call_graph.json").write_text(json.dumps(doc))
    dataset = {
        "language": "python",
        "units": [
            {"id": uid, "code": {"primary_code": "pass"}}
            for uid in ("app.py:main", "app.py:helper", "app.py:_orphan")
        ],
    }
    result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
    ids = {u["id"] for u in result["units"]}
    assert "app.py:main" in ids
    assert "app.py:helper" in ids
    # dynamic unresolved candidate becomes unknown → kept
    assert "app.py:_orphan" in ids
    by_id = {u["id"]: u for u in result["units"]}
    assert by_id["app.py:_orphan"]["reachability"] == "unknown"


def test_structural_roots_ignore_framework_decorators():
    nodes = {
        "app.py:handler": {
            "id": "app.py:handler",
            "name": "handler",
            "file_path": "app.py",
            "kind": "function",
            "unit_type": "route_handler",
            "is_exported": False,
            "visibility": "private",
            "decorators": ["@app.route('/x')"],
            "code": "@app.route('/x')\ndef handler():\n    pass\n",
        },
        "app.py:main": {
            "id": "app.py:main",
            "name": "main",
            "file_path": "app.py",
            "kind": "program_entry",
            "unit_type": "function",
            "is_exported": True,
            "visibility": "public",
            "code": "def main():\n    pass\n",
        },
    }
    roots = detect_structural_roots(nodes, language="python")
    root_ids = {r["id"] for r in roots}
    assert "app.py:main" in root_ids
    # Private route_handler without export is NOT a structural root
    assert "app.py:handler" not in root_ids


def test_legacy_correct_edges_preserved_after_finalize():
    """New schema must not drop previously correct resolved edges."""
    legacy = {
        "functions": {
            "m.py:a": {"name": "a", "file_path": "m.py"},
            "m.py:b": {"name": "b", "file_path": "m.py"},
            "m.py:c": {"name": "c", "file_path": "m.py"},
        },
        "call_graph": {
            "m.py:a": ["m.py:b", "m.py:c"],
            "m.py:b": ["m.py:c"],
        },
        "reverse_call_graph": {
            "m.py:b": ["m.py:a"],
            "m.py:c": ["m.py:a", "m.py:b"],
        },
    }
    doc = finalize_call_graph(legacy, language="python")
    pairs = {(e["caller"], e["callee"]) for e in doc["resolved_edges"]}
    assert ("m.py:a", "m.py:b") in pairs
    assert ("m.py:a", "m.py:c") in pairs
    assert ("m.py:b", "m.py:c") in pairs
    # Legacy maps only via adapter — not on canonical doc
    assert "call_graph" not in doc
    legacy_export = to_legacy_export(doc)
    assert legacy_export["call_graph"]["m.py:a"] == ["m.py:b", "m.py:c"]


def test_dynamic_unresolved_without_candidates_keeps_potential_targets(tmp_path):
    """Reachable dynamic call with no candidates must not prove others unreachable."""
    cg = {
        "language": "python",
        "nodes": {
            "app.py:main": {
                "id": "app.py:main",
                "name": "main",
                "file_path": "app.py",
                "kind": "program_entry",
                "is_exported": True,
                "visibility": "public",
            },
            "app.py:_maybe": {
                "id": "app.py:_maybe",
                "name": "_maybe",
                "file_path": "app.py",
                "kind": "function",
                "is_exported": False,
                "visibility": "private",
            },
            "other.py:_far": {
                "id": "other.py:_far",
                "name": "_far",
                "file_path": "other.py",
                "kind": "function",
                "is_exported": False,
                "visibility": "private",
            },
        },
        "resolved_edges": [],
        "unresolved_edges": [
            {
                "caller": "app.py:main",
                "callee_name": "dyn_call",
                "reason": "dynamic",
                "candidates": [],
            }
        ],
        "structural_roots": [{"id": "app.py:main", "kind": "program_entry"}],
        "provenance": {"builder": "test", "language": "python"},
    }
    write_call_graph(tmp_path / "call_graph.json", cg, language="python")
    dataset = {
        "language": "python",
        "units": [
            {"id": "app.py:main", "code": {"primary_code": "pass"}},
            {"id": "app.py:_maybe", "code": {"primary_code": "pass"}},
            {"id": "other.py:_far", "code": {"primary_code": "pass"}},
        ],
    }
    result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
    ids = {u["id"] for u in result["units"]}
    assert ids == {"app.py:main", "app.py:_maybe", "other.py:_far"}
    by_id = {u["id"]: u for u in result["units"]}
    assert by_id["app.py:main"]["reachability"] == "reachable"
    assert by_id["app.py:_maybe"]["reachability"] == "unknown"
    assert by_id["other.py:_far"]["reachability"] == "unknown"


def test_corrupt_call_graph_marks_all_unknown(tmp_path):
    (tmp_path / "call_graph.json").write_text("{not-json", encoding="utf-8")
    dataset = {
        "language": "python",
        "units": [
            {"id": "a.py:f", "code": {"primary_code": "pass"}},
            {"id": "a.py:g", "code": {"primary_code": "pass"}},
        ],
    }
    result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
    assert len(result["units"]) == 2
    assert all(u["reachability"] == "unknown" for u in result["units"])
    assert result["metadata"]["reachability_filter"]["call_graph_error"]


def test_dual_source_conflict_rejected(tmp_path):
    """Canonical nodes/edges disagreeing with legacy adjacency → unusable graph."""
    payload = {
        "language": "python",
        "nodes": {
            "a.py:main": {
                "id": "a.py:main",
                "name": "main",
                "file_path": "a.py",
                "kind": "program_entry",
                "is_exported": True,
            },
            "a.py:helper": {
                "id": "a.py:helper",
                "name": "helper",
                "file_path": "a.py",
                "kind": "function",
                "is_exported": True,
            },
        },
        "resolved_edges": [
            {
                "caller": "a.py:main",
                "callee": "a.py:helper",
                "kind": "call",
                "confidence": "exact",
            }
        ],
        "unresolved_edges": [],
        "structural_roots": [{"id": "a.py:main", "kind": "program_entry"}],
        "provenance": {"builder": "test", "language": "python"},
        # Conflicting legacy adjacency (points at a non-edge)
        "call_graph": {"a.py:main": ["a.py:missing"]},
    }
    (tmp_path / "call_graph.json").write_text(json.dumps(payload), encoding="utf-8")
    doc, err = load_call_graph(tmp_path / "call_graph.json", language="python")
    assert doc is None
    assert err == "dual_source_conflict"

    dataset = {
        "language": "python",
        "units": [
            {"id": "a.py:main", "code": {"primary_code": "pass"}},
            {"id": "a.py:helper", "code": {"primary_code": "pass"}},
        ],
    }
    result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
    assert len(result["units"]) == 2
    assert all(u["reachability"] == "unknown" for u in result["units"])


def test_write_call_graph_is_canonical_only(tmp_path):
    raw = {
        "language": "python",
        "functions": {
            "a.py:main": {"name": "main", "file_path": "a.py"},
            "a.py:h": {"name": "h", "file_path": "a.py"},
        },
        "call_graph": {"a.py:main": ["a.py:h"]},
    }
    path = tmp_path / "call_graph.json"
    write_call_graph(path, raw, language="python")
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert "functions" not in on_disk
    assert "call_graph" not in on_disk
    assert "reverse_call_graph" not in on_disk
    assert REQUIRED_KEYS <= set(on_disk.keys())


def test_low_confidence_edge_does_not_prove_reachable_or_delete_targets():
    nodes = {
        "a.py:main": {
            "id": "a.py:main",
            "name": "main",
            "file_path": "a.py",
            "is_exported": True,
        },
        "a.py:_via_regex": {
            "id": "a.py:_via_regex",
            "name": "_via_regex",
            "file_path": "a.py",
            "is_exported": False,
        },
        "a.py:_orphan": {
            "id": "a.py:_orphan",
            "name": "_orphan",
            "file_path": "a.py",
            "is_exported": False,
        },
    }
    resolved = [
        {
            "caller": "a.py:main",
            "callee": "a.py:_via_regex",
            "kind": "call",
            "confidence": "low",
        }
    ]
    status = compute_reachability(
        nodes,
        resolved,
        [],
        [{"id": "a.py:main", "kind": "program_entry"}],
        language="python",
    )
    assert status["a.py:main"] == "reachable"
    assert status["a.py:_via_regex"] == "unknown"
    assert status["a.py:_orphan"] == "unreachable"


def test_go_like_exported_and_init_roots():
    nodes = {
        "pkg/a.go:init": {
            "id": "pkg/a.go:init",
            "name": "init",
            "package": "pkg",
            "is_exported": False,
            "visibility": "private",
            "kind": "module_init",
        },
        "pkg/a.go:Public": {
            "id": "pkg/a.go:Public",
            "name": "Public",
            "package": "pkg",
            "is_exported": True,
            "visibility": "public",
            "kind": "function",
        },
        "pkg/a.go:private": {
            "id": "pkg/a.go:private",
            "name": "private",
            "package": "pkg",
            "is_exported": False,
            "visibility": "private",
            "kind": "function",
        },
        "cmd/main.go:main": {
            "id": "cmd/main.go:main",
            "name": "main",
            "package": "main",
            "is_exported": False,
            "visibility": "private",
            "kind": "program_entry",
        },
    }
    roots = detect_structural_roots(nodes, language="go")
    kinds = {r["id"]: r["kind"] for r in roots}
    assert kinds["cmd/main.go:main"] == "program_entry"
    assert kinds["pkg/a.go:init"] == "module_init"
    assert kinds["pkg/a.go:Public"] == "exported_symbol"
    assert "pkg/a.go:private" not in kinds


def test_c_like_main_and_nonstatic_roots():
    nodes = {
        "main.c:main": {
            "id": "main.c:main",
            "name": "main",
            "is_exported": True,
            "visibility": "public",
            "is_static": False,
            "kind": "program_entry",
        },
        "util.c:helper": {
            "id": "util.c:helper",
            "name": "helper",
            "is_exported": True,
            "visibility": "public",
            "is_static": False,
            "kind": "function",
        },
        "util.c:static_fn": {
            "id": "util.c:static_fn",
            "name": "static_fn",
            "is_exported": False,
            "visibility": "private",
            "is_static": True,
            "kind": "function",
        },
    }
    roots = detect_structural_roots(nodes, language="c")
    ids = {r["id"] for r in roots}
    assert "main.c:main" in ids
    assert "util.c:helper" in ids
    assert "util.c:static_fn" not in ids
