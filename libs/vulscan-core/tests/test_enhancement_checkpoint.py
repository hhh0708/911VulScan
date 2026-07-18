"""Phase 7: content-addressed Enhance checkpoints + fingerprint invalidation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from utilities.enhancement.checkpoint import EnhanceCheckpointManager, unit_id_filename
from utilities.enhancement.fingerprint import (
    EnhancementFingerprintInputs,
    compute_enhancement_fingerprint,
)
from utilities.enhancement.schema import (
    ENHANCEMENT_PROMPT_VERSION,
    ENHANCEMENT_SCHEMA_VERSION,
    empty_enhancement,
    normalize_enhancement,
    validate_enhancement,
)
from utilities.call_graph.reachability import compute_reachability


def _unit(uid: str = "src/a.ts:foo", code: str = "function foo() {}") -> dict:
    return {
        "id": uid,
        "unit_type": "function",
        "code": {
            "primary_code": code,
            "primary_origin": {
                "file_path": "src/a.ts",
                "function_name": "foo",
                "start_line": 1,
                "end_line": 1,
            },
        },
        "metadata": {},
    }


def _fp(unit, **kwargs):
    return compute_enhancement_fingerprint(
        EnhancementFingerprintInputs(
            unit=unit,
            call_graph=kwargs.get("call_graph"),
            app_context=kwargs.get("app_context"),
            analyzer_output_hash=kwargs.get("analyzer_output_hash", "analyzer1"),
            model=kwargs.get("model", "m1"),
            mode=kwargs.get("mode", "agentic"),
            prompt_version=kwargs.get("prompt_version", ENHANCEMENT_PROMPT_VERSION),
            schema_version=kwargs.get("schema_version", ENHANCEMENT_SCHEMA_VERSION),
        )
    )


def test_schema_strips_forbidden_fields():
    raw = {
        "related_units": [],
        "security_classification": "exploitable",
        "additional_callers": [{"name": "x"}],
        "data_flow": {"inputs": ["a"], "security_relevant_flows": [{"type": "sqli"}]},
        "call_context": {"direct_calls": [], "direct_callers": [], "notes": []},
        "unknowns": [],
    }
    payload = normalize_enhancement(raw, mode="single-shot", model="m")
    assert validate_enhancement(payload)
    assert "security_classification" not in payload
    assert "additional_callers" not in payload
    assert payload["dataflow_observations"] == [{"kind": "input", "value": "a"}]


def test_same_id_code_change_must_rerun(tmp_path: Path):
    mgr = EnhanceCheckpointManager(str(tmp_path))
    u1 = _unit(code="function foo() { return 1; }")
    u2 = _unit(code="function foo() { return 2; }")
    fp1 = _fp(u1)
    fp2 = _fp(u2)
    assert fp1 != fp2
    enh = empty_enhancement(mode="agentic", model="m1")
    mgr.save(u1["id"], fingerprint=fp1, enhancement=enh, usage={"input_tokens": 1})
    assert mgr.load_valid(u1["id"], fp1) is not None
    assert mgr.load_valid(u2["id"], fp2) is None  # same id, different fp → no restore
    # Fingerprint mismatch deletes stale checkpoint
    assert not Path(mgr.path_for(u1["id"])).exists()


def test_graph_app_context_model_prompt_invalidate():
    u = _unit()
    base = _fp(u)
    cg = {
        "nodes": {u["id"]: {"name": "foo", "kind": "function"}},
        "resolved_edges": [
            {"caller": u["id"], "callee": "other", "confidence": "exact"}
        ],
        "unresolved_edges": [],
    }
    assert _fp(u, call_graph=cg) != base
    assert _fp(u, app_context={"purpose": "x"}) != base
    assert _fp(u, model="m2") != base
    assert _fp(u, prompt_version="other-v") != base
    assert _fp(u, analyzer_output_hash="analyzer2") != base


def test_checkpoint_does_not_overwrite_code(tmp_path: Path):
    mgr = EnhanceCheckpointManager(str(tmp_path))
    u = _unit(code="ORIGINAL")
    fp = _fp(u)
    enh = empty_enhancement(mode="agentic", model="m1")
    mgr.save(u["id"], fingerprint=fp, enhancement=enh)
    # Manually craft illegal checkpoint with code — must be invalidated
    path = Path(mgr.path_for(u["id"]))
    bad = {
        "unit_id": u["id"],
        "fingerprint": fp,
        "schema_version": ENHANCEMENT_SCHEMA_VERSION,
        "enhancement": enh,
        "code": {"primary_code": "STALE"},
    }
    path.write_text(json.dumps(bad), encoding="utf-8")
    assert mgr.load_valid(u["id"], fp) is None
    assert not path.exists()  # invalidated
    # Unit code untouched
    assert u["code"]["primary_code"] == "ORIGINAL"


def test_filename_collision_isolation(tmp_path: Path):
    mgr = EnhanceCheckpointManager(str(tmp_path))
    id_a = "a:foo"
    id_b = "b:foo"
    assert unit_id_filename(id_a) != unit_id_filename(id_b)
    # Wrong unit_id inside hash file → invalidate
    fp = _fp(_unit(id_a))
    path = Path(mgr.path_for(id_a))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "unit_id": id_b,  # mismatch
                "fingerprint": fp,
                "schema_version": ENHANCEMENT_SCHEMA_VERSION,
                "enhancement": empty_enhancement(mode="agentic", model="m"),
            }
        ),
        encoding="utf-8",
    )
    assert mgr.load_valid(id_a, fp) is None
    assert not path.exists()


def test_corrupt_checkpoint_auto_rerun(tmp_path: Path):
    mgr = EnhanceCheckpointManager(str(tmp_path))
    u = _unit()
    fp = _fp(u)
    path = Path(mgr.path_for(u["id"]))
    path.write_text("{not-json", encoding="utf-8")
    assert mgr.load_valid(u["id"], fp) is None
    assert not path.exists()


def test_resume_restores_consistent_payload(tmp_path: Path):
    mgr = EnhanceCheckpointManager(str(tmp_path))
    u = _unit()
    fp = _fp(u)
    enh = normalize_enhancement(
        {
            "related_units": [{"id": "x", "relation_type": "callee", "reason": "call"}],
            "call_context": {
                "direct_calls": ["x"],
                "direct_callers": [],
                "notes": [],
            },
            "dataflow_observations": [{"kind": "input", "value": "req"}],
            "unknowns": [],
        },
        mode="agentic",
        model="m1",
    )
    mgr.save(u["id"], fingerprint=fp, enhancement=enh, usage={"input_tokens": 9})
    units = [u]
    restored, usage = mgr.restore_matching(units, lambda unit: _fp(unit))
    assert u["id"] in restored
    assert units[0]["enhancement"]["related_units"][0]["id"] == "x"
    assert usage[u["id"]]["input_tokens"] == 9
    # Atomic write produces sha256 filename
    digest = hashlib.sha256(u["id"].encode()).hexdigest()
    assert (tmp_path / f"{digest}.json").is_file()


def test_unresolved_edge_order_does_not_affect_reachability():
    nodes = {
        "r": {"name": "r", "file_path": "a.py"},
        "a": {"name": "a", "file_path": "a.py"},
        "b": {"name": "b", "file_path": "a.py"},
        "c": {"name": "c", "file_path": "a.py"},
    }
    resolved = [
        {"caller": "r", "callee": "a", "confidence": "exact"},
    ]
    unresolved_a = [
        {"caller": "a", "callee_name": "dyn", "candidates": ["b", "c"], "reason": "dynamic"},
        {"caller": "b", "callee_name": "other", "candidates": [], "reason": "dynamic"},
    ]
    unresolved_b = list(reversed(unresolved_a))
    roots = [{"id": "r", "kind": "program_entry"}]
    s1 = compute_reachability(nodes, resolved, unresolved_a, roots, language="python")
    s2 = compute_reachability(nodes, resolved, unresolved_b, roots, language="python")
    assert s1 == s2
    # Empty candidates forces global unknown for non-reachable sticky nodes
    assert s1["r"] == "reachable"
    assert s1["a"] == "reachable"
    assert s1["b"] == "unknown"
    assert s1["c"] == "unknown"
