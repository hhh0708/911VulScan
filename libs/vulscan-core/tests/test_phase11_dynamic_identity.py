"""Phase 11: strict TARGET_CALL_BEGIN / harness identity / preconditions / checkpoint."""

from __future__ import annotations

import json

from core.dynamic_verification.checkpoint import DynamicCheckpointManager
from core.dynamic_verification.harness import build_real_call_harness
from core.dynamic_verification.oracle import (
    decide_from_oracles,
    evaluate_preconditions,
    parse_harness_stdout,
    parse_target_call_begin,
)
from core.dynamic_verification.policy import compile_test_plan


def _expected(**kwargs):
    base = {
        "test_id": "tid",
        "finding_id": "fid",
        "unit_id": "mod.py:foo",
        "entrypoint": "foo",
        "attempt_id": "att1",
    }
    base.update(kwargs)
    return base


def test_multiple_markers_rejected():
    exp = _expected()
    line = f"TARGET_CALL_BEGIN {json.dumps(exp)}"
    meta, err = parse_target_call_begin(f"{line}\n{line}\n", expected=exp)
    assert meta is None
    assert "multiple" in err


def test_marker_mismatch_rejected():
    exp = _expected()
    bad = dict(exp)
    bad["attempt_id"] = "other"
    meta, err = parse_target_call_begin(
        f"TARGET_CALL_BEGIN {json.dumps(bad)}\n", expected=exp
    )
    assert meta is None
    assert "mismatch" in err


def test_harness_identity_must_match():
    exp = _expected()
    obj = {
        "schema_version": "1.0",
        "test_id": "tid",
        "finding_id": "fid",
        "unit_id": "WRONG",
        "attempt_id": "att1",
        "entrypoint": "foo",
        "call_begun": True,
        "call_completed": True,
    }
    parsed, err = parse_harness_stdout(json.dumps(obj), expected=exp)
    assert parsed is None
    assert "identity_mismatch" in err


def test_reproduced_requires_full_identity_and_call():
    _, decision, reason = decide_from_oracles(
        build_ok=True,
        harness_ok=True,
        call_begun=True,
        preconditions_satisfied=True,
        oracle_results={
            "success_hit": True,
            "success_executed": True,
            "negative_pass": True,
            "negative_executed": True,
        },
        harness_parse_ok=True,
        evidence_resolvable=True,
        marker_ok=True,
        harness_call_begun=False,
        identity_match=True,
    )
    assert decision != "reproduced"
    assert "identity_or_call" in reason or "mismatch" in reason


def test_preconditions_individually_satisfied():
    evidence = [
        {"evidence_id": "e1", "content_hash": "h1"},
        {"evidence_id": "e2", "content_hash": "h2"},
    ]
    ok, items = evaluate_preconditions(
        [
            {
                "precondition_id": "p1",
                "description": "auth bypassed",
                "supporting_evidence_ids": ["e1"],
            },
            {
                "precondition_id": "p2",
                "description": "input reaches sink",
                "supporting_evidence_ids": ["e2"],
            },
        ],
        evidence,
    )
    assert ok
    assert all(i["status"] == "satisfied" for i in items)

    # One missing support → not all satisfied (no blanket evidence)
    ok2, items2 = evaluate_preconditions(
        [
            {
                "precondition_id": "p1",
                "description": "a",
                "supporting_evidence_ids": ["e1"],
            },
            {
                "precondition_id": "p2",
                "description": "b",
                "supporting_evidence_ids": [],
            },
        ],
        evidence,
    )
    assert not ok2
    assert items2[1]["status"] == "unknown"


def test_harness_emits_full_identity():
    adapter, err = build_real_call_harness(
        {"entrypoint": "foo", "payload": {}},
        language="python",
        test_id="tid",
        unit_id="mod.py:foo",
        finding_id="fid",
        attempt_id="att1",
        target_module="mod",
        target_qualname="foo",
        source_basename="mod.py",
    )
    assert err == ""
    script = adapter["test_script"]
    assert "finding_id" in script.lower() or "FINDING_ID" in script
    assert "ATTEMPT_ID" in script
    assert "TARGET_CALL_BEGIN" in script


def test_compile_includes_base_image():
    compiled, err = compile_test_plan(
        {
            "entrypoint": "foo",
            "payload": {},
            "setup_requirements": [],
            "invocation": {"command": "foo"},
            "success_oracle": {"type": "return_value"},
            "negative_oracle": {"type": "exception", "value": "ValueError"},
            "expected_artifacts": [],
        },
        language="python",
        test_id="tid",
        unit_id="mod.py:foo",
        finding_id="fid",
        attempt_id="att1",
        location={"file": "mod.py", "function": "foo"},
        source_basename="mod.py",
    )
    assert err == "", err
    assert compiled["base_image"] == "python:3.11-slim"
    assert "FINDING_ID" in compiled["test_script"]


def test_checkpoint_restore_verifies_hashes(tmp_path):
    mgr = DynamicCheckpointManager(str(tmp_path))
    mgr.save(
        "t1",
        fingerprint="fp1",
        result={"execution_state": "succeeded", "decision": "reproduced"},
        image_digest="sha256:img",
        base_image_digest="sha256:base",
        policy_hash="pol",
        compiler_version="c1",
        runner_version="r1",
        test_plan_hash="tp1",
        build_context_hash="bc1",
    )
    ok = mgr.load_valid(
        "t1",
        "fp1",
        require_image_digest=True,
        expected_policy_hash="pol",
        expected_compiler_version="c1",
        expected_runner_version="r1",
        expected_test_plan_hash="tp1",
        expected_image_digest="sha256:img",
        expected_base_image_digest="sha256:base",
        expected_build_context_hash="bc1",
    )
    assert ok is not None

    bad = mgr.load_valid(
        "t1",
        "fp1",
        expected_policy_hash="WRONG",
    )
    assert bad is None
