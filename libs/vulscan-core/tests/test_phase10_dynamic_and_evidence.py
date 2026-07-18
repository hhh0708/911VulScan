"""Phase 10: Stage 2 evidence closure + dynamic verification layer tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from core.dynamic_verification.checkpoint import DynamicCheckpointManager
from core.dynamic_verification.fingerprint import (
    compute_dynamic_fingerprint,
    compute_test_id,
)
from core.dynamic_verification.input_builder import (
    build_dynamic_input,
    is_dynamic_eligible,
)
from core.dynamic_verification.policy import compile_test_plan, reject_unsafe_request
from core.dynamic_verification.schema import (
    can_emit_not_reproduced,
    empty_dynamic_result,
    normalize_dynamic_decision,
    validate_test_plan,
)
from core.verification.evidence import make_tool_evidence
from core.verification.input_builder import append_tool_evidence, build_verification_input
from core.verification.schema import (
    empty_verification_result,
    normalize_verification_result,
    skipped_result,
)


def _ev(eid: str, role: str | None = None, reject: str | None = None) -> dict:
    content: dict = {"note": eid}
    if role:
        content["role"] = role
    if reject:
        content["reject_reason"] = reject
    return {
        "evidence_id": eid,
        "kind": f"role_{role}" if role else ("counter" if reject else "obs"),
        "source": "test",
        "content": content,
        "content_hash": eid,
    }


def test_non_confirmed_cannot_enter_dynamic():
    s1 = {"decision": "candidate", "unit_id": "u"}
    evid = [{"evidence_id": "ev1", "kind": "obs"}]
    for s2 in (
        {"execution_state": "succeeded", "decision": "rejected", "finding_id": "f", "evidence": evid},
        {"execution_state": "failed", "decision": "inconclusive", "finding_id": "f", "evidence": evid},
        {"execution_state": "succeeded", "decision": "inconclusive", "finding_id": "f", "evidence": evid},
        {"execution_state": "skipped", "decision": "inconclusive", "finding_id": "f", "evidence": evid},
        None,
    ):
        ok, _ = is_dynamic_eligible(s1, s2)
        assert not ok
    ok, _ = is_dynamic_eligible(
        {"decision": "no_finding"},
        {
            "execution_state": "succeeded",
            "decision": "confirmed",
            "finding_id": "f",
            "evidence": evid,
        },
    )
    assert not ok
    ok, _ = is_dynamic_eligible(
        s1,
        {
            "execution_state": "succeeded",
            "decision": "confirmed",
            "finding_id": "fid",
            "evidence": evid,
            "evidence_ids": ["ev1"],
        },
    )
    assert ok


def test_missing_index_marks_candidate_failed_not_batch_abort():
    """Engine-level: missing index → per-candidate failed/inconclusive."""
    from unittest.mock import MagicMock

    from core.verification.engine import CandidateVerifier
    from utilities.llm_client import TokenTracker

    vin = build_verification_input(
        {
            "unit_id": "a.py:foo",
            "decision": "candidate",
            "source": "q",
            "propagation": "p",
            "sink": "s",
            "impact": "i",
            "evidence_ids": [],
        },
        unit={
            "id": "a.py:foo",
            "language": "python",
            "code": {"primary_code": "def foo(): pass\n"},
            "metadata": {},
        },
    )
    v = CandidateVerifier(index=None, client=MagicMock(), tracker=TokenTracker())
    result = v.verify(vin)
    assert result["execution_state"] == "failed"
    assert result["decision"] == "inconclusive"


def test_tool_evidence_id_fully_resolvable():
    table = []
    eid = append_tool_evidence(
        table,
        tool="search_code",
        tool_input={"q": "execute"},
        full_result={"hits": [{"file": "a.py", "line": 1}]},
    )
    assert eid
    assert any(e["evidence_id"] == eid for e in table)
    entry = table[0]
    assert entry["content_hash"]
    assert "result" in entry["content"]
    assert "result_preview" in entry["content"]
    # Preview must not affect ID: same full result → same ID even if preview differs
    e2 = make_tool_evidence(
        tool="search_code",
        tool_input={"q": "execute"},
        full_result={"hits": [{"file": "a.py", "line": 1}]},
    )
    assert e2["evidence_id"] == eid


def test_rejected_without_counter_evidence_becomes_inconclusive():
    table = [_ev("ev1", role="source")]
    result = normalize_verification_result(
        {
            "decision": "rejected",
            "evidence_ids": [],
            "counter_evidence_ids": [],
            "confidence": 0.9,
            "guards": [],
            "missing_evidence": [],
            "uncertainties": [],
        },
        finding_id="f",
        evidence_ids={"ev1"},
        evidence_table=table,
    )
    assert result["decision"] == "inconclusive"

    # Counter IDs present but no reject reason → inconclusive
    table2 = [_ev("ev_c", reject=None)]
    table2[0]["content"] = {"note": "no reason"}
    result2 = normalize_verification_result(
        {
            "decision": "rejected",
            "evidence_ids": [],
            "counter_evidence_ids": ["ev_c"],
            "confidence": 0.9,
            "guards": [],
            "missing_evidence": [],
            "uncertainties": [],
        },
        finding_id="f",
        evidence_ids={"ev_c"},
        evidence_table=table2,
    )
    assert result2["decision"] == "inconclusive"

    # Valid counter evidence → rejected
    table3 = [_ev("ev_ok", reject="path_break")]
    result3 = normalize_verification_result(
        {
            "decision": "rejected",
            "evidence_ids": [],
            "counter_evidence_ids": ["ev_ok"],
            "confidence": 0.9,
            "guards": [],
            "missing_evidence": [],
            "uncertainties": [],
        },
        finding_id="f",
        evidence_ids={"ev_ok"},
        evidence_table=table3,
    )
    assert result3["decision"] == "rejected"
    assert result3["evidence"]


def test_confirmed_requires_role_evidence():
    ids = ["ev_s", "ev_p", "ev_k", "ev_i"]
    table = [
        _ev("ev_s", role="source"),
        _ev("ev_p", role="propagation"),
        _ev("ev_k", role="sink"),
        _ev("ev_i", role="impact"),
    ]
    bad = normalize_verification_result(
        {
            "decision": "confirmed",
            "verified_source": "s",
            "propagation": "p",
            "sink": "k",
            "impact": "i",
            "evidence_ids": ids,
            "counter_evidence_ids": [],
            "confidence": 0.9,
            "guards": [],
            "missing_evidence": [],
            "uncertainties": [],
        },
        finding_id="f",
        evidence_ids=set(ids),
        evidence_table=table,
    )
    # roles on evidence content → covered
    assert bad["decision"] == "confirmed"

    no_roles = normalize_verification_result(
        {
            "decision": "confirmed",
            "verified_source": "s",
            "propagation": "p",
            "sink": "k",
            "impact": "i",
            "evidence_ids": ["ev_s"],
            "counter_evidence_ids": [],
            "confidence": 0.9,
            "guards": [],
            "missing_evidence": [],
            "uncertainties": [],
        },
        finding_id="f",
        evidence_ids={"ev_s"},
        evidence_table=[_ev("ev_s")],  # no role
    )
    assert no_roles["decision"] == "inconclusive"


def test_policy_rejects_dockerfile_privileged_host_mount():
    assert reject_unsafe_request({"dockerfile": "FROM x", "entrypoint": "main"})
    assert reject_unsafe_request({"privileged": True, "entrypoint": "main"})
    assert reject_unsafe_request({"entrypoint": "main", "volumes": ["/:/host"]})
    plan, err = validate_test_plan(
        {
            "entrypoint": "main",
            "payload": {},
            "setup_requirements": [],
            "invocation": {"command": "main"},
            "success_oracle": {"marker": "PWNED"},
            "negative_oracle": {"marker": "SAFE"},
            "expected_artifacts": [],
        }
    )
    assert plan is not None
    compiled, cerr = compile_test_plan(
        plan,
        language="python",
        test_id="t",
        unit_id="a.py:main",
        location={"file": "a.py", "function": "main"},
        source_basename="a.py",
    )
    assert compiled is not None, cerr
    assert "--read-only" in compiled["run_argv"]
    assert compiled["sandbox_policy"]["privileged"] is False
    assert "TARGET_CALL_BEGIN" in compiled["test_script"]


def test_build_failure_not_not_reproduced():
    state, decision = normalize_dynamic_decision(
        claimed="not_reproduced",
        build_ok=False,
        harness_ok=False,
        target_reached=False,
        preconditions_satisfied=False,
        positive_oracle_done=False,
        negative_oracle_done=False,
    )
    assert state == "failed"
    assert decision == "inconclusive"


def test_target_not_reached_not_not_reproduced():
    assert not can_emit_not_reproduced(
        build_ok=True,
        harness_ok=True,
        target_reached=False,
        preconditions_satisfied=True,
        positive_oracle_done=True,
        negative_oracle_done=True,
    )
    state, decision = normalize_dynamic_decision(
        claimed="not_reproduced",
        build_ok=True,
        harness_ok=True,
        target_reached=False,
        preconditions_satisfied=True,
        positive_oracle_done=True,
        negative_oracle_done=True,
    )
    assert decision == "inconclusive"


def test_dynamic_checkpoint_invalidates_on_code_plan_or_policy_change(tmp_path: Path):
    mgr = DynamicCheckpointManager(str(tmp_path))
    s1 = {"decision": "candidate", "unit_id": "u", "preconditions": []}
    s2 = {
        "finding_id": "fid",
        "execution_state": "succeeded",
        "decision": "confirmed",
        "evidence_ids": ["ev1"],
        "evidence": [{"evidence_id": "ev1", "kind": "obs"}],
    }
    din = build_dynamic_input(
        stage1_result=s1,
        stage2_result=s2,
        language="python",
        unit={"id": "u", "language": "python", "code": {"primary_code": "x=1"}},
    )
    plan = {
        "entrypoint": "main",
        "payload": {},
        "setup_requirements": [],
        "invocation": {},
        "success_oracle": {},
        "negative_oracle": {},
        "expected_artifacts": [],
    }
    fp1 = compute_dynamic_fingerprint(din, test_plan=plan, image_digest="sha256:aaa")
    result = empty_dynamic_result(
        test_id=din["test_id"],
        finding_id="fid",
        execution_state="succeeded",
        decision="reproduced",
    )
    # succeeded+reproduced allowed only when state succeeded
    result["execution_state"] = "succeeded"
    result["decision"] = "reproduced"
    mgr.save(
        din["test_id"],
        fingerprint=fp1,
        result=result,
        image_digest="sha256:aaa",
    )
    assert mgr.load_valid(din["test_id"], fp1, require_image_digest=True) is not None

    # Base fingerprint ignores digest; content change still invalidates
    din2 = build_dynamic_input(
        stage1_result=s1,
        stage2_result=s2,
        language="python",
        unit={"id": "u", "language": "python", "code": {"primary_code": "x=2"}},
    )
    fp3 = compute_dynamic_fingerprint(din2, test_plan=plan)
    assert fp3 != fp1
    assert mgr.load_valid(din["test_id"], fp3) is None


def test_dynamic_result_does_not_mutate_stage1_or_stage2():
    s1 = {"decision": "candidate", "unit_id": "u", "source": "a"}
    s2 = {
        "finding_id": "fid",
        "execution_state": "succeeded",
        "decision": "confirmed",
        "evidence_ids": ["ev1"],
        "evidence": [{"evidence_id": "ev1", "kind": "obs"}],
    }
    s1_before = copy.deepcopy(s1)
    s2_before = copy.deepcopy(s2)
    din = build_dynamic_input(stage1_result=s1, stage2_result=s2, language="python")
    envelope = {
        **s1,
        "stage2_verification": s2,
        "dynamic_verification": empty_dynamic_result(
            test_id=din["test_id"], finding_id="fid", execution_state="skipped"
        ),
    }
    assert s1 == s1_before
    assert s2 == s2_before
    assert envelope["decision"] == "candidate"
    assert envelope["stage2_verification"]["decision"] == "confirmed"


def test_dynamic_metrics_mutually_exclusive():
    metrics = {
        "reproduced": 0,
        "not_reproduced": 0,
        "inconclusive": 0,
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "skipped": 0,
        "blocked": 0,
    }

    def tally(d):
        state = d["execution_state"]
        decision = d["decision"]
        if state == "skipped":
            metrics["skipped"] += 1
            return
        if state == "blocked":
            metrics["blocked"] += 1
            metrics["attempted"] += 1
            metrics["inconclusive"] += 1
            return
        metrics["attempted"] += 1
        if state == "succeeded":
            metrics["succeeded"] += 1
        elif state == "failed":
            metrics["failed"] += 1
        if decision == "reproduced":
            metrics["reproduced"] += 1
        elif decision == "not_reproduced":
            metrics["not_reproduced"] += 1
        else:
            metrics["inconclusive"] += 1

    for d in (
        {"execution_state": "succeeded", "decision": "reproduced"},
        {"execution_state": "succeeded", "decision": "not_reproduced"},
        {"execution_state": "succeeded", "decision": "inconclusive"},
        {"execution_state": "failed", "decision": "inconclusive"},
        {"execution_state": "skipped", "decision": "inconclusive"},
        {"execution_state": "blocked", "decision": "inconclusive"},
    ):
        tally(d)

    assert metrics["reproduced"] == 1
    assert metrics["not_reproduced"] == 1
    assert metrics["reproduced"] + metrics["not_reproduced"] + metrics["inconclusive"] == (
        metrics["attempted"]
    )


def test_reporter_unverified_candidate_not_in_findings(tmp_path: Path):
    from core.reporter import build_pipeline_output

    results = {
        "dataset": "p10",
        "results": [
            {
                "unit_id": "a.py:foo",
                "route_key": "a.py:foo",
                "decision": "candidate",
                "cwe_id": 89,
            },
            {
                "unit_id": "a.py:bar",
                "route_key": "a.py:bar",
                "decision": "candidate",
                "cwe_id": 89,
                "stage2_verification": {
                    "finding_id": "fid",
                    "execution_state": "succeeded",
                    "decision": "confirmed",
                    "evidence_ids": ["ev1"],
                    "counter_evidence_ids": [],
                    "evidence": [{"evidence_id": "ev1", "kind": "obs"}],
                    "verified_source": "s",
                    "propagation": "p",
                    "sink": "k",
                    "impact": "i",
                    "guards": [],
                    "missing_evidence": [],
                    "uncertainties": [],
                    "confidence": 0.9,
                    "provenance": {},
                },
            },
        ],
        "metrics": {"total": 2, "candidate": 2},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results), encoding="utf-8")
    out = tmp_path / "po.json"
    build_pipeline_output(results_path=str(path), output_path=str(out), language="python")
    data = json.loads(out.read_text(encoding="utf-8"))
    # FinalScanArtifact: confirmed finding has final_state; unverified stays candidate
    confirmed = [
        f
        for f in data.get("findings") or []
        if f.get("final_state")
        in (
            "reproduced",
            "confirmed_not_dynamically_tested",
            "confirmed_not_reproduced",
        )
    ]
    assert len(confirmed) == 1
    assert "bar" in (confirmed[0].get("unit_id") or "")
    assert confirmed[0]["final_state"] == "confirmed_not_dynamically_tested"
    assert "stage2_verdict" not in confirmed[0]
    assert any(c["unit_id"] == "a.py:foo" for c in data["candidates"])


def test_test_id_stable():
    s1 = {"decision": "candidate", "unit_id": "u"}
    s2 = {
        "finding_id": "fid",
        "execution_state": "succeeded",
        "decision": "confirmed",
        "evidence_ids": ["ev1"],
        "evidence": [{"evidence_id": "ev1", "kind": "obs"}],
    }
    a = build_dynamic_input(stage1_result=s1, stage2_result=s2, language="python")
    b = build_dynamic_input(stage1_result=s1, stage2_result=s2, language="python")
    assert a["test_id"] == b["test_id"] == compute_test_id(a)
