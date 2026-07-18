"""Phase 9: Stage 2 candidate verification state machine tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from core.verification.checkpoint import VerifyCheckpointManager
from core.verification.fingerprint import (
    compute_finding_id,
    compute_verification_fingerprint,
)
from core.verification.input_builder import build_verification_input
from core.verification.schema import (
    empty_verification_result,
    normalize_verification_result,
    skipped_result,
    validate_verification_result,
)


def _stage1_candidate(uid: str = "a.py:foo", **overrides) -> dict:
    base = {
        "unit_id": uid,
        "decision": "candidate",
        "candidate_type": "sqli",
        "cwe_id": 89,
        "location": {"file": "a.py", "function": "foo"},
        "source": "req.query",
        "propagation": "to cursor.execute",
        "sink": "cursor.execute",
        "guards": [],
        "impact": "db read",
        "preconditions": [],
        "evidence_ids": [],
        "counter_evidence_ids": [],
        "uncertainties": [],
        "confidence": 0.8,
        "provenance": {},
    }
    base.update(overrides)
    return base


def _unit(uid: str = "a.py:foo") -> dict:
    return {
        "id": uid,
        "language": "python",
        "reachability": "reachable",
        "is_entry_point": True,
        "code": {
            "primary_code": "def foo(q):\n    cursor.execute(q)\n",
            "primary_origin": {"file_path": "a.py", "function_name": "foo"},
        },
        "metadata": {},
    }


def test_candidate_enters_verification_input():
    s1 = _stage1_candidate()
    vin = build_verification_input(s1, unit=_unit())
    assert vin["unit_id"] == "a.py:foo"
    assert vin["stage1_candidate"]["decision"] == "candidate"
    assert vin["finding_id"]
    assert len(vin["finding_id"]) == 64  # sha256 hex
    assert vin["target_code"]


def test_non_candidates_get_skipped_result():
    for decision in ("no_finding", "inconclusive", "error"):
        s2 = skipped_result(
            finding_id=f"skipped:{decision}",
            reason=f"stage1_decision={decision!r}",
        )
        assert s2["execution_state"] == "skipped"
        assert s2["decision"] == "inconclusive"
        assert s2["decision"] != "confirmed"


def test_stage2_rejected_does_not_overwrite_stage1_decision():
    s1 = _stage1_candidate()
    original = copy.deepcopy(s1)
    table = [
        {
            "evidence_id": "ev_c",
            "kind": "counter",
            "source": "t",
            "content": {"reject_reason": "valid_guard"},
        }
    ]
    s2 = normalize_verification_result(
        {
            "decision": "rejected",
            "evidence_ids": [],
            "counter_evidence_ids": ["ev_c"],
            "uncertainties": [],
            "confidence": 0.7,
            "guards": [],
            "missing_evidence": [],
        },
        finding_id="fid",
        evidence_ids={"ev_c"},
        evidence_table=table,
    )
    # Simulate attach without mutating Stage 1
    envelope = {**s1, "stage2_verification": s2}
    assert envelope["decision"] == "candidate"
    assert envelope["stage2_verification"]["decision"] == "rejected"
    assert original["decision"] == "candidate"
    assert "evidence" in s2


def test_failed_and_max_iterations_never_confirmed():
    for reason in ("max_iterations", "end_turn_without_finish", "missing target code"):
        s2 = empty_verification_result(
            "fid",
            execution_state="failed",
            decision="inconclusive",
            reason=reason,
        )
        assert s2["execution_state"] == "failed"
        assert s2["decision"] == "inconclusive"
        assert s2["decision"] != "confirmed"
        # Even if normalize is fed confirmed with failed state:
        bad = normalize_verification_result(
            {"decision": "confirmed", "evidence_ids": ["ev_x"], "counter_evidence_ids": [],
             "confidence": 1, "guards": [], "missing_evidence": [], "uncertainties": []},
            finding_id="fid",
            evidence_ids={"ev_x"},
            execution_state="failed",
        )
        assert bad["decision"] == "inconclusive"
        assert bad["execution_state"] == "failed"


def test_stage1_result_immutable_after_attach():
    s1 = _stage1_candidate()
    before = json.dumps(s1, sort_keys=True)
    vin = build_verification_input(s1, unit=_unit())
    s1["stage2_verification"] = skipped_result(vin["finding_id"], reason="test")
    # Core Stage 1 fields unchanged
    core = {k: s1[k] for k in s1 if k != "stage2_verification"}
    assert json.dumps(core, sort_keys=True) == before


def test_fictional_evidence_id_becomes_inconclusive():
    result = normalize_verification_result(
        {
            "decision": "confirmed",
            "verified_source": "x",
            "propagation": "y",
            "sink": "z",
            "guards": [],
            "impact": "i",
            "evidence_ids": ["ev_does_not_exist"],
            "counter_evidence_ids": [],
            "missing_evidence": [],
            "uncertainties": [],
            "confidence": 0.99,
        },
        finding_id="fid",
        evidence_ids={"ev_real"},
    )
    assert result["decision"] == "inconclusive"
    assert any(u.get("kind") == "unknown_evidence_id" for u in result["uncertainties"])


def test_checkpoint_invalidates_on_input_change(tmp_path: Path):
    mgr = VerifyCheckpointManager(str(tmp_path))
    s1 = _stage1_candidate()
    vin = build_verification_input(s1, unit=_unit())
    fp1 = compute_verification_fingerprint(vin, model="m1")
    evid = {e["evidence_id"] for e in vin["evidence"]}
    table = list(vin["evidence"]) + [
        {
            "evidence_id": "ev_c",
            "kind": "counter",
            "source": "t",
            "content": {"reject_reason": "path_break"},
        }
    ]
    evid = evid | {"ev_c"}
    result = normalize_verification_result(
        {
            "decision": "rejected",
            "evidence_ids": [],
            "counter_evidence_ids": ["ev_c"],
            "uncertainties": [],
            "confidence": 0.5,
            "guards": [],
            "missing_evidence": [],
        },
        finding_id=vin["finding_id"],
        evidence_ids=evid,
        evidence_table=table,
    )
    mgr.save(vin["finding_id"], fingerprint=fp1, result=result)
    assert mgr.load_valid(vin["finding_id"], fp1, evid) is not None

    fp2 = compute_verification_fingerprint(vin, model="m2")
    assert fp2 != fp1
    assert mgr.load_valid(vin["finding_id"], fp2, evid) is None


def test_metrics_decisions_mutually_exclusive():
    """confirmed/rejected/inconclusive tallies must not double-count."""
    metrics = {
        "confirmed": 0,
        "rejected": 0,
        "inconclusive": 0,
        "succeeded": 0,
        "failed": 0,
        "skipped": 0,
        "attempted": 0,
    }

    def tally(s2):
        state = s2["execution_state"]
        decision = s2["decision"]
        if state == "skipped":
            metrics["skipped"] += 1
            return
        metrics["attempted"] += 1
        if state == "succeeded":
            metrics["succeeded"] += 1
        elif state == "failed":
            metrics["failed"] += 1
        if decision == "confirmed":
            metrics["confirmed"] += 1
        elif decision == "rejected":
            metrics["rejected"] += 1
        else:
            metrics["inconclusive"] += 1

    samples = [
        {"execution_state": "succeeded", "decision": "confirmed"},
        {"execution_state": "succeeded", "decision": "rejected"},
        {"execution_state": "succeeded", "decision": "inconclusive"},
        {"execution_state": "failed", "decision": "inconclusive"},
        {"execution_state": "skipped", "decision": "inconclusive"},
    ]
    for s in samples:
        tally(s)

    assert metrics["confirmed"] == 1
    assert metrics["rejected"] == 1
    assert metrics["inconclusive"] == 2  # succeeded inconclusive + failed
    assert metrics["skipped"] == 1
    assert metrics["attempted"] == 4
    assert metrics["confirmed"] + metrics["rejected"] + metrics["inconclusive"] == metrics["attempted"]


def test_finding_id_stable_and_content_sensitive():
    s1a = _stage1_candidate()
    s1b = _stage1_candidate(sink="other")
    vin_a = build_verification_input(s1a, unit=_unit())
    vin_b = build_verification_input(s1b, unit=_unit())
    assert vin_a["finding_id"] != vin_b["finding_id"]
    # Same content → same id
    vin_a2 = build_verification_input(s1a, unit=_unit())
    assert vin_a["finding_id"] == vin_a2["finding_id"]


def test_validate_rejects_confirmed_when_failed():
    bad = empty_verification_result("f", execution_state="failed", decision="inconclusive")
    bad["decision"] = "confirmed"  # illegal combo
    assert not validate_verification_result(bad)


def test_empty_result_includes_evidence_array():
    r = empty_verification_result("f")
    assert "evidence" in r
    assert r["evidence"] == []
    assert validate_verification_result(r)
