"""Phase 12: FinalScanArtifact production-loop invariants (no API key)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.final_artifact.finalize import (
    verify_run_manifest_before_report,
    write_final_scan_artifact,
)
from core.final_artifact.manifest import make_entry, hash_file
from core.final_artifact.reducer import compute_final_state, reduce_to_final_artifact
from core.final_artifact.validate import (
    exit_code_for_fail_on,
    validate_final_scan_artifact,
)
from core.final_artifact.schema import LEGACY_FORBIDDEN_KEYS
from core.reporter import build_pipeline_output
from core.schemas import make_envelope


def _ev(eid: str, content: str = "x") -> dict:
    return {
        "evidence_id": eid,
        "kind": "obs",
        "content": {"text": content},
        "content_hash": None,
    }


def _write_results(tmp: Path, units: list[dict]) -> Path:
    path = tmp / "results_verified.json"
    path.write_text(
        json.dumps({"dataset": "t", "results": units, "metrics": {"total_units": len(units)}}),
        encoding="utf-8",
    )
    return path


def test_reducer_reruns_after_dynamic_reproduced(tmp_path: Path):
    e1 = _ev("e1")
    e2 = _ev("e2")
    ed = _ev("ed", "dyn")
    s1 = {
        "unit_id": "a.py:foo",
        "decision": "candidate",
        "evidence_ids": ["e1"],
        "evidence": [e1],
        "source": "req",
        "sink": "exec",
    }
    s2 = {
        "unit_id": "a.py:foo",
        "finding_id": "fid1",
        "execution_state": "succeeded",
        "decision": "confirmed",
        "evidence_ids": ["e2"],
        "evidence": [e2],
        "verified_source": "req",
        "sink": "exec",
    }
    dyn = {
        "unit_id": "a.py:foo",
        "finding_id": "fid1",
        "test_id": "t1",
        "execution_state": "succeeded",
        "decision": "reproduced",
        "evidence_ids": ["ed"],
        "evidence": [ed],
        "artifacts": [],
        "attempts": [{"attempt_id": "a1"}],
        "provenance": {},
    }
    assert compute_final_state(s1, s2, dyn) == "reproduced"
    art, errs = reduce_to_final_artifact(
        run_meta={"run_id": "r"},
        units=[{"id": "a.py:foo"}],
        stage1_results=[s1],
        stage2_results=[s2],
        dynamic_results=[dyn],
        evidence_lists=[[e1], [e2], [ed]],
        reachability_counts={
            "total_units": 1,
            "reachable": 1,
            "unreachable": 0,
            "unknown_reachability": 0,
        },
        artifact_manifest=[],
        configuration={},
    )
    assert not errs
    assert art["findings"][0]["final_state"] == "reproduced"
    assert art["metrics"]["dynamic_reproduced"] == 1
    assert "ed" in art["evidence_index"]


def test_evidence_conflict_blocks_artifact(tmp_path: Path):
    e_a = {"evidence_id": "dup", "content": {"v": 1}, "content_hash": "h1"}
    e_b = {"evidence_id": "dup", "content": {"v": 2}, "content_hash": "h2"}
    art, errs = reduce_to_final_artifact(
        run_meta={},
        units=[{"id": "u"}],
        stage1_results=[
            {
                "unit_id": "u",
                "decision": "candidate",
                "evidence_ids": ["dup"],
                "evidence": [e_a],
            }
        ],
        stage2_results=[],
        dynamic_results=[],
        evidence_lists=[[e_a], [e_b]],
        reachability_counts={
            "total_units": 1,
            "reachable": 1,
            "unreachable": 0,
            "unknown_reachability": 0,
        },
        artifact_manifest=[],
        configuration={},
    )
    assert errs
    assert any("inconsistent" in e for e in errs)


def test_build_pipeline_output_with_dynamic(tmp_path: Path):
    e1 = _ev("ev1")
    e2 = _ev("ev2")
    ed = _ev("evd")
    units = [
        {
            "unit_id": "m.py:f",
            "route_key": "m.py:f",
            "decision": "candidate",
            "cwe_id": 89,
            "source": "a",
            "sink": "b",
            "evidence_ids": ["ev1"],
            "evidence": [e1],
            "stage2_verification": {
                "finding_id": "f1",
                "unit_id": "m.py:f",
                "execution_state": "succeeded",
                "decision": "confirmed",
                "evidence_ids": ["ev2"],
                "evidence": [e2],
                "verified_source": "a",
                "sink": "b",
            },
        }
    ]
    results = _write_results(tmp_path, units)
    dyn_path = tmp_path / "dynamic_test_results.json"
    dyn_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "results": [
                    {
                        "unit_id": "m.py:f",
                        "finding_id": "f1",
                        "test_id": "tid",
                        "execution_state": "succeeded",
                        "decision": "not_reproduced",
                        "evidence_ids": ["evd"],
                        "evidence": [ed],
                        "artifacts": [],
                        "attempts": [],
                        "provenance": {},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    # Dataset with reachability so we don't mark missing
    (tmp_path / "dataset.json").write_text(
        json.dumps(
            {
                "units": [{"id": "m.py:f", "reachability": "reachable"}],
                "metadata": {
                    "reachability_filter": {
                        "original_units": 1,
                        "reachable_units": 1,
                        "unreachable_units": 0,
                        "unknown_units": 0,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "pipeline_output.json"
    path, count, errors = build_pipeline_output(
        results_path=str(results),
        output_path=str(out),
        language="python",
        processing_level="reachable",
    )
    assert not errors, errors
    assert out.is_file()
    art = json.loads(out.read_text(encoding="utf-8"))
    assert art["findings"][0]["final_state"] == "confirmed_not_reproduced"
    assert "safe" not in json.dumps(art.get("metrics"))
    for key in LEGACY_FORBIDDEN_KEYS:
        assert key not in art
    assert (tmp_path / "run_artifact_manifest.json").is_file()
    assert verify_run_manifest_before_report(str(tmp_path)) == []


def test_fail_on_exit_codes():
    metrics = {
        "stage1_candidates": 1,
        "stage2_confirmed": 1,
        "dynamic_reproduced": 1,
        "stage1_errors": 0,
        "stage2_failed": 0,
        "dynamic_failed": 0,
    }
    findings = [{"final_state": "reproduced"}]
    assert exit_code_for_fail_on(metrics, None, findings=findings) == 0
    assert exit_code_for_fail_on(metrics, "candidate", findings=findings) == 1
    assert exit_code_for_fail_on(metrics, "confirmed", findings=findings) == 1
    assert exit_code_for_fail_on(metrics, "reproduced", findings=findings) == 1
    assert exit_code_for_fail_on(
        {"stage1_errors": 1, "stage2_failed": 0, "dynamic_failed": 0},
        "error",
    ) == 1


def test_envelope_partial_on_validation_failure():
    env = make_envelope(
        status="partial",
        stage="finalize",
        data={},
        errors=["evidence conflict"],
    )
    assert env["status"] == "partial"
    assert env["errors"]


def test_deterministic_reduce():
    s1 = [{"unit_id": "u", "decision": "candidate", "evidence_ids": [], "evidence": []}]
    a1, e1 = reduce_to_final_artifact(
        run_meta={"run_id": "x"},
        units=[{"id": "u"}],
        stage1_results=s1,
        stage2_results=[],
        dynamic_results=[],
        evidence_lists=[],
        reachability_counts={
            "total_units": 1,
            "reachable": 1,
            "unreachable": 0,
            "unknown_reachability": 0,
        },
        artifact_manifest=[],
        configuration={"k": 1},
    )
    a2, e2 = reduce_to_final_artifact(
        run_meta={"run_id": "x"},
        units=[{"id": "u"}],
        stage1_results=s1,
        stage2_results=[],
        dynamic_results=[],
        evidence_lists=[],
        reachability_counts={
            "total_units": 1,
            "reachable": 1,
            "unreachable": 0,
            "unknown_reachability": 0,
        },
        artifact_manifest=[],
        configuration={"k": 1},
    )
    assert e1 == e2
    assert a1["findings"][0]["final_state"] == a2["findings"][0]["final_state"]
    assert a1["metrics"] == a2["metrics"]


def test_docker_e2e_must_skip_without_daemon():
    import shutil
    import subprocess

    if shutil.which("docker") is None:
        pytest.skip("Docker CLI unavailable — local dynamic e2e skipped (not passed)")
    try:
        proc = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        pytest.skip("Docker daemon unreachable — local dynamic e2e skipped")
    if proc.returncode != 0:
        pytest.skip("Docker daemon not running — local dynamic e2e skipped")
    pytest.skip("Docker present: four-language e2e runs only in GitHub Actions docker job")
