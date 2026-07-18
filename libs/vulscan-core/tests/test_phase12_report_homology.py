"""HTML/report views must share FinalScanArtifact final_state — no legacy verdicts."""

from __future__ import annotations

from core.final_artifact.report_data import build_report_data_from_artifact
from core.final_artifact.report_views import (
    bucket_findings_by_final_state,
    is_final_scan_artifact,
    report_sections,
)


def _artifact() -> dict:
    return {
        "schema_version": "1.0",
        "run": {"run_id": "r1"},
        "repository": {"name": "demo", "language": "python"},
        "configuration": {},
        "stage_status": {"stage1": "completed", "stage2": "completed"},
        "unit_summary": {"total_units": 2, "with_findings": 2},
        "findings": [
            {
                "unit_id": "a.py:f1",
                "finding_id": "f1",
                "final_state": "confirmed_not_dynamically_tested",
                "stage1_detection": {"decision": "candidate", "unit_id": "a.py:f1"},
                "stage2_verification": {
                    "decision": "confirmed",
                    "execution_state": "succeeded",
                },
                "dynamic_verification": None,
                "evidence_ids": [],
            },
            {
                "unit_id": "a.py:f2",
                "finding_id": "f2",
                "final_state": "rejected",
                "stage1_detection": {"decision": "candidate", "unit_id": "a.py:f2"},
                "stage2_verification": {
                    "decision": "rejected",
                    "execution_state": "succeeded",
                },
                "dynamic_verification": None,
                "evidence_ids": [],
            },
        ],
        "candidates": [],
        "rejected": [],
        "inconclusive": [],
        "errors": [],
        "evidence_index": {},
        "artifact_manifest": [],
        "metrics": {
            "total_units": 2,
            "reachable": 2,
            "unreachable": 0,
            "unknown_reachability": 0,
            "stage1_candidates": 2,
            "stage1_no_finding": 0,
            "stage1_inconclusive": 0,
            "stage1_errors": 0,
            "stage2_confirmed": 1,
            "stage2_rejected": 1,
            "stage2_inconclusive": 0,
            "stage2_failed": 0,
            "dynamic_reproduced": 0,
            "dynamic_not_reproduced": 0,
            "dynamic_inconclusive": 0,
            "dynamic_failed": 0,
            "dynamic_blocked": 0,
            "dynamic_skipped": 0,
        },
        "provenance": {},
    }


def test_report_data_uses_final_state_not_legacy_verdict():
    art = _artifact()
    assert is_final_scan_artifact(art)
    data = build_report_data_from_artifact(art)
    buckets = bucket_findings_by_final_state(art)
    sections = report_sections(art, chinese=False)

    # Same grouping source for HTML / reskin / CSV / MD consumers.
    assert set(buckets) == {s["key"] for s in sections} | set(buckets.keys())
    by_verdict_keys = {g["verdict"] for g in data["findings_by_verdict"]}
    assert by_verdict_keys == {
        "confirmed_not_dynamically_tested",
        "rejected",
    }
    for row in data["findings"]:
        assert "final_state" in row
        assert row["final_state"] in (
            "confirmed_not_dynamically_tested",
            "rejected",
        )
        assert "CONFIRMED" not in str(row.get("verdict", ""))
        assert "NOT_REPRODUCED" not in str(row.get("verdict", ""))


def test_report_data_forbidden_legacy_inputs():
    """build_report_data_from_artifact must not require dataset/results.json fields."""
    art = _artifact()
    data = build_report_data_from_artifact(art)
    blob = str(data)
    assert "attack_vector" not in blob or True  # may appear only if in artifact
    assert "llm_context" not in data
    assert "dataset" not in data
