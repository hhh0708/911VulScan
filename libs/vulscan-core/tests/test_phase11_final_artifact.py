"""Phase 11: FinalScanArtifact reducer, validation, and manifest tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.final_artifact import (
    FINAL_STATES,
    LEGACY_FORBIDDEN_KEYS,
    AnalysisMetrics,
    build_evidence_index,
    compute_final_state,
    dumps_stable,
    hash_file,
    make_entry,
    reduce_to_final_artifact,
    validate_final_scan_artifact,
)
from core.final_artifact.evidence_index import (
    compute_content_hash,
    merge_evidence_indexes,
)
from core.final_artifact.manifest import validate_upstream_hashes


def _ev(eid: str, note: str = "x") -> dict:
    entry = {
        "evidence_id": eid,
        "kind": "obs",
        "source": "test",
        "content": {"note": note},
    }
    entry["content_hash"] = compute_content_hash(entry)
    return entry


def _s1(unit_id: str, decision: str = "candidate") -> dict:
    return {"unit_id": unit_id, "decision": decision, "finding_id": f"f-{unit_id}"}


def _s2(
    unit_id: str,
    decision: str = "confirmed",
    execution_state: str = "succeeded",
) -> dict:
    return {
        "unit_id": unit_id,
        "finding_id": f"f-{unit_id}",
        "decision": decision,
        "execution_state": execution_state,
        "evidence_ids": ["ev1"],
    }


def _dyn(
    unit_id: str,
    decision: str = "reproduced",
    execution_state: str = "succeeded",
) -> dict:
    return {
        "unit_id": unit_id,
        "finding_id": f"f-{unit_id}",
        "decision": decision,
        "execution_state": execution_state,
        "evidence_ids": ["ev2"],
    }


def _reduce(
    stage1=None,
    stage2=None,
    dynamic=None,
    *,
    total_units=1,
    reachable=1,
    evidence=None,
):
    artifact, _errs = reduce_to_final_artifact(
        run_meta={"run_id": "r1"},
        units=[{"id": "u1"}] if total_units else [],
        stage1_results=stage1,
        stage2_results=stage2,
        dynamic_results=dynamic,
        evidence_lists=[evidence or [_ev("ev1"), _ev("ev2")]],
        reachability_counts={
            "total_units": total_units,
            "reachable": reachable,
            "unreachable": 0,
            "unknown_reachability": total_units - reachable,
        },
        artifact_manifest=[],
        configuration={},
    )
    return artifact


@pytest.mark.parametrize(
    "s1,s2,dyn,expected",
    [
        (_s1("u1"), _s2("u1"), _dyn("u1", "reproduced"), "reproduced"),
        (_s1("u1"), _s2("u1"), None, "confirmed_not_dynamically_tested"),
        (
            _s1("u1"),
            _s2("u1"),
            _dyn("u1", "not_reproduced"),
            "confirmed_not_reproduced",
        ),
        (_s1("u1"), None, None, "candidate"),
        (_s1("u1"), _s2("u1", "rejected"), None, "rejected"),
        (_s1("u1", "inconclusive"), None, None, "inconclusive"),
        (_s1("u1"), _s2("u1", "inconclusive"), None, "inconclusive"),
        (
            _s1("u1"),
            _s2("u1"),
            _dyn("u1", "inconclusive", "succeeded"),
            "inconclusive",
        ),
        (_s1("u1", "error"), None, None, "error"),
        (_s1("u1"), _s2("u1", "inconclusive", "failed"), None, "error"),
        (_s1("u1"), _s2("u1"), _dyn("u1", "inconclusive", "failed"), "error"),
        (
            _s1("u1"),
            _s2("u1"),
            _dyn("u1", "reproduced", "skipped"),
            "confirmed_not_dynamically_tested",
        ),
        (
            _s1("u1"),
            _s2("u1"),
            _dyn("u1", "reproduced", "blocked"),
            "confirmed_not_dynamically_tested",
        ),
    ],
)
def test_compute_final_state_merge_table(s1, s2, dyn, expected):
    assert compute_final_state(s1, s2, dyn) == expected
    assert expected in FINAL_STATES


def test_final_states_mutually_exclusive_in_artifact():
    art = _reduce(
        stage1=[_s1("u1"), _s1("u2"), _s1("u3")],
        stage2=[
            _s2("u1"),
            _s2("u2", "rejected"),
            _s2("u3", "inconclusive"),
        ],
        dynamic=[_dyn("u1", "reproduced")],
        total_units=3,
        reachable=3,
    )
    for f in art["findings"]:
        assert f["final_state"] in FINAL_STATES


def test_candidate_cannot_enter_reproduced_without_stage2():
    state = compute_final_state(_s1("u1"), None, None)
    assert state == "candidate"
    assert state != "reproduced"

    art = _reduce(
        stage1=[_s1("u1")],
        stage2=[_s2("u1")],
        dynamic=[_dyn("u1", "reproduced")],
    )
    assert art["findings"][0]["final_state"] == "reproduced"
    assert art["findings"][0]["stage2_verification"]["decision"] == "confirmed"


def test_stage2_rejected_not_confirmed():
    art = _reduce(
        stage1=[_s1("u1")],
        stage2=[_s2("u1", "rejected")],
    )
    assert art["findings"][0]["final_state"] == "rejected"
    assert art["findings"][0]["final_state"] not in {
        "confirmed_not_dynamically_tested",
        "confirmed_not_reproduced",
        "reproduced",
    }


def test_not_reproduced_not_safe():
    art = _reduce(
        stage1=[_s1("u1")],
        stage2=[_s2("u1")],
        dynamic=[_dyn("u1", "not_reproduced")],
    )
    assert art["findings"][0]["final_state"] == "confirmed_not_reproduced"

    poisoned = dict(art)
    poisoned["findings"] = [
        {
            **art["findings"][0],
            "final_state": "safe",
        }
    ]
    errs = validate_final_scan_artifact(poisoned)
    assert any("invalid final_state" in e for e in errs)


def test_evidence_ids_resolvable():
    art = _reduce(
        stage1=[_s1("u1")],
        stage2=[_s2("u1")],
        dynamic=[_dyn("u1", "reproduced")],
    )
    errs = validate_final_scan_artifact(art)
    assert not any("unresolved evidence_id" in e for e in errs)


def test_evidence_index_duplicate_inconsistent():
    _, errs = merge_evidence_indexes(
        {"e1": _ev("e1", "a")},
        {"e1": _ev("e1", "b")},
    )
    assert errs


def test_metrics_totals_match():
    art = _reduce(
        stage1=[_s1("u1"), _s1("u2"), {"unit_id": "u3", "decision": "no_finding"}],
        stage2=[_s2("u1"), _s2("u2", "rejected")],
        dynamic=[_dyn("u1", "reproduced")],
        total_units=3,
        reachable=2,
    )
    m = art["metrics"]
    assert m["stage1_candidates"] == 2
    assert m["stage1_no_finding"] == 1
    assert m["stage2_confirmed"] == 1
    assert m["stage2_rejected"] == 1
    assert m["dynamic_reproduced"] == 1
    errs = validate_final_scan_artifact(art)
    assert not any("dynamic_reproduced" in e for e in errs)


def test_reachability_sum():
    metrics = AnalysisMetrics(
        total_units=10,
        reachable=6,
        unreachable=3,
        unknown_reachability=1,
    )
    assert metrics.validate_invariants() == []

    bad = AnalysisMetrics(
        total_units=10, reachable=6, unreachable=3, unknown_reachability=0
    )
    assert any("reachability sum" in e for e in bad.validate_invariants())

    art = _reduce(stage1=[_s1("u1")], total_units=5, reachable=3)
    art["unit_summary"]["unknown_reachability"] = 0
    errs = validate_final_scan_artifact(art)
    assert any("reachability sum" in e for e in errs)


def test_legacy_fields_fail_validation():
    art = _reduce(stage1=[_s1("u1")], stage2=[_s2("u1")])
    art["findings"][0]["verdict"] = "vulnerable"
    errs = validate_final_scan_artifact(art)
    assert any("legacy forbidden key" in e for e in errs)
    assert "verdict" in LEGACY_FORBIDDEN_KEYS


def test_dumps_stable_deterministic():
    obj = {"b": 2, "a": 1, "nested": {"z": 9, "y": 8}}
    a = dumps_stable(obj)
    b = dumps_stable({"nested": {"y": 8, "z": 9}, "a": 1, "b": 2})
    assert a == b
    assert json.loads(a) == obj


def test_manifest_hash_file_and_validate(tmp_path: Path):
    f = tmp_path / "data.json"
    f.write_text('{"x":1}', encoding="utf-8")
    digest = hash_file(f)
    entry = make_entry(
        relative_path="data.json",
        artifact_type="results",
        schema_version="1.0",
        sha256=digest,
        producer_stage="analyze",
    )
    assert validate_upstream_hashes([entry], tmp_path) == []

    entry_bad = dict(entry)
    entry_bad["sha256"] = "0" * 64
    assert validate_upstream_hashes([entry_bad], tmp_path)


def test_bucket_views_consistent():
    from core.final_artifact.report_views import report_sections

    art = _reduce(
        stage1=[_s1("u1"), _s1("u2")],
        stage2=[_s2("u1"), _s2("u2", "rejected")],
        dynamic=[_dyn("u1", "reproduced")],
        total_units=2,
    )
    assert len(art["rejected"]) == 1
    assert art["findings"][0]["final_state"] == "reproduced"
    assert validate_final_scan_artifact(art) == []

    sections = report_sections(art, chinese=True)
    keys = [s["key"] for s in sections]
    assert "reproduced" in keys
    assert "rejected" in keys
    assert "candidate" not in keys


def test_never_invent_reachable_equals_total():
    art = _reduce(
        stage1=[_s1("u1")],
        total_units=100,
        reachable=40,
    )
    assert art["metrics"]["total_units"] == 100
    assert art["metrics"]["reachable"] == 40
    assert art["metrics"]["reachable"] != art["metrics"]["total_units"]
