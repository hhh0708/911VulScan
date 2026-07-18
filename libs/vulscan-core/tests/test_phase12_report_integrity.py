"""Phase 12 final integrity: report formats require validated FinalScanArtifact."""

from __future__ import annotations

import csv
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.final_artifact.csv_export import (
    CSV_COLUMNS,
    count_by_final_state,
    rows_from_artifact,
    write_csv_from_artifact,
)
from core.final_artifact.evidence_index import compute_content_hash
from core.final_artifact.finalize import (
    FINAL_ARTIFACT_FILENAME,
    FinalArtifactIntegrityError,
    load_and_validate_final_artifact,
    remove_stale_final_artifacts,
    write_final_scan_artifact,
)
from core.final_artifact.report_data import build_report_data_from_artifact
from core.final_artifact.report_views import REPORT_SECTION_ORDER, report_sections
from core.final_artifact.metrics import AnalysisMetrics
from vulscan import cli as vulscan_cli


def _ev(eid: str, note: str = "x") -> dict:
    entry = {
        "evidence_id": eid,
        "kind": "obs",
        "content": {"note": note},
    }
    entry["content_hash"] = compute_content_hash(entry)
    return entry


def _minimal_artifact(*, findings: list[dict] | None = None) -> dict:
    findings = list(findings or [])
    buckets = {k: [] for k in REPORT_SECTION_ORDER}
    for f in findings:
        buckets[f["final_state"]].append(f)
    metrics = AnalysisMetrics(
        total_units=max(1, len(findings)),
        reachable=max(1, len(findings)),
        stage1_candidates=len(findings),
        stage2_confirmed=sum(
            1
            for f in findings
            if f["final_state"]
            in (
                "reproduced",
                "confirmed_not_dynamically_tested",
                "confirmed_not_reproduced",
            )
        ),
        stage2_rejected=sum(1 for f in findings if f["final_state"] == "rejected"),
        dynamic_reproduced=sum(1 for f in findings if f["final_state"] == "reproduced"),
        dynamic_not_reproduced=sum(
            1 for f in findings if f["final_state"] == "confirmed_not_reproduced"
        ),
    ).to_dict()
    return {
        "schema_version": "1.0",
        "run": {"run_id": "integrity-test"},
        "repository": {"name": "demo", "language": "python"},
        "configuration": {"scope": "all"},
        "stage_status": {},
        "unit_summary": {
            "total_units": metrics["total_units"],
            "reachable": metrics["reachable"],
            "unreachable": 0,
            "unknown_reachability": 0,
            "analyzed": metrics["total_units"],
            "with_findings": len(findings),
        },
        "findings": findings,
        "candidates": buckets["candidate"],
        "rejected": buckets["rejected"],
        "inconclusive": buckets["inconclusive"],
        "errors": buckets["error"],
        "evidence_index": {},
        "artifact_manifest": [],
        "metrics": metrics,
        "provenance": {},
    }


def _finding(state: str, uid: str, eid: str | None = None) -> dict:
    s2_decision = "confirmed"
    dyn = None
    if state == "rejected":
        s2_decision = "rejected"
    elif state == "candidate":
        s2_decision = None
    elif state == "reproduced":
        dyn = {
            "decision": "reproduced",
            "execution_state": "succeeded",
            "evidence_ids": [eid] if eid else [],
        }
    elif state == "confirmed_not_reproduced":
        dyn = {
            "decision": "not_reproduced",
            "execution_state": "succeeded",
            "evidence_ids": [eid] if eid else [],
        }
    elif state == "inconclusive":
        s2_decision = "inconclusive"
    elif state == "error":
        s2_decision = None

    f = {
        "unit_id": uid,
        "finding_id": f"f-{uid}",
        "final_state": state,
        "stage1_detection": {
            "unit_id": uid,
            "decision": "candidate" if state != "error" else "error",
            "location": {"file": uid.split(":")[0], "function": uid.split(":")[-1]},
        },
        "stage2_verification": (
            {
                "unit_id": uid,
                "decision": s2_decision,
                "execution_state": "succeeded",
                "evidence_ids": [eid] if eid else [],
            }
            if s2_decision
            else None
        ),
        "dynamic_verification": dyn,
        "evidence_ids": [eid] if eid else [],
    }
    return f


def _write_validated(tmp: Path, artifact: dict) -> Path:
    # Attach evidence for referenced ids
    index = {}
    for f in artifact.get("findings") or []:
        for eid in f.get("evidence_ids") or []:
            index[eid] = _ev(eid, eid)
    artifact = dict(artifact)
    artifact["evidence_index"] = index
    path, _manifest, errors = write_final_scan_artifact(
        artifact,
        output_dir=str(tmp),
        upstream_entries=[],
        producer_stage="test",
    )
    assert not errors, errors
    return Path(path)


def test_tampered_pipeline_output_rejects_html_report_data(tmp_path):
    art = _minimal_artifact(
        findings=[_finding("confirmed_not_dynamically_tested", "a.py:f1", "e1")]
    )
    path = _write_validated(tmp_path, art)
    # Tamper after manifest was written
    data = json.loads(path.read_text(encoding="utf-8"))
    data["findings"][0]["unit_id"] = "tampered.py:x"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(FinalArtifactIntegrityError) as exc:
        load_and_validate_final_artifact(str(path))
    assert any("hash mismatch" in e for e in exc.value.errors)

    args = SimpleNamespace(results=str(path), pipeline_output=None)
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = vulscan_cli.cmd_report_data(args)
    env = json.loads(buf.getvalue())
    assert code == 2
    assert env["status"] == "failed"
    assert env["data"] == {} or not env["data"].get("findings_by_verdict")


def test_missing_evidence_id_rejects_report_data(tmp_path):
    art = _minimal_artifact(
        findings=[_finding("confirmed_not_dynamically_tested", "a.py:f1", "missing-eid")]
    )
    # Write without putting missing-eid in evidence_index via direct JSON + fake manifest
    path = tmp_path / FINAL_ARTIFACT_FILENAME
    art["evidence_index"] = {}
    path.write_text(json.dumps(art), encoding="utf-8")
    # Minimal manifest pointing at the file (hash will match file, schema fails)
    from core.final_artifact.manifest import hash_file, make_entry
    from utilities.file_io import write_json

    entry = make_entry(
        relative_path=FINAL_ARTIFACT_FILENAME,
        artifact_type="final_scan_artifact",
        schema_version="1.0",
        sha256=hash_file(str(path)),
        producer_stage="test",
    )
    write_json(
        str(tmp_path / "run_artifact_manifest.json"),
        {
            "schema_version": "1.0",
            "final_scan_artifact": {
                "relative_path": FINAL_ARTIFACT_FILENAME,
                "sha256": entry["sha256"],
            },
            "artifacts": [entry],
        },
    )

    with pytest.raises(FinalArtifactIntegrityError) as exc:
        load_and_validate_final_artifact(str(path))
    assert any("unresolved evidence_id" in e for e in exc.value.errors)

    args = SimpleNamespace(results=str(path), pipeline_output=None)
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = vulscan_cli.cmd_report_data(args)
    assert code == 2
    assert json.loads(buf.getvalue())["status"] == "failed"


def test_manifest_hash_mismatch_rejects_all_formats(tmp_path):
    art = _minimal_artifact(findings=[])
    path = _write_validated(tmp_path, art)
    manifest = tmp_path / "run_artifact_manifest.json"
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    for entry in doc["artifacts"]:
        if entry.get("relative_path") == FINAL_ARTIFACT_FILENAME:
            entry["sha256"] = "0" * 64
    manifest.write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(FinalArtifactIntegrityError):
        load_and_validate_final_artifact(str(path))

    out_csv = tmp_path / "out.csv"
    with pytest.raises(FinalArtifactIntegrityError):
        from core.reporter import generate_csv_report

        generate_csv_report(str(path), str(out_csv))


def test_autobuild_failure_does_not_read_stale_pipeline_output(tmp_path):
    stale = tmp_path / FINAL_ARTIFACT_FILENAME
    stale.write_text(
        json.dumps(_minimal_artifact(findings=[_finding("candidate", "old.py:f", None)])),
        encoding="utf-8",
    )
    (tmp_path / "run_artifact_manifest.json").write_text("{}", encoding="utf-8")
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"results": [], "metrics": {}}), encoding="utf-8")

    remove_stale_final_artifacts(str(tmp_path))
    assert not stale.exists()
    assert not (tmp_path / "run_artifact_manifest.json").exists()

    args = SimpleNamespace(
        results=str(results),
        pipeline_output=None,
        format="csv",
        output=str(tmp_path / "out.csv"),
        repo_name="t",
        project_name=None,
        language=None,
        scan_results_root=None,
        skip_dt_check=True,
        dataset=None,
    )

    with patch(
        "core.reporter.build_pipeline_output",
        return_value=(str(stale), 0, ["evidence conflict"]),
    ):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = vulscan_cli.cmd_report(args)
        env = json.loads(buf.getvalue())
        assert code in (1, 2)
        assert env["status"] in ("partial", "failed")
        assert env["errors"]
        # Must not have produced CSV from the deleted stale artifact
        assert not (tmp_path / "out.csv").exists()


def test_csv_html_markdown_counts_match_seven_states(tmp_path):
    findings = [
        _finding("reproduced", "a.py:r", "e-r"),
        _finding("confirmed_not_dynamically_tested", "a.py:c", "e-c"),
        _finding("confirmed_not_reproduced", "a.py:n", "e-n"),
        _finding("candidate", "a.py:cand", None),
        _finding("rejected", "a.py:rej", "e-rej"),
        _finding("inconclusive", "a.py:inc", None),
        _finding("error", "a.py:err", None),
    ]
    # Fix metrics for full set
    art = _minimal_artifact(findings=findings)
    art["metrics"] = AnalysisMetrics(
        total_units=7,
        reachable=7,
        stage1_candidates=6,
        stage1_errors=1,
        stage2_confirmed=3,
        stage2_rejected=1,
        stage2_inconclusive=1,
        dynamic_reproduced=1,
        dynamic_not_reproduced=1,
    ).to_dict()
    path = _write_validated(tmp_path, art)
    artifact = load_and_validate_final_artifact(str(path))

    expected = count_by_final_state(artifact)
    assert sum(expected.values()) == 7
    assert all(expected[k] == 1 for k in REPORT_SECTION_ORDER)

    # CSV
    csv_path = tmp_path / "f.csv"
    write_csv_from_artifact(artifact, str(csv_path))
    with open(csv_path, encoding="utf-8") as fh:
        text = fh.read()
        rows = list(csv.DictReader(io.StringIO(text)))
    csv_counts = {k: 0 for k in REPORT_SECTION_ORDER}
    for row in rows:
        csv_counts[row["final_state"]] += 1
    assert csv_counts == expected

    # Forbidden legacy tokens in CSV production path
    for banned in ("finding", "verdict", "vulnerable", "safe"):
        assert banned not in CSV_COLUMNS
        assert banned not in text.split("\n")[0].lower() or banned == "finding"
    header = text.split("\n")[0].lower()
    assert "verdict" not in header
    assert "vulnerable" not in header
    assert "safe" not in header
    # column name finding_id is ok; bare "finding"/"verdict" are not
    assert "verdict" not in CSV_COLUMNS

    # HTML report-data
    data = build_report_data_from_artifact(artifact)
    html_counts = {k: 0 for k in REPORT_SECTION_ORDER}
    for g in data["findings_by_verdict"]:
        html_counts[g["verdict"]] = g["count"]
    # groups omit empty — fill zeros
    for k in REPORT_SECTION_ORDER:
        html_counts.setdefault(k, 0)
    assert html_counts == expected

    # Markdown sections (same report_sections source)
    md_counts = {k: 0 for k in REPORT_SECTION_ORDER}
    for section in report_sections(artifact, chinese=False, include_empty=True):
        md_counts[section["key"]] = len(section["findings"])
    assert md_counts == expected


def test_empty_findings_consistent_empty_reports(tmp_path):
    path = _write_validated(tmp_path, _minimal_artifact(findings=[]))
    artifact = load_and_validate_final_artifact(str(path))
    assert artifact["findings"] == []

    csv_path = tmp_path / "empty.csv"
    write_csv_from_artifact(artifact, str(csv_path))
    with open(csv_path, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows == []

    data = build_report_data_from_artifact(artifact)
    assert data["findings"] == []
    assert data["findings_by_verdict"] == []
    assert report_sections(artifact, include_empty=False) == []
    assert count_by_final_state(artifact) == {k: 0 for k in REPORT_SECTION_ORDER}


def test_csv_production_path_no_legacy_verdict_columns():
    assert "verdict" not in CSV_COLUMNS
    assert "finding" not in CSV_COLUMNS
    assert "vulnerable" not in CSV_COLUMNS
    assert "safe" not in CSV_COLUMNS
    assert "final_state" in CSV_COLUMNS
