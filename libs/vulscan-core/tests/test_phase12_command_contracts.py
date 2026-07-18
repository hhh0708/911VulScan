"""Phase 12: frozen per-command data contracts + live CLI command execution."""

from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.final_artifact.evidence_index import compute_content_hash, is_valid_sha256
from core.final_artifact.manifest import hash_file
from core.schemas import (
    AnalyzeResult,
    AnalysisMetrics,
    DynamicTestStepResult,
    EnhanceResult,
    ParseResult,
    ReportResult,
    ScanResult,
    UsageInfo,
    VerifyResult,
)
from vulscan import cli as vulscan_cli

CONTRACTS = json.loads(
    (Path(__file__).parent / "fixtures" / "phase12_command_contracts.json").read_text(
        encoding="utf-8"
    )
)
ENVELOPE_STATUSES = frozenset({"completed", "partial", "failed"})


def _capture_cmd(fn, args) -> dict:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = fn(args)
    text = buf.getvalue().strip()
    assert text, "stdout must contain one JSON envelope"
    # Exactly one JSON object
    env = json.loads(text)
    assert isinstance(env, dict)
    # No trailing second object
    decoder = json.JSONDecoder()
    obj, idx = decoder.raw_decode(text)
    assert idx == len(text), "stdout must be exactly one JSON object"
    assert env["status"] in ENVELOPE_STATUSES
    assert "data" in env
    return env, code


def test_frozen_contracts_document_commands():
    expected = {
        "parse",
        "enhance",
        "analyze",
        "verify",
        "dynamic-test",
        "build-output",
        "report",
        "scan",
    }
    assert set(CONTRACTS.keys()) == expected


def test_enhance_does_not_touch_classifications(tmp_path):
    """Regression: cmd_enhance must not read result.classifications."""
    enhanced = tmp_path / "out.json"
    enhanced.write_text("{}", encoding="utf-8")

    class _EnhanceNoClassifications(EnhanceResult):
        @property
        def classifications(self):  # type: ignore[override]
            raise AttributeError("classifications must not be read")

    fake = _EnhanceNoClassifications(
        enhanced_dataset_path=str(enhanced),
        units_enhanced=1,
        error_count=0,
        usage=UsageInfo(),
    )

    args = SimpleNamespace(
        dataset=str(tmp_path / "in.json"),
        output=str(enhanced),
        analyzer_output=None,
        repo_path=None,
        mode="deterministic",
        checkpoint=None,
        workers=1,
        backoff=0,
    )
    (tmp_path / "in.json").write_text('{"units":[]}', encoding="utf-8")

    with patch("core.enhancer.enhance_dataset", return_value=fake):
        env, code = _capture_cmd(vulscan_cli.cmd_enhance, args)

    assert code == 0
    assert env["status"] == "completed"
    assert set(env["data"].keys()) == set(CONTRACTS["enhance"].keys())


def test_verify_with_candidates_outputs_canonical_keys(tmp_path):
    out = tmp_path / "verified.json"
    out.write_text("{}", encoding="utf-8")
    fake = VerifyResult(
        verified_results_path=str(out),
        candidates_input=2,
        attempted=2,
        succeeded=2,
        failed=0,
        skipped=0,
        confirmed=1,
        rejected=1,
        inconclusive=0,
        usage=UsageInfo(),
    )
    args = SimpleNamespace(
        results=str(tmp_path / "results.json"),
        output=str(tmp_path),
        analyzer_output=str(tmp_path / "ao.json"),
        app_context=None,
        repo_path=None,
        workers=1,
        checkpoint=None,
        backoff=0,
        fail_on=None,
    )
    (tmp_path / "results.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ao.json").write_text("{}", encoding="utf-8")

    with patch("core.verifier.run_verification", return_value=fake):
        env, code = _capture_cmd(vulscan_cli.cmd_verify, args)

    assert code == 0
    assert env["status"] == "completed"
    assert set(env["data"].keys()) == set(CONTRACTS["verify"].keys())
    assert "findings_input" not in env["data"]
    assert "findings_verified" not in env["data"]
    assert env["data"]["candidates_input"] == 2


def test_analyze_verify_outputs_verify_contract(tmp_path):
    results = tmp_path / "results.json"
    results.write_text("{}", encoding="utf-8")
    analyze = AnalyzeResult(
        results_path=str(results),
        metrics=AnalysisMetrics(total_units=1, stage1_candidates=1),
        usage=UsageInfo(),
    )
    verify = VerifyResult(
        verified_results_path=str(results),
        candidates_input=1,
        attempted=1,
        succeeded=1,
        confirmed=1,
        usage=UsageInfo(),
    )
    args = SimpleNamespace(
        dataset=str(tmp_path / "ds.json"),
        output=str(tmp_path),
        analyzer_output=str(tmp_path / "ao.json"),
        app_context=None,
        repo_path=None,
        limit=None,
        model=None,
        workers=1,
        checkpoint=None,
        backoff=0,
        verify=True,
        exploitable_all=False,
        exploitable_only=False,
        fail_on=None,
    )
    (tmp_path / "ds.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ao.json").write_text("{}", encoding="utf-8")

    with (
        patch("core.analyzer.run_analysis", return_value=analyze),
        patch("core.verifier.run_verification", return_value=verify),
    ):
        env, code = _capture_cmd(vulscan_cli.cmd_analyze, args)

    assert code == 0
    assert set(env["data"].keys()) == set(CONTRACTS["verify"].keys())


def test_build_output_completed(tmp_path):
    results = tmp_path / "results.json"
    results.write_text(
        json.dumps({"results": [], "metrics": {"total_units": 0}}),
        encoding="utf-8",
    )
    out = tmp_path / "pipeline_output.json"
    args = SimpleNamespace(
        results=str(results),
        output=str(out),
        repo_name="t",
        repo_url=None,
        language="python",
        commit_sha=None,
        processing_level="all",
    )

    def _fake_build(**kwargs):
        path = kwargs["output_path"]
        Path(path).write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "run": {},
                    "repository": {},
                    "configuration": {},
                    "stage_status": {},
                    "unit_summary": {"total_units": 0},
                    "findings": [],
                    "candidates": [],
                    "rejected": [],
                    "inconclusive": [],
                    "errors": [],
                    "evidence_index": {},
                    "artifact_manifest": [],
                    "metrics": AnalysisMetrics().to_dict(),
                    "provenance": {},
                }
            ),
            encoding="utf-8",
        )
        return path, 0, []

    with patch("core.reporter.build_pipeline_output", side_effect=_fake_build):
        env, code = _capture_cmd(vulscan_cli.cmd_build_output, args)

    assert code == 0
    assert env["status"] == "completed"
    assert set(env["data"].keys()) == set(CONTRACTS["build-output"].keys())


def test_build_output_evidence_conflict_partial(tmp_path):
    results = tmp_path / "results.json"
    results.write_text("{}", encoding="utf-8")
    out = tmp_path / "pipeline_output.json"
    args = SimpleNamespace(
        results=str(results),
        output=str(out),
        repo_name="t",
        repo_url=None,
        language="python",
        commit_sha=None,
        processing_level="all",
    )

    with patch(
        "core.reporter.build_pipeline_output",
        return_value=(str(out), 0, ["evidence_id 'e1' has inconsistent content"]),
    ):
        env, code = _capture_cmd(vulscan_cli.cmd_build_output, args)

    assert code == 1
    assert env["status"] == "partial"
    assert env["errors"]
    assert set(env["data"].keys()) == set(CONTRACTS["build-output"].keys())


def test_scan_finalize_failure_not_completed(tmp_path):
    fake = ScanResult(
        output_dir=str(tmp_path),
        status="failed",
        errors=["FinalScanArtifact invalid: evidence conflict"],
        pipeline_output_path=None,
        metrics=AnalysisMetrics(),
        usage=UsageInfo(),
    )
    assert set(fake.to_dict().keys()) == set(CONTRACTS["scan"].keys())
    args = SimpleNamespace(fail_on=None)
    with (
        patch.object(vulscan_cli, "build_scan_request", return_value=object()),
        patch("core.scanner.scan_repository", return_value=fake),
    ):
        env, code = _capture_cmd(vulscan_cli.cmd_scan, args)

    assert code == 2
    assert env["status"] == "failed"
    assert env["status"] != "completed"
    assert env["errors"]
    assert set(env["data"].keys()) == set(CONTRACTS["scan"].keys())


def test_parse_analyze_report_dynamic_contract_keys():
    assert set(ParseResult("p", None, 0, "python", "all").to_dict().keys()) == set(
        CONTRACTS["parse"].keys()
    )
    assert set(
        AnalyzeResult("r", AnalysisMetrics(), UsageInfo()).to_dict().keys()
    ) == set(CONTRACTS["analyze"].keys())
    assert set(ReportResult("o", "html", UsageInfo()).to_dict().keys()) == set(
        CONTRACTS["report"].keys()
    )
    assert set(
        DynamicTestStepResult("r.json").to_dict().keys()
    ) == set(CONTRACTS["dynamic-test"].keys())


def test_illegal_content_hash_rejected():
    from core.final_artifact.evidence_index import scan_raw_evidence_lists

    bad = [
        [
            {
                "evidence_id": "e1",
                "content": {"a": 1},
                "content_hash": "NOT_A_SHA256",
            }
        ]
    ]
    _idx, errs = scan_raw_evidence_lists(bad, producer_stages=["stage1"])
    assert any("illegal content_hash" in e for e in errs)

    entry = {"evidence_id": "e2", "content": {"a": 1}}
    good_hash = compute_content_hash(entry)
    assert is_valid_sha256(good_hash)
    _idx2, errs2 = scan_raw_evidence_lists(
        [[{**entry, "content_hash": good_hash}]],
        producer_stages=["stage1"],
        source_artifact_hashes=["a" * 64],
    )
    assert not errs2
    assert _idx2["e2"]["source_artifact_hash"] == "a" * 64
