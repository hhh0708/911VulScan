"""Scanner orchestration respects immutable ScanRequest / run identity."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from core.pipeline_config import (
    FIXED_PIPELINE,
    PipelineConfig,
    SCAN_MANIFEST_NAME,
    ScanRequest,
    generate_run_id,
)
from core.schemas import AnalysisMetrics, AnalyzeResult, ParseResult, ScanResult


def _fake_pipeline(monkeypatch, run_dir: Path):
    dataset = run_dir / "dataset.json"
    ao = run_dir / "analyzer_output.json"
    results = run_dir / "results.json"

    def fake_parse(**kwargs):
        assert Path(kwargs["output_dir"]) == run_dir
        run_dir.mkdir(parents=True, exist_ok=True)
        dataset.write_text(json.dumps({"units": [{"id": "u1", "code": "x"}]}), encoding="utf-8")
        ao.write_text(json.dumps({"functions": {}}), encoding="utf-8")
        (run_dir / "call_graph.json").write_text(
            json.dumps({"functions": {}, "call_graph": {}, "reverse_call_graph": {}}),
            encoding="utf-8",
        )
        return ParseResult(
            dataset_path=str(dataset),
            analyzer_output_path=str(ao),
            units_count=1,
            language="python",
            scope="all",
        )

    def fake_analyze(**kwargs):
        assert Path(kwargs["output_dir"]) == run_dir
        results.write_text(json.dumps([]), encoding="utf-8")
        return AnalyzeResult(
            results_path=str(results),
            metrics=AnalysisMetrics(total_units=1, stage1_no_finding=1),
        )

    def fake_build(**kwargs):
        path = str(run_dir / "pipeline_output.json")
        Path(path).write_text(json.dumps({"findings": []}), encoding="utf-8")
        # Production contract: (output_path, findings_count, errors).
        return path, 0, []

    monkeypatch.setattr("core.parser_adapter.parse_repository", fake_parse)
    monkeypatch.setattr(
        "core.parser_adapter.apply_reachability_filter",
        lambda dataset, output_dir, level, **kw: dataset,
    )
    monkeypatch.setattr("core.analyzer.run_analysis", fake_analyze)
    monkeypatch.setattr("core.reporter.build_pipeline_output", fake_build)
    monkeypatch.setattr("core.reporter.generate_summary_report", lambda *a, **k: None)
    monkeypatch.setattr("core.reporter.generate_disclosure_docs", lambda *a, **k: None)


def test_scan_repository_signature_is_scan_request_only():
    from core.scanner import scan_repository

    sig = inspect.signature(scan_repository)
    assert list(sig.parameters) == ["request"]


def test_scan_writes_manifest_matching_request(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")
    root = tmp_path / "out"
    run_id = "run_test_1"
    run_dir = root / "runs" / run_id
    _fake_pipeline(monkeypatch, run_dir)

    request = ScanRequest(
        repo_path=str(repo),
        config=PipelineConfig(
            language="python",
            scope="reachable",
            app_context=False,
            enhance=False,
            verify=True,
            dynamic_verify=False,
            workers=1,
            output_dir=str(root),
        ),
        model="opus",
        enhance_mode="agentic",
        skip_tests=True,
        limit=None,
        generate_report=False,
        run_id=run_id,
    )

    from core.scanner import scan_repository

    result = scan_repository(request)
    assert isinstance(result, ScanResult)
    assert result.run_id == run_id
    assert Path(result.output_dir) == run_dir.resolve()

    manifest_path = run_dir / SCAN_MANIFEST_NAME
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["request"] == request.to_dict()
    assert manifest["config_hash"] == request.config_hash()
    assert manifest["run_id"] == run_id
    assert manifest["pipeline"] == list(FIXED_PIPELINE)
    assert manifest["request"]["config"]["verify"] is True
    assert manifest["request"]["generate_report"] is False


def test_repeated_scans_use_distinct_run_dirs(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")
    root = tmp_path / "out"

    ids = ["run_a", "run_b"]
    for rid in ids:
        run_dir = root / "runs" / rid
        _fake_pipeline(monkeypatch, run_dir)
        request = ScanRequest(
            repo_path=str(repo),
            config=PipelineConfig(
                language="python",
                scope="all",
                app_context=False,
                enhance=False,
                verify=False,
                dynamic_verify=False,
                workers=1,
                output_dir=str(root),
            ),
            generate_report=False,
            run_id=rid,
        )
        from core.scanner import scan_repository
        result = scan_repository(request)
        assert (Path(result.output_dir) / SCAN_MANIFEST_NAME).exists()

    assert (root / "runs" / "run_a" / SCAN_MANIFEST_NAME).exists()
    assert (root / "runs" / "run_b" / SCAN_MANIFEST_NAME).exists()
    a = json.loads((root / "runs" / "run_a" / SCAN_MANIFEST_NAME).read_text(encoding="utf-8"))
    b = json.loads((root / "runs" / "run_b" / SCAN_MANIFEST_NAME).read_text(encoding="utf-8"))
    assert a["run_id"] != b["run_id"]


def test_scanner_rejects_kwargs_style_call():
    from core.scanner import scan_repository
    import pytest

    with pytest.raises(TypeError):
        scan_repository("/repo", output_dir="/out")  # type: ignore[call-arg]


def test_scanner_source_has_no_real_world_import():
    src = Path(__file__).resolve().parents[1] / "core" / "scanner.py"
    text = src.read_text(encoding="utf-8")
    assert "from real_world" not in text
    assert "import real_world" not in text


def test_generate_run_id_unique():
    ids = {generate_run_id() for _ in range(20)}
    assert len(ids) == 20
