"""Tests for 911VulScan_Scan_Results export layout."""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))


def test_project_results_dir_nested(tmp_path, monkeypatch):
    from utilities.scan_results_export import project_results_dir

    monkeypatch.delenv("911VULSCAN_SCAN_RESULTS_ROOT", raising=False)
    dest = project_results_dir("local/cjson", "c", root=tmp_path)
    assert dest == tmp_path / "local" / "cjson" / "c"


def test_export_static_and_dynamic(tmp_path):
    from utilities.scan_results_export import (
        export_dynamic_results,
        export_static_results,
        project_results_dir,
    )

    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "results.json").write_text("{}")
    (scan / "pipeline_output.json").write_text('{"findings": []}')
    report = scan / "report"
    report.mkdir()
    (report / "SUMMARY_REPORT.md").write_text("# Summary")
    (scan / "dynamic_test_results.json").write_text('{"results": []}')
    (scan / "DYNAMIC_TEST_RESULTS.md").write_text("# Dynamic")
    (scan / "dynamic-test.report.json").write_text('{"step": "dynamic-test", "status": "success"}')
    dyn_disc = scan / "disclosures"
    dyn_disc.mkdir()
    (dyn_disc / "DYNAMIC_DISCLOSURE_01_X.md").write_text("# dyn")

    export_static_results(scan, "local/cjson", language="c", root=tmp_path / "out")
    export_dynamic_results(scan, "local/cjson", language="c", root=tmp_path / "out")

    base = project_results_dir("local/cjson", "c", root=tmp_path / "out")
    assert (base / "static" / "SUMMARY_REPORT.md").is_file()
    assert (base / "static" / "results.json").is_file()
    assert (base / "dynamic" / "DYNAMIC_TEST_RESULTS.md").is_file()
    assert (base / "dynamic" / "dynamic-test.report.json").is_file()
    assert (base / "dynamic" / "disclosures" / "DYNAMIC_DISCLOSURE_01_X.md").is_file()
    assert (base / "INDEX.md").is_file()
