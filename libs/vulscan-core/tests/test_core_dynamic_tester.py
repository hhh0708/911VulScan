"""Tests for the core dynamic-test wrapper (Phase 12).

Current contract (`core.dynamic_tester.run_tests`):
- Consumes a results JSON with canonical Stage 1 / Stage 2 unit records
  (``results`` list) via the ``results_path`` keyword — the old
  ``pipeline_output_path`` / ``findings`` shape is gone.
- Only units with Stage 1 ``decision=candidate`` AND full canonical Stage 2
  (``execution_state=succeeded``, ``decision=confirmed``, ``finding_id``,
  resolvable ``evidence[]``) are eligible; legacy ``stage2_verdict``-only
  records are skipped.
- Writes ``dynamic_test_results.json`` into ``output_dir`` and never mutates
  the input results file.
"""

import json


def _results_file(tmp_path, units):
    path = tmp_path / "results.json"
    path.write_text(
        json.dumps({"dataset": "test", "results": units}),
        encoding="utf-8",
    )
    return path


def test_core_dynamic_tester_skips_verdict_only(tmp_path, monkeypatch):
    from core import dynamic_tester

    results_path = _results_file(
        tmp_path,
        [{"unit_id": "a.py:foo", "id": "VULN-001", "stage2_verdict": "confirmed"}],
    )
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    monkeypatch.setattr(dynamic_tester.shutil, "which", lambda name: "/usr/bin/docker")

    result = dynamic_tester.run_tests(
        results_path=str(results_path),
        output_dir=str(output_dir),
        max_retries=0,
    )
    assert result.candidates_input == 0
    data = json.loads(
        (output_dir / "dynamic_test_results.json").read_text(encoding="utf-8")
    )
    assert data["metrics"]["candidates_input"] == 0
    assert data["results"] == []


def test_core_dynamic_tester_runs_canonical_confirmed(tmp_path, monkeypatch):
    from core import dynamic_tester

    unit = {
        "unit_id": "a.py:foo",
        "decision": "candidate",
        "location": {"file": "a.py", "function": "a.py:foo"},
        "preconditions": [],
        "stage2_verification": {
            "finding_id": "fid",
            "execution_state": "succeeded",
            "decision": "confirmed",
            "evidence_ids": ["ev1"],
            "evidence": [{"evidence_id": "ev1", "kind": "obs"}],
            "verified_source": "s",
            "propagation": "p",
            "sink": "k",
            "impact": "i",
        },
    }
    results_path = _results_file(tmp_path, [unit])
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    monkeypatch.setattr(dynamic_tester.shutil, "which", lambda name: "/usr/bin/docker")

    def fake_run_one(**kwargs):
        return {
            "test_id": "abc",
            "finding_id": "fid",
            "execution_state": "skipped",
            "decision": "inconclusive",
            "target_reached": False,
            "preconditions_satisfied": False,
            "oracle_results": {},
            "evidence_ids": [],
            "evidence": [],
            "artifacts": [],
            "attempts": [],
            "confidence": 0.0,
            "provenance": {"reason": "test"},
        }

    monkeypatch.setattr(
        "core.dynamic_verification.engine.run_one_dynamic_verification",
        fake_run_one,
    )

    result = dynamic_tester.run_tests(
        results_path=str(results_path),
        output_dir=str(output_dir),
        max_retries=0,
    )
    assert result.candidates_input == 1
    assert result.skipped == 1

    data = json.loads(
        (output_dir / "dynamic_test_results.json").read_text(encoding="utf-8")
    )
    assert data["metrics"]["candidates_input"] == 1
    assert [r["unit_id"] for r in data["results"]] == ["a.py:foo"]
    assert data["results"][0]["finding_id"] == "fid"

    # The input results JSON is consumed read-only — never mutated in place.
    source = json.loads(results_path.read_text(encoding="utf-8"))
    assert "dynamic_verification" not in source["results"][0]
    assert source["results"][0]["stage2_verification"]["decision"] == "confirmed"
