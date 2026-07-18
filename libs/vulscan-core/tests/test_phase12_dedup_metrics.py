"""Dedup is display-only: stage metrics stay undeduped; evidence_ids fold onto survivor."""

from __future__ import annotations

import json
from pathlib import Path

from core.final_artifact.evidence_index import compute_content_hash
from core.reporter import build_pipeline_output


def _ev(eid: str, text: str, source_hash: str) -> dict:
    entry = {
        "evidence_id": eid,
        "kind": "observation",
        "content": {"text": text},
    }
    entry["content_hash"] = compute_content_hash(entry)
    entry["source_artifact_hash"] = source_hash
    return entry


def test_merge_keeps_stage_metrics_and_resolves_all_evidence(tmp_path: Path):
    scan = tmp_path
    # Caller -> callee edge (resolved_edges).
    call_graph = {
        "nodes": {
            "a.py:caller": {"id": "a.py:caller"},
            "a.py:callee": {"id": "a.py:callee"},
        },
        "resolved_edges": [
            {"caller": "a.py:caller", "callee": "a.py:callee"},
        ],
    }
    (scan / "call_graph.json").write_text(json.dumps(call_graph), encoding="utf-8")

    shared = "shared-sink"
    results = {
        "dataset": "dedup-fixture",
        "metrics": {
            "total_units": 2,
            "reachable": 2,
            "unreachable": 0,
            "unknown_reachability": 0,
        },
        "results": [
            {
                "unit_id": "a.py:caller",
                "decision": "candidate",
                "finding_id": "fid-caller",
                "evidence_ids": ["ev-caller"],
                "evidence": [_ev("ev-caller", "caller", "b" * 64)],
                "stage1_detection": {
                    "unit_id": "a.py:caller",
                    "decision": "candidate",
                    "finding_id": "fid-caller",
                    "evidence_ids": ["ev-caller"],
                    "source": "src",
                    "sink": "sink",
                },
                "stage2_verification": {
                    "unit_id": "a.py:caller",
                    "finding_id": "fid-caller",
                    "execution_state": "succeeded",
                    "decision": "confirmed",
                    "evidence_ids": ["ev-caller", "ev-shared"],
                    "evidence": [
                        _ev("ev-caller", "caller", "b" * 64),
                        _ev("ev-shared", shared, "b" * 64),
                    ],
                    "source": "src",
                    "sink": "sink",
                },
                "source": "src",
                "sink": "sink",
            },
            {
                "unit_id": "a.py:callee",
                "decision": "candidate",
                "finding_id": "fid-callee",
                "evidence_ids": ["ev-callee"],
                "evidence": [_ev("ev-callee", "callee", "b" * 64)],
                "stage1_detection": {
                    "unit_id": "a.py:callee",
                    "decision": "candidate",
                    "finding_id": "fid-callee",
                    "evidence_ids": ["ev-callee"],
                    "source": "src",
                    "sink": "sink",
                },
                "stage2_verification": {
                    "unit_id": "a.py:callee",
                    "finding_id": "fid-callee",
                    "execution_state": "succeeded",
                    "decision": "confirmed",
                    "evidence_ids": ["ev-callee", "ev-shared"],
                    "evidence": [
                        _ev("ev-callee", "callee", "b" * 64),
                        _ev("ev-shared", shared, "b" * 64),
                    ],
                    "source": "src",
                    "sink": "sink",
                },
                "source": "src",
                "sink": "sink",
            },
        ],
    }
    results_path = scan / "results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    out = scan / "pipeline_output.json"

    path, count, errors = build_pipeline_output(
        results_path=str(results_path),
        output_path=str(out),
        repo_name="dedup",
        language="python",
        processing_level="all",
    )
    assert not errors, errors
    art = json.loads(Path(path).read_text(encoding="utf-8"))

    # Stage metrics from undeduped stage1/stage2
    assert art["metrics"]["stage1_candidates"] == 2
    assert art["metrics"]["stage2_confirmed"] == 2

    # Display findings collapsed to 1
    assert len(art["findings"]) == 1
    assert count == 1
    survivor = art["findings"][0]
    assert survivor["unit_id"] == "a.py:caller"
    eids = set(survivor.get("evidence_ids") or [])
    assert "ev-caller" in eids
    assert "ev-callee" in eids or "ev-shared" in eids
    # All evidence_ids resolvable
    for eid in eids:
        assert eid in art["evidence_index"], eid
    prov = survivor.get("merge_provenance") or {}
    assert "a.py:callee" in (prov.get("merged_from_unit_ids") or [])
