"""Dynamic testing wrapper (Phase 12).

Consumes canonical Stage 1 DetectionResult + Stage 2 VerificationResult from
results JSON. Never reads or mutates FinalScanArtifact / pipeline_output.json.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Any

from core.schemas import DynamicTestStepResult
from core import tracking
from utilities.file_io import read_json, write_json


def _empty_metrics() -> dict[str, int]:
    return {
        "candidates_input": 0,
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "blocked": 0,
        "skipped": 0,
        "reproduced": 0,
        "not_reproduced": 0,
        "inconclusive": 0,
    }


def _tally(metrics: dict, dyn: dict) -> None:
    state = dyn.get("execution_state", "failed")
    decision = dyn.get("decision", "inconclusive")
    if state == "skipped":
        metrics["skipped"] += 1
        return
    if state == "blocked":
        metrics["blocked"] += 1
        metrics["attempted"] += 1
        metrics["inconclusive"] += 1
        return
    metrics["attempted"] += 1
    if state == "succeeded":
        metrics["succeeded"] += 1
    elif state == "failed":
        metrics["failed"] += 1
    if decision == "reproduced":
        metrics["reproduced"] += 1
    elif decision == "not_reproduced":
        metrics["not_reproduced"] += 1
    else:
        metrics["inconclusive"] += 1


def _stage1_from_unit(unit: dict[str, Any]) -> dict[str, Any]:
    """Extract canonical Stage 1 DetectionResult fields only — no fallback synthesis."""
    if isinstance(unit.get("stage1_detection"), dict):
        return dict(unit["stage1_detection"])
    # Analyzer writes Stage 1 fields at the unit root with decision=candidate
    return {
        "unit_id": unit.get("unit_id") or unit.get("route_key") or "",
        "decision": unit.get("decision") or "",
        "candidate_type": unit.get("candidate_type"),
        "cwe_id": unit.get("cwe_id") or 0,
        "cwe_name": unit.get("cwe_name"),
        "location": unit.get("location") or {},
        "source": unit.get("source") or "",
        "propagation": unit.get("propagation") or "",
        "sink": unit.get("sink") or "",
        "impact": unit.get("impact") or "",
        "preconditions": unit.get("preconditions") or [],
        "evidence_ids": unit.get("evidence_ids") or [],
        "evidence": unit.get("evidence") or [],
        "confidence": unit.get("confidence"),
        "provenance": unit.get("provenance") or {},
    }


def _is_dynamic_eligible_unit(unit: dict[str, Any]) -> bool:
    """Stage 1 candidate + Stage 2 succeeded+confirmed with finding_id + evidence."""
    s1 = _stage1_from_unit(unit)
    if s1.get("decision") != "candidate":
        return False
    s2 = unit.get("stage2_verification")
    if not isinstance(s2, dict):
        return False
    if s2.get("execution_state") != "succeeded" or s2.get("decision") != "confirmed":
        return False
    if not s2.get("finding_id"):
        return False
    evidence = s2.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return False
    return any(isinstance(e, dict) and e.get("evidence_id") for e in evidence)


def _canonical_dynamic_record(dyn: dict[str, Any], *, unit_id: str) -> dict[str, Any]:
    """Flatten dynamic result — never nest under legacy status."""
    return {
        "unit_id": unit_id or dyn.get("unit_id") or "",
        "finding_id": dyn.get("finding_id") or "",
        "test_id": dyn.get("test_id") or "",
        "execution_state": dyn.get("execution_state") or "failed",
        "decision": dyn.get("decision") or "inconclusive",
        "evidence_ids": list(dyn.get("evidence_ids") or []),
        "evidence": list(dyn.get("evidence") or []),
        "artifacts": list(dyn.get("artifacts") or []),
        "attempts": list(dyn.get("attempts") or []),
        "provenance": dict(dyn.get("provenance") or {}),
        "target_reached": dyn.get("target_reached"),
        "preconditions_satisfied": dyn.get("preconditions_satisfied"),
        "precondition_results": dyn.get("precondition_results"),
        "oracle_results": dyn.get("oracle_results"),
        "confidence": dyn.get("confidence"),
        "reason": (dyn.get("provenance") or {}).get("reason") or dyn.get("reason"),
    }


def run_tests(
    *,
    results_path: str,
    output_dir: str,
    max_retries: int = 3,
    repo_path: str | None = None,
    project_name: str | None = None,
    language: str | None = None,
    dataset_path: str | None = None,
) -> DynamicTestStepResult:
    """Run dynamic verification from Stage 1/2 results — not FinalScanArtifact."""
    del dataset_path  # reserved for future unit/code lookup; engine uses repo_path
    if not shutil.which("docker"):
        raise RuntimeError(
            "Docker is required for dynamic testing but was not found. "
            "Install Docker and ensure it is running."
        )

    if not os.path.exists(results_path):
        raise FileNotFoundError(f"results JSON not found: {results_path}")

    os.makedirs(output_dir, exist_ok=True)

    experiment = read_json(results_path)
    units = experiment.get("results") or []
    eligible = [u for u in units if isinstance(u, dict) and _is_dynamic_eligible_unit(u)]
    metrics = _empty_metrics()
    metrics["candidates_input"] = len(eligible)

    print(
        f"[Dynamic Test] {len(eligible)} Stage-2-confirmed units eligible "
        f"(out of {len(units)} results)",
        file=sys.stderr,
    )

    results_out = os.path.join(output_dir, "dynamic_test_results.json")
    if not eligible:
        write_json(
            results_out,
            {
                "schema_version": "1.0",
                "repository": project_name or experiment.get("dataset", "unknown"),
                "total_units": len(units),
                "metrics": metrics,
                "total_cost_usd": 0.0,
                "results": [],
            },
        )
        return DynamicTestStepResult(
            results_json_path=results_out,
            candidates_input=0,
            usage=tracking.get_usage(),
        )

    from core.dynamic_verification.checkpoint import DynamicCheckpointManager
    from core.dynamic_verification.engine import run_one_dynamic_verification
    from utilities.llm_client import get_global_tracker

    checkpoint = DynamicCheckpointManager(
        os.path.join(output_dir, "dynamic_verification_checkpoints")
    )
    checkpoint.ensure_dir()
    tracker = get_global_tracker()
    repo_name = project_name or experiment.get("dataset", "unknown")
    lang = language or ""

    dyn_results: list[dict[str, Any]] = []
    for unit in eligible:
        s1 = _stage1_from_unit(unit)
        s2 = dict(unit["stage2_verification"])
        unit_id = (
            s1.get("unit_id")
            or unit.get("unit_id")
            or unit.get("route_key")
            or ""
        )
        s2.setdefault("unit_id", unit_id)

        dyn = run_one_dynamic_verification(
            stage1_result=s1,
            stage2_result=s2,
            finding=None,
            unit=unit,
            language=lang,
            repo_path=repo_path or "",
            repo_name=repo_name,
            checkpoint=checkpoint,
            tracker=tracker,
            max_infra_retries=max(0, max_retries - 1),
            execute=True,
        )
        record = _canonical_dynamic_record(dyn, unit_id=unit_id)
        _tally(metrics, record)
        dyn_results.append(record)

    write_json(
        results_out,
        {
            "schema_version": "1.0",
            "repository": repo_name,
            "total_units": len(units),
            "metrics": metrics,
            "total_cost_usd": getattr(tracker, "total_cost_usd", 0.0)
            if hasattr(tracker, "total_cost_usd")
            else 0.0,
            "results": dyn_results,
        },
    )

    tracking.log_usage("Dynamic Test")
    print(f"\n[Dynamic Test] Metrics: {metrics}", file=sys.stderr)

    return DynamicTestStepResult(
        results_json_path=results_out,
        results_md_path=None,
        candidates_input=metrics["candidates_input"],
        attempted=metrics["attempted"],
        succeeded=metrics["succeeded"],
        failed=metrics["failed"],
        blocked=metrics["blocked"],
        skipped=metrics["skipped"],
        reproduced=metrics["reproduced"],
        not_reproduced=metrics["not_reproduced"],
        inconclusive=metrics["inconclusive"],
        usage=tracking.get_usage(),
    )
